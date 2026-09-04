"""Minimal synchronous Cursor AgentService client using HTTP/1.1 compatibility RPC.

Single-file stdlib-only library: protobuf wire codec, Connect/SSE transport,
and stateless Cursor Agent client.

Runtime-reported native tools for composer-2.5:
    ExecServerMessage, Shell, Grep, Delete, WebSearch, WebFetch,
    GenerateImage, ReadLints, EditNotebook, TodoWrite, StrReplace, Write,
    Read, Glob, AskQuestion, Task, Await, ListMcpResources,
    FetchMcpResource, SwitchMode.

This model-reported inventory is distinct from the complete protobuf
ExecServerMessage oneof enumeration in EXEC_SERVER_TOOL_FIELDS.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import errno
import fcntl
import gzip
import hashlib
import json
import logging
import os
import selectors
import tempfile
import socket
import ssl
import struct
import threading
import time
from types import MappingProxyType
from typing import Mapping
import uuid
from urllib.parse import urljoin, urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import codec as cursor_schema

log = logging.getLogger("cursor_transport")


# === Configuration globals ===

DEFAULT_BASE_URL = "https://api2.cursor.sh"
DEFAULT_CLIENT_VERSION = "cli-2026.07.08-0c04a8a"
DEFAULT_TIMEOUT = 30 * 60
KEY_EXCHANGE_TIMEOUT = 30
HEARTBEAT_TIMEOUT = 30
POST_BLOB_PROGRESS_TIMEOUT = 30
INITIAL_MODEL_PROGRESS_TIMEOUT = 30
BIDI_APPEND_PIPELINE_DEPTH = 8
RESPONSE_USAGE_GRACE_TIMEOUT = 3
USAGE_LOOKUP_ATTEMPTS = 4
USAGE_LOOKUP_RETRY_DELAY = 1
USAGE_LOOKUP_WINDOW_MS = 5_000



# Content-addressed session router. model -> {conversation_id: session}, where a
# session records the turn keys of the last graph served on that envelope. Long
# lived gateway processes keep this in memory; entries expire lazily under the
# lock so a code-agent session that goes idle stops attracting routes.
_CURSOR_SESSIONS: dict[str, dict[str, dict]] = {}
_CURSOR_SESSION_LOCK = threading.Lock()
_CURSOR_SESSION_IDLE_SECONDS = 60 * 60
# Bound on branches tracked per envelope. Branch retention is server-side and
# unmeasured; this only bounds client-side scoring cost.
_CURSOR_SESSION_MAX_BRANCHES = 32

# Envelopes with a run in flight, keyed (model, conversation_id). Only one
# request may run on an envelope at a time: routing skips busy envelopes, so a
# concurrent colliding request gets a fresh envelope, and the shared prefix is
# recovered from server-side cache on a later non-concurrent request.
_CURSOR_ENVELOPE_BUSY: set[tuple[str, str]] = set()

KEY_EXCHANGE_URL = "https://api2.cursor.sh/auth/exchange_user_api_key"
AUTH_CACHE_PATH = os.path.expanduser(
    os.environ.get("CURSOR_AUTH_CACHE_PATH") or "~/.cursor/auth-cache.json"
)
AUTH_LOCK_PATH = os.path.expanduser(
    os.environ.get("CURSOR_AUTH_LOCK_PATH") or "~/.cursor/auth-cache.lock"
)
ACCESS_TOKEN_LIFETIME = 60 * 60
ACCESS_TOKEN_REFRESH_MARGIN = 5 * 60
AGENT_RUNSSE_PATH = "agent.v1.AgentService/RunSSE"
BIDI_APPEND_PATH = "aiserver.v1.BidiService/BidiAppend"
FILTERED_USAGE_PATH = "aiserver.v1.DashboardService/GetFilteredUsageEvents"
AVAILABLE_MODELS_PATH = "aiserver.v1.AiService/AvailableModels"

# Cursor uses this identifier for inference routing/cache affinity.
# A code-agent process represents one conversation session.
_SESSION_CONVERSATION_ID = str(uuid.uuid4())

# Turn fields f4 (encrypted_model, optional string) and f5
# (dynamic_tool_count, optional uint32) are never populated by the shipped
# Cursor client. We once synthesized a turn-token UUID and a 0/1 complete flag
# there; live A/B on 2026-08-04 showed omitting them is identical across
# pure-text recall, native tool calls, and multi-turn interleaved tool calls,
# at slightly lower input tokens, so the affirmative path was deleted.

# resumeAction wire bytes: ConversationAction{resumeAction{}} - the semantic
# mid-turn resume action proven to continue inference from a checkpoint graph.
_RESUME_ACTION_BYTES = bytes.fromhex("12021200")

# Harmless nonce used solely to register a fresh conversation envelope; supplied
# synthetic state supersedes it on every real call.
_REGISTRATION_PROMPT = (
    "Reply with exactly the word ok and nothing else. Do not use any tools."
)

# conversation_id -> True once a userMessageAction Run has registered the envelope
# server-side. Guarded by a lock; this transport is synchronous so check-and-set
# under the lock is sufficient for concurrency safety.
_REGISTERED_CONVERSATIONS: dict[tuple[str, str], bool] = {}
_REGISTRATION_LOCK = threading.Lock()


def _registration_envelope_key(
    conversation_id: str, conversation_group_id: str | None
) -> tuple[str, str]:
    """Registry identity for a conversation envelope: (id, groupId) pair.

    The server treats conversationId and conversationGroupId as independent
    registration axes (distinct explicit groups are supported), so both must
    match before a checkpoint resume is attempted without re-registering."""
    return (conversation_id, conversation_group_id or conversation_id)

DEBUG = False


def _debug_bidi_event(event: str, **details) -> None:
    if not DEBUG:
        return
    record = {
        "timestamp_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "event": event,
        **details,
    }
    path = f"/tmp/coda-cursor-bidi-{_SESSION_CONVERSATION_ID[:8]}.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        pass


# === Message classification ===


NATIVE_EXEC_FIELD_NAMES = {
    2: "shell_args", 3: "write_args", 4: "delete_args", 5: "grep_args",
    7: "read_args", 8: "ls_args", 9: "diagnostics_args",
    10: "request_context_args", 14: "shell_stream_args",
    16: "background_shell_spawn_args", 17: "list_mcp_resources_exec_args",
    18: "read_mcp_resource_exec_args", 20: "fetch_args",
    21: "record_screen_args", 22: "computer_use_args",
    23: "write_shell_stdin_args", 27: "execute_hook_args",
    28: "subagent_args", 29: "redacted_read_args",
    30: "force_background_shell_args", 31: "force_background_subagent_args",
    36: "mcp_state_exec_args", 37: "subagent_await_args",
    38: "smart_mode_classifier_args", 40: "canvas_diagnostics_args",
    41: "shell_allowlist_precheck_args", 42: "mcp_allowlist_precheck_args",
    43: "web_fetch_allowlist_precheck_args", 44: "git_diff_request",
    45: "pi_read_args", 46: "pi_bash_args", 47: "pi_edit_args",
    48: "pi_write_args", 49: "pi_grep_args", 50: "pi_find_args",
    51: "pi_ls_args", 53: "conversation_search_args",
}

NATIVE_TOOL_PREFIX = "native_"



@dataclass(frozen=True, slots=True)
class ConnectFrame:
    """A Connect frame whose wire_payload is exactly the bytes after its header."""

    flags: int
    wire_payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.flags, int) or not 0 <= self.flags <= 0xff:
            raise ValueError("flags must be an integer in 0..255")
        if not isinstance(self.wire_payload, bytes):
            raise TypeError("wire_payload must be bytes")

    @property
    def compressed(self) -> bool:
        return bool(self.flags & 1)

    @property
    def eos(self) -> bool:
        return bool(self.flags & 2)

    @property
    def decoded_payload(self) -> bytes:
        return gzip.decompress(self.wire_payload) if self.compressed else self.wire_payload

    @classmethod
    def from_decoded(cls, payload: bytes, *, flags: int = 0, compress: bool = False) -> "ConnectFrame":
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if compress:
            flags |= 1
            return cls(flags, gzip.compress(payload, mtime=0))
        if flags & 1:
            raise ValueError("compressed flag requires compress=True or precompressed wire_payload")
        return cls(flags, payload)

    def encode(self) -> bytes:
        return bytes((self.flags,)) + len(self.wire_payload).to_bytes(4, "big") + self.wire_payload

    def __repr__(self) -> str:
        return f"ConnectFrame(flags=0x{self.flags:02x}, wire_payload=0x{self.wire_payload.hex()})"






@dataclass(frozen=True, slots=True, repr=False)
class CursorMessage:
    """A decoded Run_res / AgentClientMessage envelope plus its classification."""

    decoded: dict
    classification: str
    direction: str

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"classification={self.classification!r}, "
            f"direction={self.direction!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeExec(CursorMessage):
    field_number: int
    subtype: str
    arguments: dict


@dataclass(frozen=True, slots=True, repr=False)
class LiveMCPCall(CursorMessage):
    server_message_id: int
    execution_id: bytes
    tool_call_id: str
    name: str
    provider_identifier: str
    tool_name: str
    server_identifier: str
    arguments: dict


@dataclass(frozen=True, slots=True, repr=False)
class CompletedMCPUpdate(CursorMessage):
    tool_call_id: str
    name: str
    provider_identifier: str
    tool_name: str
    arguments: dict


@dataclass(frozen=True, slots=True, repr=False)
class AnswerText(CursorMessage):
    text: str


@dataclass(frozen=True, slots=True, repr=False)
class InteractionUpdate(CursorMessage):
    subtype_number: int
    subtype: str
    update: object


@dataclass(frozen=True, slots=True, repr=False)
class AgentExecMessage(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class CheckpointUpdate(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class KVServerMessage(CursorMessage):
    subtype: str




@dataclass(frozen=True, slots=True, repr=False)
class InteractionQuery(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class RunRequest(CursorMessage):
    pass

@dataclass(frozen=True, slots=True, repr=False)
class ClientHeartbeat(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class ClientExecMessage(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class KVResponse(CursorMessage):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class Control(CursorMessage):
    pass


def classify(payload: bytes, direction: str) -> CursorMessage:
    direction = direction.upper()
    if direction not in ("IN", "OUT"):
        raise ValueError("direction must be IN or OUT")
    message_type = "AgentClientMessage" if direction == "OUT" else "Run_res"
    decoded = cursor_schema.decode(payload, message_type)

    def make(kind, name, *extra):
        return kind(decoded, name, direction, *extra)

    if direction == "OUT":
        for key, kind, name in (
            ("runRequest", RunRequest, "agent_client.run_request"),
            ("execClientMessage", ClientExecMessage, "agent_client.exec_message"),
            ("kvClientMessage", KVResponse, "agent_client.kv_response"),
            ("execClientControlMessage", Control, "agent_client.control"),
            ("conversationAction", Control, "agent_client.control"),
        ):
            if key in decoded:
                return make(kind, name)
        if "clientHeartbeat" in decoded:
            return make(ClientHeartbeat, "agent_client.heartbeat")
        return make(CursorMessage, "unknown")

    interaction = decoded.get("interactionUpdate")
    if interaction:
        for field in cursor_schema.MESSAGES["InteractionUpdate"]:
            if field.name not in interaction:
                continue
            subtype = _snake(field.name)
            value = interaction[field.name]
            if field.name == "textDelta":
                return make(
                    AnswerText,
                    "agent_server.answer_text",
                    value.get("text", "") if isinstance(value, dict) else "",
                )
            return make(
                InteractionUpdate,
                f"agent_server.interaction_update.{subtype}",
                field.num,
                subtype,
                value,
            )
        return make(
            InteractionUpdate,
            "agent_server.interaction_update.unclassified",
            0,
            "unclassified",
            {},
        )

    execution = decoded.get("execServerMessage")
    if execution:
        for field in cursor_schema.MESSAGES["ExecServerMessage"]:
            if field.name not in execution or field.num in (1, 15):
                continue
            if field.num in (19, 55):
                # span_context (19) / accept_hook_additional_contexts (55):
                # metadata we intentionally do not surface; notice instead of
                # silent skip so unexpected payload shapes are visible.
                log.info(
                    "execServerMessage carries %s (f%d); not surfaced",
                    field.name, field.num,
                )
                continue
            value = execution[field.name]
            if field.name == "mcpArgs":
                return _live_mcp_from_schema(
                    decoded, execution, value, direction
                )
            subtype = NATIVE_EXEC_FIELD_NAMES.get(field.num)
            if subtype is None:
                continue
            return make(
                NativeExec,
                f"agent_server.native_exec.{subtype}",
                field.num,
                subtype,
                value,
            )
        return make(AgentExecMessage, "agent_server.exec_message.unclassified")

    if "conversationCheckpointUpdate" in decoded:
        return make(CheckpointUpdate, "agent_server.conversation_checkpoint_update")
    kv = decoded.get("kvServerMessage")
    if kv is not None:
        subtype = (
            "get_blob_args" if "getBlobArgs" in kv else
            "set_blob_args" if "setBlobArgs" in kv else
            "unclassified"
        )
        return make(
            KVServerMessage,
            f"agent_server.kv_server_message.{subtype}",
            subtype,
        )
    return make(CursorMessage, "unknown")


def decode_cursor_payload(payload: bytes, direction: str) -> CursorMessage:
    return classify(payload, direction)


def _snake(name: str) -> str:
    return "".join(
        ("_" + char.lower()) if char.isupper() else char
        for char in name
    ).lstrip("_")


def _live_mcp_from_schema(
    decoded, execution, args, direction,
) -> LiveMCPCall:
    name = args.get("name") or args.get("toolName") or "mcp"
    return LiveMCPCall(
        decoded,
        f"agent_server.mcp_exec.{name}",
        direction,
        execution.get("id", 0),
        execution.get("execId", "").encode(),
        args.get("toolCallId") or execution.get("execId", ""),
        name,
        args.get("providerIdentifier", ""),
        args.get("toolName") or name,
        args.get("serverIdentifier", ""),
        args,
    )


def parse_eos_metadata(payload: bytes) -> tuple[object | None, str | None]:
    if not payload or not payload.strip():
        return None, None
    try:
        metadata = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed Connect EOS JSON payload") from exc
    if not isinstance(metadata, dict):
        raise ValueError("Connect EOS metadata must be a JSON object")
    error = metadata.get("error")
    if error is None:
        return metadata, None
    if not isinstance(error, dict):
        return metadata, str(error)
    for detail in error.get("details", ()):
        if not isinstance(detail, dict):
            continue
        details = detail.get("debug", {}).get("details", {})
        if isinstance(details, dict):
            title = details.get("title", "")
            text = details.get("detail", "")
            if title or text:
                return metadata, " ".join(part for part in (title, text) if part)
    return metadata, str(error.get("message") or error)


@dataclass(frozen=True, slots=True)
class CursorFrame:
    connect: ConnectFrame
    direction: str
    classification: str
    message: CursorMessage | None
    eos_metadata: object | None = None
    eos_error: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        direction = self.direction.upper()
        if direction not in ("IN", "OUT"):
            raise ValueError("direction must be IN or OUT")
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if self.connect.eos and self.classification != "connect_end_stream":
            raise ValueError("EOS frame classification must be connect_end_stream")
        if not self.connect.eos and self.message is None:
            raise ValueError("non-EOS frame requires a message")

    @classmethod
    def decode(cls, connect: ConnectFrame, direction: str,
               metadata: Mapping[str, object] | None = None) -> "CursorFrame":
        payload = connect.decoded_payload
        if connect.eos:
            eos_metadata, eos_error = parse_eos_metadata(payload)
            return cls(connect, direction, "connect_end_stream", None,
                       eos_metadata, eos_error, metadata or {})
        message = decode_cursor_payload(payload, direction)
        return cls(connect, direction, message.classification, message,
                   metadata=metadata or {})

    @property
    def flags(self) -> int:
        return self.connect.flags

    @property
    def wire_payload(self) -> bytes:
        return self.connect.wire_payload

    @property
    def decoded_payload(self) -> bytes:
        return self.connect.decoded_payload

    def encode_connect(self) -> bytes:
        return self.connect.encode()




# === Connect/SSE transport ===




class SSEError(Exception):
    pass




class _PostPipeline:
    def __init__(self, client, parts):
        self.client = client
        self.selector = client.selector
        self.parts = parts
        self.port = self.parts.port or (
            443 if self.parts.scheme == "https" else 80
        )
        self.sock = None
        self.connected = False
        self.tls_handshake_done = False
        self.outgoing = bytearray()
        self.incoming = bytearray()
        self.pending = deque()
        self.closed = False
        self._reset_response()
        self._connect()

    def _reset_response(self):
        self.response_body = bytearray()
        self.headers_done = False
        self.status = None
        self.response_headers = {}
        self.chunked = False
        self.content_remaining = None
        self.chunk_remaining = None

    def _connect(self):
        addresses = socket.getaddrinfo(
            self.parts.hostname,
            self.port,
            type=socket.SOCK_STREAM,
        )
        last_error = None
        for family, socktype, proto, _, address in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            error = sock.connect_ex(address)
            if error in (
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
            ):
                self.sock = sock
                break
            last_error = OSError(
                error, errno.errorcode.get(error, "connect")
            )
            sock.close()
        else:
            raise last_error or SSEError("No usable address found")

        self.selector.register(
            self.sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
            self,
        )

    def _finish_connect(self):
        error = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, errno.errorcode.get(error, "connect"))
        self.connected = True

        if self.parts.scheme == "https":
            self.selector.unregister(self.sock)
            context = self.client.ssl_context or ssl.create_default_context()
            self.sock = context.wrap_socket(
                self.sock,
                server_hostname=self.parts.hostname,
                do_handshake_on_connect=False,
            )
            self.sock.setblocking(False)
            self.selector.register(
                self.sock,
                selectors.EVENT_READ | selectors.EVENT_WRITE,
                self,
            )
        else:
            self.tls_handshake_done = True

    def _do_tls_handshake(self):
        try:
            self.sock.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return
        self.tls_handshake_done = True

    def submit(self, parts, body, headers, callback):
        if self.closed:
            raise SSEError("Uplink pipeline is closed")
        body = bytes(body)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query

        default_port = 443 if self.parts.scheme == "https" else 80
        host = self.parts.hostname
        if self.port != default_port:
            host = f"{host}:{self.port}"

        request_headers = {
            "Host": host,
            "Content-Length": str(len(body)),
            "Content-Type": "application/octet-stream",
            "User-Agent": "stdlib-sse-client/1.0",
        }
        request_headers.update(self.client.headers)
        request_headers.update(headers or {})
        request = [f"POST {target} HTTP/1.1"]
        request.extend(
            f"{name}: {value}" for name, value in request_headers.items()
        )
        request.extend(("", ""))
        self.outgoing.extend(
            "\r\n".join(request).encode("iso-8859-1") + body
        )
        self.pending.append(callback)
        self._set_interest()
        return self

    def _set_interest(self):
        if self.closed or self.sock is None:
            return
        events = selectors.EVENT_READ
        if (
            not self.connected
            or not self.tls_handshake_done
            or self.outgoing
        ):
            events |= selectors.EVENT_WRITE
        self.selector.modify(self.sock, events, self)

    def _send(self):
        if not self.outgoing:
            return
        try:
            sent = self.sock.send(self.outgoing)
            del self.outgoing[:sent]
        except (
            BlockingIOError,
            ssl.SSLWantReadError,
            ssl.SSLWantWriteError,
        ):
            pass

    def _receive(self):
        try:
            data = self.sock.recv(65536)
        except (
            BlockingIOError,
            ssl.SSLWantReadError,
            ssl.SSLWantWriteError,
        ):
            return
        if not data:
            if self.pending:
                raise SSEError(
                    "Uplink pipeline closed with responses outstanding"
                )
            self.close()
            return

        self.incoming.extend(data)
        self._parse_responses()

    def _parse_responses(self):
        while self.pending and not self.closed:
            if not self.headers_done:
                marker = self.incoming.find(b"\r\n\r\n")
                if marker < 0:
                    if len(self.incoming) > 65536:
                        raise SSEError(
                            "HTTP response headers are too large"
                        )
                    return
                raw_headers = bytes(self.incoming[:marker])
                del self.incoming[:marker + 4]
                lines = raw_headers.decode("iso-8859-1").split("\r\n")
                parts = lines[0].split(" ", 2)
                if len(parts) < 2 or not parts[1].isdigit():
                    raise SSEError(
                        f"Invalid HTTP status line: {lines[0]!r}"
                    )
                self.status = int(parts[1])
                for line in lines[1:]:
                    if ":" not in line:
                        raise SSEError(f"Invalid HTTP header: {line!r}")
                    name, value = line.split(":", 1)
                    self.response_headers[
                        name.strip().lower()
                    ] = value.strip()

                transfer_encoding = self.response_headers.get(
                    "transfer-encoding", ""
                )
                self.chunked = "chunked" in {
                    item.strip().lower()
                    for item in transfer_encoding.split(",")
                }
                content_length = self.response_headers.get(
                    "content-length"
                )
                if content_length is not None and not self.chunked:
                    try:
                        self.content_remaining = int(content_length)
                    except ValueError:
                        raise SSEError("Invalid Content-Length")
                    if self.content_remaining < 0:
                        raise SSEError("Invalid Content-Length")
                elif not self.chunked:
                    raise SSEError(
                        "Pipelined response requires Content-Length "
                        "or chunked encoding"
                    )
                self.headers_done = True

            if self.chunked:
                if not self._parse_chunked_body():
                    return
            else:
                count = min(
                    len(self.incoming), self.content_remaining
                )
                self.response_body.extend(self.incoming[:count])
                del self.incoming[:count]
                self.content_remaining -= count
                if self.content_remaining:
                    return

            self._complete_response()

    def _parse_chunked_body(self):
        while True:
            if self.chunk_remaining is None:
                marker = self.incoming.find(b"\r\n")
                if marker < 0:
                    return False
                line = bytes(self.incoming[:marker])
                del self.incoming[:marker + 2]
                try:
                    self.chunk_remaining = int(
                        line.split(b";", 1)[0], 16
                    )
                except ValueError:
                    raise SSEError("Invalid chunk size")
                if self.chunk_remaining == 0:
                    if len(self.incoming) < 2:
                        return False
                    if self.incoming[:2] != b"\r\n":
                        raise SSEError("Invalid chunk terminator")
                    del self.incoming[:2]
                    return True

            needed = self.chunk_remaining + 2
            if len(self.incoming) < needed:
                return False
            if (
                self.incoming[self.chunk_remaining:needed]
                != b"\r\n"
            ):
                raise SSEError("Invalid chunk terminator")
            self.response_body.extend(
                self.incoming[:self.chunk_remaining]
            )
            del self.incoming[:needed]
            self.chunk_remaining = None

    def _complete_response(self):
        callback = self.pending.popleft()
        response = {
            "status": self.status,
            "headers": dict(self.response_headers),
            "body": bytes(self.response_body),
        }
        closing = (
            self.response_headers.get("connection", "").lower()
            == "close"
        )
        self._reset_response()
        if closing:
            if self.pending:
                raise SSEError(
                    "Uplink closed with pipelined responses outstanding"
                )
            self.close()
        if callback is not None:
            callback(response)

    def run(self, mask):
        if self.closed or self.sock is None:
            return
        if not self.connected:
            self._finish_connect()
        if self.closed or self.sock is None:
            return
        if not self.tls_handshake_done:
            self._do_tls_handshake()
        else:
            if mask & selectors.EVENT_WRITE:
                self._send()
            if (
                not self.closed
                and self.sock is not None
                and mask & selectors.EVENT_READ
            ):
                self._receive()
        if not self.closed and self.sock is not None:
            self._set_interest()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.sock is not None:
            try:
                self.selector.unregister(self.sock)
            except (KeyError, ValueError):
                pass
            self.sock.close()
            self.sock = None
        self.client._post_pipeline_closed(self.parts, self)


class SSEClient:
    def __init__(
        self, url, callback, headers=None, timeout=None, ssl_context=None,
        stream_callback=None, accepted_content_types=("text/event-stream",),
        method="GET", body=b"", headers_callback=None,
    ):
        self.url = url
        self.callback = callback
        self.method = method.upper()
        self.request_body = bytes(body)
        if self.method not in ("GET", "POST"):
            raise ValueError("method must be GET or POST")
        self.stream_callback = stream_callback
        self.headers_callback = headers_callback
        self.accepted_content_types = tuple(
            item.lower() for item in accepted_content_types
        )
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.ssl_context = ssl_context

        self.selector = selectors.DefaultSelector()
        self.sock = None
        self.closed = False
        self.connected = False

        self._tls_handshake_done = False
        self._want_read = False
        self._want_write = True
        self._outgoing = bytearray()
        self._incoming = bytearray()
        self._body = bytearray()
        self._headers_done = False
        self._chunked = False
        self._content_remaining = None
        self._chunk_remaining = None
        self._chunk_finished = False
        self._event_lines = []
        self.last_event_id = None
        self.retry = None
        self._idle_post_connections = {}
        self._post_pipelines = {}
        self._grace_deadline = None
        self._post_blob_deadline = None
        self._post_blob_debug = {}

        self._parts = urlsplit(url)
        if self._parts.scheme not in ("http", "https"):
            raise ValueError("URL scheme must be http or https")
        if not self._parts.hostname:
            raise ValueError("URL must include a hostname")

        self._port = self._parts.port or (
            443 if self._parts.scheme == "https" else 80
        )
        self._connect()

    def _connect(self):
        addresses = socket.getaddrinfo(
            self._parts.hostname,
            self._port,
            type=socket.SOCK_STREAM,
        )
        last_error = None

        for family, socktype, proto, _, address in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            error = sock.connect_ex(address)
            if error in (
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
            ):
                self.sock = sock
                break
            last_error = OSError(error, errno.errorcode.get(error, "connect"))
            sock.close()
        else:
            raise last_error or SSEError("No usable address found")

        self.selector.register(
            self.sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
            self,
        )

    def _finish_connect(self):
        error = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, errno.errorcode.get(error, "connect"))

        self.connected = True

        if self._parts.scheme == "https":
            self.selector.unregister(self.sock)
            context = self.ssl_context or ssl.create_default_context()
            self.sock = context.wrap_socket(
                self.sock,
                server_hostname=self._parts.hostname,
                do_handshake_on_connect=False,
            )
            self.sock.setblocking(False)
            self.selector.register(
                self.sock,
                selectors.EVENT_READ | selectors.EVENT_WRITE,
                self,
            )
        else:
            self._tls_handshake_done = True
            self._prepare_request()

    def _do_tls_handshake(self):
        try:
            self.sock.do_handshake()
        except ssl.SSLWantReadError:
            self._want_read = True
            self._want_write = False
            return
        except ssl.SSLWantWriteError:
            self._want_read = False
            self._want_write = True
            return

        self._tls_handshake_done = True
        self._want_read = False
        self._want_write = True
        self._prepare_request()

    def _prepare_request(self):
        target = self._parts.path or "/"
        if self._parts.query:
            target += "?" + self._parts.query

        default_port = 443 if self._parts.scheme == "https" else 80
        host = self._parts.hostname
        if self._port != default_port:
            host = f"{host}:{self._port}"

        headers = {
            "Host": host,
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "User-Agent": "stdlib-sse-client/1.0",
        }
        if self.method == "POST":
            headers["Content-Length"] = str(len(self.request_body))
        headers.update(self.headers)
        if self.last_event_id is not None:
            headers.setdefault("Last-Event-ID", self.last_event_id)

        request = [f"{self.method} {target} HTTP/1.1"]
        request.extend(f"{name}: {value}" for name, value in headers.items())
        request.extend(("", ""))
        self._outgoing.extend(
            "\r\n".join(request).encode("iso-8859-1") + self.request_body
        )

    def _set_interest(self):
        if self.closed:
            return
        events = selectors.EVENT_READ
        if (
            not self.connected
            or not self._tls_handshake_done
            or self._outgoing
        ):
            events |= selectors.EVENT_WRITE
        self.selector.modify(self.sock, events, self)

    def _send(self):
        if not self._outgoing:
            return
        try:
            sent = self.sock.send(self._outgoing)
            del self._outgoing[:sent]
        except (BlockingIOError, ssl.SSLWantWriteError):
            pass
        except ssl.SSLWantReadError:
            pass

    def _receive(self):
        try:
            data = self.sock.recv(65536)
            if DEBUG:
                with open(f"/tmp/coda-cursor-protobuf-{_SESSION_CONVERSATION_ID[:8]}.log",'ab') as f:
                    f.write(data)
        except (BlockingIOError, ssl.SSLWantReadError):
            return
        except ssl.SSLWantWriteError:
            return

        if not data:
            if self._event_lines:
                self._dispatch_event()
            self.close()
            return

        self._incoming.extend(data)
        if not self._headers_done:
            self._parse_headers()
        if self._headers_done:
            self._parse_body()

    def _parse_headers(self):
        marker = self._incoming.find(b"\r\n\r\n")
        if marker < 0:
            if len(self._incoming) > 65536:
                raise SSEError("HTTP response headers are too large")
            return

        raw_headers = bytes(self._incoming[:marker])
        del self._incoming[:marker + 4]
        lines = raw_headers.decode("iso-8859-1").split("\r\n")

        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise SSEError(f"Invalid HTTP status line: {lines[0]!r}")

        status = int(parts[1])
        if status != 200:
            raise SSEError(f"SSE request returned HTTP {status}")

        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                raise SSEError(f"Invalid HTTP header: {line!r}")
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        content_type = headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type not in self.accepted_content_types:
            raise SSEError(f"Unexpected Content-Type: {content_type!r}")

        transfer_encoding = headers.get("transfer-encoding", "")
        self._chunked = "chunked" in {
            item.strip().lower() for item in transfer_encoding.split(",")
        }

        content_length = headers.get("content-length")
        if content_length is not None and not self._chunked:
            try:
                self._content_remaining = int(content_length)
            except ValueError:
                raise SSEError("Invalid Content-Length")

        self._headers_done = True
        if self.headers_callback is not None:
            self.headers_callback(status, dict(headers))

    def _parse_body(self):
        if self._chunked:
            self._parse_chunked_body()
            return

        if self._content_remaining is None:
            if self._incoming:
                self._feed_sse(bytes(self._incoming))
                self._incoming.clear()
            return

        count = min(len(self._incoming), self._content_remaining)
        if count:
            self._feed_sse(bytes(self._incoming[:count]))
            del self._incoming[:count]
            self._content_remaining -= count
        if self._content_remaining == 0:
            self.close()

    def _parse_chunked_body(self):
        while not self._chunk_finished:
            if self._chunk_remaining is None:
                marker = self._incoming.find(b"\r\n")
                if marker < 0:
                    return
                line = bytes(self._incoming[:marker])
                del self._incoming[:marker + 2]
                size_text = line.split(b";", 1)[0]
                try:
                    self._chunk_remaining = int(size_text, 16)
                except ValueError:
                    raise SSEError("Invalid chunk size")
                if self._chunk_remaining == 0:
                    self._chunk_finished = True
                    self.close()
                    return

            needed = self._chunk_remaining + 2
            if len(self._incoming) < needed:
                return
            if self._incoming[self._chunk_remaining:needed] != b"\r\n":
                raise SSEError("Invalid chunk terminator")

            data = bytes(self._incoming[:self._chunk_remaining])
            del self._incoming[:needed]
            self._chunk_remaining = None
            self._feed_sse(data)

    def _feed_sse(self, data):
        if self.stream_callback is not None:
            self.stream_callback(data)
            return
        self._body.extend(data)
        while True:
            newline = self._body.find(b"\n")
            if newline < 0:
                return
            raw_line = bytes(self._body[:newline])
            del self._body[:newline + 1]
            if raw_line.endswith(b"\r"):
                raw_line = raw_line[:-1]
            line = raw_line.decode("utf-8", errors="replace")
            if line == "":
                self._dispatch_event()
            else:
                self._event_lines.append(line)

    def _dispatch_event(self):
        data_lines = []
        event_type = None
        event_id = None
        retry = None

        for line in self._event_lines:
            if line.startswith(":"):
                continue

            if ":" in line:
                field, value = line.split(":", 1)
                if value.startswith(" "):
                    value = value[1:]
            else:
                field, value = line, ""

            if field == "data":
                data_lines.append(value)
            elif field == "event":
                event_type = value
            elif field == "id" and "\x00" not in value:
                event_id = value
            elif field == "retry" and value.isdigit():
                retry = int(value)

        self._event_lines.clear()

        if event_id is not None:
            self.last_event_id = event_id
        if retry is not None:
            self.retry = retry

        if not data_lines:
            return

        event = {
            "data": "\n".join(data_lines),
            "event": event_type or "message",
        }
        if event_id is not None:
            event["id"] = event_id
        if retry is not None:
            event["retry"] = retry
        self.callback(event)

    @staticmethod
    def _post_connection_key(parts):
        return (
            parts.scheme,
            parts.hostname,
            parts.port or (443 if parts.scheme == "https" else 80),
        )



    def _post_pipeline_closed(self, parts, pipeline):
        key = self._post_connection_key(parts)
        if self._post_pipelines.get(key) is pipeline:
            del self._post_pipelines[key]

    def post(self, url, body=b"", headers=None, callback=None):
        """Pipeline a POST request on the origin's HTTP/1.1 connection."""
        if self.closed:
            raise SSEError("SSE client is closed")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("URL scheme must be http or https")
        if not parts.hostname:
            raise ValueError("URL must include a hostname")
        key = self._post_connection_key(parts)
        pipeline = self._post_pipelines.get(key)
        if pipeline is None or pipeline.closed:
            pipeline = _PostPipeline(self, parts)
            self._post_pipelines[key] = pipeline
        return pipeline.submit(parts, body, headers, callback)

    def run_once(self, timeout=None):
        if self.closed:
            return False

        wait = self.timeout if timeout is None else timeout
        for key, mask in self.selector.select(wait):
            if self.closed:
                break
            handler = key.data
            if handler is self:
                if not self.connected:
                    self._finish_connect()

                if not self._tls_handshake_done:
                    self._do_tls_handshake()
                else:
                    if mask & selectors.EVENT_WRITE:
                        self._send()
                    if mask & selectors.EVENT_READ:
                        self._receive()

                if not self.closed:
                    self._set_interest()
            else:
                handler.run(mask)

        return not self.closed

    def reset_heartbeat_timeout(self):
        self._heartbeat_deadline = time.monotonic() + HEARTBEAT_TIMEOUT

    def start_grace_period(self, timeout):
        self._grace_deadline = time.monotonic() + timeout

    def arm_post_blob_timeout(self, timeout):
        self._post_blob_deadline = time.monotonic() + timeout
        details = getattr(self, "_post_blob_debug", {})
        _debug_bidi_event(
            "post_blob_timeout_armed", timeout=timeout, **details
        )

    def clear_post_blob_timeout(self):
        details = getattr(self, "_post_blob_debug", {})
        if self._post_blob_deadline is not None:
            _debug_bidi_event(
                "post_blob_timeout_cleared", **details
            )
        self._post_blob_deadline = None
        self._post_blob_debug = {}

    def run_forever(
        self, timeout=None, *, heartbeat_timeout=None,
    ):
        now = time.monotonic()
        deadline = None if timeout is None else now + timeout
        self._heartbeat_deadline = (
            None if heartbeat_timeout is None else now + heartbeat_timeout
        )
        while not self.closed:
            now = time.monotonic()
            waits = []
            if deadline is not None:
                remaining = deadline - now
                if remaining <= 0:
                    raise SSEError("request deadline exceeded")
                waits.append(remaining)
            if self._heartbeat_deadline is not None:
                remaining = self._heartbeat_deadline - now
                if remaining <= 0:
                    raise SSEError("server heartbeat timeout")
                waits.append(remaining)
            if self._grace_deadline is not None:
                remaining = self._grace_deadline - now
                if remaining <= 0:
                    self._grace_deadline = None
                    self.close()
                    break
                waits.append(remaining)
            if getattr(self, "_post_blob_deadline", None) is not None:
                remaining = self._post_blob_deadline - now
                if remaining <= 0:
                    _debug_bidi_event(
                        "post_blob_timeout_expired",
                        **getattr(self, "_post_blob_debug", {}),
                    )
                    phase = getattr(
                        self, "_post_blob_debug", {}
                    ).get("phase")
                    if phase == "initial_model_progress":
                        raise SSEError(
                            "no model progress after initial request"
                        )
                    raise SSEError(
                        "no model progress after blob hydration"
                    )
                waits.append(remaining)
            wait = min(waits) if waits else None
            if not self.run_once(wait):
                break

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.selector.unregister(self.sock)
        except (KeyError, ValueError):
            pass
        self.sock.close()
        pipelines = getattr(self, "_post_pipelines", {})
        for pipeline in tuple(pipelines.values()):
            pipeline.close()
        pipelines.clear()
        idle_connections = getattr(
            self, "_idle_post_connections", {}
        )
        for connections in idle_connections.values():
            for sock in connections:
                sock.close()
        idle_connections.clear()
        self.selector.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


# === Cursor Agent client ===


def extract_prefetched_blobs(client_payload: bytes) -> dict[bytes, bytes]:
    client = cursor_schema.decode(client_payload, "AgentClientMessage")
    run = client.get("runRequest", {})
    blobs = {
        blob["blobId"]: blob["value"]
        for blob in run.get("prefetchedBlobs", ())
        if "blobId" in blob and "value" in blob
    }
    # Raw field-17 occurrences carry PrefetchedBlob messages when supplied via
    # the unknown-field map (no named member exists in the merged schema).
    for _wire_type, raw in run.get(cursor_schema.UNKNOWN, {}).get("17", ()):
        blob = cursor_schema.decode(raw, "PrefetchedBlob")
        if "blobId" in blob and "value" in blob:
            blobs[blob["blobId"]] = blob["value"]
    return blobs


def is_generation_progress(message: CursorMessage | None) -> bool:
    if isinstance(message, AnswerText):
        return bool(message.text)
    if isinstance(message, (NativeExec, LiveMCPCall, CompletedMCPUpdate)):
        return True
    if not isinstance(message, InteractionUpdate):
        return False
    return message.subtype in {
        "text_delta",
        "tool_call_started",
        "tool_call_completed",
        "thinking_delta",
        "thinking_completed",
        "partial_tool_call",
        "token_delta",
        "tool_call_delta",
    }


def build_kv_response(server: Mapping[str, object], blobs) -> bytes | None:
    kv = server.get("kvServerMessage")
    if kv is None:
        return None
    response = {"id": kv.get("id", 0)}
    if "getBlobArgs" in kv:
        blob_id = kv["getBlobArgs"].get("blobId")
        if blob_id is None:
            return None
        result = {}
        if blob_id in blobs:
            result["_field1"] = blobs[blob_id]
        response["getBlobResult"] = result
    elif "setBlobArgs" in kv:
        response["setBlobResult"] = {}
    else:
        return None
    return cursor_schema.encode(
        {"kvClientMessage": response}, "AgentClientMessage"
    )


def is_response_boundary_blob_write(
    server: Mapping[str, object], request_id: str
) -> bool:
    try:
        kv = server.get("kvServerMessage")
        if not kv:
            return False
        set_args = kv.get("setBlobArgs")
        if not set_args:
            return False
        blob_payload = set_args.get("blobData")
        if blob_payload is None:
            return False
        blob = cursor_schema.decode(blob_payload, "_BoundaryBlob")
        structure = blob.get("structure")
        if not structure:
            return False
        unknown = structure.get(cursor_schema.UNKNOWN)
        if unknown:
            return False
        user_messages = structure.get("userMessage")
        steps = structure.get("step") or ()
        request_id_value = structure.get("requestId", "")
    except (ValueError, IndexError):
        return False

    if (
        not isinstance(user_messages, bytes)
        or len(user_messages) != 32
        or not steps
        or any(len(step) != 32 for step in steps)
    ):
        return False

    try:
        return request_id_value == request_id
    except UnicodeDecodeError:
        return False


def build_user_cancelled_message() -> bytes:
    return cursor_schema.encode(
        {"conversationAction": {"cancelAction": {"reason": "user_cancelled"}}},
        "AgentClientMessage",
    )

def _partition_native_tools(tools):
    """Split declared Cursor-native tools from MCP-encoded tool definitions.

    A tool named native_<X> declares client support for Cursor's native tool X
    and is kept out of the MCP tool list; every other tool is MCP-encoded as
    before. Returns (mcp_tools, declared_native_names)."""
    declared = set()
    mcp = []
    for tool in tools:
        name = tool.name
        if isinstance(name, str) and name.startswith(NATIVE_TOOL_PREFIX):
            declared.add(name[len(NATIVE_TOOL_PREFIX):])
        else:
            mcp.append(tool)
    return tuple(mcp), declared

def build_unsupported_native_reply(call: "ToolCall") -> bytes:
    """In-band reply telling the server an undeclared native tool is refused."""
    throw = {"error": f"unsupported native tool: {call.name}"}
    if call.server_message_id:
        throw["id"] = call.server_message_id
    return cursor_schema.encode(
        {"execClientControlMessage": {"throw": throw}},
        "AgentClientMessage",
    )


@dataclass(frozen=True)
class ConversationMessage:
    role: str
    content: str = ""
    tool_calls: tuple["ToolCall", ...] = ()
    tool_call_id: str = ""
    tool_name: str = ""


def _value_dict(value):
    if value is None:
        return {"nullValue": 0}
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, (int, float)):
        return {"numberValue": float(value)}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, dict):
        return {
            "structValue": {
                "fields": [
                    {"key": str(key), "value": _value_dict(item)}
                    for key, item in value.items()
                ]
            }
        }
    if isinstance(value, (list, tuple)):
        return {"listValue": {"values": [_value_dict(item) for item in value]}}
    return {
        "stringValue": json.dumps(value, separators=(",", ":"))
    }


def _varint_bytes(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _canonical_prefix_digest(domain: str, parts) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain.encode() + b"\0")
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _boundary_uuid(domain: str, parts) -> str:
    """Deterministic UUID-shaped id from a domain-separated prefix hash."""
    return str(uuid.UUID(bytes=_canonical_prefix_digest(domain, parts)[:16]))


def _message_prefix_parts(history, boundary: int) -> list[bytes]:
    parts = []
    for message in history[:boundary]:
        parts.append(message.role.encode())
        parts.append(message.content.encode())
        parts.append(message.tool_call_id.encode())
        parts.append(message.tool_name.encode())
        for call in message.tool_calls:
            arguments = json.dumps(
                call.arguments, separators=(",", ":"), sort_keys=True
            )
            for value in (call.id, call.name, arguments):
                encoded = value.encode()
                parts.append(len(encoded).to_bytes(8, "big"))
                parts.append(encoded)
    return parts


def completed_tool_step(
    call: "ToolCall", result: ConversationMessage | None
) -> bytes:
    """Completed tool-step blob in the live-validated structure:
    f2{f8{f1{f1 path}, f2{f1 result{...}}}, f57 toolCallId}. Timestamps are omitted
    so identical prefixes produce byte-identical blobs."""
    path = "tool-results/" + call.id
    content = result.content if result is not None else ""
    lines = content.count("\n") + 1 if content else 0
    size = len(content.encode())

    def raw(fields: dict) -> bytes:
        return cursor_schema.encode({cursor_schema.UNKNOWN: fields}, "Empty")

    result_msg = raw({
        1: [(2, content.encode())],
        4: [(0, _varint_bytes(lines))],
        5: [(0, _varint_bytes(size))],
        7: [(2, path.encode())],
        8: [(2, raw({1: [(0, b"\x01")], 2: [(0, b"\x02")]}))],
    })
    payload = raw({
        1: [(2, raw({1: [(2, path.encode())]}))],
        2: [(2, raw({1: [(2, result_msg)]}))],
    })
    return raw({
        2: [(2, raw({
            8: [(2, payload)],
            57: [(2, call.id.encode())],
        }))],
    })


def _user_root_json(text: str, request_id: str) -> bytes:
    """User JSON root, exact accepted Cursor shape."""
    return json.dumps(
        {
            "role": "user",
            "content": [{"type": "text", "text": text}],
            "providerOptions": {"cursor": {"requestId": request_id}},
        },
        separators=(",", ":"),
    ).encode()


def _assistant_root_json(content: str | None, message_id: str) -> bytes:
    text = "" if content in (None, "[empty]") else content
    return json.dumps(
        {
            "role": "assistant",
            "id": message_id,
            "content": [{"type": "text", "text": text}],
        },
        separators=(",", ":"),
    ).encode()


def _assistant_tool_request_json(calls) -> bytes:
    return json.dumps(
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool-call",
                    "toolCallId": call.id,
                    "toolName": call.name,
                    "args": call.arguments,
                }
                for call in calls
            ],
        },
        separators=(",", ":"),
    ).encode()


def _tool_root_json(results) -> bytes:
    entries = []
    for message in results:
        try:
            parsed = json.loads(message.content)
        except json.JSONDecodeError:
            parsed = message.content
        entry = {
            "type": "tool-result",
            "toolCallId": message.tool_call_id,
            "toolName": message.tool_name,
            "result": parsed,
        }
        success = {
            "content": message.content,
            "totalLines": message.content.count("\n") + 1
            if message.content else 0,
            "fileSize": len(message.content.encode()),
            "path": "tool-results/" + message.tool_call_id,
        }
        entry["providerOptions"] = {"cursor": {
            "highLevelToolCallResult": {
                "output": {"success": success},
                "isError": False,
            },
        }}
        entries.append(entry)
    return json.dumps({"role": "tool", "content": entries},
                      separators=(",", ":")).encode()


def encode_conversation_state(
    history,
    mode: int = 1,
    conversation_id: str | None = None,
) -> tuple[bytes, list[dict]]:
    """Build a wholly synthetic checkpoint graph + its content-addressed blob map.

    Turn structure carries only the fields the server needs: the UserMessage
    address (f1), completed tool-step addresses (f2), and the conversation id
    (f3). The real schema also declares f4 encrypted_model and f5
    dynamic_tool_count; the server ignores both, so they are omitted. All ids
    are derived deterministically from the conversation prefix, so no random
    values enter the graph blobs."""
    history = list(history)
    conversation_id = conversation_id or "00000000-0000-0000-0000-000000000000"
    blob_map: dict[bytes, bytes] = {}

    def add_blob(value: bytes) -> bytes:
        blob_id = hashlib.sha256(value).digest()
        blob_map[blob_id] = value
        return blob_id

    # Group history into user-boundary turns exactly like the legacy encoder did,
    # but every id now derives from the canonical prefix at the boundary.
    turns_meta = []  # (prefix_parts, messages) per turn
    index = 0
    while index < len(history):
        if history[index].role != "user":
            index += 1
            continue
        end = index + 1
        while end < len(history) and history[end].role != "user":
            end += 1
        turns_meta.append((index, end))
        index = end

    root_blobs = []
    turn_addrs = []
    for start, end in turns_meta:
        messages = history[start:end]
        prefix_parts = _message_prefix_parts(history, start + 1)
        message_id = _boundary_uuid("coda-cursor-message-id", prefix_parts)
        request_id = _boundary_uuid("coda-cursor-request-id", prefix_parts)

        um_bytes = cursor_schema.encode(
            {
                "text": messages[0].content,
                "messageId": message_id,
                "selectedContext": {},
                "mode": mode,
            },
            "UserMessage",
        )
        um_addr = add_blob(um_bytes)

        results = {
            m.tool_call_id: m for m in messages[1:] if m.role == "tool"
        }
        turn_roots = [add_blob(
            _user_root_json(messages[0].content, request_id))]
        child_addrs = []
        for m in messages[1:]:
            if m.role != "assistant":
                continue
            calls = tuple(m.tool_calls)
            if calls:
                turn_roots.append(add_blob(
                    _assistant_tool_request_json(calls)))
                for call in calls:
                    child_addrs.append(add_blob(
                        completed_tool_step(call, results.get(call.id))))
                if m.content and m.content != "[empty]":
                    turn_roots.append(add_blob(
                        _assistant_root_json(m.content, message_id)))
            elif m.content and m.content != "[empty]":
                turn_roots.append(add_blob(
                    _assistant_root_json(m.content, message_id)))
            else:
                continue
        tool_results = [m for m in messages[1:] if m.role == "tool"]
        if tool_results:
            turn_roots.append(add_blob(_tool_root_json(tool_results)))

        root_blobs.extend(turn_roots)

        inner_fields = {
            1: [(2, um_addr)],
            3: [(2, conversation_id.encode())],
        }
        for addr in child_addrs:
            inner_fields.setdefault(2, []).append((2, addr))
        inner = cursor_schema.encode(
            {cursor_schema.UNKNOWN: inner_fields}, "Empty")
        turn_addrs.append(add_blob(cursor_schema.encode(
            {"_field1": inner}, "_HistoricalTurn")))

    state = {
        "rootPromptMessagesJson": root_blobs,
        "turns": turn_addrs,
        "mode": mode,
    }
    checkpoint = cursor_schema.encode(
        state, "ConversationCheckpointUpdate")
    prefetched = [
        {"blobId": blob_id, "value": value}
        for blob_id, value in sorted(blob_map.items())
    ]
    return checkpoint, prefetched


def build_registration_run_request(
    prompt: str,
    model: str,
    *,
    conversation_id: str,
    run_config: RunConfig | None = None,
) -> bytes:
    """Harmless one-shot userMessageAction Run used only to register a fresh
    envelope server-side. Its synthetic state is empty; it is never shown to a
    model as part of a resumed graph because supplied state supersedes it."""
    run_config = run_config or RunConfig()
    action = {"userMessageAction": {
        "userMessage": {
            "text": prompt,
            "messageId": str(uuid.uuid4()),
            "selectedContext": {},
            "mode": 1,
        },
        "requestContext": {},
    }}
    unknown = {
        1: [(2, cursor_schema.encode({}, "ConversationCheckpointUpdate"))],
        2: [(2, cursor_schema.encode(action, "ConversationAction"))],
        3: [(2, encode_model_details(model))],
        4: [(2, cursor_schema.encode({}, "Empty"))],
        # conversationId (field 5) is supplied via the named run_request key.
        10: [(0, b"\x00")],
        12: [(0, b"\x00")],
        23: [(0, b"\x00")],
    }
    run_request = {
        "conversationId": conversation_id,
        "suggestNextPrompt": None,
        cursor_schema.UNKNOWN: unknown,
    }
    return cursor_schema.encode({"runRequest": run_request},
                                "AgentClientMessage")



def encode_model_details(model: str) -> bytes:
    """Encode AgentRunRequest model details (field 3)."""
    return cursor_schema.encode(
        {
            "_field1": model,
            "_field3": model,
            "_field4": model,
            "_field5": model,
            "_field7": True,
        },
        "_ModelDetails",
    )


def _run_messages(prompt: str, history) -> list[ConversationMessage]:
    """The exact message list a checkpoint graph is built from.

    The router must key on precisely this sequence: it is what the server sees
    flattened into a prefix cache key, so any divergence here is a cache miss.
    """
    messages = list(history)
    if prompt:
        messages.append(ConversationMessage(role="user", content=prompt))
    elif not messages:
        messages.append(ConversationMessage(role="user", content=""))
    return messages


def build_run_request(
    prompt: str,
    model: str,
    *,
    tools=(),
    history=(),
    conversation_id: str | None = None,
    message_id: str | None = None,
    user_config: UserMessageConfig | None = None,
    run_config: RunConfig | None = None,
    workspace_uri: str | None = None,
    client_name: str | None = None,
) -> bytes:
    """Build a synthetic-checkpoint resumeAction RunRequest.

    The conversation graph (checkpoint + content-addressed blob map) is built from
    the authoritative history plus any final user prompt; inference continues via
    resumeAction with no synthetic reminder text. RunConfig.action still overrides
    the action for callers that need a different ConversationAction."""
    user_config = user_config or UserMessageConfig()
    run_config = run_config or RunConfig()
    conversation_id = (
        conversation_id
        or run_config.conversation_id
        or _SESSION_CONVERSATION_ID
    )

    messages = _run_messages(prompt, history)

    conversation_state, prefetched = encode_conversation_state(
        messages,
        user_config.mode,
        conversation_id=conversation_id,
    )
    if run_config.conversation_state is not None:
        conversation_state = run_config.conversation_state
    model_details = encode_model_details(model)
    unknown: dict[int, list[tuple[int, bytes]]] = {
        1: [(2, conversation_state)],
        3: [(2, run_config.model_details or model_details)],
        4: [(2, encode_mcp_tools(tools))],
    }
    if run_config.action is not None:
        unknown[2] = [(2, run_config.action)]
    else:
        unknown[2] = [(2, _RESUME_ACTION_BYTES)]
    for number, value in (
        (6, run_config.mcp_file_system_options),
        (7, run_config.skill_options),
    ):
        if value is not None:
            unknown[number] = [(2, value)]
    for number, value in (
        (8, run_config.custom_system_prompt),
        (11, run_config.subagent_type_name),
        (13, run_config.harness),
        (16, run_config.conversation_group_id),
        (18, run_config.dev_raw_model_slug),
    ):
        if value is not None:
            unknown[number] = [(2, value.encode())]
    for number, value in (
        (10, run_config.suggest_next_prompt),
        (12, run_config.exclude_workspace_context),
        (19, run_config.client_supports_inline_images),
        (21, run_config.can_create_cloud_subagents),
        (22, run_config.suppress_subagent_progress_update_tool),
        (23, run_config.client_supports_send_to_user),
    ):
        if value is not None:
            unknown[number] = [(0, bytes([int(bool(value))]))]
    for value in run_config.selected_subagent_models:
        unknown.setdefault(14, []).append((2, value))
    for value in run_config.selected_subagent_model_details:
        unknown.setdefault(15, []).append((2, value))
    for value in run_config.subagent_model_overrides:
        unknown.setdefault(20, []).append((2, value))
    for number, occurrences in (run_config.extra_fields or {}).items():
        unknown.setdefault(number, []).extend(occurrences)
    for blob in prefetched:
        # Field 17 (repeated PrefetchedBlob) has no named member in the merged
        # RunRequest schema; supply it as raw length-delimited occurrences.
        unknown.setdefault(17, []).append(
            (2, cursor_schema.encode(blob, "PrefetchedBlob")))
    run_request = {
        "conversationId": conversation_id,
        "suggestNextPrompt": None,
        cursor_schema.UNKNOWN: unknown,
    }
    client_message = {
        "runRequest": run_request,
    }
    return cursor_schema.encode(client_message, "AgentClientMessage")


def build_bidi_request_id(request_id: str) -> bytes:
    return cursor_schema.encode({"requestId": request_id}, "_BidiRequestId")


def build_bidi_append(
    request_id: str,
    payload: bytes,
    *,
    append_seqno: int = 0,
    binary: bool = True,
) -> bytes:
    obj = {}
    if not binary:
        obj["payloadHex"] = payload.hex()
    obj["requestId"] = {"requestId": request_id}
    if append_seqno:
        obj["appendSeqno"] = append_seqno
    if binary:
        obj["payload"] = payload
    return cursor_schema.encode(obj, "_BidiAppendRequest")


class ConnectStreamDecoder:
    def __init__(self, callback):
        self.callback = callback
        self.buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while len(self.buffer) >= 5:
            length = int.from_bytes(self.buffer[1:5], "big")
            if len(self.buffer) < 5 + length:
                return
            frame = ConnectFrame(self.buffer[0], bytes(self.buffer[5:5 + length]))
            del self.buffer[:5 + length]
            self.callback(frame)

    def finish(self) -> None:
        if self.buffer:
            raise ValueError("truncated Connect frame")


@dataclass(frozen=True)
class TurnUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0


def parse_turn_usage(update: Mapping[str, object]) -> TurnUsage:
    return TurnUsage(
        input_tokens=update.get("inputTokens", 0),
        output_tokens=update.get("outputTokens", 0),
        cache_read_tokens=update.get("cacheReadTokens", 0),
        cache_write_tokens=update.get("cacheWriteTokens", 0),
        reasoning_tokens=update.get("reasoningTokens", 0),
    )


def openai_usage(usage: TurnUsage) -> dict:
    return {
        "prompt_tokens": usage.input_tokens,
        "completion_tokens": usage.output_tokens,
    }


def _checkpoint_timestamp(frame: CursorFrame) -> int | None:
    if not isinstance(frame.message, CheckpointUpdate):
        return None
    value = frame.message.decoded.get("conversationCheckpointUpdate", {}).get(
        "conversationStartedTimestampMs", 0
    )
    return value or None


def build_filtered_usage_request(
    start_date: int,
    end_date: int,
    *,
    page: int = 1,
    page_size: int = 20,
) -> bytes:
    return cursor_schema.encode(
        {
            "_field1": 0,
            "startDate": start_date,
            "endDate": end_date,
            "page": page,
            "pageSize": page_size,
        },
        "_FilteredUsageRequest",
    )


def parse_filtered_usage(
    payload: bytes,
    conversation_id: str,
    request_started_ms: int,
) -> TurnUsage | None:
    response = cursor_schema.decode(payload, "_FilteredUsageResponse")
    candidates = []
    for event in response.get("events", ()):
        timestamp = event.get("timestamp", 0)
        if (
            event.get("conversationId", "") != conversation_id
            or not event.get("_field8")
            or timestamp < request_started_ms
        ):
            continue
        token = event.get("tokenUsage")
        if not token:
            continue
        uncached_input = token.get("uncachedInput", 0)
        cache_read = token.get("cacheRead", 0)
        candidates.append((
            timestamp,
            TurnUsage(
                input_tokens=uncached_input + cache_read,
                output_tokens=token.get("outputTokens", 0),
                cache_read_tokens=cache_read,
                cache_write_tokens=token.get("cacheWrite", 0),
            ),
        ))
    return min(candidates, key=lambda item: item[0])[1] if candidates else None


def get_filtered_usage(
    token: str,
    base_url: str,
    conversation_id: str,
    anchor_timestamp: int,
    request_started_ms: int,
    *,
    timeout: float = KEY_EXCHANGE_TIMEOUT,
) -> TurnUsage | None:
    payload = build_filtered_usage_request(
        anchor_timestamp - USAGE_LOOKUP_WINDOW_MS,
        anchor_timestamp + USAGE_LOOKUP_WINDOW_MS,
    )
    request = Request(
        urljoin(base_url.rstrip("/") + "/", FILTERED_USAGE_PATH),
        data=payload,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/proto",
            "Accept": "application/proto",
            "Connect-Protocol-Version": "1",
            "User-Agent": "connect-es/1.6.1",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            return parse_filtered_usage(
                response.read(), conversation_id, request_started_ms
            )
    except (HTTPError, OSError, ValueError):
        return None


@dataclass
class RunResult:
    frames: list[CursorFrame]
    text: str
    tool_calls: list["ToolCall | UnknownToolCall"]
    turn_ended: bool
    checkpoint_updates: list[CursorFrame]
    eos_metadata: object | None
    eos_error: str | None
    usage: TurnUsage | None = None


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str = ""
    parameters: dict | str | None = None
    provider_identifier: str = ""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict
    provider_identifier: str = ""
    tool_name: str = ""
    server_identifier: str = ""
    native: bool = False
    server_message_id: int = 0
    exec_id: str = ""
    field_number: int = 0
    oneof_name: str = ""
    payload_type: str = ""


@dataclass(frozen=True)
class UnknownToolCall:
    field_number: int
    oneof_name: str
    arguments: object
    server_message_id: int = 0
    exec_id: str = ""


@dataclass(frozen=True)
class UserMessageConfig:
    selected_context: bytes | None = None
    mode: int = 1
    is_simulated_msg: bool | None = None
    best_of_n_group_id: str | None = None
    try_use_best_of_n_promotion: bool | None = None
    rich_text: str | None = None
    simulated_msg_reason: int | None = None
    conversation_state_blob_id: bytes = b""
    subagent_system_reminder: str | None = None
    triggering_user_info: bytes | None = None
    execute_plan_info: bytes | None = None
    simulated_message_metadata: bytes | None = None
    prompt_reference_id: str | None = None
    thread_id: str | None = None
    text_blob_id: bytes | None = None
    rich_text_blob_id: bytes | None = None
    hook_additional_contexts: tuple[bytes, ...] = ()
    custom_mode_intent: bytes | None = None


@dataclass(frozen=True)
class RunConfig:
    conversation_state: bytes | None = None
    action: bytes | None = None
    model_details: bytes | None = None
    conversation_id: str | None = None
    mcp_file_system_options: bytes | None = None
    skill_options: bytes | None = None
    custom_system_prompt: str | None = None
    suggest_next_prompt: bool | None = None
    subagent_type_name: str | None = None
    exclude_workspace_context: bool | None = None
    harness: str | None = None
    selected_subagent_models: tuple[bytes, ...] = ()
    selected_subagent_model_details: tuple[bytes, ...] = ()
    conversation_group_id: str | None = None
    dev_raw_model_slug: str | None = None
    client_supports_inline_images: bool | None = None
    subagent_model_overrides: tuple[bytes, ...] = ()
    can_create_cloud_subagents: bool | None = None
    suppress_subagent_progress_update_tool: bool | None = None
    client_supports_send_to_user: bool | None = False
    # Raw wire occurrences appended verbatim to runRequest:
    # {field_number: [(wire_type, raw_bytes_or_int), ...]}
    extra_fields: dict[int, list[tuple[int, int | bytes]]] | None = None


def _decode_value(value: Mapping[str, object]):
    if "numberValue" in value:
        return value["numberValue"]
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return value["boolValue"]
    struct_value = value.get("structValue")
    if struct_value is not None:
        return {
            entry["key"]: _decode_value_field(entry.get("value"))
            for entry in struct_value.get("fields", ())
        }
    list_value = value.get("listValue")
    if list_value is not None:
        return [
            _decode_value_field(item)
            for item in list_value.get("values", ())
        ]
    return None


def _decode_value_field(value):
    if isinstance(value, dict) and cursor_schema.UNKNOWN in value and len(value) == 1:
        occurrences = next(iter(value[cursor_schema.UNKNOWN].values()))
        wt, raw = occurrences[0]
        if wt == 0:
            return None
        if wt == 1:
            return struct.unpack("<d", raw)[0]
        if wt == 2:
            return raw.decode(errors="replace")
        return False
    return _decode_dict_value(value)


def _decode_dict_value(value):
    if isinstance(value, dict):
        if "structValue" in value or "listValue" in value:
            decoded = {}
            if "structValue" in value:
                decoded = {
                    entry["key"]: _decode_value_field(entry.get("value"))
                    for entry in value["structValue"].get("fields", ())
                }
            else:
                decoded = [
                    _decode_value_field(item)
                    for item in value["listValue"].get("values", ())
                ]
            return decoded
        return _decode_value(value)
    if isinstance(value, str):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, bool):
        return value
    return None


EXEC_SERVER_TOOL_FIELDS = {
    2: ("shell_args", "agent.v1.ShellArgs"),
    3: ("write_args", "agent.v1.WriteArgs"),
    4: ("delete_args", "agent.v1.DeleteArgs"),
    5: ("grep_args", "agent.v1.GrepArgs"),
    7: ("read_args", "agent.v1.ReadArgs"),
    29: ("redacted_read_args", "agent.v1.ReadArgs"),
    8: ("ls_args", "agent.v1.LsArgs"),
    9: ("diagnostics_args", "agent.v1.DiagnosticsArgs"),
    10: ("request_context_args", "agent.v1.RequestContextArgs"),
    11: ("mcp_args", "agent.v1.McpArgs"),
    14: ("shell_stream_args", "agent.v1.ShellArgs"),
    16: ("background_shell_spawn_args", "agent.v1.BackgroundShellSpawnArgs"),
    17: ("list_mcp_resources_exec_args", "agent.v1.ListMcpResourcesExecArgs"),
    18: ("read_mcp_resource_exec_args", "agent.v1.ReadMcpResourceExecArgs"),
    36: ("mcp_state_exec_args", "agent.v1.McpStateExecArgs"),
    20: ("fetch_args", "agent.v1.FetchArgs"),
    21: ("record_screen_args", "agent.v1.RecordScreenArgs"),
    22: ("computer_use_args", "agent.v1.ComputerUseArgs"),
    23: ("write_shell_stdin_args", "agent.v1.WriteShellStdinArgs"),
    27: ("execute_hook_args", "agent.v1.ExecuteHookArgs"),
    28: ("subagent_args", "agent.v1.SubagentArgs"),
    30: ("force_background_shell_args", "agent.v1.ForceBackgroundShellArgs"),
    31: ("force_background_subagent_args", "agent.v1.ForceBackgroundSubagentArgs"),
    37: ("subagent_await_args", "agent.v1.SubagentAwaitArgs"),
    38: ("smart_mode_classifier_args", "agent.v1.SmartModeClassifierArgs"),
    40: ("canvas_diagnostics_args", "agent.v1.CanvasDiagnosticsArgs"),
    41: ("shell_allowlist_precheck_args", "agent.v1.ShellAllowlistPrecheckArgs"),
    42: ("mcp_allowlist_precheck_args", "agent.v1.McpAllowlistPrecheckArgs"),
    43: ("web_fetch_allowlist_precheck_args", "agent.v1.WebFetchAllowlistPrecheckArgs"),
    44: ("git_diff_request", "aiserver.v1.GetDiffRequest"),
    45: ("pi_read_args", "agent.v1.PiReadExecArgs"),
    46: ("pi_bash_args", "agent.v1.PiBashExecArgs"),
    47: ("pi_edit_args", "agent.v1.PiEditExecArgs"),
    48: ("pi_write_args", "agent.v1.PiWriteExecArgs"),
    49: ("pi_grep_args", "agent.v1.PiGrepExecArgs"),
    50: ("pi_find_args", "agent.v1.PiFindExecArgs"),
    51: ("pi_ls_args", "agent.v1.PiLsExecArgs"),
    53: ("conversation_search_args", "agent.v1.ConversationSearchArgs"),
}




def _generic_arguments(arguments: Mapping[str, object]) -> dict:
    return {
        _snake(name): value
        for name, value in arguments.items()
        if name != cursor_schema.UNKNOWN
    }


def decode_tool_call(
    message: CursorMessage,
) -> ToolCall | UnknownToolCall | None:
    execution = message.decoded.get("execServerMessage")
    if not execution:
        return None
    server_message_id = execution.get("id", 0)
    exec_id = execution.get("execId", "")

    if "mcpArgs" in execution:
        mcp = execution["mcpArgs"]
        name = mcp.get("name") or mcp.get("toolName") or "mcp"
        tool_name = mcp.get("toolName") or name
        call_id = mcp.get("toolCallId") or exec_id
        # arguments is a repeated ArgsEntry ({key, value}), not (key, value)
        # pairs: iterating a dict yields its key names.
        arguments = {}
        for entry in mcp.get("arguments", ()):
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if value is None:
                continue
            arguments[entry.get("key")] = _decode_value(value)
        return ToolCall(
            id=call_id,
            name=name,
            arguments=arguments,
            provider_identifier=mcp.get("providerIdentifier", ""),
            tool_name=tool_name,
            server_identifier=mcp.get("serverIdentifier", ""),
            native=False,
            server_message_id=server_message_id,
            exec_id=exec_id,
            field_number=11,
            oneof_name="mcp_args",
            payload_type="agent.v1.McpArgs",
        )

    fields = {field.name: field for field in cursor_schema.MESSAGES["ExecServerMessage"]}
    for name, arguments in execution.items():
        field = fields.get(name)
        if field is None or field.num in (1, 15, 19, 55):
            continue
        definition = EXEC_SERVER_TOOL_FIELDS.get(field.num)
        if definition is None:
            return UnknownToolCall(
                field.num, "field_" + str(field.num), arguments,
                server_message_id, exec_id,
            )
        oneof_name, payload_type = definition
        return ToolCall(
            id=exec_id,
            name=oneof_name.removesuffix("_args"),
            arguments=_generic_arguments(arguments),
            tool_name=oneof_name.removesuffix("_args"),
            native=True,
            server_message_id=server_message_id,
            exec_id=exec_id,
            field_number=field.num,
            oneof_name=oneof_name,
            payload_type=payload_type,
        )
    return None


def encode_mcp_tools(tools) -> bytes:
    definitions = []
    for tool in tools:
        parameters = tool.parameters
        if parameters is None:
            parameters = {}
        if not isinstance(parameters, str):
            parameters = json.dumps(parameters, separators=(",", ":"))
        definitions.append(
            {
                "_field1": tool.name,
                "_field4": tool.provider_identifier,
                "_field5": tool.name,
                "_field2": tool.description,
                "_field6": parameters,
            }
        )
    return cursor_schema.encode({"_field1": definitions}, "_McpTools")




def exchange_api_key(
    api_key: str,
    *,
    url: str = KEY_EXCHANGE_URL,
) -> dict:
    request = Request(
        url,
        data=b"{}",
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=KEY_EXCHANGE_TIMEOUT) as response:
        return json.load(response)


def _wire_varint(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = buf[i]
        result |= (byte & 0x7F) << shift
        shift += 7
        i += 1
        if not byte & 0x80:
            return result, i
        if shift > 63:
            raise ValueError("varint too long")

def _wire_fields(buf: bytes):
    """Yield (field_number, wire_type, value) for one protobuf message."""
    i = 0
    while i < len(buf):
        tag, i = _wire_varint(buf, i)
        field, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            value, i = _wire_varint(buf, i)
            yield field, wire_type, value
        elif wire_type == 1:
            yield field, wire_type, buf[i:i + 8]
            i += 8
        elif wire_type == 5:
            yield field, wire_type, buf[i:i + 4]
            i += 4
        elif wire_type == 2:
            size, i = _wire_varint(buf, i)
            yield field, wire_type, buf[i:i + size]
            i += size
        else:
            raise ValueError(f"unsupported wire type {wire_type}")

def list_available_models(
    token: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    client_version: str = DEFAULT_CLIENT_VERSION,
) -> list[str]:
    """Enumerate model variant slugs from the official AvailableModels RPC.

    The response proto has no schema in schema; the model list is the
    repeated slug at response field 2 -> entry field 30 -> variant field 11,
    matching the slugs the backend accepts (e.g. cursor-grok-4.6-high).
    """
    request = Request(
        urljoin(base_url.rstrip("/") + "/", AVAILABLE_MODELS_PATH),
        data=bytes.fromhex("28013801"),
        headers={
            "Authorization": "Bearer " + token,
            "Connect-Protocol-Version": "1",
            "Content-Type": "application/proto",
            "User-Agent": "connect-es/1.6.1",
            "x-cursor-client-type": "cli",
            "x-cursor-client-version": client_version,
            "x-ghost-mode": "true",
            "x-request-id": str(uuid.uuid4()),
        },
        method="POST",
    )
    with urlopen(request, timeout=KEY_EXCHANGE_TIMEOUT) as response:
        body = response.read()
    names = []
    for top_field, top_wire, entry in _wire_fields(body):
        if top_field != 2 or top_wire != 2:
            continue
        for entry_field, entry_wire, item in _wire_fields(entry):
            if entry_field != 30 or entry_wire != 2:
                continue
            for item_field, item_wire, variant in _wire_fields(item):
                if item_field == 11 and item_wire == 2:
                    names.append(variant.decode("utf-8"))
    return sorted(set(names))


def _token_expiration(payload: Mapping[str, object], exchanged_at: float) -> float:
    for key in ("expiresAt", "expires_at"):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    for key in ("expiresIn", "expires_in"):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return exchanged_at + float(value)
    token = payload.get("accessToken")
    if isinstance(token, str):
        parts = token.split(".")
        if len(parts) == 3:
            try:
                import base64
                encoded = parts[1] + "=" * (-len(parts[1]) % 4)
                claims = json.loads(base64.urlsafe_b64decode(encoded).decode())
                expiration = claims.get("exp")
                if isinstance(expiration, (int, float)):
                    return float(expiration)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                pass
    return exchanged_at + ACCESS_TOKEN_LIFETIME


def _read_cached_token(path: str, now: float) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            cached = json.load(stream)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(cached, dict):
        return None
    token = cached.get("access_token")
    expires_at = cached.get("expires_at")
    if (
        isinstance(token, str)
        and token
        and isinstance(expires_at, (int, float))
        and expires_at > now + ACCESS_TOKEN_REFRESH_MARGIN
    ):
        return token
    return None


def _write_cached_token(path: str, token: str, expires_at: float) -> None:
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix=".cursor-auth-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"access_token": token, "expires_at": expires_at}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def get_access_token(
    api_key: str,
    *,
    cache_path: str = AUTH_CACHE_PATH,
    lock_path: str = AUTH_LOCK_PATH,
) -> str:
    if not api_key:
        raise ValueError("api_key is required")
    directory = os.path.dirname(cache_path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        now = time.time()
        token = _read_cached_token(cache_path, now)
        if token is not None:
            return token
        payload = exchange_api_key(api_key)
        token = payload.get("accessToken")
        if not isinstance(token, str) or not token:
            raise ValueError("Cursor key exchange returned no access token")
        _write_cached_token(cache_path, token, _token_expiration(payload, now))
        return token
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


class CursorClient:
    def __init__(
        self,
        token: str,
        *,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        client_version: str = DEFAULT_CLIENT_VERSION,
        timeout: float | None = DEFAULT_TIMEOUT,
        tools=(),
        user_config: UserMessageConfig | None = None,
        run_config: RunConfig | None = None,

    ):
        if not token:
            raise ValueError("token is required")
        self.token = token
        self.base_url = base_url.rstrip("/") + "/"
        self.client_version = client_version
        self.timeout = timeout
        self.model = model
        self.tools = tuple(tools)
        self.user_config = user_config or UserMessageConfig()
        self.run_config = run_config or RunConfig()


    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + self.token,
            "x-cursor-client-type": "cli",
            "x-cursor-client-version": self.client_version,
        }

    def _ensure_conversation_registered(
        self, conversation_id: str, group_id: str | None, model: str,
    ) -> None:
        """Register a fresh conversation envelope server-side exactly once.

        The server only accepts checkpoint graphs for conversations it has seen a
        normal userMessageAction Run for; a harmless one-shot registration Run
        satisfies that prerequisite without polluting resumed inference. Identity
        is the (conversationId, conversationGroupId) pair so distinct explicit
        groups are registered independently. The registry is marked only AFTER a
        clean registration run; concurrent callers block on the in-flight lock and
        re-check rather than slipping through an unfinished/failing registration."""
        envelope = _registration_envelope_key(conversation_id, group_id)
        with _REGISTRATION_LOCK:
            if _REGISTERED_CONVERSATIONS.get(envelope):
                return
        try:
            self.run(
                _REGISTRATION_PROMPT,
                model,
                run_config=RunConfig(
                    conversation_id=conversation_id,
                    conversation_group_id=group_id,
                ),
                _registering=True,
            )
        except SSEError as exc:
            raise SSEError(f"conversation registration failed: {exc}") from exc
        with _REGISTRATION_LOCK:
            _REGISTERED_CONVERSATIONS[envelope] = True


    def run(
        self,
        prompt: str,
        model: str | None = None,
        *,
        tools=None,
        history=(),
        user_config: UserMessageConfig | None = None,
        run_config: RunConfig | None = None,
        _registering: bool = False,
    ) -> RunResult:
        request_id = str(uuid.uuid4())
        model = self.model if model is None else model
        tools = self.tools if tools is None else tuple(tools)
        mcp_tools, declared_native = _partition_native_tools(tools)
        effective_run_config = run_config or self.run_config
        conversation_id = (
            effective_run_config.conversation_id or _SESSION_CONVERSATION_ID
        )
        if (
            not _registering
            and effective_run_config.action is None
            and not _REGISTERED_CONVERSATIONS.get(_registration_envelope_key(
                conversation_id, effective_run_config.conversation_group_id))
        ):
            # First real Run on this envelope: register it server-side with a
            # harmless userMessageAction so the checkpoint graph is accepted.
            self._ensure_conversation_registered(
                conversation_id, effective_run_config.conversation_group_id,
                model,
            )
        request_started_ms = int(time.time() * 1000)
        _debug_bidi_event(
            "request_started",
            request_id=request_id,
            conversation_id=conversation_id,
            model=model,
        )
        if _registering:
            input_payload = build_registration_run_request(
                prompt, model, conversation_id=conversation_id,
            )
        else:
            input_payload = build_run_request(
                prompt,
                model,
                tools=mcp_tools,
                history=history,
                user_config=user_config or self.user_config,
                run_config=effective_run_config,
                conversation_id=conversation_id,
            )
        prefetched_blobs = extract_prefetched_blobs(input_payload)
        downlink_body = ConnectFrame.from_decoded(
            build_bidi_request_id(request_id)
        ).encode()
        frames: list[CursorFrame] = []
        text_parts: list[str] = []
        tool_calls: list[ToolCall | UnknownToolCall] = []
        seen_tool_calls = set()
        turn_ended = False
        checkpoint_updates = []
        eos_metadata = None
        eos_error = None
        usage = None
        response_boundary_seen = False
        accounting_anchor_ms = request_started_ms
        blob_response_generation = 0

        def receive(connect: ConnectFrame) -> None:
            nonlocal turn_ended, eos_metadata, eos_error, usage
            nonlocal response_boundary_seen, accounting_anchor_ms
            nonlocal blob_response_generation
            frame = CursorFrame.decode(
                connect, "IN", {"connection_id": request_id}
            )
            frames.append(frame)
            if DEBUG:
                _debug_bidi_event(
                    "downlink_frame",
                    request_id=request_id,
                    conversation_id=conversation_id,
                    classification=frame.classification,
                    flags=connect.flags,
                    decoded_payload_hex=connect.decoded_payload.hex(),
                )
            if is_generation_progress(frame.message):
                blob_response_generation += 1
                clear_timeout = getattr(
                    transport, "clear_post_blob_timeout", None
                )
                if clear_timeout is not None:
                    clear_timeout()
            if isinstance(frame.message, AnswerText):
                text_parts.append(frame.message.text)
            if (
                frame.classification
                == "agent_server.interaction_update.heartbeat"
            ):
                transport.reset_heartbeat_timeout()
            if not connect.eos:
                kv_response = build_kv_response(
                    frame.message.decoded, prefetched_blobs
                )
                if kv_response is not None:
                    if (
                        isinstance(frame.message, KVServerMessage)
                        and frame.message.subtype == "get_blob_args"
                    ):
                        blob_response_generation += 1
                        generation = blob_response_generation
                        clear_timeout = getattr(
                            transport, "clear_post_blob_timeout", None
                        )
                        if clear_timeout is not None:
                            clear_timeout()

                        def blob_appended(response, generation=generation):
                            appended(response)
                            if generation == blob_response_generation:
                                arm_timeout = getattr(
                                    transport, "arm_post_blob_timeout", None
                                )
                                if arm_timeout is not None:
                                    transport._post_blob_debug = {
                                        "request_id": request_id,
                                        "conversation_id": conversation_id,
                                        "append_seqno": generation,
                                    }
                                    arm_timeout(
                                        POST_BLOB_PROGRESS_TIMEOUT
                                    )

                        append(kv_response, callback=blob_appended)
                    else:
                        append(kv_response)
                call = decode_tool_call(frame.message)
                if call is not None:
                    identity = (
                        type(call),
                        call.field_number,
                        getattr(call, "id", ""),
                        call.exec_id,
                    )
                    if identity not in seen_tool_calls:
                        seen_tool_calls.add(identity)
                        if (
                            isinstance(call, ToolCall)
                            and call.native
                            and call.name not in declared_native
                        ):
                            # Undeclared native tool: refuse it in-band and
                            # let inference continue; it is never surfaced to
                            # the client or replayed into history.
                            log.warning(
                                "refusing undeclared native tool %r: "
                                "declare it as a native_%s tool definition "
                                "to enable it",
                                call.name,
                                call.name,
                            )
                            append(build_unsupported_native_reply(call))
                            return
                        tool_calls.append(call)
                        response_boundary_seen = True
                        turn_ended = True
                        clear_timeout = getattr(
                            transport, "clear_post_blob_timeout", None
                        )
                        if clear_timeout is not None:
                            clear_timeout()
                        append(
                            build_user_cancelled_message(),
                            callback=cancelled,
                        )
                        return
            if (
                frame.classification
                == "agent_server.interaction_update.turn_ended"
            ):
                turn_ended = True
                usage = parse_turn_usage(frame.message.update)
                if usage.input_tokens == 0 and usage.output_tokens == 0:
                    # Some turn_ended updates carry no token counts; treat as
                    # absent so the usage-events fallback below runs.
                    usage = None
                transport.close()
            elif (
                frame.classification
                == "agent_server.conversation_checkpoint_update"
            ):
                checkpoint_updates.append(frame)
                timestamp = _checkpoint_timestamp(frame)
                if timestamp is not None:
                    accounting_anchor_ms = timestamp
            elif (
                not response_boundary_seen
                and not connect.eos
                and is_response_boundary_blob_write(
                    frame.message.decoded, request_id
                )
            ):
                response_boundary_seen = True
                turn_ended = True
                if tool_calls:
                    append(
                        build_user_cancelled_message(),
                        callback=cancelled,
                    )
                else:
                    transport.start_grace_period(
                        RESPONSE_USAGE_GRACE_TIMEOUT
                    )
            if connect.eos:
                eos_metadata = frame.eos_metadata
                eos_error = frame.eos_error

        decoder = ConnectStreamDecoder(receive)
        downlink_url = urljoin(
            self.base_url, AGENT_RUNSSE_PATH
        )
        append_url = urljoin(
            self.base_url, BIDI_APPEND_PATH
        )
        request_headers = {
            **self.headers,
            "x-ghost-mode": "true",
            "x-request-id": request_id,
            "x-original-request-id": request_id,
        }
        downlink_headers = {
            **request_headers,
            "Accept": "application/connect+proto",
            "Content-Type": "application/connect+proto",
            "Connect-Protocol-Version": "1",
            "Connect-Accept-Encoding": "gzip",
        }
        append_result = []
        append_started = False
        append_seqno = -1
        append_queue = deque()
        append_in_flight = 0

        def appended(response):
            append_result.append(response)
            if response["status"] != 200:
                raise SSEError(
                    f"BidiAppend returned HTTP {response['status']}"
                )

        def cancelled(response):
            appended(response)
            transport.close()

        def pump_append_queue():
            nonlocal append_in_flight
            while (
                append_in_flight < BIDI_APPEND_PIPELINE_DEPTH
                and append_queue
                and not transport.closed
            ):
                (
                    seqno,
                    payload,
                    wrapped_payload,
                    classification,
                    callback,
                ) = append_queue.popleft()
                append_in_flight += 1
                _debug_bidi_event(
                    "bidi_append_started",
                    request_id=request_id,
                    conversation_id=conversation_id,
                    append_seqno=seqno,
                    classification=classification,
                    pipeline_depth=append_in_flight,
                    payload_hex=payload.hex(),
                    wrapped_payload_hex=wrapped_payload.hex(),
                )

                def completed(
                    response,
                    seqno=seqno,
                    classification=classification,
                    callback=callback,
                ):
                    nonlocal append_in_flight
                    _debug_bidi_event(
                        "bidi_append_completed",
                        request_id=request_id,
                        conversation_id=conversation_id,
                        append_seqno=seqno,
                        classification=classification,
                        pipeline_depth=append_in_flight,
                        status=response["status"],
                        headers=response["headers"],
                        body_hex=response["body"].hex(),
                    )
                    append_in_flight -= 1
                    callback(response)
                    pump_append_queue()

                transport.post(
                    append_url,
                    wrapped_payload,
                    headers={
                        **request_headers,
                        "Content-Type": "application/proto",
                        "Accept": "application/proto",
                    },
                    callback=completed,
                )

        def append(payload, callback=appended):
            nonlocal append_seqno
            append_seqno += 1
            seqno = append_seqno
            wrapped_payload = build_bidi_append(
                request_id,
                payload,
                append_seqno=seqno,
            )
            try:
                classification = decode_cursor_payload(
                    payload, "OUT"
                ).classification
            except ValueError:
                classification = "decode_error"
            append_queue.append((
                seqno,
                payload,
                wrapped_payload,
                classification,
                callback,
            ))
            pump_append_queue()

        def downlink_ready(status, headers):
            nonlocal append_started
            _debug_bidi_event(
                "downlink_ready",
                request_id=request_id,
                conversation_id=conversation_id,
                status=status,
                headers=headers,
            )
            if append_started:
                return
            append_started = True
            generation = blob_response_generation

            def initial_appended(response):
                appended(response)
                if _registering:
                    append(
                        build_user_cancelled_message(),
                        callback=cancelled,
                    )
                elif (
                    generation == blob_response_generation
                    and not response_boundary_seen
                ):
                    transport._post_blob_debug = {
                        "request_id": request_id,
                        "conversation_id": conversation_id,
                        "append_seqno": 0,
                        "phase": "initial_model_progress",
                    }
                    arm_timeout = getattr(
                        transport, "arm_post_blob_timeout", None
                    )
                    if arm_timeout is not None:
                        arm_timeout(INITIAL_MODEL_PROGRESS_TIMEOUT)

            append(input_payload, callback=initial_appended)

        with SSEClient(
            downlink_url,
            callback=lambda event: None,
            headers=downlink_headers,
            timeout=self.timeout,
            stream_callback=decoder.feed,
            accepted_content_types=("application/connect+proto",),
            method="POST",
            body=downlink_body,
            headers_callback=downlink_ready,
        ) as transport:
            transport.run_forever(
                timeout=self.timeout,
                heartbeat_timeout=HEARTBEAT_TIMEOUT,
            )
            if not append_result and not frames:
                raise SSEError("BidiAppend did not complete")
        decoder.finish()

        if eos_error and not response_boundary_seen:
            raise SSEError(eos_error)
        if turn_ended and usage is None:
            for attempt in range(USAGE_LOOKUP_ATTEMPTS):
                usage = get_filtered_usage(
                    self.token,
                    self.base_url,
                    conversation_id,
                    accounting_anchor_ms,
                    request_started_ms,
                )
                if usage is not None:
                    break
                if attempt + 1 < USAGE_LOOKUP_ATTEMPTS:
                    time.sleep(USAGE_LOOKUP_RETRY_DELAY)
        _debug_bidi_event(
            "request_completed",
            request_id=request_id,
            conversation_id=conversation_id,
            frame_count=len(frames),
            turn_ended=turn_ended,
            eos_error=eos_error,
        )
        return RunResult(
            frames,
            "".join(text_parts),
            tool_calls,
            turn_ended,
            checkpoint_updates,
            eos_metadata,
            eos_error,
            usage,
        )


def run(
    prompt: str,
    *,
    api_key: str,
    model: str,
    tools=(),
    history=(),
    timeout: float | None = DEFAULT_TIMEOUT,
    base_url: str = DEFAULT_BASE_URL,
    client_version: str = DEFAULT_CLIENT_VERSION,
    user_config: UserMessageConfig | None = None,
    run_config: RunConfig | None = None,
) -> RunResult:
    """Perform one independent stateless Cursor Agent request."""
    deadline = (
        None if timeout is None else time.monotonic() + timeout
    )
    token = get_access_token(api_key)

    remaining_timeout = None
    if deadline is not None:
        remaining_timeout = deadline - time.monotonic()
        if remaining_timeout <= 0:
            raise SSEError("request deadline exceeded")

    normalized_tools = tuple(
        item if isinstance(item, ToolDefinition)
        else ToolDefinition(**item)
        for item in tools
    )
    normalized_history = _normalize_history(history)

    return CursorClient(
        token,
        base_url=base_url,
        client_version=client_version,
        timeout=remaining_timeout,
        model=model,
        tools=normalized_tools,
        user_config=user_config,
        run_config=run_config,
    ).run(prompt, history=normalized_history)


def _normalize_history(history) -> list[ConversationMessage]:
    """Coerce dict/ConversationMessage history into ConversationMessage form.

    The router and the checkpoint encoder must both see the same normalized
    sequence, so this is the single place the conversion happens.
    """
    normalized = []
    for item in history:
        if isinstance(item, ConversationMessage):
            normalized.append(item)
            continue
        values = dict(item)
        values["tool_calls"] = tuple(
            call if isinstance(call, ToolCall) else ToolCall(**call)
            for call in values.get("tool_calls", ())
        )
        normalized.append(ConversationMessage(**values))
    return normalized


def _chat_content_text(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise TypeError("message content must be a string, list, or None")
    parts = []
    for item in content:
        if not isinstance(item, dict):
            raise TypeError("content parts must be objects")
        if item.get("type") not in ("text", "input_text"):
            raise ValueError(
                f"Cursor does not support content type {item.get('type')!r}"
            )
        parts.append(str(item.get("text", "")))
    return "".join(parts)


def _openai_tools(tools):
    result = []
    for item in tools or ():
        if not isinstance(item, dict) or item.get("type") != "function":
            raise ValueError("only OpenAI function tools are supported")
        function = item.get("function")
        if not isinstance(function, dict) or not function.get("name"):
            raise ValueError("function tool requires a name")
        result.append({
            "name": function["name"],
            "description": function.get("description", ""),
            "parameters": function.get("parameters", {}),
            "provider_identifier": "openai",
        })
    return result


def _openai_messages(messages):
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a nonempty list")

    parsed = []
    system_parts = []
    active_user_index = -1

    for message in messages:
        if not isinstance(message, dict):
            raise TypeError("messages must contain objects")
        role = message.get("role") or "user"
        content = _chat_content_text(message.get("content")) or "[empty]"

        if role == "system":
            system_parts.append(content)
            continue

        converted = {"role": role, "content": content}
        if role == "assistant":
            calls = []
            for item in message.get("tool_calls") or ():
                function = item.get("function") or {}
                arguments = function.get("arguments", "{}")
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                calls.append({
                    "id": item.get("id", ""),
                    "name": function.get("name", ""),
                    "arguments": arguments,
                    "tool_name": function.get("name", ""),
                    "provider_identifier": "openai",
                })
            converted["tool_calls"] = calls
        elif role == "tool":
            converted["tool_call_id"] = message.get("tool_call_id", "")
            converted["tool_name"] = message.get("name", "")
        elif role != "user":
            raise ValueError(f"unsupported message role: {role!r}")

        parsed.append(converted)
        if role == "user":
            active_user_index = len(parsed) - 1

    if not parsed:
        raise ValueError("messages must contain a non-system message")

    if system_parts:
        addendum = (
            "<system-addendum>\n"
            + "\n\n".join(system_parts)
            + "\n</system-addendum>"
        )
        for message in parsed:
            if message["role"] == "user":
                message["content"] = addendum + "\n\n" + message["content"]
                break

    if active_user_index == len(parsed) - 1:
        prompt = parsed[active_user_index]["content"]
        history = parsed[:active_user_index]
    elif parsed[-1]["role"] == "tool":
        # Tool results are folded into the synthetic checkpoint graph; no
        # reminder prompt is injected (resumeAction needs no new user text).
        prompt = ""
        history = parsed
    else:
        prompt = (
            "Continue the conversation from the preceding messages. "
            "Respond to the latest message or tool result without repeating "
            "an earlier request."
        )
        history = parsed

    return prompt, history




def _openai_tool_call(call: ToolCall) -> dict:
    if call.native:
        # Surface Cursor's native tool under its own name (prefixed to avoid
        # colliding with client tool names) with the raw Cursor arguments,
        # rather than rendering it into another tool's calling convention.
        name = NATIVE_TOOL_PREFIX + call.name
        arguments = call.arguments
    else:
        name = call.name
        arguments = call.arguments
    return {
        "id": call.id or call.exec_id or "tool_" + uuid.uuid4().hex,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments, separators=(",", ":")),
        },
    }




def _turn_fingerprints(history) -> tuple[tuple[bytes, int], ...]:
    """Conversation-independent (identity, weight) of each turn in a history.

    The turn blob embeds conversation_id, so its content hash is bound to one
    envelope and cannot be compared across candidates. The identity half
    deliberately excludes the envelope: only the UserMessage blob and the
    completed tool-step blobs (both envelope-independent) are hashed, which is
    exactly the content the server's prefix cache is keyed on. The weight half
    is the turn's serialized size, used directly as the routing score.
    """
    history = list(history)
    turns = []
    index = 0
    while index < len(history):
        if history[index].role != "user":
            index += 1
            continue
        end = index + 1
        while end < len(history) and history[end].role != "user":
            end += 1
        turns.append((index, end))
        index = end

    fingerprints = []
    for start, end in turns:
        messages = history[start:end]
        prefix_parts = _message_prefix_parts(history, start + 1)
        message_id = _boundary_uuid("coda-cursor-message-id", prefix_parts)
        um_bytes = cursor_schema.encode(
            {
                "text": messages[0].content,
                "messageId": message_id,
                "selectedContext": {},
                "mode": 1,
            },
            "UserMessage",
        )
        results = {
            message.tool_call_id: message
            for message in messages[1:] if message.role == "tool"
        }
        children = []
        for message in messages[1:]:
            if message.role == "assistant":
                for call in message.tool_calls:
                    children.append(
                        completed_tool_step(call, results.get(call.id))
                    )
        weight = len(um_bytes) + sum(len(child) for child in children)
        for message in messages[1:]:
            weight += len(message.content.encode())
            if message.role == "tool":
                weight += len(message.tool_call_id.encode())
        key = _canonical_prefix_digest(
            "coda-cursor-turn-key", [um_bytes, *children])
        fingerprints.append((key, weight))
    return tuple(fingerprints)


def _is_turn_prefix(short, long) -> bool:
    return len(short) <= len(long) and long[:len(short)] == short


def _route_cursor_session(model, turn_keys, turn_weights, now):
    """Pick the live envelope whose cached graph best matches this request.

    Scoring is the largest shared-prefix byte weight across the envelope's
    recorded branches. Live A/B probes showed that divergent tails retained on
    an envelope are not charged when another branch is requested, so they must
    not reduce its score. A fresh envelope scores zero and is selected only
    when no live envelope shares any turn prefix. Envelopes with a run in
    flight are skipped so concurrent requests never share one.
    """
    sessions = _CURSOR_SESSIONS.setdefault(model, {})
    best_id = None
    best_score = 0.0
    for conversation_id, session in list(sessions.items()):
        if (model, conversation_id) in _CURSOR_ENVELOPE_BUSY:
            continue
        if now - session["last_used"] > _CURSOR_SESSION_IDLE_SECONDS:
            del sessions[conversation_id]
            continue
        best_shared = 0.0
        for keys, weights in session["branches"]:
            shared = 0.0
            for index, key in enumerate(turn_keys):
                if index >= len(keys) or keys[index] != key:
                    break
                shared += weights[index]
            if shared > best_shared:
                best_shared = shared
        if best_shared > best_score:
            best_score = best_shared
            best_id = conversation_id
    return best_id


def _record_cursor_session(
    model, conversation_id, turn_keys, turn_weights, now
) -> None:
    """Record this request's graph as a branch now cached on the envelope.

    Probes showed an envelope retains branches and recovers any of them at
    full cache on return, so branches are accumulated rather than replaced.
    A branch already covered by a longer one is dropped, which keeps an
    append-only session at a single branch instead of one per request.
    """
    sessions = _CURSOR_SESSIONS.setdefault(model, {})
    session = sessions.get(conversation_id)
    if session is None:
        session = {"branches": [], "last_used": now}
        sessions[conversation_id] = session
    branches = []
    covered = False
    for keys, weights in session["branches"]:
        if _is_turn_prefix(keys, turn_keys):
            continue
        if _is_turn_prefix(turn_keys, keys):
            covered = True
        branches.append((keys, weights))
    if not covered:
        branches.append((turn_keys, turn_weights))
    del branches[:-_CURSOR_SESSION_MAX_BRANCHES]
    session["branches"] = branches
    session["last_used"] = now


def _select_cursor_conversation(model: str, prompt: str, history) -> str:
    """Route this request to the envelope whose cache already holds its prefix."""
    messages = _run_messages(prompt, _normalize_history(history))
    fingerprints = _turn_fingerprints(messages)
    if not fingerprints:
        conversation_id = str(uuid.uuid4())
        with _CURSOR_SESSION_LOCK:
            _CURSOR_ENVELOPE_BUSY.add((model, conversation_id))
        return conversation_id
    turn_keys = tuple(key for key, _ in fingerprints)
    turn_weights = tuple(weight for _, weight in fingerprints)
    now = time.time()
    with _CURSOR_SESSION_LOCK:
        conversation_id = _route_cursor_session(
            model, turn_keys, turn_weights, now
        )
        if conversation_id is None:
            conversation_id = str(uuid.uuid4())
        _record_cursor_session(
            model, conversation_id, turn_keys, turn_weights, now
        )
        _CURSOR_ENVELOPE_BUSY.add((model, conversation_id))
    return conversation_id


def _release_cursor_conversation(model: str, conversation_id: str) -> None:
    """Free the envelope for the next request once its run is done."""
    with _CURSOR_SESSION_LOCK:
        _CURSOR_ENVELOPE_BUSY.discard((model, conversation_id))



def chat_completions(api_key: str, body: dict) -> dict:
    """Run one non-streaming OpenAI Chat Completions-compatible request."""
    if not isinstance(body, dict):
        raise TypeError("body must be a dictionary")
    if body.get("stream"):
        raise ValueError("streaming chat completions are not supported")
    prompt, history = _openai_messages(body.get("messages"))
    model = body.get("model")
    if not isinstance(model, str) or not model:
        raise ValueError("model is required")
    timeout = body.get("timeout", DEFAULT_TIMEOUT)
    conversation_id = _select_cursor_conversation(model, prompt, history)
    try:
        result = run(
            prompt,
            api_key=api_key,
            model=model,
            tools=_openai_tools(body.get("tools")),
            history=history,
            timeout=timeout,
            run_config=RunConfig(conversation_id=conversation_id),
        )
    finally:
        _release_cursor_conversation(model, conversation_id)
    tool_calls = [
        _openai_tool_call(call)
        for call in result.tool_calls
        if isinstance(call, ToolCall)
    ]
    message = {
        "role": "assistant",
        "content": None if tool_calls else (result.text or None),
    }
    if tool_calls:
        message["tool_calls"] = tool_calls
    response = {
        "id": "chatcmpl-" + uuid.uuid4().hex,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": "tool_calls" if tool_calls else "stop",
        }],
    }
    if result.usage is not None:
        # Real backend-reported usage: input tokens come from the run stream
        # or the GetFilteredUsageEvents fallback, not a client-side estimate.
        response["usage"] = openai_usage(result.usage)
    return response


