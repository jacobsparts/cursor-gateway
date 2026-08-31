"""Minimal OpenAI Chat Completions-compatible server over the Cursor transport."""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cursor_transport import cursor as transport
from code_agent_compat import codeagent_chat_completions

DEFAULT_HOST = os.environ.get("CURSOR_GATEWAY_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("CURSOR_GATEWAY_PORT", "8931"))


def _error(message: str, code: str = "invalid_request_error"):
    return {"error": {"message": message, "type": code, "code": code}}


# code-agent-specific wrapper lives in code_agent_compat.py; see the
# comment there for the /v1/code-agent/chat/completions contract.



class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return None

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path in ("/health", "/healthz"):
            self._send(200, {"status": "ok"})
            return
        if self.path == "/v1/models":
            auth = self.headers.get("Authorization", "")
            if not auth.lower().startswith("bearer "):
                self._send(
                    401,
                    _error("missing Bearer token in Authorization header", "auth_error"),
                )
                return
            api_key = auth[7:].strip()
            if not api_key:
                self._send(401, _error("empty Bearer token", "auth_error"))
                return
            try:
                token = transport.get_access_token(api_key)
                names = transport.list_available_models(token)
            except Exception as exc:  # transport raises plain exceptions
                self._send(
                    502, _error(f"cursor transport failed: {exc}", "transport_error")
                )
                return
            now = int(time.time())
            data = [
                {"id": name, "object": "model", "created": now, "owned_by": "cursor"}
                for name in names
            ]
            self._send(200, {"object": "list", "data": data})
            return
        self._send(404, _error(f"unknown path {self.path}", "not_found"))

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        endpoints = {
            "/v1/chat/completions": transport.chat_completions,
            "/v1/code-agent/chat/completions": codeagent_chat_completions,
        }
        handler = endpoints.get(self.path)
        if handler is None:
            self._send(404, _error(f"unknown path {self.path}", "not_found"))
            return
        body = self._read_body()
        if body is None:
            self._send(400, _error("body must be a JSON object"))
            return
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            self._send(
                401,
                _error("missing Bearer token in Authorization header", "auth_error"),
            )
            return
        api_key = auth[7:].strip()
        if not api_key:
            self._send(401, _error("empty Bearer token", "auth_error"))
            return
        try:
            response = handler(api_key, body)
        except Exception as exc:  # transport raises plain exceptions
            self._send(
                502, _error(f"cursor transport failed: {exc}", "transport_error")
            )
            return
        self._send(200, response)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(
            "[cursor-gateway] %s - %s\n" % (self.address_string(), fmt % args)
        )


def main() -> None:
    server = ThreadingHTTPServer((DEFAULT_HOST, DEFAULT_PORT), Handler)
    print(
        "cursor-gateway listening on http://%s:%d" % (DEFAULT_HOST, DEFAULT_PORT),
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
