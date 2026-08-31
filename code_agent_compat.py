"""code-agent compatibility layer for cursor-gateway.

The only code-agent-specific part of the gateway: it declares Cursor's
native tools on the request and rewrites native tool calls in the response
into repl_execute python code. The bare /v1/chat/completions endpoint stays
general-purpose: native calls surface verbatim as native_<X> with raw
Cursor arguments, and clients are free to implement their own handling.
"""

from __future__ import annotations

import json
import shlex

from cursor_transport import cursor as transport

# Native tools with python renderers. Declared via native_<X> tool
# definitions; the Cursor backend only uses native tools the client has
# declared.
NATIVE_TOOLS = ("exec_server_message", "shell_stream", "grep", "read")


def _native_tool_defs():
    return [
        {
            "type": "function",
            "function": {"name": "native_" + name, "parameters": {}},
        }
        for name in NATIVE_TOOLS
    ]


def _native_call_content(params):
    for key in ("content", "command", "code", "text", "1"):
        if key in params:
            return params[key]
    return params


def _native_repl_code(name: str, params: dict) -> str:
    """Render one native Cursor tool call as python REPL code."""
    pretty = "".join(word.capitalize() for word in name.split("_"))
    content = _native_call_content(params)
    content_literal = json.dumps(str(content), ensure_ascii=False)
    if pretty == "ExecServerMessage":
        return f"think({content_literal})"
    if pretty == "ShellStream":
        command = params.get("command", "")
        working_directory = params.get("working_directory")
        if working_directory:
            command = f"cd -- {shlex.quote(working_directory)} && {command}"
        timeout = params.get("timeout")
        if timeout is not None:
            timeout = timeout / 1000
            if timeout.is_integer():
                timeout = int(timeout)
        return (
            f"bash(command={command!r}, timeout={timeout!r}, "
            f"bg={bool(params.get('is_background', False))!r})"
        )
    if pretty == "Grep":
        arguments = {
            "pattern": params.get("pattern", ""),
            "path": params.get("path"),
            "glob": params.get("glob"),
            "file_type": params.get("type"),
            "context": params.get("context"),
            "case_insensitive": params.get("case_insensitive"),
            "multiline": params.get("multiline"),
        }
        rendered = ", ".join(
            f"{key}={value!r}"
            for key, value in arguments.items()
            if value is not None
        )
        return f"grep({rendered})"
    if pretty == "Read":
        path = params.get("path", "")
        offset = params.get("offset")
        limit = params.get("limit")
        if offset is None and limit is None:
            return f"view({path!r})"
        if offset is None:
            slice_spec = f":{limit}"
        elif limit is None:
            slice_spec = f"{offset}:"
        else:
            slice_spec = f"{offset}:{offset + limit}"
        return f"print(read({path!r})[{slice_spec}])"
    return f"# unsupported tool call: {pretty}({params!r})"


def _codeagent_transform(response: dict) -> dict:
    """Rewrite native_<X> tool calls into repl_execute python code."""
    for choice in response.get("choices", ()):
        for call in choice.get("message", {}).get("tool_calls") or ():
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            name = function.get("name", "")
            if not name.startswith("native_"):
                continue
            try:
                params = json.loads(function.get("arguments") or "{}")
            except ValueError:
                params = {"1": function.get("arguments")}
            function["name"] = "repl_execute"
            function["arguments"] = json.dumps(
                {"code": _native_repl_code(name[len("native_"):], params)},
                separators=(",", ":"),
            )
    return response


def codeagent_chat_completions(api_key: str, body: dict) -> dict:
    body = dict(body)
    body["tools"] = list(body.get("tools") or ()) + _native_tool_defs()
    return _codeagent_transform(transport.chat_completions(api_key, body))
