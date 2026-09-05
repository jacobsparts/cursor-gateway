# cursor-gateway

A pure-Python, dependency-light gateway that exposes Cursor's agent backend as an
OpenAI-compatible Chat Completions API. It implements a synthetic Cursor
client that speaks Cursor's protobuf protocol directly (real inference via
`resumeAction` over client-built synthetic checkpoints), so any plain HTTP
client can drive the Cursor agent models with tools, multi-turn history, and
Cursor native tool support.

## Quick start

Requirements: Python 3.9+ with only the standard library. No installation
step.

```sh
cd cursor-gateway
export CURSOR_GATEWAY_HOST=127.0.0.1   # optional; this is the default
export CURSOR_GATEWAY_PORT=8931        # optional; this is the default
python3 server.py
```

Then verify it is up:

```sh
curl -s http://127.0.0.1:8931/health
# {"status": "ok"}
```

The server itself does not need the Cursor API key at startup; the key is
supplied per request as the Bearer token (see Authentication).

## Authentication

Every chat and `/v1/models` request needs a Cursor user API key as the Bearer
token. It is
exchanged for a short-lived access token per request and never stored.

```sh
curl -s -X POST http://127.0.0.1:8931/v1/chat/completions \
  -H "Authorization: Bearer $CURSOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "composer-2.5", "messages": [{"role": "user", "content": "hi"}]}'
```

Requests without a valid `Authorization: Bearer <key>` header get `401`.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health`, `/healthz` | Liveness probe |
| GET | `/v1/models` | Available models (same Bearer key as chat) |
| POST | `/v1/chat/completions` | Chat completion (non-streaming, raw native tools) |
| POST | `/v1/code-agent/chat/completions` | Chat completion with Code Agent native-tool rewriting |

## Models

`/v1/models` is answered live from Cursor's official AvailableModels RPC
(`aiserver.v1.AiService/AvailableModels`), so it always reflects every model
variant the backend currently accepts (220 at time of writing, including
`composer-2.5`, `cursor-grok-4.6-high`, `claude-4.6-sonnet-high`,
`gpt-5.6-luna-high`, `kimi-k3-high`). It requires the same Bearer key as chat
requests.

## Tools

Tools are passed as standard OpenAI function definitions:

```json
{
  "type": "function",
  "function": {
    "name": "get_weather",
    "description": "Get weather for a city",
    "parameters": {
      "type": "object",
      "properties": {"city": {"type": "string"}},
      "required": ["city"]
    }
  }
}
```

Everything except the `native_` namespace below is offered to the model as a
regular MCP tool. When the model calls one of your tools, the response has
`finish_reason: "tool_calls"` and the assistant message carries OpenAI-style
`tool_calls` entries (`function.name`, `function.arguments` as a JSON string).

Replay a tool result as a normal `tool` message:

```json
{
  "role": "tool",
  "tool_call_id": "<id from the tool_call>",
  "name": "get_weather",
  "content": "21C, sunny"
}
```

`content` may be any string (plain text or JSON). It is folded into the
conversation checkpoint under `tool-results/<tool_call_id>` and attributed to
the matching tool call.

## Native tools

Cursor's backend has its own built-in tool set (read, shell, grep, ...). By
default the gateway suppresses these: if the model attempts a native call that
you have not declared, the gateway refuses it in-band (an
`ExecClientControlMessage.throw` message with `unsupported native tool: <name>`) and
inference continues; the model falls back to your tools or answers in text.
Nothing about the refused call reaches your client.

To let the model use Cursor's native tools, declare support by defining tools
whose names are prefixed with `native_`. A tool named `native_<X>` declares
Cursor native tool `X`:

```json
{
  "type": "function",
  "function": {
    "name": "native_read",
    "description": "Read a file from the filesystem. Args: path (string), offset (int), limit (int)."
  }
}
```

Declared native tools are NOT sent as MCP tools. When the model calls one, the
gateway surfaces it verbatim as a tool call named `native_<X>` whose
`function.arguments` is the raw Cursor argument object (Cursor field names,
e.g. `path`, `tool_call_id`, `limit` for `native_read`). Feed the result back
exactly like any other tool result (`role: "tool"`, same `tool_call_id`, the
output as `content`).

### Available native tools

| `native_` tool | Purpose | Raw argument fields |
|---|---|---|
| `shell` | Run a shell command (may auto-background) | `command, workingDirectory, timeout, toolCallId, simpleCommands, hasInputRedirect, hasOutputRedirect, fileOutputThresholdBytes, isBackground, skipApproval, timeoutBehavior, hardTimeout, description, closeStdin, conversationId, admin_command_denylist` |
| `write` | Create or overwrite a file | `path, fileText, toolCallId, returnFileContentAfterWrite, fileBytes, encodingHint` |
| `delete` | Delete a file or directory | `path, toolCallId` |
| `grep` | Ripgrep-style content search | `pattern, path, glob, outputMode, contextBefore, contextAfter, context, caseInsensitive, type, headLimit, multiline, sort, sortAscending, toolCallId, offset` |
| `read` | Read a file from the filesystem | `path, toolCallId, offset, limit, encodingHint` |
| `ls` | List a directory | `path, ignore, toolCallId, timeoutMs` |
| `diagnostics` | Editor diagnostics for a file | `path, toolCallId` |
| `request_context` | Request additional context | `notesSessionId, workspaceId, readOnlyPinnedTreeSha, readOnlyPluginCacheRoot, useCached` |
| `shell_stream` | Stream events of a running shell (stdout/stderr/exit/start) | `(internal payload)` |
| `background_shell_spawn` | Spawn a background shell | `command, workingDirectory, toolCallId, enableWriteShellStdinTool, description, skipApproval, conversationId, admin_command_denylist` |
| `list_mcp_resources_exec` | List resources of an MCP server | `server` |
| `read_mcp_resource_exec` | Read an MCP resource to a file | `server, uri, downloadPath, toolCallId` |
| `fetch` | Fetch a URL | `url, toolCallId` |
| `record_screen` | Capture the screen | `mode, toolCallId, saveAsFilename` |
| `computer_use` | Drive the machine (mouse/keyboard) | `toolCallId, description, bind_unmapped_characters` |
| `write_shell_stdin` | Write characters to a running shell stdin | `shellId, chars` |
| `execute_hook` | Execute a registered hook | `(internal payload)` |
| `subagent` | Spawn a nested Cursor subagent | `toolCallId, subagentType, modelId, prompt, readonly, resumeAgentId, runInBackground, parentConversationId, interrupt, mode, forkAgentId, rootParentConversationId, directMetaParentChildSubagent, environment, cloudBaseBranch` |
| `redacted_read` | Read a file with secrets redacted | `(internal payload)` |
| `force_background_shell` | Force the current shell to background | `toolCallId` |
| `force_background_subagent` | Force a subagent to background | `toolCallId` |
| `mcp_state_exec` | Internal MCP state sync | `args, kickOnly` |
| `subagent_await` | Wait for a background subagent | `agentId, timeoutMs` |
| `smart_mode_classifier` | Internal smart-mode risk classification | `toolCallId, parentConversationId` |
| `canvas_diagnostics` | Diagnostics for a canvas file | `path, toolCallId` |
| `shell_allowlist_precheck` | Pre-check a shell command against the allowlist | `command, workingDirectory, toolCallId` |
| `mcp_allowlist_precheck` | Pre-check an MCP tool against the allowlist | `providerIdentifier, toolName, toolCallId` |
| `web_fetch_allowlist_precheck` | Pre-check a URL against the fetch allowlist | `url, toolCallId` |
| `git_diff_request` | Request a git diff | `diff_type` |
| `pi_read` | Pi-mode file read | `path, offset, limit` |
| `pi_bash` | Pi-mode shell command | `command, timeout` |
| `pi_edit` | Pi-mode file edit | `path` |
| `pi_write` | Pi-mode file write | `path, content` |
| `pi_grep` | Pi-mode content search | `pattern, path, glob, ignoreCase, literal, context, limit` |
| `pi_find` | Pi-mode file find | `pattern, path, limit` |
| `pi_ls` | Pi-mode directory listing | `path, limit` |
| `conversation_search` | Search past conversation history | `query, toolCallId, limit` |

Notes:

- Argument lists above are Cursor's own protobuf field names for the tool's
  args message; message-typed fields are omitted. `toolCallId` is always set
  by the backend and is echoed as the tool call `id`.
- `native_shell` / `native_background_shell_spawn` results arrive as stream
  events; a running shell is addressed by its id for `native_write_shell_stdin`.
- The `pi_*` family and several `_precheck` / internal tools are part of
  Cursor's internal plumbing; declaring them is rarely useful.

## Code Agent Integration

`cursor-gateway` includes a dedicated endpoint for [Code Agent](https://github.com/jacobsparts/code-agent):

```
POST /v1/code-agent/chat/completions
```

### How it works

Cursor backend models are trained to invoke native client tools (`read`, `grep`, `shell_stream`, `exec_server_message`) rather than outputting plain text or standard function calls. When called via the standard `/v1/chat/completions` endpoint, those surface as `native_<tool>` calls.

The `/v1/code-agent/chat/completions` endpoint bridges this:
1. Declares Cursor native tools on incoming requests so models can utilize their native capabilities.
2. Intercepts native tool calls in responses and translates them into Code Agent's Python REPL convention:
   - `read` → `view("path")` or `print(read("path")[offset:limit])`
   - `grep` → `grep(pattern=..., path=...)`
   - `shell_stream` → `bash(command=..., timeout=..., bg=...)`
   - `exec_server_message` → `think("...")`
3. Packages the resulting code into a standard `repl_execute` function call that Code Agent executes directly in its REPL.

### Code Agent Configuration

Add the provider and desired models to `~/.code-agent/config.py`:

```python
register_provider(
    "cursor",
    host="127.0.0.1",
    port=8931,
    path="/v1/code-agent/chat/completions",
    api_key="crsr_...",
    rpm=60,
    concurrency=5,
    timeout=1800,
    tools=True,
    api_type="completions",
)

register_model(
    "cursor", "composer-2.5",
    model="composer-2.5",
    tool_mode="repl_execute",
    context_window=200_000,
)

register_model(
    "cursor", "grok-4.6",
    model="cursor-grok-4.6-high",
    tool_mode="repl_execute",
    context_window=256_000,
)

register_model(
    "cursor", "kimi-k3",
    model="kimi-k3-high",
    tool_mode="repl_execute",
    context_window=200_000,
)
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CURSOR_GATEWAY_HOST` | `127.0.0.1` | Bind address |
| `CURSOR_GATEWAY_PORT` | `8931` | Bind port |

### Running as a service

The gateway has no built-in daemon mode; run it under your init system or
container supervisor. A systemd unit is one option:

```ini
# /etc/systemd/system/cursor-gateway.service
[Unit]
Description=cursor-gateway

[Service]
User=youruser
Environment=PYTHONUNBUFFERED=1
# Optional: load CURSOR_GATEWAY_HOST/PORT (or anything else) from a file.
# systemd accepts an optional `export ` prefix in the file.
EnvironmentFile=/etc/cursor-gateway.env
WorkingDirectory=/opt/cursor-gateway
ExecStart=/usr/bin/python3 /opt/cursor-gateway/server.py
Type=exec
Restart=always

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cursor-gateway
journalctl -u cursor-gateway -f
```

## Implementation map

- `server.py` - OpenAI-compatible HTTP server; one thread per request.
- `cursor_transport/cursor.py` - the Cursor client: synthetic checkpoint
  construction, run/resume/cancel framing, tool partitioning, and the
  `chat_completions` entry point.
- `cursor_transport/codec.py` + `wire.py` + `schema.py` - dict-based
  protobuf codec over the schema extracted from Cursor's real `.proto` files.
- `schema_build/` - schema extraction/generation utilities (build-time only;
  `regen.sh` regenerates `cursor_transport/schema.py` and cleans up the
  intermediate compiled pb2 modules).
- `tests/` - decode tests.

## Limitations

- Non-streaming only: `"stream": true` is rejected.
- One run per request; a surfaced tool call ends the run and the client is
  expected to call back with the tool result (stateless multi-turn via
  synthetic checkpoints).
- `usage` values are the backend-reported token counts (from the run stream
  or the usage-events fallback); no client-side estimation is performed.

## Related Projects

Part of a family of developer tools for agentic coding and model gateways:

- **[Code Agent](https://github.com/jacobsparts/code-agent)** — A Python REPL-native coding agent designed around lean context, persistent execution state, and infinite context via lossless turn coalescing.
- **[AgentLib](https://github.com/jacobsparts/agentlib)** — A lightweight, production-proven library for building and shipping LLM agents quickly, where composable agents are defined as Python classes—making it both simple and powerful.
- **[codex-gateway](https://github.com/jacobsparts/codex-gateway)** — Pure-Python OpenAI Responses API-compatible gateway for Codex/ChatGPT OAuth accounts with quota management, account rotation, and automated resets.
- **[cursor-gateway](https://github.com/jacobsparts/cursor-gateway)** — Pure-Python OpenAI-compatible Chat Completions gateway that wraps the Cursor Agent API with synthetic checkpoints to provide real native tool calling and cache-friendly session routing.
