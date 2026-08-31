#!/usr/bin/env bash
# Regenerate cursor_transport/schema.py from the extracted .proto files.
#
# Build-time only; the service runtime never runs this. The intermediate
# compiled pb2 modules (protoc output) are a transient artifact created in a
# temp dir and deleted at the end.
#
# Steps:
#   1. protoc: proto/*.proto -> compiled pb2 modules (temp dir)
#   2. gen_schema.py: pb2 descriptor pool -> cursor_transport/schema.py
#   3. verify_proto.py (optional): cross-check pb2 against the VSIX
#      extraction; requires the extraction JSON (see step below).
#
# Full pipeline when Cursor ships a new client:
#   1. extract_schema.py: tapped VSIX index.js -> /tmp/cursor_schema_full.json
#      (needs the tapped bundle mounted at /tmp/cursor-agent-tapped/)
#   2. emit_proto_real.py: that JSON -> proto/*.proto
#   3. this script

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PY=${PYTHON:-python3.11}

PB_OUT=$(mktemp -d)
trap 'rm -rf "$PB_OUT"' EXIT

"$PY" -m grpc_tools.protoc -I "$ROOT/proto" --python_out="$PB_OUT" \
    "$ROOT"/proto/*.proto

"$PY" "$HERE/gen_schema.py" "$PB_OUT"

if [ -f /tmp/cursor_schema_full.json ]; then
    "$PY" "$HERE/verify_proto.py" /tmp/cursor_schema_full.json "$PB_OUT"
else
    echo "verify skipped: /tmp/cursor_schema_full.json not present"
fi
