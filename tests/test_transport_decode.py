"""Regression tests for decoding on the real extracted proto schema.

These cover bugs that only live traffic exposed: the hand-written capture
schema was incomplete, so the real schema changes decoded shapes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cursor_transport import cursor as T
from cursor_transport import codec


def _exec_mcp_frame(arguments):
    """Build a decoded AgentServerMessage carrying ExecServerMessage mcpArgs."""
    mcp = {
        "name": "get_weather",
        "toolCallId": "call_1",
        "toolName": "get_weather",
        "providerIdentifier": "prov",
        "serverIdentifier": "srv",
        "arguments": arguments,
    }
    return {"execServerMessage": {"id": 7, "execId": "exec-1", "mcpArgs": mcp}}


class _Msg:
    def __init__(self, decoded):
        self.decoded = decoded


def _tool_call(decoded):
    return T.decode_tool_call(_Msg(decoded))


def test_mcp_args_entry_decodes_to_mapping():
    """McpArgs.arguments is repeated ArgsEntry, not (key, value) pairs.

    Iterating an ArgsEntry dict yields its key names ('key', 'value'), which
    previously raised AttributeError: 'str' object has no attribute 'get'.
    """
    call = _tool_call(_exec_mcp_frame([
        {"key": "city", "value": {"stringValue": "Paris"}},
    ]))
    assert call is not None
    assert call.name == "get_weather"
    assert call.id == "call_1"
    assert call.arguments == {"city": "Paris"}


def test_mcp_args_nested_struct_and_list():
    call = _tool_call(_exec_mcp_frame([
        {"key": "city", "value": {"stringValue": "Paris"}},
        {"key": "opts", "value": {"structValue": {"fields": [
            {"key": "units", "value": {"stringValue": "celsius"}},
            {"key": "days", "value": {"numberValue": 3.0}},
        ]}}},
        {"key": "tags", "value": {"listValue": {"values": [
            {"stringValue": "a"}, {"stringValue": "b"},
        ]}}},
        {"key": "flag", "value": {"boolValue": True}},
    ]))
    assert call.arguments["city"] == "Paris"
    assert call.arguments["opts"] == {"units": "celsius", "days": 3.0}
    assert call.arguments["tags"] == ["a", "b"]
    assert call.arguments["flag"] is True


def test_mcp_args_absent_entries_skipped():
    call = _tool_call(_exec_mcp_frame([
        {"key": "city", "value": {"stringValue": "Paris"}},
        {"key": "empty", "value": None},
    ]))
    assert "empty" not in call.arguments
    assert call.arguments["city"] == "Paris"


def test_prefetched_blobs_is_named_repeated_field():
    """RunRequest field 17 is a named repeated PreFetchedBlob in the real
    schema, so the unknown-field fallback is no longer needed."""
    fields = [f for f in codec.MESSAGES["AgentRunRequest"] if f.num == 17]
    assert fields, "field 17 missing from AgentRunRequest"
    assert fields[0].rep


def test_kv_client_message_id_is_uint32():
    """Real schema types KvClientMessage.id as uint32, not int32."""
    types = {f.num: f.type for f in codec.MESSAGES["KvClientMessage"]}
    assert types[1] == "uint32"


def test_scalar_roundtrip_all_types():
    """Every protobuf scalar type must survive encode/decode."""
    import struct

    cases = [
        ("bool", True, b"\x01"),
        ("int32", -7, None),
        ("int64", -1234567890123, None),
        ("uint32", 4000000000, None),
        ("uint64", 2 ** 63 + 5, None),
        ("sint32", -99, None),
        ("sint64", -2 ** 40, None),
        ("double", -1.5, None),
        ("float", 2.25, None),
        ("fixed32", 2 ** 32 - 1, None),
        ("fixed64", 2 ** 64 - 1, None),
        ("sfixed32", -12345, None),
        ("sfixed64", -2 ** 40, None),
        ("string", "hi", None),
        ("bytes", b"\x00\xff", None),
    ]
    from cursor_transport import wire
    for ftype, value, _ in cases:
        enc = wire._enc_scalar(ftype, value)
        wt = wire._wt_of(ftype)
        if wt == 0:
            raw, _i = wire._varint(enc, 0)
        elif wt in (1, 5):
            raw = enc
        else:
            ln, i = wire._varint(enc, 0)
            raw = enc[i:i + ln]
        assert wire._scalar(ftype, wt, raw) == value, ftype
