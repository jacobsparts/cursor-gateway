"""Generate cursor_transport/schema.py from the extracted .proto files.

Build-time only. Walks the real descriptors (importable via compiled pb2
modules under python3.11) and emits a static table of field definitions for the
messages the transport actually uses, plus everything reachable from them.

Runtime therefore carries no protobuf dependency: the emitted module is plain
data consumed by wire.py.

    python3.11 schema_build/gen_schema.py <compiled-pb2-dir>

The compiled pb2 directory is a transient build artifact; schema_build/regen.sh
runs protoc into a temp dir, invokes this script, and cleans up.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if len(sys.argv) < 2:
    sys.exit("usage: gen_schema.py <compiled-pb2-dir> (see regen.sh)")
PB = os.path.abspath(sys.argv[1])
sys.path.insert(0, ROOT)
sys.path.insert(0, PB)

import importlib

_TY = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 12: "bytes",
    13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32",
    18: "sint64",
}
_PACKABLE = {1, 2, 3, 4, 5, 6, 7, 8, 13, 15, 16, 17, 18}

# Messages the transport encodes or decodes directly.
ROOTS = [
    "agent.v1.AgentClientMessage",
    "agent.v1.AgentServerMessage",
    "agent.v1.AgentRunRequest",
    "agent.v1.ConversationStateStructure",
    "agent.v1.ConversationAction",
    "agent.v1.UserMessage",
    "agent.v1.ModelDetails",
    "agent.v1.RequestedModel",
    "agent.v1.PreFetchedBlob",
    "agent.v1.McpTools",
    "agent.v1.ExecServerMessage",
    "agent.v1.InteractionUpdate",
    "aiserver.v1.BidiRequestId",
    "aiserver.v1.BidiAppendRequest",
]

# Messages that are ours rather than Cursor's: they have no counterpart in the
# extracted protos, so they are carried over verbatim from the legacy table.
SYNTHETIC = [
    "Empty",
    "_BoundaryBlob",
    "_BoundaryStructure",
    "_HistoricalTurn",
    "_HistoricalToolStep",
    "_HistoricalToolStepContainer",
    "_HistoricalToolStepPayload",
    "_HistoricalToolOutcome",
    "_HistoricalToolText",
    "_HistoricalToolTextWrapper",
    "_FilteredUsageRequest",
    "_FilteredUsageResponse",
    "_FilteredUsageEvent",
    "_FilteredUsageToken",
    "_McpTools",
    "_McpTool",
]

# Real proto message -> legacy capture-derived name(s) that must keep resolving.
# Cursor's caller code is written against the legacy vocabulary; names are not
# wire-visible, so we keep them and take only numbers/types/repetition from the
# real protos.
LEGACY_ALIASES = {
    "AgentServerMessage": ["Run_res"],
    "AgentRunRequest": ["RunRequest", "Run_req"],
    "ConversationStateStructure": ["ConversationCheckpointUpdate"],
    "PreFetchedBlob": ["PrefetchedBlob"],
    "ModelDetails": ["_ModelDetails"],
    "McpTools": ["_McpTools"],
    "BidiRequestId": ["_BidiRequestId"],
    "BidiAppendRequest": ["_BidiAppendRequest"],
    "AgentClientMessage": ["AgentClientMessage"],
    "ConversationAction": ["ConversationAction"],
    "UserMessage": ["UserMessage"],
    "ExecServerMessage": ["ExecServerMessage"],
    "InteractionUpdate": ["InteractionUpdate"],
    # google.protobuf well-known types. Field numbers match the legacy
    # hand-rolled copies exactly (1-6), so keep the legacy camelCase arms
    # the transport code already handles.
    "Value": ["_Value"],
    "Struct": ["_Struct"],
    "ListValue": ["_ListValue"],
    "FieldsEntry": ["_StructEntry"],
}


def legacy_field_names(short, legacy):
    """Map field number -> legacy name for a real message, joined on number.

    Any legacy message sharing the real short name contributes vocabulary, not
    just the explicitly aliased ones; otherwise messages like KvClientMessage
    or McpArgs would silently switch to the proto names and break callers.
    """
    for cand in [short] + LEGACY_ALIASES.get(short, []):
        if cand in legacy.LEGACY_FIELD_NAMES:
            return {int(k): v
                    for k, v in legacy.LEGACY_FIELD_NAMES[cand].items()}
    return {}


def legacy_aliases(short, legacy):
    """Legacy message names that should also resolve to this real message."""
    return LEGACY_ALIASES.get(short, [])


def load_pool():
    """Import every generated pb2 module so the default pool is populated."""
    mods = [f[:-3] for f in sorted(os.listdir(PB)) if f.endswith("_pb2.py")]
    for m in mods:
        importlib.import_module(m)
    from google.protobuf import descriptor_pool
    return descriptor_pool.Default()


def children(container):
    attr = ("message_types_by_name" if hasattr(container, "message_types_by_name")
            else "nested_types_by_name")
    return list(getattr(container, attr).values())


def walk_msgs(m, out):
    out.append(m)
    for c in children(m):
        walk_msgs(c, out)


def collect(pool, roots):
    """Transitive closure of nested message types reachable from roots."""
    seen, out, order = set(), [], list(roots)
    while order:
        full = order.pop(0)
        if full in seen:
            continue
        seen.add(full)
        d = pool.FindMessageTypeByName(full)
        out.append(d)
        for f in d.fields:
            if f.type == 11:  # message
                order.append(f.message_type.full_name)
    # stable: also include nested types of everything we found
    final, seenf = [], set()
    for d in out:
        stack = [d]
        while stack:
            m = stack.pop()
            if m.full_name in seenf:
                continue
            seenf.add(m.full_name)
            final.append(m)
            stack.extend(children(m))
    final.sort(key=lambda m: m.full_name)
    return final


def ftypename(fd, keymap):
    if fd.type == 11:
        return "M:" + keymap[fd.message_type.full_name]
    if fd.type == 14:
        # Enums ride the wire as int32; callers pass and compare ints.
        return "int32"
    return _TY.get(fd.type, "int32")


def _load_legacy_data():
    """Load the frozen legacy schema data.

    The legacy capture-derived codec was deleted once this migration landed.
    The pieces of it that remain load-bearing (our own synthetic messages and
    the legacy field vocabulary) are frozen in schema_build/legacy_schema_data.json.
    """
    import json
    from dataclasses import dataclass

    path = os.path.join(HERE, "legacy_schema_data.json")
    with open(path) as fh:
        data = json.load(fh)

    @dataclass(frozen=True)
    class F:
        name: str
        num: int
        type: str = None
        rep: bool = False
        packed: bool = False
        map: tuple = None
        enum: dict = None

    class _Codec:
        MESSAGES = {
            name: [F(**f) for f in fields]
            for name, fields in data["synthetic"].items()
        }

    legacy = _Codec()
    legacy.LEGACY_FIELD_NAMES = data["legacy_field_names"]
    return legacy


def main():
    pool = load_pool()
    msgs = collect(pool, ROOTS)
    # The codec resolves submessage types by short name, so a short name that
    # is not unique must be keyed by full name or encode/decode would bind the
    # field to the wrong message.
    import collections
    counts = collections.Counter(m.full_name.split(".")[-1] for m in msgs)
    keymap = {}
    for m in msgs:
        short = m.full_name.split(".")[-1]
        keymap[m.full_name] = short if counts[short] == 1 else m.full_name
    used = collections.Counter(keymap.values())
    assert not any(v > 1 for v in used.values()), sorted(
        k for k, v in used.items() if v > 1)
    legacy = _load_legacy_data()
    missing = [n for n in SYNTHETIC if n not in legacy.MESSAGES]
    assert not missing, missing
    lines = [
        '"""Generated by schema_build/gen_schema.py from the extracted .proto files.',
        "",
        "Field numbers, types, and repetition come from the real Cursor protobuf",
        "schema, not from capture-derived guesses. Do not edit by hand.",
        '"""',
        "",
        "from cursor_transport.wire import F",
        "",
        "MESSAGES = {",
    ]
    renamed = 0
    for d in msgs:
        short = keymap[d.full_name]
        lnames = legacy_field_names(d.full_name.split(".")[-1], legacy)
        fields = []
        for f in d.fields:
            rep = bool(getattr(f, "is_repeated", False))
            t = ftypename(f, keymap)
            packed = rep and f.type in _PACKABLE
            name = lnames.get(f.number, f.name)
            if name != f.name:
                renamed += 1
            fields.append(
                "        F(%r, %d, type=%r%s%s),"
                % (name, f.number, t, ", rep=True" if rep else "",
                   ", packed=True" if packed else ""))
        # Emit under the real proto name plus every legacy alias that differs,
        # so both vocabularies resolve to the same field definitions.
        keys = [short]
        for alias in legacy_aliases(d.full_name.split(".")[-1], legacy):
            if alias not in keys:
                keys.append(alias)
        for key in keys:
            lines.append("    %r: [" % key)
            lines.extend(fields)
            lines.append("    ],")
    print("kept %d legacy field names; rest use real proto names" % renamed)
    for name in SYNTHETIC:
        lines.append("    %r: [" % name)
        for f in legacy.MESSAGES[name]:
            lines.append(
                "        F(%r, %d, type=%r%s%s),"
                % (f.name, f.num, f.type, ", rep=True" if f.rep else "",
                   ", packed=True" if f.packed else ""))
        lines.append("    ],")
    lines.append("}")
    lines.append("")
    out = os.path.join(ROOT, "cursor_transport", "schema.py")
    with open(out, "w") as fh:
        fh.write("\n".join(lines))
    print("wrote %s: %d messages" % (out, len(msgs)))


if __name__ == "__main__":
    main()
