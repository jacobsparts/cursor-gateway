"""Verify generated *_pb2 modules against the extracted Cursor schema.

Run after schema_build/extract_schema.py and schema_build/emit_proto_real.py + protoc.

Checks, for every message and enum in the extracted schema:
  - the type exists in the generated descriptor pool
  - field numbers match exactly
  - field names match
  - message/enum field types resolve to the same fully-qualified name
  - repeated / optional labels match
  - nested types are nested under the same parent
"""

import glob
import importlib
import json
import os
import sys

from google.protobuf import descriptor as D
from google.protobuf import descriptor_pool

SCALAR_NAME = {
    D.FieldDescriptor.TYPE_DOUBLE: "double",
    D.FieldDescriptor.TYPE_FLOAT: "float",
    D.FieldDescriptor.TYPE_INT64: "int64",
    D.FieldDescriptor.TYPE_UINT64: "uint64",
    D.FieldDescriptor.TYPE_INT32: "int32",
    D.FieldDescriptor.TYPE_FIXED64: "fixed64",
    D.FieldDescriptor.TYPE_FIXED32: "fixed32",
    D.FieldDescriptor.TYPE_BOOL: "bool",
    D.FieldDescriptor.TYPE_STRING: "string",
    D.FieldDescriptor.TYPE_BYTES: "bytes",
    D.FieldDescriptor.TYPE_UINT32: "uint32",
    D.FieldDescriptor.TYPE_SFIXED32: "sfixed32",
    D.FieldDescriptor.TYPE_SFIXED64: "sfixed64",
    D.FieldDescriptor.TYPE_SINT32: "sint32",
    D.FieldDescriptor.TYPE_SINT64: "sint64",
}
# protobuf-ES scalar codes -> proto3 type names (must match emit_proto_real)
ES_TO_PROTO = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 12: "bytes",
    13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32",
    18: "sint64",
}


def main():
    schema_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cursor_schema_full.json"
    gen_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/pbout"

    sys.path.insert(0, gen_dir)
    for f in sorted(glob.glob(os.path.join(gen_dir, "*_pb2.py"))):
        importlib.import_module(os.path.basename(f)[:-3])

    schema = json.load(open(schema_path))
    msgs = schema["messages"]
    enums = schema["enums"]

    pool = descriptor_pool.Default()
    DESC, EDESC = {}, {}

    def add_msg(md, prefix):
        full = f"{prefix}.{md.name}" if prefix else md.name
        DESC[full] = md
        for e in md.enum_types:
            EDESC[f"{full}.{e.name}"] = e
        for n in md.nested_types:
            add_msg(n, full)

    files = 0
    for f in sorted(glob.glob(os.path.join(gen_dir, "*_pb2.py"))):
        stem = os.path.basename(f)[: -len("_pb2.py")]
        try:
            fd = pool.FindFileByName(stem + ".proto")
        except KeyError:
            continue
        files += 1
        for name in fd.message_types_by_name:
            add_msg(fd.message_types_by_name[name], fd.package)
        for name in fd.enum_types_by_name:
            EDESC[f"{fd.package}.{name}"] = fd.enum_types_by_name[name]

    print(f"generated files in pool : {files}")
    print(f"generated messages      : {len(DESC)}")
    print(f"generated enums         : {len(EDESC)}")
    print(f"schema messages         : {len(msgs)}")
    print(f"schema enums            : {len(enums)}")
    print()

    problems = []

    missing_m = sorted(n for n in msgs if n not in DESC)
    missing_e = sorted(n for n in enums if n not in EDESC)
    for n in missing_m:
        problems.append(("message missing", n, "", ""))
    for n in missing_e:
        problems.append(("enum missing", n, "", ""))

    # enum value lists
    for n, info in enums.items():
        ed = EDESC.get(n)
        if ed is None:
            continue
        gen = {v.name: v.number for v in ed.values}
        want = {v[1]: v[0] for v in info["values"]}
        if gen != want:
            only_gen = sorted(set(gen) - set(want))[:4]
            only_want = sorted(set(want) - set(gen))[:4]
            numdiff = sorted(k for k in set(gen) & set(want) if gen[k] != want[k])[:4]
            problems.append(("enum values", n,
                             f"gen_only={only_gen} schema_only={only_want}",
                             f"num_mismatch={numdiff}"))

    # field-level
    nchecked = 0
    for n, m in msgs.items():
        md = DESC.get(n)
        if md is None:
            continue
        nchecked += 1
        gmap = {f.number: f for f in md.fields}
        smap = {f["no"]: f for f in m["fields"]}
        if set(gmap) != set(smap):
            problems.append(("field numbers", n,
                             f"gen_only={sorted(set(gmap) - set(smap))[:5]}",
                             f"schema_only={sorted(set(smap) - set(gmap))[:5]}"))
            continue
        for num, gf in gmap.items():
            s = smap[num]
            if gf.name != s["name"]:
                problems.append(("field name", f"{n}.{num}", gf.name, s["name"]))
                continue
            kind = s["kind"]
            if kind == "message":
                want = s.get("msg_resolved")
                got = gf.message_type.full_name if gf.message_type else None
                if want and got != want:
                    problems.append(("field type", f"{n}.{num}", str(got), str(want)))
            elif kind == "enum":
                want = s.get("enum_resolved")
                got = gf.enum_type.full_name if gf.enum_type else None
                if want and got != want:
                    problems.append(("field type", f"{n}.{num}", str(got), str(want)))
            elif kind == "scalar":
                want = ES_TO_PROTO.get(s.get("T"))
                got = SCALAR_NAME.get(gf.type)
                if want and got != want:
                    problems.append(("field type", f"{n}.{num}", str(got), str(want)))
            elif kind == "map":
                pass
            # label. upb FieldDescriptor has no .is_map; a map field is a
            # repeated message whose type has map_entry set.
            is_map_field = bool(
                gf.message_type and gf.message_type.GetOptions().map_entry)
            g_rep = bool(gf.is_repeated) or is_map_field
            s_rep = bool(s.get("repeated")) or kind == "map"
            if g_rep != s_rep:
                problems.append(("field label", f"{n}.{num}",
                                 f"repeated={g_rep}", f"repeated={s_rep}"))

    print(f"messages field-checked  : {nchecked}")
    print(f"problems                : {len(problems)}")
    by_kind = {}
    for p in problems:
        by_kind.setdefault(p[0], []).append(p)
    for k, v in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
        print(f"  {k:16s} {len(v)}")
        for p in v[:6]:
            print(f"      {p[1]}  {p[2]}  {p[3]}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
