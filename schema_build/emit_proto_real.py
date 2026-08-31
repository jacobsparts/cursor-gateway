"""Emit real .proto files from the extracted Cursor schema.

Input:  JSON from schema_build/extract_schema.py
Output: one .proto per (source module, package) pair, mirroring Cursor's own
        proto/dist/generated layout.

Why per-module rather than per-package: the module dependency graph is
ACYCLIC (verified: 82 SCCs, 0 nontrivial), but the package graph is not --
agent.v1 and aiserver.v1 import each other, and protoc rejects recursive
imports. Per-module files have no cycles.

Nested messages (agent.v1.UserMessage.SimulatedMessageMetadata) are emitted
nested; they never cross modules (verified).
"""

import collections
import json
import os
import sys

SCALAR = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 12: "bytes",
    13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32",
    18: "sint64",
}


def pkg_of(fullname):
    """agent.v1.Foo.Bar -> agent.v1"""
    p = fullname.split(".")
    return ".".join(p[:2]) if len(p) > 2 else p[0]


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cursor_schema_full.json"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "/home/jacob/cursor-gateway/proto"
    d = json.load(open(src))
    messages = d["messages"]
    enums = d["enums"]

    owner = {n: m["module"] for n, m in messages.items()}
    owner.update({n: e["module"] for n, e in enums.items()})

    groups = collections.defaultdict(list)
    for n in set(messages) | set(enums):
        groups[(owner[n], pkg_of(n))].append(n)

    def pkg_of_p(mod):
        parts = mod.split("/")
        for i, p in enumerate(parts):
            if p in ("agent", "aiserver") and i + 1 < len(parts):
                return f"{p}_{parts[i+1]}"
        return parts[-2] if len(parts) > 1 else "misc"

    def base_name(mod, pkg):
        stem = mod.split("/")[-1].replace("_pb.js", "").replace(".js", "")
        # A single module can declare types in more than one package
        # (telemetry_pb.js declares aiserver.v1.* AND a local
        # google.protobuf.Duration). Disambiguate by package, or the two
        # groups collide on one filename and one silently overwrites the other.
        return f"{pkg.replace('.', '_')}_{stem}"

    files = {}
    for key in groups:
        files[key] = os.path.join(outdir, base_name(*key) + ".proto")

    deps = collections.defaultdict(set)
    for n, m in messages.items():
        srcg = (owner[n], pkg_of(n))
        for f in m["fields"]:
            t = f.get("msg_resolved") or f.get("enum_resolved")
            if f["kind"] == "map":
                t = f.get("V", {}).get("resolved")
            if t and t in owner:
                dstg = (owner[t], pkg_of(t))
                if dstg != srcg:
                    deps[srcg].add(dstg)

    os.makedirs(outdir, exist_ok=True)
    stats = collections.Counter()

    for key, names in sorted(groups.items()):
        mod, pkg = key
        tree = {}
        for n in sorted(names):
            rest = n[len(pkg) + 1:].split(".")
            cur = tree
            for i, part in enumerate(rest):
                cur = cur.setdefault(
                    part, {"full": ".".join([pkg] + rest[:i + 1]),
                           "kids": {}})["kids"]

        lines = ['syntax = "proto3";', "", f"package {pkg};", ""]
        dd = sorted(deps[key], key=lambda g: os.path.basename(files[g]))
        for g in dd:
            lines.append(f'import "{os.path.basename(files[g])}";')
        if dd:
            lines.append("")

        def emit(fullname, indent):
            node = None
            cur = tree
            for part in fullname[len(pkg) + 1:].split("."):
                node = cur[part]
                cur = node["kids"]
            out = []
            if fullname in enums:
                stats["enums"] += 1
                out.append(f"{indent}enum {fullname.split('.')[-1]} {{")
                for num, val in sorted(enums[fullname]["values"],
                                       key=lambda kv: kv[0]):
                    out.append(f"{indent}  {val} = {num};")
                out.append(f"{indent}}}")
            else:
                stats["messages"] += 1
                out.append(f"{indent}message {fullname.split('.')[-1]} {{")
                out.extend(body(messages.get(fullname, {"fields": []})["fields"],
                                indent + "  "))
                for kid in sorted(node["kids"]):
                    out.append("")
                    out.extend(emit(node["kids"][kid]["full"], indent + "  "))
                out.append(f"{indent}}}")
            return out

        def body(fields, ind):
            out, i, seen = [], 0, set()
            while i < len(fields):
                f = fields[i]
                on = f.get("oneof")
                if on and on not in seen:
                    seen.add(on)
                    stats["oneofs"] += 1
                    out.append(f"{ind}oneof {on} {{")
                    while i < len(fields) and fields[i].get("oneof") == on:
                        stats["fields"] += 1
                        out.append(f"{ind}  {decl(fields[i])}")
                        i += 1
                    out.append(f"{ind}}}")
                    continue
                stats["fields"] += 1
                out.append(f"{ind}{decl(f)}")
                i += 1
            return out

        for part in sorted(tree):
            lines.append("")
            lines.extend(emit(tree[part]["full"], ""))

        open(files[key], "w").write("\n".join(lines) + "\n")
        stats["files"] += 1

    print("files    :", stats["files"])
    print("messages :", stats["messages"])
    print("enums    :", stats["enums"])
    print("fields   :", stats["fields"])
    print("oneofs   :", stats["oneofs"])
    print("maps     :", stats["maps"])


def decl(f):
    lbl = ""
    if f.get("repeated") and f["kind"] != "map":
        lbl = "repeated "
    elif f.get("opt"):
        lbl = "optional "
    k, n, nm = f["kind"], f["no"], f["name"]
    if k == "scalar":
        return f"{lbl}{SCALAR[f['T']]} {nm} = {n};"
    if k == "message":
        return f"{lbl}.{f['msg_resolved']} {nm} = {n};"
    if k == "enum":
        return f"{lbl}.{f['enum_resolved']} {nm} = {n};"
    if k == "map":
        kt = SCALAR[f["K"]]
        v = f.get("V", {})
        if v.get("kind") == "scalar":
            vt = SCALAR.get(v.get("T"), "string")
        elif v.get("kind") == "message":
            vt = "." + v["resolved"] if v.get("resolved") else "bytes"
        elif v.get("kind") == "enum":
            vt = "." + v["enum_resolved"] if v.get("enum_resolved") else "int32"
        else:
            vt = "string"
        return f"map<{kt}, {vt}> {nm} = {n};"
    return f"bytes {nm} = {n};"


if __name__ == "__main__":
    main()
