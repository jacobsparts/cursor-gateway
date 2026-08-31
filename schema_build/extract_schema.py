"""Extract the complete Cursor protobuf schema from the tapped VSIX bundle.

The bundle ships no .proto files, but index.js contains 82 webpack modules of
@bufbuild/protobuf (protobuf-ES) generated code. Three declaration forms carry
everything:

  Var.typeName="agent.v1.AgentRunRequest"
  Var.fields=X.C.util.newFieldList((()=>[{no:1,name:"...",kind:"...",T:...}]))
  function(e){e[e.X=0]="X"}(En||(En={})),X.C.util.setEnumType(En,"name",[...])

Minified names are reused across modules, so every map is scoped per module.
The module head's `n.d(t,{RealName:()=>minVar})` gives the authoritative
name->var binding, and `var Alias=n("path")` gives cross-module refs.
"""

import collections
import json
import re
import sys

BUNDLE = "/tmp/cursor-agent-tapped/index.js"

# ,"./src/x.ts"(e,t,n){  -- webpack module header
HDR = re.compile(r'(?:^|,)"([^"\n]{1,300})"\(([a-z_$][\w$]*),([a-z_$][\w$]*),([a-z_$][\w$]*)\)\{')

# n.d(t,{Name:()=>var, ...})
EXPORTS = re.compile(r'n\.d\(t,\{([^{}]*)\}\)')
# Two forms. Internal:      RealName:()=>minVar
#             Cross-module: <mangledExport>:()=>minVar
# Both are name -> local var; which one is used depends on the referencing side.
EXPORT_PAIR = re.compile(r'([A-Za-z_$][\w$]*)\s*:\s*\(\)\s*=>\s*([A-Za-z_$][\w$]*)')

# Requires are CHAINED: var a=n("x"),l=n("y"),u=n("z") -- only the first has
# `var`. Dropping the `var` requirement is safe here because this pattern is
# unique to webpack's module loader in this bundle.
# No \b anchor: aliases may be bare '$', and \b does not match between two
# non-word chars (a leading comma and '$'), which silently dropped such binds.
REQUIRE = re.compile(r'([A-Za-z_$][\w$]*)=n\("([^"]*)"\)')

# Var.typeName="pkg.Msg". No \b anchor: some vars are bare '$', and \b does not
# match between a non-word char and '$'.
TYPENAME = re.compile(r'([A-Za-z_$][\w$]*)\.typeName="([A-Za-z0-9_.]+)"')

# Var.fields=X.C.util.newFieldList((()=>[ ... ]))
FIELDS = re.compile(
    r'\b([A-Za-z_$][\w$]*)\.fields=[A-Za-z_$][\w$]*\.C\.util\.newFieldList\(\(\(\)=>\[(.*?)\]\)\)',
    re.S,
)

# enum: function(e){e[e.X=0]="X",...}(En||(En={})),X.C.util.setEnumType(En,"name",[...])
ENUM_IIFE = re.compile(
    r'function\(e\)\{((?:e\[e\.[A-Za-z_0-9]+=\d+\]="[A-Za-z_0-9]+",?)+)\}\(([A-Za-z_$][\w$]*)\|\|\([A-Za-z_$][\w$]*=\{\}\)\)[;,]?'
)
ENUM_MEMBER = re.compile(r'e\[e\.([A-Za-z_0-9]+)=(\d+)\]="[A-Za-z_0-9]+"')
SET_ENUM = re.compile(
    r'[A-Za-z_$][\w$]*\.C\.util\.setEnumType\(([A-Za-z_$][\w$]*),"([A-Za-z0-9_.]+)",\[(.*?)\]\)',
    re.S,
)
ENUM_DECL = re.compile(r'\{no:(\d+),name:"([A-Za-z0-9_]+)"\}')

# newFieldList entries. Field objects are brace-delimited but may nest one level
# (map values, message T:{...}). Match a single entry by scanning braces.
def split_field_entries(text):
    out, depth, cur = [], 0, []
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            if cur:
                out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [e for e in (s.strip() for s in out) if e.startswith("{")]


def parse_field(entry):
    f = {}
    m = re.match(r'\{no:(\d+),name:"([A-Za-z0-9_]+)",kind:"(\w+)"', entry)
    if not m:
        return None
    f["no"] = int(m.group(1))
    f["name"] = m.group(2)
    f["kind"] = m.group(3)
    rest = entry[m.end():]
    if re.search(r'\brepeated:!?0?1?\b|repeated:!0', rest):
        f["repeated"] = "repeated:!0" in rest.replace(" ", "")
    if "opt:!0" in rest.replace(" ", ""):
        f["opt"] = True
    m = re.search(r'oneof:"([A-Za-z0-9_]+)"', rest)
    if m:
        f["oneof"] = m.group(1)
    if "packed:!1" in rest.replace(" ", ""):
        f["packed"] = False
    if f["kind"] == "scalar":
        m = re.search(r'T:(\d+)', rest)
        f["T"] = int(m.group(1)) if m else None
    elif f["kind"] == "message":
        # Normal form is `T:SomeVar`, but the minifier also emits JS object
        # shorthand `T` (meaning T: T) when the class is literally named T.
        m = re.search(r'T:\s*([A-Za-z_$][\w$.]*)', rest)
        if m:
            f["msg"] = m.group(1)
        elif re.search(r',T(?=[,}])', rest):
            f["msg"] = "T"
    elif f["kind"] == "enum":
        m = re.search(r'T:[A-Za-z_$][\w$]*\.C\.getEnumType\(([A-Za-z_$][\w$.]*)\)', rest)
        f["enum"] = m.group(1) if m else None
    elif f["kind"] == "map":
        m = re.search(r'K:(\d+)', rest)
        f["K"] = int(m.group(1)) if m else None
        m = re.search(r'V:\{kind:"(\w+)"(?:,T:\s*([^,}]+))?', rest)
        if m:
            f["V"] = {"kind": m.group(1)}
            if m.group(2):
                f["V"]["ref"] = m.group(2).strip()
    return f


def main():
    src = open(BUNDLE, encoding="utf-8", errors="replace").read()
    heads = list(HDR.finditer(src))
    segs = []
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(src)
        segs.append((h.group(1), src[h.start():end]))
    modules = {p: s for p, s in segs if p.endswith("_pb.js")}
    module_by_path = dict(segs)

    # Path -> which module owns it (for resolving requires)
    path_to_module = {}
    for p, s in segs:
        path_to_module[p] = s
        # normalize: modules referenced relatively from another module
    messages = {}      # fullname -> {module, var, fields}
    enums = {}         # fullname -> {module, var, values}
    mod_ctx = {}       # module path -> {var: fullname, alias: path}

    for path, body in modules.items():
        exports = {}
        m = EXPORTS.search(body)
        if m:
            for name, var in EXPORT_PAIR.findall(m.group(1)):
                exports[name] = var
        aliases = {a: p for a, p in REQUIRE.findall(body)}
        export2var = {}
        m = EXPORTS.search(body)
        if m:
            for name, var in EXPORT_PAIR.findall(m.group(1)):
                export2var[name] = var
        var2name = {}
        for var, tname in TYPENAME.findall(body):
            var2name[var] = tname
        # enum value lists
        enum_vals = {}
        for mn in SET_ENUM.finditer(body):
            evar, ename, decls = mn.group(1), mn.group(2), mn.group(3)
            enum_vals[evar] = {"name": ename,
                               "values": [(int(a), b) for a, b in ENUM_DECL.findall(decls)]}
        # IIFE-declared enum objects (authoritative ordering) merged in
        for m in ENUM_IIFE.finditer(body):
            members, evar = m.group(1), m.group(2)
            enum_vals.setdefault(evar, {"name": None, "values": []})
            if not enum_vals[evar]["values"]:
                enum_vals[evar]["values"] = [
                    (int(n), v) for v, n in ENUM_MEMBER.findall(members)]
        mod_ctx[path] = {"exports": exports, "export2var": export2var,
                         "aliases": aliases,
                         "var2name": var2name, "enums": enum_vals}

        for var, tname in var2name.items():
            messages[tname] = {"module": path, "var": var, "fields": []}
        for var, info in enum_vals.items():
            if info["name"]:
                enums[info["name"]] = {"module": path, "var": var,
                                       "values": info["values"]}

        for fm in FIELDS.finditer(body):
            var, flist = fm.group(1), fm.group(2)
            tname = var2name.get(var)
            if not tname:
                continue
            parsed = []
            for entry in split_field_entries(flist):
                pf = parse_field(entry)
                if pf:
                    parsed.append(pf)
            messages[tname]["fields"] = parsed

    # ---- resolve references (scoped per module) -------------------------
    # A message-typed field's T is either a local var ("ai") or a
    # cross-module ref ("rr.Or"). Cross-module refs name the TARGET MODULE'S
    # EXPORT NAME, not its local var: `n.d(t,{Or:()=>someLocal})`. So resolve
    # alias -> module, then export name -> local var -> typeName.
    EK = "msg_resolved"

    def resolve_msg(ctx, ref):
        if "." in ref:
            alias, key = ref.split(".", 1)
            tgt = ctx["aliases"].get(alias)
            c = mod_ctx.get(tgt)
            if not c:
                return None
            local = c["export2var"].get(key) or key
            return c["var2name"].get(local)
        return ctx["var2name"].get(ref)

    def resolve_enum(ctx, ref):
        if "." in ref:
            alias, key = ref.split(".", 1)
            tgt = ctx["aliases"].get(alias)
            c = mod_ctx.get(tgt)
            if not c:
                return None
            local = c["export2var"].get(key) or key
            info = c["enums"].get(local)
            return info["name"] if info else None
        info = ctx["enums"].get(ref)
        return info["name"] if info else None

    for name, m in messages.items():
        ctx = mod_ctx[m["module"]]
        for f in m["fields"]:
            if f["kind"] == "message" and f.get("msg"):
                r = resolve_msg(ctx, f["msg"])
                if r:
                    f[EK] = r
            elif f["kind"] == "enum" and f.get("enum"):
                r = resolve_enum(ctx, f["enum"])
                if r:
                    f["enum_resolved"] = r
            elif f["kind"] == "map" and f.get("V", {}).get("kind") == "message":
                r = resolve_msg(ctx, f["V"]["ref"])
                if r:
                    f["V"]["resolved"] = r

    tot_msg = sum(1 for m in messages.values() for f in m["fields"]
                  if f["kind"] == "message" and f.get("msg"))
    res_msg = sum(1 for m in messages.values() for f in m["fields"] if f.get(EK))
    tot_en = sum(1 for m in messages.values() for f in m["fields"]
                 if f["kind"] == "enum")
    res_en = sum(1 for m in messages.values() for f in m["fields"]
                 if f.get("enum_resolved"))
    print(f"msg refs resolved    : {res_msg}/{tot_msg}")
    print(f"enum refs resolved   : {res_en}/{tot_en}")

    with_fields = {k: v for k, v in messages.items() if v["fields"]}
    print(f"modules(_pb.js)      : {len(modules)}")
    print(f"messages (typeName)  : {len(messages)}")
    print(f"messages with fields : {len(with_fields)}")
    print(f"enums                : {len(enums)}")
    print(f"enums with values    : {sum(1 for e in enums.values() if e['values'])}")
    print(f"total fields         : {sum(len(v['fields']) for v in messages.values())}")
    print(f"map fields           : {sum(1 for v in messages.values() for f in v['fields'] if f.get('kind')=='map')}")
    print(f"enum-typed fields    : {sum(1 for v in messages.values() for f in v['fields'] if f.get('kind')=='enum')}")
    print(f"oneof fields         : {sum(1 for v in messages.values() for f in v['fields'] if f.get('oneof'))}")

    out = {
        "modules": {
            p: {"exports": c["exports"], "export2var": c["export2var"],
                "aliases": c["aliases"],
                "var2name": c["var2name"],
                "enums": {k: v for k, v in c["enums"].items()}}
            for p, c in mod_ctx.items()
        },
        "messages": {k: {"module": v["module"], "var": v["var"],
                         "fields": v["fields"]} for k, v in messages.items()},
        "enums": enums,
    }
    dest = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cursor_schema_full.json"
    with open(dest, "w") as fh:
        json.dump(out, fh)
    print("wrote", dest)
    # sanity: the two messages we care most about
    for key in ("agent.v1.AgentRunRequest",
                "agent.v1.AgentConversationTurnStructure"):
        v = messages.get(key)
        print(f"\n{key}: {len(v['fields']) if v else 0} fields")
        if v:
            for f in v["fields"][:6]:
                print("   ", f)


if __name__ == "__main__":
    main()
