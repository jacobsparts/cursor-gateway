"""Schema-independent protobuf wire primitives for the Cursor transport.

The field tables live in cursor_transport.schema (generated from the real
extracted .proto files) and are installed by cursor_transport.codec. Nothing in
this module knows about a particular schema.

The primitives were extracted verbatim from the old capture-derived
cursor_codec.py so that encoded output stays byte-identical; only the source of
the field tables changed.
"""

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class F:
    name: str
    num: int
    type: str = None
    rep: bool = False
    packed: bool = False
    map: tuple = None
    enum: dict = None


UNKNOWN = "__unknown__"

# Populated by cursor_transport.codec at import time.
MESSAGES = {}


_FIXED = {"double": ("d", 8), "fixed64": ("Q", 8), "sfixed64": ("q", 8),
          "float": ("f", 4), "fixed32": ("I", 4), "sfixed32": ("i", 4)}

# The capture-derived codec only ever saw the handful of scalar types present in
# captured traffic. The real schema introduces the rest (uint32/uint64, sint32,
# fixed*/sfixed*), which must map to their correct wire types or they silently
# encode as length-delimited bytes.
_VARINT = frozenset({"bool", "int32", "int64", "uint32", "uint64",
                     "sint32", "sint64"})
_FIXED64 = frozenset({"double", "fixed64", "sfixed64"})
_FIXED32 = frozenset({"float", "fixed32", "sfixed32"})


def _varint(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1
        r |= (c & 0x7F) << s
        if not c & 0x80:
            return r, i
        s += 7

def _enc_varint(v):
    if v < 0:
        v += 1 << 64
    out = bytearray()
    while True:
        x = v & 0x7F; v >>= 7
        out.append(x | 0x80 if v else x)
        if not v:
            return bytes(out)

def _zz_enc(v): return (v << 1) ^ (v >> 63)
def _zz_dec(v): return (v >> 1) ^ -(v & 1)
def _zz_enc32(v): return ((v << 1) ^ (v >> 31)) & 0xFFFFFFFF
def _zz_dec32(v): return (v >> 1) ^ -(v & 1)

def _fields(buf):
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            v = buf[i:i + 8]; i += 8
        elif wt == 2:
            l, i = _varint(buf, i); v = buf[i:i + l]; i += l
        elif wt == 5:
            v = buf[i:i + 4]; i += 4
        else:
            raise ValueError(f"bad wire type {wt}")
        yield fn, wt, v

def _wt_of(ftype):
    if ftype in _VARINT:
        return 0
    if ftype in _FIXED64:
        return 1
    if ftype in _FIXED32:
        return 5
    return 2

def _scalar(ftype, wt, raw):
    if wt == 0:
        if ftype == "sint64":
            return _zz_dec(raw)
        if ftype == "sint32":
            return _zz_dec32(raw)
        if ftype == "bool":
            return bool(raw)
        # Negative int32/int64 are sign-extended to 64 bits on the wire.
        if ftype in ("int32", "int64"):
            return raw - (1 << 64) if raw >= (1 << 63) else raw
        return raw
    if wt != 2:
        if ftype in ("double", "float"):
            return struct.unpack("<" + _FIXED[ftype][0], raw)[0]
        signed = ftype in ("sfixed32", "sfixed64")
        return int.from_bytes(raw, "little", signed=signed)
    return raw.decode("utf-8") if ftype == "string" else raw

def _enc_scalar(ftype, v):
    if ftype == "bool":
        return _enc_varint(int(bool(v)))
    if ftype in ("int32", "int64", "uint32", "uint64"):
        return _enc_varint(int(v))
    if ftype == "sint64":
        return _enc_varint(_zz_enc(int(v)))
    if ftype == "sint32":
        return _enc_varint(_zz_enc32(int(v)))
    if ftype in _FIXED:
        num = float(v) if ftype in ("double", "float") else int(v)
        return struct.pack("<" + _FIXED[ftype][0], num)
    b = v.encode("utf-8") if ftype == "string" else v
    return _enc_varint(len(b)) + b


def _orig_decode(data, msg_type):
    by_num = {f.num: f for f in MESSAGES[msg_type]}
    out, unk = {}, {}
    for fn, wt, raw in _fields(bytes(data)):
        f = by_num.get(fn)
        if f is None:
            unk.setdefault(str(fn), []).append((wt, raw))
            continue
        val = _decode_field(f, wt, raw)
        if f.enum is not None:
            if isinstance(val, list):
                val = [f.enum.get(item, item) for item in val]
            else:
                val = f.enum.get(val, val)
        if f.map:
            out.setdefault(f.name, []).append(val)
        elif f.packed and wt == 2:
            prev = out.get(f.name)
            if prev is None:
                out[f.name] = val
            elif prev and isinstance(prev[0], list):
                prev.append(val)
            else:
                out[f.name] = [prev, val]
        elif f.rep:
            out.setdefault(f.name, []).append(val)
        elif f.name in out:
            if not isinstance(out[f.name], list):
                out[f.name] = [out[f.name]]
            out[f.name].append(val)
        else:
            out[f.name] = val
    if unk:
        out[UNKNOWN] = unk
    return out

def _decode_field(f, wt, raw):
    if f.map:
        k, vals = None, []
        for efn, ewt, ev in _fields(raw):
            if efn == 1:
                k = _scalar(f.map[0], ewt, ev)
            elif efn == 2:
                vt = f.map[1]
                vals.append(decode(ev, vt[2:]) if vt.startswith("M:")
                            else _scalar(vt, ewt, ev))
        return (k, vals[0] if len(vals) == 1 else (vals or None))
    if f.type and f.type.startswith("M:"):
        return decode(raw, f.type[2:])
    if f.packed and wt == 2:
        if f.type in _VARINT and f.type != "bool":
            vals, i = [], 0
            while i < len(raw):
                v, i = _varint(raw, i)
                vals.append(_zz_dec32(v) if f.type == "sint32"
                            else _zz_dec(v) if f.type == "sint64" else v)
            return vals
        ch, size = _FIXED[f.type]
        return list(struct.unpack(f"<{len(raw) // size}{ch}", raw))
    return _scalar(f.type, wt, raw)

def _unlab(f, v):
    if isinstance(v, list):
        return [_unlab(f, item) for item in v]
    if isinstance(v, str) and getattr(f, "enum", None):
        for iv, lab in f.enum.items():
            if lab == v:
                return iv
        if v.isdigit():
            return int(v)
        raise ValueError(f"unknown enum label {v!r} for {f.name} "
                         f"(known: {sorted(f.enum.values())})")
    return v


def _orig_encode(obj, msg_type):
    msgs = MESSAGES[msg_type]
    by_name = {g.name: g for g in msgs}
    by_name.update({f"f{g.num}": g for g in msgs})
    items, seen = [], {}
    for k, v in obj.items():
        if v is None:
            continue
        if k == UNKNOWN:
            for num, occs in v.items():
                n = int(num)
                if n in seen and seen[n] != UNKNOWN:
                    raise ValueError(f"field {n} of {msg_type} supplied "
                                     f"twice: {seen[n]!r} and {UNKNOWN}")
                seen[n] = UNKNOWN
                for wt, raw in occs:
                    items.append((n, None,
                                  (wt, _enc_varint(raw) if isinstance(raw, int)
                                   else raw)))
            continue
        f = by_name.get(k)
        if f is None:
            valid = sorted({g.name for g in msgs}
                           | {f"f{g.num}" for g in msgs} | {UNKNOWN})
            raise KeyError(f"{k!r} is not a field of {msg_type}; "
                           f"valid keys: {valid}")
        if f.num in seen:
            raise ValueError(f"field {f.num} of {msg_type} supplied twice: "
                             f"{seen[f.num]!r} and {k!r}")
        seen[f.num] = k
        els = [v] if f.packed else (v if isinstance(v, list) else [v])
        for el in els:
            items.append((f.num, f, el if f.map else _unlab(f, el)))
    items.sort(key=lambda t: t[0])
    parts = []
    for fn, f, el in items:
        if f is None:
            wt, raw = el
            parts.append(_enc_varint(fn << 3 | wt))
            if wt == 2:
                parts.append(_enc_varint(len(raw)))
            parts.append(raw)
        else:
            parts.append(_encode_field(fn, f, el))
    return b"".join(parts)

def _encode_field(fn, f, v):
    if f.map:
        kt, vt = f.map
        inner = []
        if v[0] is not None:
            inner.append((1, kt, v[0]))
        if v[1] is not None:
            inner.extend((2, vt, e) for e in
                         (v[1] if isinstance(v[1], list) else [v[1]]))
        blob = b"".join(_emit(n, t, e) for n, t, e in inner)
        return _enc_varint(fn << 3 | 2) + _enc_varint(len(blob)) + blob
    if f.packed:
        runs = v if (v and isinstance(v[0], list)) else [v]
        return b"".join(
            _enc_varint(fn << 3 | 2) + _enc_varint(len(p)) + p
            for p in (b"".join(_enc_scalar(f.type, e) for e in run)
                      for run in runs))
    return _emit(fn, f.type, v)

def _emit(num, ftype, v):
    if ftype.startswith("M:"):
        blob = encode(v, ftype[2:])
        return _enc_varint(num << 3 | 2) + _enc_varint(len(blob)) + blob
    return _enc_varint(num << 3 | _wt_of(ftype)) + _enc_scalar(ftype, v)

def _encode_unsorted(obj, msg_type):
    msgs = MESSAGES[msg_type]
    by_name = {g.name: g for g in msgs}
    by_name.update({f"f{g.num}": g for g in msgs})
    items = []
    seen = {}
    for k, v in obj.items():
        if v is None:
            continue
        if k == UNKNOWN:
            for num, occs in v.items():
                n = int(num)
                if n in seen and seen[n] != UNKNOWN:
                    raise ValueError(f"field {n} of {msg_type} supplied twice: {seen[n]!r} and {UNKNOWN}")
                seen[n] = UNKNOWN
                for wt, raw in occs:
                    items.append((n, None, (wt, _enc_varint(raw) if isinstance(raw, int) else raw)))
            continue
        f = by_name.get(k)
        if f is None:
            valid = sorted({g.name for g in msgs} | {f"f{g.num}" for g in msgs} | {UNKNOWN})
            raise KeyError(f"{k!r} is not a field of {msg_type}; valid keys: {valid}")
        if f.num in seen:
            raise ValueError(f"field {f.num} of {msg_type} supplied twice: {seen[f.num]!r} and {k!r}")
        seen[f.num] = k
        els = [v] if f.packed else (v if isinstance(v, list) else [v])
        for el in els:
            items.append((f.num, f, el if f.map else _unlab(f, el)))
    # preserve insertion order for underscore messages
    parts = []
    for fn, f, el in items:
        if f is None:
            wt, raw = el
            parts.append(_enc_varint(fn << 3 | wt))
            if wt == 2:
                parts.append(_enc_varint(len(raw)))
            parts.append(raw if isinstance(raw, bytes) else _enc_varint(raw))
        else:
            parts.append(_encode_field_wrapper(fn, f, el))
    return b"".join(parts)

def _encode_field_wrapper(fn, f, v):
    if f.map:
        kt, vt = f.map
        inner = []
        if v[0] is not None:
            inner.append((1, kt, v[0]))
        if v[1] is not None:
            inner.extend((2, vt, e) for e in (v[1] if isinstance(v[1], list) else [v[1]]))
        blob = b"".join(_emit_wrapper(n, t, e) for n, t, e in inner)
        return _enc_varint(fn << 3 | 2) + _enc_varint(len(blob)) + blob
    if f.packed:
        runs = v if (v and isinstance(v[0], list)) else [v]
        return b"".join(
            _enc_varint(fn << 3 | 2) + _enc_varint(len(p)) + p
            for p in (b"".join(_enc_scalar(f.type, e) for e in run) for run in runs))
    return _emit_wrapper(fn, f.type, v)

def _emit_wrapper(num, ftype, v):
    if ftype.startswith("M:"):
        blob = encode(v, ftype[2:])
        return _enc_varint(num << 3 | 2) + _enc_varint(len(blob)) + blob
    return _enc_varint(num << 3 | _wt_of(ftype)) + _enc_scalar(ftype, v)
def encode(obj, msg_type):
    if isinstance(msg_type, str) and msg_type.startswith("_"):
        return _encode_unsorted(obj, msg_type)
    return _orig_encode(obj, msg_type)


def decode(data, msg_type):
    return _orig_decode(data, msg_type)
