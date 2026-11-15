"""L2: the neutral value projection of a decoded value.

The projection is the SEP-51 XDR-JSON the corpus oracle (stellar-xdr, whose output is each entry's `decoded`
sidecar) emits, as a value. It walks the SDK's decoded Python object against the shape of its generated class
(schema.py: the XDR text in each class docstring, paired with the constructor's attributes), so it renders
exactly what the SDK decoded. Names follow the oracle's rules, implemented here and not taken from the SDK's
own JSON helpers (to_json_dict):

  struct field   snake_case of the XDR field name (word boundaries at lower/digit -> upper and at the end of an
                 acronym)
  enum member    the XDR identifier without the prefix every member of the enum shares (whole "_"-separated
                 words; an identifier starting with a digit keeps the prefix's first letter), then the
                 generator's CamelCase rendered in serde's snake_case
  union arm      the discriminant's enum member name as above; "v<N>" for integer discriminants; a void arm is
                 the bare name, any other arm an object with that single key
  integers       32-bit as JSON numbers, 64-bit as decimal strings, 128/256-bit parts as one decimal string
  opaque         lower-case hex
  string<>       printable ASCII as is, \\0 \\t \\n \\r \\\\ and \\xNN for every other byte, from the raw bytes
  strkey types   PublicKey (AccountID, NodeID) G..., MuxedAccount G.../M..., SignerKey G.../T.../X.../P...,
                 SCAddress as its arm, ContractID C..., PoolID L..., ClaimableBalanceID B..., MuxedContract
                 W..., asset codes as text; the strkeys are encoded here (strkey.py), not by the SDK

project(value) renders a whole value; pointer(projection, p) resolves a JSON Pointer in a projection.
"""
from __future__ import annotations

import enum
import keyword
import re

from . import strkey
from .schema import SchemaError, TypeRef, is_generated, shape, union_case


class ProjectionError(Exception):
    """A value the walker cannot render; reported as a driver-side failure, never as an SDK outcome."""


# ---- names ---------------------------------------------------------------------------------------------------


def snake(name: str) -> str:
    """snake_case of a camelCase or PascalCase identifier. The SDK's generated source text writes an XDR field
    whose name is a Python keyword with a trailing underscore (`from` as `from_`); the XDR name has none."""
    if name.endswith("_") and keyword.iskeyword(name[:-1]):
        name = name[:-1]
    out = []
    for i, ch in enumerate(name):
        prev = name[i - 1] if i > 0 else ""
        nxt = name[i + 1] if i + 1 < len(name) else ""
        if i > 0 and ch.isupper() and (prev.islower() or prev.isdigit() or (prev.isupper() and nxt.islower())):
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _underscore(word: str) -> str:
    """A word of an XDR identifier split where its case changes (txSUCCESS -> tx_success)."""
    w = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", word)
    w = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", w)
    return w.lower()


def _variant(words: list[str]) -> str:
    """The generator's CamelCase of the words, in serde's snake_case: an underscore before every upper-case
    letter but the first (so a word that starts with a digit joins the word before it)."""
    camel = "".join(p[:1].upper() + p[1:] for w in words for p in _underscore(w).split("_") if p)
    out = []
    for i, ch in enumerate(camel):
        if i > 0 and ch.isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


_enum_names: dict[type, dict[int, str]] = {}


def enum_names(cls: type) -> dict[int, str]:
    names = _enum_names.get(cls)
    if names is not None:
        return names
    members = [(m.name, m.value) for m in cls]
    words = [n.split("_") for n, _ in members]
    prefix = 0
    if len(words) > 1:
        while all(len(w) > prefix + 1 and w[prefix] == words[0][prefix] for w in words):
            prefix += 1
    names = {}
    for (n, v), w in zip(members, words):
        rest = w[prefix:]
        if prefix and rest[0][:1].isdigit():
            rest = [w[0][0] + rest[0]] + rest[1:]
        names[v] = _variant(rest)
    _enum_names[cls] = names
    return names


def enum_name(value: enum.Enum) -> str:
    return enum_names(type(value)).get(value.value, str(value.value))


# ---- strings and bytes ---------------------------------------------------------------------------------------


def escape(b: bytes) -> str:
    out = []
    for c in b:
        if c == 0:
            out.append("\\0")
        elif c == 9:
            out.append("\\t")
        elif c == 10:
            out.append("\\n")
        elif c == 13:
            out.append("\\r")
        elif c == 92:
            out.append("\\\\")
        elif 32 <= c <= 126:
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return "".join(out)


def leaf(obj: object) -> tuple[object, TypeRef | None]:
    """Follow typedef wrappers down to the primitive Python value, with the primitive's declared type."""
    t = None
    while is_generated(obj) and not isinstance(obj, enum.Enum):
        s = shape(type(obj))
        if s.kind != "typedef":
            raise ProjectionError(f"{type(obj).__name__} is a {s.kind}, not a primitive")
        t = s.value.type
        obj = getattr(obj, s.value.attr)
    return obj, t


def raw_bytes(obj: object) -> bytes:
    b, _ = leaf(obj)
    if not isinstance(b, bytes):
        raise ProjectionError(f"expected bytes, got {type(b).__name__}")
    return b


def raw_int(obj: object) -> int:
    v, _ = leaf(obj)
    if not isinstance(v, int):
        raise ProjectionError(f"expected an integer, got {type(v).__name__}")
    return v


# ---- special types -------------------------------------------------------------------------------------------


def _arm(obj: object):
    """(case, arm value) of a union object."""
    s = shape(type(obj))
    disc = getattr(obj, s.disc.attr)
    c = union_case(s, disc)
    if c is None:
        raise ProjectionError(f"{type(obj).__name__}: no case for discriminant {disc!r}")
    return disc, c, (getattr(obj, c.decl.attr) if c.decl is not None else None)


def _struct_fields(obj: object) -> dict[str, object]:
    s = shape(type(obj))
    return {d.name: getattr(obj, d.attr) for d in s.fields}


def _muxed(obj: object, letter: str) -> str:
    """M... (MuxedEd25519Account and MuxedAccount's med25519 arm) and W... (MuxedContract): the 32-byte key
    or contract, then the 64-bit ID big-endian."""
    f = _struct_fields(obj)
    ident = raw_int(f["id"])
    key = raw_bytes(f.get("ed25519", f.get("contractId")))
    return strkey.encode(letter, key + (ident % (1 << 64)).to_bytes(8, "big"))


def _signed_payload(obj: object) -> str:
    f = _struct_fields(obj)
    payload = raw_bytes(f["payload"])
    pad = b"\0" * ((4 - len(payload) % 4) % 4)
    return strkey.encode("P", raw_bytes(f["ed25519"]) + len(payload).to_bytes(4, "big") + payload + pad)


def _public_key(obj):
    disc, c, v = _arm(obj)
    return strkey.encode("G", raw_bytes(v)) if c.decl is not None else None


def _muxed_account(obj):
    disc, c, v = _arm(obj)
    if c.decl is None:
        return None
    if isinstance(v, bytes) or shape(type(v)).kind == "typedef":
        return strkey.encode("G", raw_bytes(v))
    return _muxed(v, "M")


def _signer_key(obj):
    disc, c, v = _arm(obj)
    letter = {0: "G", 1: "T", 2: "X"}.get(int(disc))
    if letter is not None:
        return strkey.encode(letter, raw_bytes(v))
    if int(disc) == 3:
        return _signed_payload(v)
    return None


def _claimable_balance_id(obj):
    disc, c, v = _arm(obj)
    if c.decl is None:
        return None
    return strkey.encode("B", bytes([int(disc)]) + raw_bytes(v))


def _arm_only(obj):
    disc, c, v = _arm(obj)
    return project(v) if c.decl is not None else None


def _parts(obj):
    f = list(_struct_fields(obj).values())
    acc = 0
    for x in f:
        acc = (acc << 64) | (raw_int(x) % (1 << 64))
    bits = 64 * len(f)
    _, t = leaf(f[0])
    if t is not None and t.base == "hyper" and acc >= 1 << (bits - 1):
        acc -= 1 << bits
    return str(acc)


def _code(obj, keep):
    b = raw_bytes(obj)
    end = len(b)
    while end > keep and b[end - 1] == 0:
        end -= 1
    return escape(b[:end])


SPECIAL = {
    "PublicKey": _public_key,
    "MuxedAccount": _muxed_account,
    "MuxedAccountMed25519": lambda o: _muxed(o, "M"),
    "MuxedEd25519Account": lambda o: _muxed(o, "M"),
    "MuxedContract": lambda o: _muxed(o, "W"),
    "SignerKey": _signer_key,
    "SignerKeyEd25519SignedPayload": _signed_payload,
    "SCAddress": _arm_only,
    "ClaimableBalanceID": _claimable_balance_id,
    "PoolID": lambda o: strkey.encode("L", raw_bytes(o)),
    "ContractID": lambda o: strkey.encode("C", raw_bytes(o)),
    "AssetCode4": lambda o: _code(o, 0),
    "AssetCode12": lambda o: _code(o, 5),
    "AssetCode": _arm_only,
    "Int128Parts": _parts,
    "UInt128Parts": _parts,
    "Int256Parts": _parts,
    "UInt256Parts": _parts,
}


# ---- the walk ------------------------------------------------------------------------------------------------


#
# The walk is iterative: project_step and typed_step are generators that yield ("project", obj) or
# ("typed", value, type) for each child and receive its projection back, and _walk runs them on an explicit
# stack. A value nested as deep as a ledger can carry (stellar-core admits an argument of about 250 nested
# vectors) then costs heap, not interpreter frames: the SDK decodes it under the interpreter's default
# recursion limit, and the projection must not fail where the SDK did not.


def _walk(first):
    stack = [first]
    sent = None
    while stack:
        try:
            req = stack[-1].send(sent)
        except StopIteration as done:
            stack.pop()
            sent = done.value
            continue
        stack.append(project_step(req[1]) if req[0] == "project" else typed_step(req[1], req[2]))
        sent = None
    return sent


def project(obj: object):
    """The projection of a generated XDR object (struct, union, typedef or enum member)."""
    return _walk(project_step(obj))


def typed(v: object, t: TypeRef):
    """The projection of a value declared with type t."""
    return _walk(typed_step(v, t))


def project_step(obj: object):
    if isinstance(obj, enum.Enum):
        return enum_name(obj)
    if not is_generated(obj):
        raise ProjectionError(f"not a generated XDR value: {type(obj).__name__}")
    special = SPECIAL.get(type(obj).__name__)
    if special is not None:
        r = special(obj)
        if r is not None:
            return r
    try:
        s = shape(type(obj))
    except SchemaError as e:
        raise ProjectionError(str(e)) from e
    if s.kind == "struct":
        out = {}
        for d in s.fields:
            out[snake(d.name)] = yield ("typed", getattr(obj, d.attr), d.type)
        return out
    if s.kind == "typedef":
        return (yield ("typed", getattr(obj, s.value.attr), s.value.type))
    if s.kind == "union":
        disc = getattr(obj, s.disc.attr)
        c = union_case(s, disc)
        if c is None:
            raise ProjectionError(f"{type(obj).__name__}: no case for discriminant {disc!r}")
        name = enum_name(disc) if isinstance(disc, enum.Enum) else f"v{int(disc)}"
        if c.decl is None:
            return name
        return {name: (yield ("typed", getattr(obj, c.decl.attr), c.decl.type))}
    raise ProjectionError(f"{type(obj).__name__}: cannot project a {s.kind}")


def typed_step(v: object, t: TypeRef):
    if t.optional and v is None:
        return None
    if t.array is not None:
        if not isinstance(v, list):
            raise ProjectionError(f"expected a list, got {type(v).__name__}")
        elem = TypeRef(t.base, t.name)
        out = []
        for x in v:
            out.append((yield ("typed", x, elem)))
        return out
    if is_generated(v):
        return (yield ("project", v))
    b = t.base
    if b in ("int", "uint"):
        return int(v)
    if b in ("hyper", "uhyper"):
        return str(int(v))
    if b == "bool":
        return bool(v)
    if b in ("float", "double"):
        return float(v)
    if b == "opaque":
        return bytes(v).hex()
    if b == "string":
        return escape(bytes(v))
    raise ProjectionError(f"a {b} declaration holds a {type(v).__name__}")


def pointer(v, p: str):
    """(found, value) at a JSON Pointer (RFC 6901) in a projection."""
    if p == "":
        return True, v
    if not p.startswith("/"):
        return False, None
    for tok in p[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(v, dict):
            if tok not in v:
                return False, None
            v = v[tok]
        elif isinstance(v, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", tok) or int(tok) >= len(v):
                return False, None
            v = v[int(tok)]
        else:
            return False, None
    return True, v
