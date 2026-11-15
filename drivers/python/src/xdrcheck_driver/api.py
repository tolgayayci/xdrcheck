"""L4: the SDK-neutral api operations (the manifest schema's apiOp list) mapped onto PyPI stellar-sdk 17.x, and
strkey texts, with the argument names and result shapes every conformance driver uses:

  bytes      {"hex": ...} (lower-case), {"native": "bytes", "hex": ...}, or a plain string under a name ending _hex
  numbers    {"native": "number" | "string" | "bigint", "value": "<decimal>"}: number and bigint become a Python
             int, exact (an application writes the literal; Python has no 2^53 rounding); string stays a str
  strings    a bare string is a native string
  results    IDs as decimal strings, hashes and pool IDs as lower-case hex; self_decode whenever an xdr_hex or a
             strkey is produced

  op                         arguments ([optional])                         value / xdr_hex
  asset.compare              asset_a, asset_b ("native" or "CODE:ISSUER")   -1, 0 or 1
  liquidity_pool.id          asset_a, asset_b, [fee=30]                     pool ID hex
  liquidity_pool.asset       asset_a, asset_b, [fee=30]                     pool ID hex / ChangeTrustAsset
  muxed_account.encode       account (G...), id                             M... / MuxedAccount
  muxed_account.decode       text (M...)                                    {account, id}
  offer.manage_sell / _buy   offer_id, [selling=native], [buying=USD:GA7Q...VSGZ], [amount="1"], [price="1"]
                                                                            offer ID read back / Operation
  scval.from_native          value (JSON, tagged leaves), [type]            map keys "<arm>:<text>" or the one
                             type: a scval.to_* name (u32, i64, symbol,     key / ScVal
                             ...), for a map {key: [key type, value type]},
                             for a vec a list; without it the Python type
                             decides (bool, None, bytes, str -> string,
                             int -> i64/u64/i128/u128/i256/u256 by range,
                             list -> vec, dict -> map)
  scval.sort_map             keys ("u32:10", "bytes:0a", "symbol:a", "string:b", or {"xdr_hex"})
                                                                            keys in resulting order / ScVal
  scval.to_native            xdr_hex (ScVal)                                {map_entries} for a map, else the
                                                                            native value as JSON
  scval.native_roundtrip     xdr_hex (ScVal), [type]                        bytes_preserved / the ScVal back
  strkey.encode              type, payload_hex                              strkey text
  strkey.decode              text, [type]                                   payload hex
  transaction.parse          xdr_hex (TransactionEnvelope), passphrase      {tx_hash, operations} / envelope
  transaction.hash           xdr_hex, passphrase                            hash hex
  memo.text_roundtrip        xdr_hex (Memo)                                 hex of the native text / Memo
  address.to_strkey          xdr_hex, [xdr_type=MuxedAccount, or AccountId] strkey
  address.from_sc_address    xdr_hex (ScAddress)                            strkey
  signer_key.to_strkey       xdr_hex (SignerKey)                            strkey
  operation.object_roundtrip xdr_hex (Operation)                            bytes_preserved / Operation
  asset.from_operation       xdr_hex (Asset)                                {type, code, issuer}
  xdrjson.decode             xdr_type, json (text or a JSON value)          - / the value's XDR

A missing or unusable argument is the vector's fault, not an SDK outcome: ArgError, which the protocol layer
answers with a protocol error. A tagged ID whose Python type the SDK parameter's annotation does not admit (the
muxed-account ID and the offer ID are annotated int, so a string tag cannot be passed) is
n_a/argument_type_not_accepted, decided from the installed SDK's annotation before the call. price.encode and xdr.custom_union_encode are not offered (not in api_ops;
n_a / op_not_supported).
"""
from __future__ import annotations

import base64
import inspect
import json
import types
import typing

from .errors import decode_code, is_fault, object_code, reason, strkey_code
from .schema import is_generated

DEFAULT_ISSUER = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"


class Result:
    """A run outcome."""

    def __init__(self, outcome, rsn=None, actual=None):
        self.outcome = outcome
        self.reason = rsn
        self.actual = actual


def okv(api: dict) -> Result:
    return Result("ok", None, {"api": api})


def na(message: str) -> Result:
    return Result("n_a", {"code": "op_not_supported", "message": message})


class ArgError(Exception):
    """The vector is malformed for this op: not an SDK outcome (a protocol error)."""


class DecodeStep(Exception):
    """The XDR decode step of an op refused its input: reported with the decode reason and entry point."""

    def __init__(self, err, entry_point):
        super().__init__(str(err))
        self.err = err
        self.entry_point = entry_point


def from_hex(h) -> bytes:
    if not isinstance(h, str):
        raise ArgError(f"not a hex string: {str(h)[:40]}")
    try:
        return bytes.fromhex(h)
    except ValueError as e:
        raise ArgError(f"not a hex string: {h[:40]}") from e


def native_arg(v):
    """The native Python value a tagged argument stands for."""
    if isinstance(v, dict):
        if "native" in v:
            kind = v["native"]
            if kind in ("number", "bigint"):
                s = str(v.get("value"))
                try:
                    return int(s)
                except ValueError:
                    try:
                        return float(s)
                    except ValueError as e:
                        raise ArgError(f"{kind} {s!r} is not a number literal") from e
            if kind == "string":
                return str(v.get("value"))
            if kind == "bool":
                return v.get("value") is True or v.get("value") == "true"
            if kind == "bytes":
                return from_hex(v.get("hex", v.get("value")))
            raise ArgError(f"unknown native tag {kind}")
        if len(v) == 1 and "hex" in v:
            return from_hex(v["hex"])
    return v


def tag_type(v):
    """The Python type a tagged number, bigint or string argument is passed as, or None for anything else."""
    if not isinstance(v, dict) or v.get("native") not in ("number", "bigint", "string"):
        return None
    if v["native"] == "string":
        return str
    s = str(v.get("value"))
    return float if v["native"] == "number" and ("." in s or "e" in s.lower()) else int


def declared_types(fn, param):
    """The types a parameter's annotation in the installed SDK admits (int | None -> {int, NoneType}), or None
    when it has no annotation the driver can read (the value is then passed as tagged)."""
    try:
        ann = inspect.signature(fn).parameters[param].annotation
    except (KeyError, TypeError, ValueError):
        return None
    if ann is inspect.Parameter.empty:
        return None
    if isinstance(ann, str):
        try:
            ann = typing.get_type_hints(fn).get(param, ann)
        except Exception:
            return None
        if isinstance(ann, str):
            return None
    args = typing.get_args(ann) if typing.get_origin(ann) in (typing.Union, types.UnionType) else (ann,)
    return {a for a in args if isinstance(a, type)} or None


def not_accepted(v, fn, param):
    """argument_type_not_accepted (docs/conformance-protocol.md): a tagged argument whose Python type the SDK
    parameter's annotation does not admit at all; decided from the annotation before the call. The message, or
    None when the value is passed."""
    t = tag_type(v)
    allowed = declared_types(fn, param)
    if t is None or allowed is None:
        return None
    if any(issubclass(t, a) for a in allowed if a is not type(None)):
        return None
    names = " | ".join(sorted(a.__name__ for a in allowed))
    return f"the SDK annotates {param} as {names}; a {t.__name__} cannot be passed"


def native_deep(v):
    n = native_arg(v)
    if n is not v:
        return n
    if isinstance(v, list):
        return [native_deep(x) for x in v]
    if isinstance(v, dict):
        return {k: native_deep(x) for k, x in v.items()}
    return v


def need(args: dict, name: str):
    if name not in args:
        raise ArgError(f"argument {name} is required")
    return native_arg(args[name])


def hex_bytes(args: dict, name: str) -> bytes:
    """A byte argument: {"hex"}, a bytes tag, or a plain hex string (names ending _hex)."""
    v = need(args, name)
    return v if isinstance(v, bytes) else from_hex(v)


def jsonable(x, depth=0):
    """A JSON-safe rendering of a native value for the report: bytes as hex, a dict as entry pairs, integers
    beyond 32 bits as decimal strings, SDK objects as text."""
    if depth > 200:
        return "[deep]"
    if x is None or isinstance(x, (bool, str)):
        return x
    if isinstance(x, int):
        return x if -(2**31) <= x < 2**32 else str(x)
    if isinstance(x, float):
        return x
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).hex()
    if isinstance(x, dict):
        return [[jsonable(k, depth + 1), jsonable(v, depth + 1)] for k, v in x.items()]
    if isinstance(x, (list, tuple)):
        return [jsonable(v, depth + 1) for v in x]
    if isinstance(getattr(x, "address", None), str):
        return x.address
    if is_generated(x):
        return x.to_xdr()
    return str(x)


def summary(n) -> str:
    s = json.dumps(jsonable(n), separators=(",", ":"), ensure_ascii=False)
    return s if len(s) <= 300 else s[:299] + "…"


WIDE = {"SCV_U64", "SCV_I64", "SCV_TIMEPOINT", "SCV_DURATION", "SCV_U128", "SCV_I128", "SCV_U256", "SCV_I256"}


def native_json(n, sv):
    """The native value of an ScVal as JSON, guided by the value's own arms: 64-bit and wider integers as
    decimal strings, bytes as hex, a nested map as [key, value] pairs."""
    t = sv.type.name
    if t in WIDE and isinstance(n, int):
        return str(n)
    if t == "SCV_VEC" and sv.vec is not None and isinstance(n, list) and len(n) == len(sv.vec.sc_vec):
        return [native_json(x, e) for x, e in zip(n, sv.vec.sc_vec)]
    if t == "SCV_MAP" and sv.map is not None and isinstance(n, dict) and len(n) == len(sv.map.sc_map):
        return [[native_json(k, e.key), native_json(v, e.val)] for (k, v), e in zip(n.items(), sv.map.sc_map)]
    return jsonable(n)


STRKEY = {
    "account": ("encode_ed25519_public_key", "decode_ed25519_public_key"),
    "muxed_account": ("encode_med25519_public_key", "decode_med25519_public_key"),
    "secret_seed": ("encode_ed25519_secret_seed", "decode_ed25519_secret_seed"),
    "pre_auth_tx": ("encode_pre_auth_tx", "decode_pre_auth_tx"),
    "hash_x": ("encode_sha256_hash", "decode_sha256_hash"),
    "signed_payload": ("encode_ed25519_signed_payload", "decode_ed25519_signed_payload"),
    "contract": ("encode_contract", "decode_contract"),
    "muxed_contract": ("encode_muxed_contract", "decode_muxed_contract"),
    "liquidity_pool": ("encode_liquidity_pool", "decode_liquidity_pool"),
    "claimable_balance": ("encode_claimable_balance", "decode_claimable_balance"),
}
BY_LETTER = {"G": "account", "M": "muxed_account", "S": "secret_seed", "T": "pre_auth_tx", "X": "hash_x",
             "P": "signed_payload", "C": "contract", "W": "muxed_contract", "L": "liquidity_pool",
             "B": "claimable_balance"}


def strkey_decode(S, text, declared=None) -> Result:
    """Strkey text -> payload (the strkey entry kind, and strkey.decode)."""
    typ = declared
    if not typ:
        # The letter decides which decoder an application would call; a non-ASCII first character is folded to
        # its low byte, so look-alike letters still reach a decoder (which must refuse them).
        c = chr(ord(str(text)[:1] or "\0") & 0xFF).upper()
        typ = BY_LETTER.get(c, "account")
    names = STRKEY.get(typ)
    if names is None:
        raise ArgError(f"unknown strkey type {typ}")
    fn = getattr(S.StrKey, names[1], None)
    if fn is None:
        return na(f"no StrKey.{names[1]} in this version")
    try:
        return okv({"value": fn(text).hex()})
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(strkey_code(e), e, f"StrKey.{names[1]}"))


# scval.to_* helper per ScVal arm, for building a value back from its native form.
TO_HELPER = {
    "SCV_BOOL": "to_bool", "SCV_VOID": "to_void", "SCV_U32": "to_uint32", "SCV_I32": "to_int32",
    "SCV_U64": "to_uint64", "SCV_I64": "to_int64", "SCV_TIMEPOINT": "to_timepoint", "SCV_DURATION": "to_duration",
    "SCV_U128": "to_uint128", "SCV_I128": "to_int128", "SCV_U256": "to_uint256", "SCV_I256": "to_int256",
    "SCV_BYTES": "to_bytes", "SCV_STRING": "to_string", "SCV_SYMBOL": "to_symbol", "SCV_ADDRESS": "to_address",
    "SCV_EXECUTABLE_TAG": "to_executable_tag",
}
# Type names (the arm names, as the other drivers spell them) mapped onto the helpers.
TYPE_HELPER = {
    "bool": "to_bool", "void": "to_void", "u32": "to_uint32", "i32": "to_int32", "u64": "to_uint64",
    "i64": "to_int64", "timepoint": "to_timepoint", "duration": "to_duration", "u128": "to_uint128",
    "i128": "to_int128", "u256": "to_uint256", "i256": "to_int256", "bytes": "to_bytes", "string": "to_string",
    "symbol": "to_symbol", "address": "to_address",
}
INTEGER_TYPES = {"u32", "i32", "u64", "i64", "timepoint", "duration", "u128", "i128", "u256", "i256"}


def native_back(S, n, sv):
    """Build an ScVal back from the native value n, with the arms of the original value sv as the types (what an
    application that knows its contract's types would do). A native vec or map whose length no longer matches
    the original raises: the conversion lost entries."""
    scval = S.scval
    t = sv.type.name
    if t == "SCV_VEC" and sv.vec is not None:
        items = sv.vec.sc_vec
        if not isinstance(n, list) or len(n) != len(items):
            raise ValueError("the native vec does not match the value")
        return scval.to_vec([native_back(S, x, e) for x, e in zip(n, items)])
    if t == "SCV_MAP" and sv.map is not None:
        entries = sv.map.sc_map
        if not isinstance(n, dict) or len(n) != len(entries):
            raise ValueError("the native map does not have the value's entries")
        out = {}
        for (k, v), e in zip(n.items(), entries):
            out[native_back(S, k, e.key)] = native_back(S, v, e.val)
        return scval.to_map(out)
    helper = TO_HELPER.get(t)
    if helper is None:
        raise ValueError(f"no scval helper for {t}")
    f = getattr(scval, helper)
    return f() if helper == "to_void" else f(n)


def key_text(sv) -> str:
    t = sv.type.name.replace("SCV_", "").lower()
    if t == "u32":
        v = str(sv.u32.uint32)
    elif t == "i32":
        v = str(sv.i32.int32)
    elif t == "bytes":
        v = sv.bytes.sc_bytes.hex()
    elif t == "symbol":
        v = sv.sym.sc_symbol.decode("utf-8", "backslashreplace")
    elif t == "string":
        v = sv.str.sc_string.decode("utf-8", "backslashreplace")
    else:
        return f"{t}:{sv.to_xdr_bytes().hex()}"
    return f"{t}:{v}"


def make_api(S):
    xdr = S.xdr
    sc = S.scval

    def asset(spec):
        a = native_arg(spec)
        if a in ("native", "XLM:native"):
            return S.Asset.native()
        if not isinstance(a, str) or ":" not in a:
            raise ArgError(f"asset {a!r}: want native or CODE:ISSUER")
        i = a.rfind(":")
        return S.Asset(a[:i], a[i + 1:])

    def fee(args):
        return native_arg(args["fee"]) if "fee" in args else S.LIQUIDITY_POOL_FEE_V18

    def xdr_value(args, type_name, allowed=None):
        name = args.get("xdr_type", type_name)
        py = {"ScVal": "SCVal", "ScAddress": "SCAddress", "AccountId": "AccountID"}.get(name, name)
        if allowed is not None and py not in allowed:
            raise ArgError(f"xdr_type {name} is not one of {sorted(allowed)}")
        T = getattr(xdr, py, None)
        if T is None or not hasattr(T, "from_xdr_bytes"):
            raise ArgError(f"no generated XDR type {name}")
        b = hex_bytes(args, "xdr_hex")
        try:
            return T.from_xdr_bytes(b), T.__name__
        except Exception as e:
            if is_fault(e):
                raise
            raise DecodeStep(e, f"xdr.{T.__name__}.from_xdr_bytes") from e

    def self_decode(T, b):
        try:
            T.from_xdr_bytes(b)
            return "accepted"
        except Exception as e:
            if is_fault(e):
                raise
            return "rejected"

    def strkey_self_decode(text):
        names = STRKEY.get(BY_LETTER.get(text[:1], ""))
        if names is None:
            return "rejected"
        try:
            getattr(S.StrKey, names[1])(text)
            return "accepted"
        except Exception as e:
            if is_fault(e):
                raise
            return "rejected"

    def mk_key(spec):
        if isinstance(spec, dict) and "xdr_hex" in spec:
            return xdr.SCVal.from_xdr_bytes(from_hex(spec["xdr_hex"]))
        if not isinstance(spec, str) or ":" not in spec:
            raise ArgError(f"key {spec!r}: want <type>:<value> or {{xdr_hex}}")
        t, _, v = spec.partition(":")
        if t == "bytes":
            return sc.to_bytes(from_hex(v))
        return typed_native(v, t)

    def typed_native(value, typ):
        helper = TYPE_HELPER.get(typ)
        if helper is None:
            raise ArgError(f"unknown scval type {typ}")
        if helper == "to_void":
            return sc.to_void()
        if typ in INTEGER_TYPES and isinstance(value, str):
            try:
                value = int(value)
            except ValueError as e:
                raise ArgError(f"{typ} value {value!r} is not an integer") from e
        return getattr(sc, helper)(value)

    def untyped_native(value):
        if value is None:
            return sc.to_void()
        if isinstance(value, bool):
            return sc.to_bool(value)
        if isinstance(value, bytes):
            return sc.to_bytes(value)
        if isinstance(value, str):
            return sc.to_string(value)
        if isinstance(value, int):
            for lo, hi, f in ((-(2**63), 2**63, sc.to_int64), (0, 2**64, sc.to_uint64), (-(2**127), 2**127, sc.to_int128),
                              (0, 2**128, sc.to_uint128), (-(2**255), 2**255, sc.to_int256)):
                if lo <= value < hi:
                    return f(value)
            return sc.to_uint256(value)
        if isinstance(value, list):
            return sc.to_vec([untyped_native(v) for v in value])
        if isinstance(value, dict):
            return sc.to_map({untyped_native(k): untyped_native(v) for k, v in value.items()})
        raise ArgError(f"no ScVal for a native {type(value).__name__}")

    def from_native(value, typ):
        if typ is None:
            return untyped_native(value)
        if isinstance(typ, str):
            return typed_native(value, typ)
        if isinstance(typ, dict) and isinstance(value, dict):
            out = {}
            for k, v in value.items():
                kt = typ.get(k)
                if not isinstance(kt, list) or len(kt) != 2:
                    raise ArgError(f"no [key type, value type] for map key {k}")
                out[from_native(k, kt[0])] = from_native(v, kt[1])
            return sc.to_map(out)
        if isinstance(typ, list) and isinstance(value, list) and len(typ) == len(value):
            return sc.to_vec([from_native(v, t) for v, t in zip(value, typ)])
        raise ArgError("type must be a scval type name, a map of [key type, value type], or a list")

    def map_keys(sv):
        if sv.type.name == "SCV_MAP" and sv.map is not None:
            return [key_text(e.key) for e in sv.map.sc_map]
        return key_text(sv)

    def offer(args, buy):
        selling = asset(args.get("selling", "native"))
        buying = asset(args.get("buying", f"USD:{DEFAULT_ISSUER}"))
        price = native_arg(args.get("price", "1"))
        amount = native_arg(args.get("amount", "1"))
        offer_id = need(args, "offer_id")
        ep = "ManageBuyOffer" if buy else "ManageSellOffer"
        try:
            if buy:
                op = S.ManageBuyOffer(selling=selling, buying=buying, amount=amount, price=price, offer_id=offer_id)
            else:
                op = S.ManageSellOffer(selling=selling, buying=buying, amount=amount, price=price, offer_id=offer_id)
            b = op.to_xdr_object().to_xdr_bytes()
        except Exception as e:
            if is_fault(e):
                raise
            return Result("reject", reason(object_code(e, "other"), e, ep))
        try:
            back = S.Operation.from_xdr_object(xdr.Operation.from_xdr_bytes(b))
        except Exception as e:
            if is_fault(e):
                raise
            return Result("diverge", reason("own_output_rejected", e, "Operation.from_xdr_object"),
                          {"api": {"xdr_hex": b.hex(), "self_decode": "rejected"}})
        return {"xdr_hex": b.hex(), "value": str(back.offer_id), "self_decode": "accepted"}

    def strkey_encode(a, _pp):
        typ = need(a, "type")
        names = STRKEY.get(typ) if isinstance(typ, str) else None
        if names is None:
            raise ArgError(f"unknown strkey type {typ!r}")
        enc = getattr(S.StrKey, names[0], None)
        dec = getattr(S.StrKey, names[1], None)
        if enc is None:
            return na(f"no StrKey.{names[0]} in this version")
        payload = hex_bytes(a, "payload_hex")
        try:
            text = enc(payload)
        except Exception as e:
            if is_fault(e):
                raise
            return Result("reject", reason(object_code(e, "strkey_payload"), e, f"StrKey.{names[0]}"))
        try:
            back = dec(text)
        except Exception as e:
            if is_fault(e):
                raise
            return Result("diverge", reason("own_output_rejected", e, f"StrKey.{names[0]}"),
                          {"api": {"value": text, "self_decode": "rejected"}})
        if back != payload:
            return Result("diverge", {"code": "own_output_rejected", "message": f"StrKey.{names[1]} returned {back.hex()}",
                                      "entry_point": f"StrKey.{names[0]}"}, {"api": {"value": text, "self_decode": "rejected"}})
        return {"value": text, "self_decode": "accepted"}

    def parse_tx(a, pp):
        b64 = base64.b64encode(hex_bytes(a, "xdr_hex")).decode()
        passphrase = native_arg(a["passphrase"]) if "passphrase" in a else pp
        if not isinstance(passphrase, str):
            raise ArgError("argument passphrase is required")
        return S.TransactionBuilder.from_xdr(b64, passphrase)

    def tx_ops(te):
        inner = getattr(te.transaction, "inner_transaction_envelope", None)
        return inner.transaction.operations if inner is not None else te.transaction.operations

    def lp_asset(a):
        return S.LiquidityPoolAsset(asset(need(a, "asset_a")), asset(need(a, "asset_b")), fee(a))

    def compare(a, _pp):
        x, y = asset(need(a, "asset_a")), asset(need(a, "asset_b"))
        if x == y:
            return {"value": 0}
        return {"value": -1 if S.LiquidityPoolAsset.is_valid_lexicographic_order(x, y) else 1}

    def lp_change_trust(a, _pp):
        lpa = lp_asset(a)
        b = lpa.to_change_trust_asset_xdr_object().to_xdr_bytes()
        return {"value": lpa.liquidity_pool_id, "xdr_hex": b.hex(), "self_decode": self_decode(xdr.ChangeTrustAsset, b)}

    def muxed_encode(a, _pp):
        account = need(a, "account")
        if not isinstance(account, str):
            raise ArgError("argument account must be a G... strkey")
        m = S.MuxedAccount(account, need(a, "id"))
        b = m.to_xdr_object().to_xdr_bytes()
        text = m.account_muxed
        sd = self_decode(xdr.MuxedAccount, b)
        if text is not None and strkey_self_decode(text) == "rejected":
            sd = "rejected"
        return {"value": text, "xdr_hex": b.hex(), "self_decode": sd}

    def muxed_decode(a, _pp):
        text = need(a, "text")
        if not isinstance(text, str):
            raise ArgError("argument text must be a strkey")
        m = S.MuxedAccount.from_account(text)
        return {"value": {"account": m.account_id, "id": None if m.account_muxed_id is None else str(m.account_muxed_id)}}

    def scval_from_native(a, _pp):
        sv = from_native(native_deep(need(a, "value")), a.get("type"))
        b = sv.to_xdr_bytes()
        return {"value": map_keys(sv), "xdr_hex": b.hex(), "self_decode": self_decode(xdr.SCVal, b)}

    def scval_sort_map(a, _pp):
        keys = a.get("keys")
        if not isinstance(keys, list):
            raise ArgError("argument keys must be a list")
        sv = sc.to_map({mk_key(k): sc.to_void() for k in keys})
        b = sv.to_xdr_bytes()
        return {"value": map_keys(sv), "xdr_hex": b.hex(), "self_decode": self_decode(xdr.SCVal, b)}

    def scval_to_native(a, _pp):
        sv, _ = xdr_value(a, "SCVal", {"SCVal"})
        n = sc.to_native(sv)
        if sv.type.name == "SCV_MAP":
            return {"value": {"map_entries": len(n) if isinstance(n, dict) else 0}}
        return {"value": native_json(n, sv)}

    def scval_roundtrip(a, _pp):
        sv, _ = xdr_value(a, "SCVal", {"SCVal"})
        orig = sv.to_xdr_bytes()
        n = sc.to_native(sv)
        back = from_native(n, a["type"]) if "type" in a else native_back(S, n, sv)
        b = back.to_xdr_bytes()
        return {"value": b == orig, "xdr_hex": b.hex(), "self_decode": self_decode(xdr.SCVal, b)}

    def transaction_parse(a, pp):
        te = parse_tx(a, pp)
        b = te.to_xdr_object().to_xdr_bytes()
        return {"value": {"tx_hash": te.hash_hex(), "operations": len(tx_ops(te))}, "xdr_hex": b.hex(),
                "self_decode": self_decode(xdr.TransactionEnvelope, b)}

    def memo_roundtrip(a, _pp):
        v, _ = xdr_value(a, "Memo", {"Memo"})
        m = S.Memo.from_xdr_object(v)
        text = getattr(m, "memo_text", None)
        if text is None:
            return Result("reject", {"code": "other", "message": f"{type(m).__name__} is not a text memo",
                                     "entry_point": "Memo.from_xdr_object"})
        raw = text if isinstance(text, bytes) else str(text).encode("utf-8")
        b = S.TextMemo(text).to_xdr_object().to_xdr_bytes()
        return {"value": raw.hex(), "xdr_hex": b.hex(), "self_decode": self_decode(xdr.Memo, b)}

    def address_to_strkey(a, _pp):
        v, name = xdr_value(a, "MuxedAccount", {"MuxedAccount", "AccountID"})
        if name == "MuxedAccount":
            text = S.MuxedAccount.from_xdr_object(v).universal_account_id
        else:
            text = S.StrKey.encode_ed25519_public_key(v.account_id.ed25519.uint256)
        return {"value": text, "self_decode": strkey_self_decode(text)}

    def from_sc_address(a, _pp):
        v, _ = xdr_value(a, "SCAddress", {"SCAddress"})
        text = S.Address.from_xdr_sc_address(v).address
        return {"value": text, "self_decode": strkey_self_decode(text)}

    def signer_key_strkey(a, _pp):
        v, _ = xdr_value(a, "SignerKey", {"SignerKey"})
        text = S.SignerKey.from_xdr_object(v).encoded_signer_key
        try:
            S.SignerKey.from_encoded_signer_key(text)
        except Exception as e:
            if is_fault(e):
                raise
            return Result("diverge", reason("own_output_rejected", e, "SignerKey.encoded_signer_key"),
                          {"api": {"value": text, "self_decode": "rejected"}})
        return {"value": text, "self_decode": "accepted"}

    def operation_roundtrip(a, _pp):
        v, _ = xdr_value(a, "Operation", {"Operation"})
        orig = v.to_xdr_bytes()
        b = S.Operation.from_xdr_object(v).to_xdr_object().to_xdr_bytes()
        return {"value": b == orig, "xdr_hex": b.hex(), "self_decode": self_decode(xdr.Operation, b)}

    def asset_from_operation(a, _pp):
        v, _ = xdr_value(a, "Asset", {"Asset"})
        x = S.Asset.from_xdr_object(v)
        return {"value": {"type": x.type, "code": x.code, "issuer": x.issuer}}

    def xdrjson_decode(a, _pp):
        name = need(a, "xdr_type")
        py = {"ScVal": "SCVal", "ScAddress": "SCAddress", "AccountId": "AccountID"}.get(name, name)
        T = getattr(xdr, py, None) if isinstance(py, str) else None
        if T is None or not hasattr(T, "from_json"):
            raise ArgError(f"no generated XDR type {name}")
        if "json" not in a:
            raise ArgError("argument json is required")
        text = a["json"] if isinstance(a["json"], str) else json.dumps(a["json"])
        b = T.from_json(text).to_xdr_bytes()
        return {"xdr_hex": b.hex(), "self_decode": self_decode(T, b)}

    # op -> (entry point, fn(args, passphrase) -> api result dict or Result)
    ops = {
        "asset.compare": ("LiquidityPoolAsset.is_valid_lexicographic_order", compare),
        "liquidity_pool.id": ("LiquidityPoolAsset.liquidity_pool_id", lambda a, pp: {"value": lp_asset(a).liquidity_pool_id}),
        "liquidity_pool.asset": ("LiquidityPoolAsset", lp_change_trust),
        "muxed_account.encode": ("MuxedAccount", muxed_encode),
        "muxed_account.decode": ("MuxedAccount.from_account", muxed_decode),
        "offer.manage_sell": ("ManageSellOffer", lambda a, pp: offer(a, False)),
        "offer.manage_buy": ("ManageBuyOffer", lambda a, pp: offer(a, True)),
        "scval.from_native": ("scval.to_*", scval_from_native),
        "scval.sort_map": ("scval.to_map", scval_sort_map),
        "scval.to_native": ("scval.to_native", scval_to_native),
        "scval.native_roundtrip": ("scval.to_native + scval.to_*", scval_roundtrip),
        "strkey.encode": ("StrKey.encode_*", strkey_encode),
        "strkey.decode": ("StrKey.decode_*", lambda a, pp: strkey_decode(S, need(a, "text"), a.get("type"))),
        "transaction.parse": ("TransactionBuilder.from_xdr", transaction_parse),
        "transaction.hash": ("TransactionEnvelope.hash_hex", lambda a, pp: {"value": parse_tx(a, pp).hash_hex()}),
        "memo.text_roundtrip": ("Memo.from_xdr_object", memo_roundtrip),
        "address.to_strkey": ("MuxedAccount.from_xdr_object", address_to_strkey),
        "address.from_sc_address": ("Address.from_xdr_sc_address", from_sc_address),
        "signer_key.to_strkey": ("SignerKey.from_xdr_object", signer_key_strkey),
        "operation.object_roundtrip": ("Operation.from_xdr_object", operation_roundtrip),
        "asset.from_operation": ("Asset.from_xdr_object", asset_from_operation),
        "xdrjson.decode": ("<Type>.from_json", xdrjson_decode),
    }

    # The SDK parameter each tagged argument is passed to, for the argument_type_not_accepted rule: op ->
    # argument -> (callable, parameter name). Its annotation is read from the installed SDK.
    declared = {
        "muxed_account.encode": {"id": (S.MuxedAccount.__init__, "account_muxed_id")},
        "offer.manage_sell": {"offer_id": (S.ManageSellOffer.__init__, "offer_id")},
        "offer.manage_buy": {"offer_id": (S.ManageBuyOffer.__init__, "offer_id")},
    }

    class API:
        names = sorted(ops)

        @staticmethod
        def run(op, args, passphrase):
            """A Result; raises ArgError when the arguments are unusable (a protocol error)."""
            o = ops.get(op)
            if o is None:
                return na(f"api op {op} is not offered by the Python driver")
            if not isinstance(args, dict):
                raise ArgError("api args must be an object")
            for name, (fn, param) in declared.get(op, {}).items():
                refused = not_accepted(args.get(name), fn, param)
                if refused is not None:
                    return Result("n_a", {"code": "argument_type_not_accepted", "message": refused, "entry_point": o[0]})
            try:
                r = o[1](args, passphrase)
                return r if isinstance(r, Result) else okv(r)
            except ArgError:
                raise
            except DecodeStep as e:
                return Result("reject", reason(decode_code(e.err), e.err, e.entry_point))
            except Exception as e:
                if is_fault(e):
                    raise
                code = strkey_code(e) if op.startswith("strkey.") else object_code(e, "other")
                return Result("reject", reason(code, e, o[0]))

    return API
