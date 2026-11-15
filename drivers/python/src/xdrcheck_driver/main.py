"""xdrcheck-driver-python: the conformance driver for PyPI stellar-sdk 17.x (xdrlib3). One source serves every pinned
version; each version directory under drivers/python/ installs its own locked venv and runs this package with
that venv's interpreter.

It speaks the driver protocol xcc.driver/1 (corpus/schema/driver-protocol.schema.json; contract in
drivers/README.md): one JSON request per line on stdin, one response per line on stdout, serially. It reports
what the SDK did, never compares with expected values and never reads the manifest.

Levels (all five are declared):
  L0  xdr.<Type>.from_xdr_bytes(bytes) (strict: rejects trailing bytes), re-encode with .to_xdr_bytes(); the
      lower-level <Type>.unpack(Unpacker), which does not check that the input was consumed, is listed under
      lenient_entry_points when it disagrees
  L1  TransactionEnvelope: TransactionBuilder.from_xdr(base64, passphrase); LedgerCloseMeta(Batch): every
      envelope of the transaction set, in set order, through TransactionBuilder.from_xdr; Memo, Operation,
      Asset, ScAddress, MuxedAccount, SignerKey through their object classes
  L2  the neutral value projection of the decoded value (project.py), whole or at the requested pointers
  L3  ScVal through scval.to_native and back through the scval.to_* helper of each arm; Memo through
      Memo.from_xdr_object
  L4  api operations (api.py) and strkey texts

Inputs are never validated before the SDK sees them: whatever the SDK and xdrlib3 accept or refuse is what the
levels report. The SDK's default decode depth and the interpreter's default
recursion limit are left as they are; the L2 projection walk is iterative, so it fails nowhere the SDK's own
decode does not.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys

import stellar_sdk as S
import stellar_sdk.scval  # noqa: F401  (S.scval)
from stellar_sdk import xdr
from xdrlib3 import Unpacker

from . import reach, sdk, spec
from .api import ArgError, Result, make_api, native_back, strkey_decode, summary
from .errors import decode_code, fault_code, is_fault, native_code, object_code, reason, trim
from .project import ProjectionError, enum_name, pointer, project, snake
from .schema import is_generated, shape, union_case

TAG = "xcc.driver/1"
DRIVER = {"name": "xdrcheck-driver-python", "version": "0.1.0", "adapter": "python-v17"}
LEVELS = ["L0", "L1", "L2", "L3", "L4", "spec"]

TYPES = sdk.xdr_types()
API = make_api(S)


def ok(actual=None) -> Result:
    return Result("ok", None, actual)


def na(code: str, message: str | None = None) -> Result:
    r = {"code": code}
    if message:
        r["message"] = message
    return Result("n_a", r)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def xdr_type(name: str):
    return TYPES.get(str(name).lower())


# ---- input ---------------------------------------------------------------------------------------------------


def frame(b: bytes, index: int) -> bytes:
    """RFC 5531 record marking: 4-byte header, high bit = last fragment, low 31 bits = fragment length."""
    frames, cur, off = [], [], 0
    while off < len(b):
        if off + 4 > len(b):
            raise ValueError("record mark truncated")
        h = int.from_bytes(b[off:off + 4], "big")
        n = h & 0x7FFFFFFF
        off += 4
        if off + n > len(b):
            raise ValueError("record fragment truncated")
        cur.append(b[off:off + n])
        off += n
        if h & 0x80000000:
            frames.append(b"".join(cur))
            cur = []
    if index >= len(frames):
        raise ValueError(f"frame {index} of {len(frames)}")
    return frames[index]


def input_bytes(inp: dict) -> bytes:
    if "path" in inp:
        with open(inp["path"], "rb") as f:
            b = f.read()
    else:
        b = bytes.fromhex(inp.get("xdr_hex", ""))
    if inp.get("framing") == "record-marked":
        b = frame(b, inp.get("frame_index", 0))
    return b


def decode_strict(inp: dict):
    """(T, bytes, value), or a Result (reject or n_a)."""
    T = xdr_type(inp["xdr_type"])
    if T is None:
        return na("type_not_generated", f"no generated XDR type {inp['xdr_type']}")
    b = input_bytes(inp)
    try:
        return T, b, T.from_xdr_bytes(b)
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(decode_code(e), e, f"xdr.{T.__name__}.from_xdr_bytes"))


# ---- L0 ------------------------------------------------------------------------------------------------------


def lenient_entry_points(T, b: bytes, strict_accepted: bool) -> list:
    """The SDK's lower-level decode entry point, listed only where it disagrees with the strict one."""
    try:
        T.unpack(Unpacker(b))
        accepted = True
    except Exception as e:
        if is_fault(e):
            raise
        accepted = False
    if accepted != strict_accepted:
        return [{"entry_point": f"xdr.{T.__name__}.unpack", "accepted": accepted}]
    return []


def run_l0(inp: dict) -> Result:
    d = decode_strict(inp)
    if isinstance(d, Result):
        T = xdr_type(inp["xdr_type"])
        if d.outcome == "reject" and T is not None:
            lenient = lenient_entry_points(T, input_bytes(inp), False)
            if lenient:
                d.actual = {"lenient_entry_points": lenient}
        return d
    T, b, v = d
    try:
        re = v.to_xdr_bytes()
    except Exception as e:
        if is_fault(e):
            raise
        return Result("diverge", reason("own_output_rejected", e, f"xdr.{T.__name__}.to_xdr_bytes"), {"consumed_bytes": len(b)})
    actual = {"consumed_bytes": len(b), "reencoded_sha256": sha256(re)}
    lenient = lenient_entry_points(T, b, True)
    if lenient:
        actual["lenient_entry_points"] = lenient
    if re != b:
        if len(re) <= 4096:
            actual["reencoded_hex"] = re.hex()
        return Result("diverge", {"code": "reencode_mismatch", "entry_point": f"xdr.{T.__name__}.to_xdr_bytes"}, actual)
    return ok(actual)


# ---- L1 ------------------------------------------------------------------------------------------------------


def collect(obj, cls, out: list) -> list:
    """Every value of class cls below obj, in declaration (= transaction-set) order."""
    if isinstance(obj, cls):
        out.append(obj)
    elif isinstance(obj, list):
        for x in obj:
            collect(x, cls, out)
    elif is_generated(obj) and not isinstance(obj, int):
        s = shape(type(obj))
        if s.kind == "struct":
            for d in s.fields:
                collect(getattr(obj, d.attr), cls, out)
        elif s.kind == "typedef":
            collect(getattr(obj, s.value.attr), cls, out)
        elif s.kind == "union":
            c = union_case(s, getattr(obj, s.disc.attr))
            if c is not None and c.decl is not None:
                collect(getattr(obj, c.decl.attr), cls, out)
    return out


def arm(obj):
    s = shape(type(obj))
    c = union_case(s, getattr(obj, s.disc.attr))
    return getattr(obj, c.decl.attr) if c is not None and c.decl is not None else None


def envelope_hash(env, passphrase: str) -> str:
    """The envelope's hash from the XDR layer alone (for envelopes the transaction parser refused):
    sha256(sha256(passphrase) || envelope type || transaction), a v0 transaction re-tagged as v1 (its source
    key becomes a MuxedAccount of type ed25519 and its optional time bounds share v1's encoding)."""
    t = int(env.type)
    inner = arm(env)
    tx = inner.tx.to_xdr_bytes()
    if t == 0:
        tagged = (2).to_bytes(4, "big") + (0).to_bytes(4, "big") + tx
    else:
        tagged = t.to_bytes(4, "big") + tx
    return hashlib.sha256(hashlib.sha256(passphrase.encode()).digest() + tagged).hexdigest()


def tx_ops(te):
    inner = getattr(te.transaction, "inner_transaction_envelope", None)
    return inner.transaction.operations if inner is not None else te.transaction.operations


def op_type(op) -> str:
    """The operation's type as the XDR-JSON arm name (change_trust), from the type the SDK object declares."""
    t = getattr(type(op), "_XDR_OPERATION_TYPE", None)
    return enum_name(t) if t is not None else snake(type(op).__name__)


# The counterpart address of an operation (the SDK object's attribute), and its asset, per operation class.
ADDRESS_ATTR = {
    "CreateAccount": "destination", "Payment": "destination", "PathPaymentStrictReceive": "destination",
    "PathPaymentStrictSend": "destination", "AccountMerge": "destination", "AllowTrust": "trustor",
    "SetTrustLineFlags": "trustor", "Clawback": "from_", "BeginSponsoringFutureReserves": "sponsored_id",
}
ASSET_ATTR = {
    "Payment": "asset", "PathPaymentStrictReceive": "dest_asset", "PathPaymentStrictSend": "dest_asset",
    "SetTrustLineFlags": "asset", "Clawback": "asset", "CreateClaimableBalance": "asset", "ChangeTrust": "asset",
}


def asset_text(a) -> str:
    return "native" if a.is_native() else f"{a.code}:{a.issuer}"


def derive_from_operation(op) -> dict:
    """Derived values read back from one parsed operation (the closed list of derived keys). operation_source is
    the operation's own source; muxed_id is the counterpart address's muxed ID, else the own source's."""
    d = {"operation_type": op_type(op)}
    try:
        name = type(op).__name__
        line = getattr(op, "asset", None) or getattr(op, "line", None)
        if isinstance(line, S.LiquidityPoolAsset):
            d["pool_id"] = line.liquidity_pool_id
        elif isinstance(getattr(op, "liquidity_pool_id", None), str):
            d["pool_id"] = op.liquidity_pool_id
        a = getattr(op, ASSET_ATTR[name], None) if name in ASSET_ATTR else None
        if isinstance(a, S.Asset):
            d["asset"] = asset_text(a)
        muxed = None
        addr = getattr(op, ADDRESS_ATTR[name], None) if name in ADDRESS_ATTR else None
        if isinstance(addr, S.MuxedAccount):
            d["address"], muxed = addr.universal_account_id, addr.account_muxed_id
        elif isinstance(addr, str):
            d["address"] = addr
        if isinstance(getattr(op, "offer_id", None), int):
            d["offer_id"] = str(op.offer_id)
        src = getattr(op, "source", None)
        if src is not None:
            d["operation_source"] = src.universal_account_id
            if muxed is None:
                muxed = src.account_muxed_id
        if muxed is not None:
            d["muxed_id"] = str(muxed)
    except Exception as e:
        if is_fault(e):
            raise
    return d


MEMO_TYPES = {"NoneMemo": "none", "TextMemo": "text", "IdMemo": "id", "HashMemo": "hash", "ReturnHashMemo": "return"}


def memo_type(te):
    """memo_type of a parsed transaction envelope (a fee bump's inner transaction); None when unknown."""
    tx = te.transaction
    inner = getattr(tx, "inner_transaction_envelope", None)
    if inner is not None:
        tx = inner.transaction
    return MEMO_TYPES.get(type(getattr(tx, "memo", None)).__name__)


def with_memo(d: dict, te) -> dict:
    m = memo_type(te)
    if m is not None:
        d["memo_type"] = m
    return d


def parse_envelope(b64: str, passphrase: str):
    return S.TransactionBuilder.from_xdr(b64, passphrase)


def run_l1_ledger(inp: dict, T, value) -> Result:
    passphrase = inp.get("passphrase", "")
    lcms = value.ledger_close_metas if isinstance(value, xdr.LedgerCloseMetaBatch) else [value]
    envs, apply_hashes = [], []
    for lcm in lcms:
        body = arm(lcm)
        collect(body.tx_set, xdr.TransactionEnvelope, envs)
        for r in body.tx_processing or []:
            apply_hashes.append(r.result.transaction_hash.hash.hex())
    # Each envelope's place in apply order (txProcessing), found by its hash computed from the XDR layer alone;
    # an envelope with no place there sorts after the others, in set order.
    apply_index = {h: i for i, h in enumerate(apply_hashes)}

    def place(env, set_index):
        try:
            return apply_index.get(envelope_hash(env, passphrase), len(apply_hashes) + set_index)
        except Exception as e:
            if is_fault(e):
                raise
            return len(apply_hashes) + set_index

    obj = {"transactions": len(envs), "envelopes_parsed": 0}
    rejected, hashes, parsed = [], [], {}
    operations = 0
    first = None
    for i, env in sorted(enumerate(envs), key=lambda x: place(x[1], x[0])):
        try:
            te = parse_envelope(base64.b64encode(env.to_xdr_bytes()).decode(), passphrase)
            h = te.hash_hex()
            hashes.append(h)
            parsed[h] = te
            operations += len(tx_ops(te))
            obj["envelopes_parsed"] += 1
        except Exception as e:
            if is_fault(e):
                raise
            code = object_code(e, "object_validation")
            r = {"tx_index": place(env, i), "code": code, "message": trim(str(e) or type(e).__name__)}
            try:
                r["tx_hash"] = envelope_hash(env, passphrase)
            except Exception as he:
                if is_fault(he):
                    raise
            rejected.append(r)
            if first is None:
                first = reason(code, e, "TransactionBuilder.from_xdr")
    obj["operations"] = operations
    obj["tx_hashes"] = hashes
    f = inp.get("focus") or {}
    ti = f.get("tx_index")
    if ti is not None and ti < len(apply_hashes):
        te = parsed.get(apply_hashes[ti])
        if te is not None:
            ops = tx_ops(te)
            oi = f.get("op_index")
            obj["focus"] = {
                "tx_hash": te.hash_hex(),
                "operation_types": [op_type(o) for o in ops],
                "derived": with_memo(derive_from_operation(ops[oi]) if oi is not None and oi < len(ops) else {}, te),
            }
    if rejected:
        obj["envelopes_rejected"] = rejected
        return Result("reject", first, {"object": obj})
    return ok({"object": obj})


def run_l1_envelope(inp: dict) -> Result:
    b = input_bytes(inp)
    try:
        te = parse_envelope(base64.b64encode(b).decode(), inp.get("passphrase", ""))
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(object_code(e, "object_validation"), e, "TransactionBuilder.from_xdr"))
    ops = tx_ops(te)
    obj = {"tx_hash": te.hash_hex(), "operation_types": [op_type(o) for o in ops], "operations": len(ops), "transactions": 1}
    f = inp.get("focus") or {}
    oi = f.get("op_index")
    obj["derived"] = with_memo(derive_from_operation(ops[oi]) if oi is not None and oi < len(ops) else {}, te)
    try:
        re = te.to_xdr_object().to_xdr_bytes()
    except Exception as e:
        if is_fault(e):
            raise
        return Result("diverge", reason("own_output_rejected", e, "TransactionEnvelope.to_xdr_object"), {"object": obj})
    obj["reencoded_sha256"] = sha256(re)
    if re != b:
        actual = {"object": obj}
        if len(re) <= 4096:
            actual["reencoded_hex"] = re.hex()
        return Result("diverge", {"code": "object_reencode_mismatch", "entry_point": "TransactionEnvelope.to_xdr_object"}, actual)
    return ok({"object": obj})


MEMO_TYPES = {"NoneMemo": "none", "TextMemo": "text", "IdMemo": "id", "HashMemo": "hash", "ReturnHashMemo": "return"}


def _memo(v):
    m = S.Memo.from_xdr_object(v)
    return {"derived": {"memo_type": MEMO_TYPES.get(type(m).__name__, snake(type(m).__name__))},
            "back": m.to_xdr_object().to_xdr_bytes()}


def _operation(v):
    o = S.Operation.from_xdr_object(v)
    return {"derived": derive_from_operation(o), "operation_types": [op_type(o)], "back": o.to_xdr_object().to_xdr_bytes()}


def _asset(v):
    a = S.Asset.from_xdr_object(v)
    return {"derived": {"asset": "native" if a.is_native() else f"{a.code}:{a.issuer}"}, "back": a.to_xdr_object().to_xdr_bytes()}


def _address(v):
    a = S.Address.from_xdr_sc_address(v)
    return {"derived": {"address": a.address}, "back": a.to_xdr_sc_address().to_xdr_bytes()}


def _muxed(v):
    m = S.MuxedAccount.from_xdr_object(v)
    derived = {"address": m.universal_account_id}
    if m.account_muxed_id is not None:
        derived["muxed_id"] = str(m.account_muxed_id)
    return {"derived": derived, "back": m.to_xdr_object().to_xdr_bytes()}


def _signer_key(v):
    k = S.SignerKey.from_xdr_object(v)
    return {"derived": {"address": k.encoded_signer_key}, "back": k.to_xdr_object().to_xdr_bytes()}


# L1 for single values with an object class: XDR class name -> (entry point, parse(value) -> {derived, back}),
# where back is the object's own XDR, compared with the input.
OBJECT_PARSERS = {
    "Memo": ("Memo.from_xdr_object", _memo),
    "Operation": ("Operation.from_xdr_object", _operation),
    "Asset": ("Asset.from_xdr_object", _asset),
    "SCAddress": ("Address.from_xdr_sc_address", _address),
    "MuxedAccount": ("MuxedAccount.from_xdr_object", _muxed),
    "SignerKey": ("SignerKey.from_xdr_object", _signer_key),
}


def run_l1(inp: dict) -> Result:
    T = xdr_type(inp["xdr_type"])
    if T is xdr.TransactionEnvelope:
        return run_l1_envelope(inp)
    d = decode_strict(inp)
    if isinstance(d, Result):
        return d
    T, b, v = d
    if T in (xdr.LedgerCloseMeta, xdr.LedgerCloseMetaBatch):
        return run_l1_ledger(inp, T, v)
    p = OBJECT_PARSERS.get(T.__name__)
    if p is None:
        return na("no_object_layer", f"no object parser for {inp['xdr_type']}")
    try:
        r = p[1](v)
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(object_code(e, "object_validation"), e, p[0]))
    obj = {}
    if r.get("derived"):
        obj["derived"] = r["derived"]
    if r.get("operation_types"):
        obj["operation_types"] = r["operation_types"]
        obj["operations"] = len(r["operation_types"])
    back = r.get("back")
    if back is not None:
        obj["reencoded_sha256"] = sha256(back)
        if back != b:
            actual = {"object": obj}
            if len(back) <= 4096:
                actual["reencoded_hex"] = back.hex()
            return Result("diverge", {"code": "object_reencode_mismatch", "entry_point": p[0]}, actual)
    return ok({"object": obj})


# ---- L2 ------------------------------------------------------------------------------------------------------


def run_l2(inp: dict) -> Result:
    d = decode_strict(inp)
    if isinstance(d, Result):
        return d
    T, b, v = d
    try:
        proj = project(v)
    except ProjectionError as e:
        return Result("reject", reason("decode_error", e, "xdrcheck-driver-python projection"))
    pins = inp.get("pinpoints")
    if pins is None:
        return ok({"projection": proj})
    out = []
    for p in pins:
        found, val = pointer(proj, p)
        out.append({"path": p, "found": True, "value": val} if found else {"path": p, "found": False})
    return ok({"pinpoints": out})


# ---- L3 ------------------------------------------------------------------------------------------------------


def native_error(n) -> dict:
    """The native error fact (docs/conformance-protocol.md, "The native error fact"): the ScErrorType and
    ScErrorCode the SDK's native value of an scvError carries, as XDR-JSON names (a contract error's code as its
    decimal number), a key left out when the native value does not carry it. scval.to_native returns the SCVal itself
    for an error, whose SCError holds both."""
    err = n.error if isinstance(n, xdr.SCVal) else n if isinstance(n, xdr.SCError) else None
    if err is None:
        return {}
    t = err.type.name.removeprefix("SCE_").lower()
    if err.type == xdr.SCErrorType.SCE_CONTRACT:
        code = str(err.contract_code.uint32) if err.contract_code is not None else None
    else:
        code = err.code.name.removeprefix("SCEC_").lower() if err.code is not None else None
    return {"type": t} if code is None else {"type": t, "code": code}


def run_l3(inp: dict) -> Result:
    T = xdr_type(inp["xdr_type"])
    if T not in (xdr.SCVal, xdr.Memo):
        return na("no_native_layer", f"no native conversion for {inp['xdr_type']}")
    d = decode_strict(inp)
    if isinstance(d, Result):
        return d
    T, b, v = d
    if T is xdr.Memo:
        try:
            m = S.Memo.from_xdr_object(v)
        except Exception as e:
            if is_fault(e):
                raise
            return Result("reject", reason(native_code(e), e, "Memo.from_xdr_object"))
        value = next((getattr(m, a) for a in ("memo_text", "memo_id", "memo_hash", "memo_return") if hasattr(m, a)), None)
        native = {"type": type(value).__name__ if value is not None else "NoneType", "summary": summary(value)}
        try:
            back = (type(m)() if value is None else type(m)(value)).to_xdr_object().to_xdr_bytes()
            native["reencoded_sha256"] = sha256(back)
            native["bytes_preserved"] = back == b
        except Exception as e:
            if is_fault(e):
                raise
            native["bytes_preserved"] = False
        return ok({"native": native})
    try:
        n = S.scval.to_native(v)
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(native_code(e), e, "scval.to_native"))
    native = {"type": type(n).__name__, "summary": summary(n)}
    if v.type == xdr.SCValType.SCV_ERROR:
        native["error"] = native_error(n)
    if v.type == xdr.SCValType.SCV_MAP:
        native["map_entries"] = len(n) if isinstance(n, dict) else 0
    try:
        back = native_back(S, n, v).to_xdr_bytes()
        native["reencoded_sha256"] = sha256(back)
        native["bytes_preserved"] = back == b
    except Exception as e:
        if is_fault(e):
            raise
        native["bytes_preserved"] = False
    return ok({"native": native})


# ---- protocol ------------------------------------------------------------------------------------------------


def describe(req_id: int) -> dict:
    probes = {
        "sc_address_type_muxed_contract": any(m.value == 5 for m in xdr.SCAddressType),
        "stellar_value_signed_ms": any(m.value == 3 for m in xdr.StellarValueType),
    }
    xdr_schema = {"probes": probes}
    # An enum the ceiling names is in every SDK the driver supports: a missing one is a driver error.
    protocol = reach.schema_protocol(probes, reach.beyond_known(lambda e: (m.value for m in getattr(xdr, e))))
    if protocol is not None:
        xdr_schema["protocol"] = protocol
    every = "TransactionBuilder.from_xdr (every envelope of the transaction set)"
    return {
        "xcc": TAG, "id": req_id, "op": "describe",
        "driver": DRIVER,
        "sdk": sdk.describe_sdk(),
        "runtime": sdk.runtime(),
        "xdr_schema": xdr_schema,
        "levels": LEVELS,
        "object_parsers": {
            "TransactionEnvelope": "TransactionBuilder.from_xdr",
            "LedgerCloseMeta": every,
            "LedgerCloseMetaBatch": every,
            **{("ScAddress" if k == "SCAddress" else k): v[0] for k, v in OBJECT_PARSERS.items()},
        },
        "native_converters": {"ScVal": "scval.to_native", "Memo": "Memo.from_xdr_object"},
        "api_ops": API.names,
        "decode": {
            "entry_point": "xdr.<Type>.from_xdr_bytes",
            "default_depth": sdk.default_depth(),
            "depth_configurable": False,
            "checks_consumed_length": True,
        },
    }


def run_spec(inp: dict) -> Result:
    """The spec level: the SDK's contract-spec reader (spec.py)."""
    container = inp.get("container")
    if container not in ("wasm", "xdr-stream") or "path" not in inp:
        raise ArgError("a spec input needs container and path")
    with open(inp["path"], "rb") as f:
        data = f.read()
    entry_point = "ContractSpec.from_wasm" if container == "wasm" else "ContractSpec.from_xdr_bytes"
    try:
        entry_point, entries = spec.read_spec(data, container)
    except Exception as e:
        if is_fault(e):
            raise
        return Result("reject", reason(spec.refusal_code(e, data, container, decode_code), e, entry_point))
    return ok({"spec": {"entries": [spec.entry_fact(x) for x in entries], "entry_point": entry_point}})


def run_request(req: dict) -> Result:
    inp = req["input"]
    level = req["level"]
    if level == "spec":
        if inp.get("kind") != "spec":
            return na("op_not_supported", "spec needs a spec input")
        return run_spec(inp)
    if level == "L4":
        if inp.get("kind") == "strkey":
            return strkey_decode(S, inp.get("text", ""), inp.get("declared_type"))
        if inp.get("kind") == "api":
            return API.run(inp.get("api_op"), inp.get("args", {}), inp.get("passphrase"))
        return na("op_not_supported", "L4 needs an api or strkey input")
    if inp.get("kind") != "xdr" or "xdr_type" not in inp:
        return na("op_not_supported", f"{level} needs an xdr input")
    return {"L0": run_l0, "L1": run_l1, "L2": run_l2, "L3": run_l3}[level](inp)


def respond(req: dict) -> dict:
    resp = {"xcc": TAG, "id": req["id"], "op": "run", "entry": req["entry"]}
    if "variant" in req:
        resp["variant"] = req["variant"]
    resp["level"] = req["level"]
    if "profile" in req:
        resp["profile"] = req["profile"]
    try:
        o = run_request(req)
    except ArgError as e:
        # The vector cannot be run as given: not an SDK outcome.
        return {"xcc": TAG, "id": req["id"], "op": "protocol_error", "error": f"{req.get('level')} {req['entry']}: {e}"}
    except Exception as e:
        # Fault-class errors and driver bugs: never a reject.
        o = Result("crash", reason(fault_code(e) if is_fault(e) else "internal_error", e))
    resp["outcome"] = o.outcome
    if o.reason:
        resp["reason"] = o.reason
    if o.actual:
        resp["actual"] = o.actual
    return resp


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            send({"xcc": TAG, "op": "protocol_error", "error": "the request is not JSON"})
            continue
        rid = req.get("id") if isinstance(req, dict) else None
        id_ok = isinstance(rid, int) and not isinstance(rid, bool) and rid >= 1

        def perr(msg):
            send({"xcc": TAG, **({"id": rid} if id_ok else {}), "op": "protocol_error", "error": msg})

        if not isinstance(req, dict) or req.get("xcc") != TAG:
            perr(f"unsupported protocol tag {json.dumps(req.get('xdrcheck') if isinstance(req, dict) else None)}")
            continue
        if not id_ok:
            perr("the request has no valid id")
            continue
        op = req.get("op")
        if op == "describe":
            send(describe(rid))
        elif op == "shutdown":
            send({"xcc": TAG, "id": rid, "op": "shutdown", "ok": True})
            break
        elif op == "run":
            if not isinstance(req.get("entry"), str) or req.get("level") not in LEVELS or not isinstance(req.get("input"), dict):
                perr("a run request needs entry, level and input")
                continue
            send(respond(req))
        else:
            perr(f"unknown op {json.dumps(op)}")
    return 0
