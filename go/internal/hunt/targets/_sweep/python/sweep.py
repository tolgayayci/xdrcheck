"""Python sweep: every check of the kit's python target (stellar-sdk) over a list of ledgers.

usage: python sweep.py LIST_TSV TXS_DIR OUT_DIR
  LIST_TSV rows: seq<TAB>path of the zstd LedgerCloseMetaBatch object.
  TXS_DIR/<seq>.jsonl.zst: the reference cut (seq, idx, hash, env, pair, meta as base64; optionally *_json).
  env SWEEP_PASSPHRASE: network passphrase (default pubnet).
Writes OUT_DIR/rows.jsonl (one JSON row per failure) and OUT_DIR/stats.json.
Checks: codec, tx-parse, tx-hash, envelope-encode (parsed envelope .to_xdr()), json-roundtrip, json-reference,
op-rebuild (parsed operation .to_xdr_object() against the envelope's operation bytes), tx-rebuild (the transaction
rebuilt through TransactionBuilder from its parsed parts), feebump-rebuild (TransactionBuilder.build_fee_bump_transaction
on the parsed inner envelope), cb-id / pool-id / contract-id (computed helpers against the ids the result and meta
state, from the cut's truth), scval-native (scval.to_native on every contract value of the meta).
"""
import json, os, re, subprocess, sys, warnings

import stellar_sdk
from stellar_sdk import xdr as X
from stellar_sdk.helpers import parse_transaction_envelope_from_xdr
from stellar_sdk import TransactionBuilder, Account, Asset, FeeBumpTransactionEnvelope, scval as SV

warnings.simplefilter("ignore")
PASS = os.environ.get("SWEEP_PASSPHRASE") or "Public Global Stellar Network ; September 2015"
list_tsv, txs_dir, out_dir = sys.argv[1:4]
os.makedirs(out_dir, exist_ok=True)
CHECKS = ["codec", "tx-parse", "tx-hash", "envelope-encode", "json-roundtrip", "json-reference", "load", "op-rebuild",
          "tx-rebuild", "feebump-rebuild", "cb-id", "pool-id", "contract-id", "scval-native", "harness"]
stats = {"target": "python", "version": stellar_sdk.__version__, "ledgers": 0, "txs": 0, "tested": {c: 0 for c in CHECKS}}
out = open(os.path.join(out_dir, "rows.jsonl"), "w")


def strip(s):
    s = re.sub(r"\"[^\"]*\"|'[^']*'", "<s>", str(s))
    s = re.sub(r"\b[GCMBTXP][A-Z2-7]{55,}\b", "<key>", s)
    s = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<hex>", s)
    s = re.sub(r"-?\d+(\.\d+)?", "N", s)
    return " ".join(s.split())[:140]


def fail(check, seq, idx, h, op, op_type, cls, detail):
    out.write(json.dumps({"check": check, "class": cls, "ledger": int(seq), "tx": -1 if idx == "" else int(idx), "hash": h,
                          "op": str(op), "op_type": op_type, "detail": " ".join(str(detail).split())[:400]}) + "\n")


def tname(v):
    if v is None: return "null"
    if isinstance(v, bool): return "boolean"
    if isinstance(v, (int, float)): return "number"
    if isinstance(v, str): return "string"
    if isinstance(v, list): return "array"
    if isinstance(v, dict): return "object"
    return type(v).__name__


def show(v):
    try:
        return json.dumps(v)[:80]
    except Exception:
        return repr(v)[:80]


def diff(a, b, path):
    """First differing path and a (kind, detail) pair."""
    ta, tb = tname(a), tname(b)
    if ta != tb:
        return path, f"type:{ta}>{tb}", f"type {ta} vs {tb}: {show(a)} vs {show(b)}"
    if ta == "array":
        if len(a) != len(b):
            return path, "array-length", f"array length {len(a)} vs {len(b)}"
        for x, y in zip(a, b):
            d = diff(x, y, path + "[*]")
            if d: return d
        return None
    if ta == "object":
        norm = lambda k: k.replace("_", "").lower()
        for k in a:
            if k not in b:
                k2 = next((x for x in b if x not in a and norm(x) == norm(k)), None)
                if k2 is not None:
                    return f"{path}.{k}", f"key-name:{k}>{k2}", f"key named {k} in sdk json, {k2} in ref json"
                return f"{path}.{k}", "key-only-in-sdk", "key only in sdk json"
        for k in b:
            if k not in a:
                return f"{path}.{k}", "key-only-in-ref", "key only in ref json"
        for k in a:
            d = diff(a[k], b[k], f"{path}.{k}")
            if d: return d
        return None
    if a != b:
        return path, "value", f"value {show(a)} vs {show(b)}"
    return None


def from_b64(T, b64):
    """Base64 decode across stellar-sdk API generations (from_xdr, later from_xdr_base64)."""
    f = getattr(T, "from_xdr", None) or getattr(T, "from_xdr_base64")
    return f(b64)


def to_b64(v):
    f = getattr(v, "to_xdr", None) or getattr(v, "to_xdr_base64")
    return f()


def raw_ops(env):
    # older models carry every arm as an attribute (None when unset); newer ones only the arm present
    if getattr(env, "v0", None) is not None: return env.v0.tx.operations
    if getattr(env, "v1", None) is not None: return env.v1.tx.operations
    return env.fee_bump.tx.inner_tx.v1.tx.operations


def op_name(o):
    t = getattr(o.body, "type", None)
    return (getattr(t, "name", None) or type(o.body).__name__).lower()


def unzstd(p):
    return subprocess.run(["zstd", "-dcq", p], check=True, capture_output=True).stdout


def xb(o):
    """XDR bytes of an XDR object of either model generation (None stays None)."""
    if o is None: return None
    f = getattr(o, "to_xdr_bytes", None)
    if f: return f()
    return repr(o).encode()


def raw_env_parts(env):
    """(the transaction object, the fee-bump transaction object or None) of a decoded envelope."""
    if getattr(env, "v0", None) is not None: return env.v0.tx, None
    if getattr(env, "v1", None) is not None: return env.v1.tx, None
    fb = env.fee_bump.tx
    return fb.inner_tx.v1.tx, fb


TX_FIELDS = ("source_account", "source_account_ed25519", "fee", "seq_num", "cond", "time_bounds", "memo", "operations", "ext")


def tx_diff(a, b):
    out = []
    for f in TX_FIELDS:
        if not hasattr(a, f) and not hasattr(b, f): continue
        va, vb = getattr(a, f, None), getattr(b, f, None)
        if f == "operations":
            if len(va) != len(vb): out.append("ops:count"); continue
            for i, (x, y) in enumerate(zip(va, vb)):
                if xb(x) != xb(y): out.append(f"ops:differs:{op_name(y)}"); break
            continue
        if xb(va) != xb(vb):
            out.append(f + ":differs")
    return ";".join(out) or "bytes-differ"


def builder_checks(te, r, seq, idx, h, types):
    raw = from_b64(X.TransactionEnvelope, r["env"])
    raw_tx, raw_fb = raw_env_parts(raw)
    is_fb = isinstance(te, FeeBumpTransactionEnvelope)
    inner_env = te.transaction.inner_transaction_envelope if is_fb else te
    t = inner_env.transaction
    # op-rebuild: each parsed operation encodes back to the envelope's bytes
    ops = raw_tx.operations
    for i, op in enumerate(t.operations):
        stats["tested"]["op-rebuild"] += 1
        try:
            if i >= len(ops) or xb(op.to_xdr_object()) != xb(ops[i]):
                fail("op-rebuild", seq, idx, h, i, op_name(ops[i]) if i < len(ops) else "?", "op-differs", "parsed operation re-encodes differently")
        except Exception as e:
            fail("op-rebuild", seq, idx, h, i, op_name(ops[i]) if i < len(ops) else "?", f"throws:{type(e).__name__}:{strip(e)}", f"{type(e).__name__}: {e}")
    # tx-rebuild: TransactionBuilder from the parsed parts
    n = len(t.operations)
    rf = t.soroban_data.resource_fee.int64 if t.soroban_data is not None and hasattr(t.soroban_data.resource_fee, "int64") else (t.soroban_data.resource_fee if t.soroban_data is not None else 0)
    stats["tested"]["tx-rebuild"] += 1
    tags = []
    try:
        incl = t.fee - rf
        if n and incl % n: tags.append("fee:not-multiple")
        b = TransactionBuilder(Account(t.source, t.sequence - 1), te.network_passphrase if hasattr(te, "network_passphrase") else PASS, base_fee=(incl // n if n else 0), v1=t.v1)
        pc = t.preconditions
        if pc is not None:
            if pc.time_bounds is not None: b.add_time_bounds(pc.time_bounds.min_time, pc.time_bounds.max_time)
            if pc.ledger_bounds is not None: b.set_ledger_bounds(pc.ledger_bounds.min_ledger, pc.ledger_bounds.max_ledger)
            if pc.min_sequence_number is not None: b.set_min_sequence_number(pc.min_sequence_number)
            if pc.min_sequence_age is not None: b.set_min_sequence_age(pc.min_sequence_age)
            if pc.min_sequence_ledger_gap is not None: b.set_min_sequence_ledger_gap(pc.min_sequence_ledger_gap)
            for k in pc.extra_signers or []: b.add_extra_signer(k)
        b.add_memo(t.memo)
        for op in t.operations: b.append_operation(op)
        if t.soroban_data is not None: b.set_soroban_data(t.soroban_data)
        nt = b.build().transaction.to_xdr_object()
        if xb(nt) != xb(raw_tx):
            fail("tx-rebuild", seq, idx, h, "", types, "rebuild-differs:" + ";".join([tx_diff(nt, raw_tx)] + tags), "TransactionBuilder rebuild differs: " + tx_diff(nt, raw_tx))
    except Exception as e:
        fail("tx-rebuild", seq, idx, h, "", types, f"rebuild-throws:{type(e).__name__}:{strip(e)}", f"TransactionBuilder rebuild: {type(e).__name__}: {e}")
    # feebump-rebuild
    if is_fb:
        stats["tested"]["feebump-rebuild"] += 1
        fb = te.transaction
        try:
            F = fb.fee if isinstance(fb.fee, int) else int(xb(raw_fb.fee).hex(), 16)
            oi = F - rf
            ftags = ["feebump.fee:not-multiple"] if oi % (n + 1) else []
            nb = TransactionBuilder.build_fee_bump_transaction(fb.fee_source, oi // (n + 1), inner_env, PASS).transaction.to_xdr_object()
            if xb(nb) != xb(raw_fb):
                d = [f + ":differs" for f in ("fee_source", "fee", "inner_tx", "ext") if xb(getattr(nb, f, None)) != xb(getattr(raw_fb, f, None))]
                fail("feebump-rebuild", seq, idx, h, "", types, "rebuild-differs:" + ";".join(d + ftags), "build_fee_bump_transaction differs: " + ";".join(d))
        except Exception as e:
            fail("feebump-rebuild", seq, idx, h, "", types, f"rebuild-throws:{type(e).__name__}:{strip(e)}", f"build_fee_bump_transaction: {type(e).__name__}: {e}")
    # computed ids against what the result and meta state
    tr = r.get("truth") or {}
    for i, want in (tr.get("cb_ids") or {}).items():
        stats["tested"]["cb-id"] += 1
        try:
            got = t.get_claimable_balance_id(int(i))
            if got.lower() != want.lower():
                fail("cb-id", seq, idx, h, i, "create_claimable_balance", "id-differs", f"get_claimable_balance_id {got} ledger {want}")
        except Exception as e:
            fail("cb-id", seq, idx, h, i, "create_claimable_balance", f"throws:{type(e).__name__}:{strip(e)}", f"{type(e).__name__}: {e}")
    for i, want in (tr.get("pool_ids") or {}).items():
        stats["tested"]["pool-id"] += 1
        try:
            got = t.operations[int(i)].asset.liquidity_pool_id
            if got.lower() != want.lower():
                fail("pool-id", seq, idx, h, i, "change_trust", "id-differs", f"liquidity_pool_id {got} ledger {want}")
        except Exception as e:
            fail("pool-id", seq, idx, h, i, "change_trust", f"throws:{type(e).__name__}:{strip(e)}", f"{type(e).__name__}: {e}")
    for i, want in (tr.get("contract_ids") or {}).items():
        try:
            hf = t.operations[int(i)].host_function
            cc = getattr(hf, "create_contract", None) or getattr(hf, "create_contract_v2", None) or getattr(hf, "v", None) or getattr(hf, "value", None)
            pre = cc.contract_id_preimage
            fa = getattr(pre, "from_asset", None)
            if fa is None: continue
            stats["tested"]["contract-id"] += 1
            got = Asset.from_xdr_object(fa).contract_id(PASS)
            if got != want:
                fail("contract-id", seq, idx, h, i, "invoke_host_function", "asset-contract-id-differs", f"Asset.contract_id {got} ledger {want}")
        except Exception as e:
            stats["tested"]["contract-id"] += 1
            fail("contract-id", seq, idx, h, i, "invoke_host_function", f"throws:{type(e).__name__}:{strip(e)}", f"{type(e).__name__}: {e}")


def is_scval(o):
    q = type(o).__qualname__
    return q == "SCVal" or q.startswith("SCVal.")


def walk_scvals(o, out, depth=0):
    if depth > 40 or len(out) >= 400 or o is None or isinstance(o, (int, str, bytes, bool, float)): return
    if is_scval(o):
        out.append(o); return
    if isinstance(o, (list, tuple)):
        for x in o: walk_scvals(x, out, depth + 1)
        return
    d = getattr(o, "__dict__", None)
    vals = list(d.values()) if d else [getattr(o, k, None) for k in getattr(type(o), "__slots__", ())]
    for v in vals: walk_scvals(v, out, depth + 1)


def scval_checks(r, seq, idx, h, types):
    try:
        m = from_b64(X.TransactionMeta, r["meta"])
        vals = []
        walk_scvals(m, vals)
    except Exception as e:
        stats["tested"]["scval-native"] += 1
        fail("scval-native", seq, idx, h, "", types, f"meta-walk:{type(e).__name__}:{strip(e)}", f"meta walk: {type(e).__name__}: {e}")
        return
    for v in vals:
        stats["tested"]["scval-native"] += 1
        try:
            SV.to_native(v)
        except Exception as e:
            k = getattr(getattr(v, "type", None), "name", None) or type(v).__qualname__
            fail("scval-native", seq, idx, h, "", types, f"{k}:{type(e).__name__}:{strip(e)}", f"to_native({k}): {type(e).__name__}: {e}")


for line in open(list_tsv):
    cols = line.rstrip("\n").split("\t")
    seq0, path = cols[0], cols[1]
    if not seq0.isdigit(): continue
    stats["tested"]["load"] += 1
    try:
        rows = [json.loads(l) for l in unzstd(f"{txs_dir}/{seq0}.jsonl.zst").decode().split("\n") if l.strip()]
    except Exception as e:
        fail("load", seq0, "", "", "", "", "no-reference-rows", f"{type(e).__name__}: {e}")
        continue
    raw = unzstd(path)
    stats["tested"]["codec"] += 1
    try:
        b = X.LedgerCloseMetaBatch.from_xdr_bytes(raw)
        stats["ledgers"] += len(b.ledger_close_metas)
        if b.to_xdr_bytes() != raw:
            fail("codec", seq0, "", "", "", "", "re-encode-differs", "re-encode differs")
        del b
    except Exception as e:
        fail("codec", seq0, "", "", "", "", f"exception:{type(e).__name__}:{strip(e)}", f"exception: {type(e).__name__}: {e}")
    for r in rows:
        stats["txs"] += 1
        seq, idx, h = r["seq"], r["idx"], r["hash"]
        types = "?"
        try:
            ops = raw_ops(from_b64(X.TransactionEnvelope, r["env"]))
            types = "+".join(dict.fromkeys(op_name(o) for o in ops))
        except Exception as e:
            fail("codec", seq, idx, h, "", "", f"envelope-decode:{type(e).__name__}:{strip(e)}", f"TransactionEnvelope.from_xdr: {type(e).__name__}: {e}")
        te = None
        stats["tested"]["tx-parse"] += 1
        try:
            te = parse_transaction_envelope_from_xdr(r["env"], PASS)
        except Exception as e:
            fail("tx-parse", seq, idx, h, "", types, f"{type(e).__name__}:{strip(e)}", f"{type(e).__name__}: {e}")
        if te is not None:
            stats["tested"]["tx-hash"] += 1
            try:
                hh = te.hash_hex()
                if hh != h: fail("tx-hash", seq, idx, h, "", types, "hash-differs", f"sdk hash {hh}")
            except Exception as e:
                fail("tx-hash", seq, idx, h, "", types, f"exception:{type(e).__name__}:{strip(e)}", f"exception: {type(e).__name__}: {e}")
            stats["tested"]["envelope-encode"] += 1
            try:
                if te.to_xdr() != r["env"]:
                    fail("envelope-encode", seq, idx, h, "", types, "to_xdr-differs", "to_xdr() differs from input")
            except Exception as e:
                fail("envelope-encode", seq, idx, h, "", types, f"exception:{type(e).__name__}:{strip(e)}", f"exception: {type(e).__name__}: {e}")
            try:
                builder_checks(te, r, seq, idx, h, types)
            except Exception as e:
                fail("harness", seq, idx, h, "", types, f"builder-checks:{type(e).__name__}:{strip(e)}", f"builder checks: {type(e).__name__}: {e}")
        scval_checks(r, seq, idx, h, types)
        for name, T, b64, ref in (("TransactionEnvelope", X.TransactionEnvelope, r["env"], r.get("env_json")),
                                  ("TransactionResultPair", X.TransactionResultPair, r["pair"], r.get("pair_json")),
                                  ("TransactionMeta", X.TransactionMeta, r["meta"], r.get("meta_json"))):
            new_json = hasattr(T, "from_json_value")
            if not new_json and (not hasattr(T, "to_json") or not hasattr(T, "from_json")): continue
            j = None
            stats["tested"]["json-roundtrip"] += 1
            try:
                if new_json:
                    j = from_b64(T, b64).to_json_value()
                    back = T.from_json_value(j)
                else:
                    s = from_b64(T, b64).to_json()
                    j = json.loads(s)
                    back = T.from_json(s)
                if to_b64(back) != b64:
                    fail("json-roundtrip", seq, idx, h, "", types, f"{name}:reencode-differs", f"{name}: from_json(to_json(x)) re-encodes differently")
            except Exception as e:
                fail("json-roundtrip", seq, idx, h, "", types, f"{name}:exception:{type(e).__name__}:{strip(e)}", f"{name}: exception: {type(e).__name__}: {e}")
            if j is not None and ref is not None:
                stats["tested"]["json-reference"] += 1
                d = diff(j, ref, name)
                if d:
                    p = re.sub(r"[.]v[0-9]+([.]|$)", r".vN\1", d[0])
                    fail("json-reference", seq, idx, h, "", types, f"{p}:{d[1]}", f"{d[0]} :: {d[2]}")
    out.flush()
out.close()
json.dump(stats, open(os.path.join(out_dir, "stats.json"), "w"))
