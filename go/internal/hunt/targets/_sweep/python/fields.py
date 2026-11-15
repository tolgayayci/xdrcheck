"""Fields mode (xcheck): for each transaction of the reference cut, the fields stellar-sdk computes.
usage: python fields.py LIST_TSV TXS_DIR OUT.jsonl   (env SWEEP_PASSPHRASE)"""
import hashlib, json, os, re, subprocess, sys
from stellar_sdk import FeeBumpTransactionEnvelope, MuxedAccount
from stellar_sdk.helpers import parse_transaction_envelope_from_xdr
from stellar_sdk import memo as M
from stellar_sdk import xdr as X, scval as SV, Address

def from_b64(T, b64):
    f = getattr(T, "from_xdr", None) or getattr(T, "from_xdr_base64")
    return f(b64)


def int_of(x):
    for _ in range(4):
        if isinstance(x, int): return x
        for a in ("int64", "uint64", "uint32", "int32", "value"):
            if hasattr(x, a):
                x = getattr(x, a); break
        else:
            return x
    return x


def ckey(k):
    if isinstance(k, Address): return k.address
    if isinstance(k, bytes): return k.decode("utf-8", "replace")
    return str(k)


def canon(v):
    if v is None: return None
    if isinstance(v, bool): return v
    if isinstance(v, int): return f"n:{v}"
    if isinstance(v, str): return "s:" + v
    if isinstance(v, (bytes, bytearray)): return "b:" + bytes(v).hex()
    if isinstance(v, Address): return "s:" + v.address
    if isinstance(v, (list, tuple)): return [canon(x) for x in v]
    if isinstance(v, dict): return sorted(([("s:" + ckey(k)), canon(x)] for k, x in v.items()), key=lambda p: json.dumps(p[0], ensure_ascii=False).encode())
    return "?:" + type(v).__name__


def is_scval(o):
    q = type(o).__qualname__
    return q == "SCVal" or q.startswith("SCVal.")


def event_vals(o, out, inside=False, depth=0):
    if depth > 30 or o is None or isinstance(o, (int, str, bytes, bool, float)): return
    if inside and is_scval(o):
        out.append(o); return
    if isinstance(o, (list, tuple)):
        for x in o: event_vals(x, out, inside, depth + 1)
        return
    d = getattr(o, "__dict__", None)
    items = list(d.items()) if d else [(k, getattr(o, k, None)) for k in getattr(type(o), "__slots__", ())]
    for k, v in items:
        if k in ("changes", "tx_changes_before", "tx_changes_after", "ext") and not inside: continue
        event_vals(v, out, inside or "event" in k or k == "return_value", depth + 1)

PASS = os.environ.get("SWEEP_PASSPHRASE") or "Public Global Stellar Network ; September 2015"
list_tsv, txs_dir, out_path = sys.argv[1:4]
out = open(out_path, "w")
snake = lambda s: re.sub(r"(?<!^)([A-Z])", r"_\1", s).lower()


def acct(a):
    if a is None: return None
    if isinstance(a, MuxedAccount): return a.universal_account_id
    return str(a)


def asset(a):
    if a is None: return None
    if getattr(a, "is_native", lambda: False)(): return "native"
    if hasattr(a, "liquidity_pool_id"): return "pool:" + a.liquidity_pool_id
    if hasattr(a, "code"): return f"{a.code}:{a.issuer}"
    return str(a)


def memo(m):
    if isinstance(m, M.NoneMemo): return {"type": "none"}
    if isinstance(m, M.TextMemo): return {"type": "text", "value": m.memo_text.decode("utf-8", "replace") if isinstance(m.memo_text, bytes) else m.memo_text}
    if isinstance(m, M.IdMemo): return {"type": "id", "value": str(m.memo_id)}
    if isinstance(m, M.HashMemo): return {"type": "hash", "value": m.memo_hash.hex()}
    if isinstance(m, M.ReturnHashMemo): return {"type": "return", "value": m.memo_return.hex()}
    return {"type": type(m).__name__}


for line in open(list_tsv):
    seq = line.split("\t")[0]
    if not seq.isdigit(): continue
    raw = subprocess.run(["zstd", "-dcq", f"{txs_dir}/{seq}.jsonl.zst"], check=True, capture_output=True).stdout
    for l in raw.decode().split("\n"):
        if not l.strip(): continue
        r = json.loads(l)
        row = {"ledger": r["seq"], "tx": r["idx"]}
        try:
            te = parse_transaction_envelope_from_xdr(r["env"], PASS)
            row["hash"] = te.hash_hex()
            if isinstance(te, FeeBumpTransactionEnvelope):
                row["fee_source"] = acct(te.transaction.fee_source)
                row["fee"] = str(int_of(te.transaction.to_xdr_object().fee))
                tx = te.transaction.inner_transaction_envelope.transaction
                row["inner_hash"] = te.transaction.inner_transaction_envelope.hash_hex()
            else:
                tx = te.transaction
                row["fee"] = str(tx.fee)
            row["source"] = acct(tx.source)
            row["op_count"] = len(tx.operations)
            row["seq"] = str(tx.sequence)
            pc = tx.preconditions
            if pc is not None:
                if pc.ledger_bounds is not None: row["ledger_bounds"] = f"{pc.ledger_bounds.min_ledger}-{pc.ledger_bounds.max_ledger}"
                if pc.min_sequence_number is not None: row["min_seq_num"] = str(pc.min_sequence_number)
                if pc.min_sequence_age is not None: row["min_seq_age"] = str(pc.min_sequence_age)
                if pc.min_sequence_ledger_gap is not None: row["min_seq_ledger_gap"] = str(pc.min_sequence_ledger_gap)
                if pc.extra_signers: row["extra_signers"] = [k.encoded_signer_key for k in pc.extra_signers]
            row["memo"] = memo(tx.memo)
            tb = tx.preconditions.time_bounds if tx.preconditions else None
            row["time_bounds"] = {"min": str(tb.min_time), "max": str(tb.max_time)} if tb and (tb.min_time or tb.max_time) else None
            ops = []
            for i, o in enumerate(tx.operations):
                x = {"type": snake(type(o).__name__)}
                if hasattr(o, "starting_balance"): x["amount"] = str(o.starting_balance)
                for k, n in (("offer_id", "offer_id"), ("bump_to", "bump_to"), ("home_domain", "home_domain"), ("trustor", "trustor"), ("balance_id", "balance_id"),
                             ("liquidity_pool_id", "liquidity_pool_id"), ("master_weight", "master_weight"), ("low_threshold", "low_threshold"), ("med_threshold", "med_threshold"),
                             ("high_threshold", "high_threshold"), ("set_flags", "set_flags"), ("clear_flags", "clear_flags"), ("inflation_dest", "inflation_dest"),
                             ("from_", "from"), ("sponsored_id", "sponsored_id"), ("data_name", "name")):
                    v = getattr(o, k, None)
                    if v is not None: x[n] = str(int(v)) if k.endswith("_flags") else (acct(v) if k in ("from_", "trustor", "inflation_dest", "sponsored_id") else str(v))
                if type(o).__name__ == "ManageData": x["data_value"] = None if o.data_value is None else bytes(o.data_value).hex()
                sg = getattr(o, "signer", None)
                if sg is not None and hasattr(sg, "weight"):  # SetOptions; RevokeSponsorship's signer has no weight
                    x["signer_weight"] = str(sg.weight)
                    try: x["signer_key"] = sg.signer_key.encoded_signer_key
                    except Exception as e: x["signer_key"] = f"error: {e}"
                if type(o).__name__ == "CreateClaimableBalance":
                    try: x["cb_id"] = tx.get_claimable_balance_id(i)
                    except Exception as e: x["cb_id"] = f"error: {e}"
                a = getattr(o, "asset", None)
                if a is not None and hasattr(a, "contract_id"):
                    try: x["asset_cid"] = a.contract_id(PASS)
                    except Exception as e: x["asset_cid"] = f"error: {e}"
                if o.source: x["source"] = acct(o.source)
                for k in ("destination", "amount", "limit", "send_amount", "dest_min", "send_max", "dest_amount"):
                    if getattr(o, k, None) is not None: x[k] = acct(getattr(o, k)) if k == "destination" else str(getattr(o, k))
                for k in ("asset", "selling", "buying", "send_asset", "dest_asset"):
                    if getattr(o, k, None) is not None: x[k] = asset(getattr(o, k))
                if getattr(o, "price", None) is not None: x["price"] = f"{o.price.n}/{o.price.d}"
                ops.append(x)
            row["operations"] = ops
            if hasattr(X.TransactionEnvelope, "from_json_value"):  # SEP-51 JSON model (stellar-xdr); the older to_json is another dialect
                def jd(T, b):
                    try: return hashlib.sha256(json.dumps(from_b64(T, b).to_json_value(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:12]
                    except Exception as e: return f"error: {e}"
                row["json"] = {"env": jd(X.TransactionEnvelope, r["env"]), "pair": jd(X.TransactionResultPair, r["pair"]), "meta": jd(X.TransactionMeta, r["meta"])}
            try: row["fee_charged"] = str(int_of(from_b64(X.TransactionResultPair, r["pair"]).result.fee_charged))
            except Exception as e: row["fee_charged"] = f"error: {e}"
            try:
                vals = []
                event_vals(from_b64(X.TransactionMeta, r["meta"]), vals)
                row["scv_count"] = len(vals)
                out_v = {}
                for v in vals:
                    k = hashlib.sha256(v.to_xdr_bytes()).hexdigest()[:12]
                    try: out_v[k] = json.dumps(canon(SV.to_native(v)), separators=(",", ":"), ensure_ascii=False)
                    except Exception as e: out_v[k] = "error: " + type(e).__name__
                row["scv"] = out_v
            except Exception as e:
                row["scv_count"] = f"error: {e}"
        except Exception as e:
            row["error"] = f"{type(e).__name__}: {e}"
        out.write(json.dumps(row) + "\n")
out.close()
