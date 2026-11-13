#!/usr/bin/env python3
"""Mutation test of the judge's verdict mode.

A toy indexer derives rows (the common row schema) from the judge's own facts, then plants one
bug per run. Every planted bug must be flagged with its expected class at its place; the
unmutated run must be 100% `ok`.

    mutation_test.py --judge target/release/xdrcheck-judge --facts facts.jsonl --work DIR

Facts must be sorted by ledger (the judge writes them that way). Exit code 0 = all caught.
"""
import argparse
import json
import os
import subprocess
import sys

I64 = 2**63


def wrap64(n):
    n &= 2**64 - 1
    return n - 2**64 if n >= I64 else n


def base_rows(facts_path, rows_path):
    """Write the toy indexer's rows and return candidate targets for each plant."""
    cand = {k: None for k in (
        "drop_row", "off_by_one", "int64_wrap", "duplicate_row", "drop_muxed_participant",
        "credit_failed_tx", "credit_non_sac_event", "skip_ledger", "halt", "drop_entry",
        "duplicate_event", "exports_nothing", "drop_kind", "unknown_tx_index",
        "sac_contract_keyed_row", "wrong_signer_key", "noop_field")}
    failed = {}
    ledgers_with_rows = []
    n = 0
    with open(facts_path) as f, open(rows_path, "w") as out:
        for line in f:
            d = json.loads(line)
            k = d["kind"]
            row = None
            if k == "ledger":
                row = {"kind": "ledger", "ledger": d["ledger"], "tx_count": d["tx_count"],
                       "protocol": d["protocol"], "close_time": d["close_time"]}
                if d["tx_count"] > 0:
                    ledgers_with_rows.append(d["ledger"])
            elif k == "tx":
                if not d["success"]:
                    failed[(d["ledger"], d["tx_hash"])] = d
            elif k == "balance_change" and d.get("tx_hash") and d["complete"] and d["amount"] != "0":
                row = {"kind": "balance_change", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                       "holder": d["holder"], "asset": d["asset"], "amount": d["amount"]}
                if cand["drop_row"] is None and d["ledger"] > 1000000:
                    cand["drop_row"] = (n, d)
                if cand["off_by_one"] is None and d["ledger"] > 50000000:
                    cand["off_by_one"] = (n, d)
                if cand["duplicate_row"] is None and d["ledger"] > 60000000:
                    cand["duplicate_row"] = (n, d)
                if cand["sac_contract_keyed_row"] is None and d["asset"] != "native" \
                        and "trustline" in d["via"] and d["ledger"] < 50000000:
                    cand["sac_contract_keyed_row"] = (n, d)
                if cand["int64_wrap"] is None and abs(int(d["amount"])) >= I64:
                    cand["int64_wrap"] = (n, d)
            elif k == "participant" and d["roles"] == ["claimant"]:
                pass  # a claimant only: not a participant by the judge's convention
            elif k == "participant":
                row = {"kind": "participant", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                       "holder": d["address"]}
                if d["muxed_ids"]:
                    row["muxed_id"] = d["muxed_ids"][0]
                    if cand["drop_muxed_participant"] is None and "counterparty" in d["roles"] \
                            and "source" not in d["roles"] and "fee_payer" not in d["roles"]:
                        cand["drop_muxed_participant"] = (n, d)
                key = (d["ledger"], d["tx_hash"])
                if cand["credit_failed_tx"] is None and key in failed \
                        and "counterparty" in d["roles"] and "fee_payer" not in d["roles"]:
                    cand["credit_failed_tx"] = (n, d)
            elif k == "entry_change" and d.get("tx_hash"):
                row = {"kind": "entry_change", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                       "change": d["change"], "entry_key": d["key"]}
                if cand["drop_entry"] is None and d["ledger"] > 40000000:
                    cand["drop_entry"] = (n, d)
            elif k == "entry_change":
                row = {"kind": "entry_change", "ledger": d["ledger"], "change": d["change"],
                       "entry_key": d["key"]}
            elif k == "entry_field" and d.get("tx_hash"):
                # Attribute rows by subject; flags as the bits set / cleared.
                base = {"kind": "entry_change", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                        "subject": d["subject"]}
                if d.get("op_index") is not None:
                    base["op_index"] = d["op_index"]
                if d["field"] == "flags":
                    o, nw = int(d.get("old") or 0), int(d.get("new") or 0)
                    for f2, bits in (("flags:set", nw & ~o), ("flags:clear", o & ~nw if d.get("new") is not None else 0)):
                        if bits:
                            out.write(json.dumps(dict(base, field=f2, new=str(bits)), separators=(",", ":")) + "\n")
                            n += 1
                else:
                    row = dict(base, field=d["field"])
                    for f2 in ("old", "new"):
                        if d.get(f2) is not None:
                            row[f2] = d[f2]
                    if cand["wrong_signer_key"] is None and d["field"].startswith("signer:") \
                            and d.get("new") is not None:
                        cand["wrong_signer_key"] = (n, d)
                    if cand["noop_field"] is None and d["field"].startswith("threshold:"):
                        cand["noop_field"] = (n, d)
            elif k == "token_event":
                row = {"kind": "token_event", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                       "contract": d["contract"], "event": d["event"]}
                for f2 in ("from", "to", "amount", "to_muxed_id"):
                    if d.get(f2) is not None:
                        row[f2] = d[f2]
                if cand["duplicate_event"] is None and d["sac"]:
                    cand["duplicate_event"] = (n, d)
                if cand["credit_non_sac_event"] is None and not d["sac"] \
                        and d["event"] == "transfer" and d.get("to") and d.get("amount") \
                        and int(d["amount"]) > 0:
                    cand["credit_non_sac_event"] = (n, d)
            if row is not None:
                out.write(json.dumps(row, separators=(",", ":")) + "\n")
                n += 1
    if len(ledgers_with_rows) >= 3:
        cand["skip_ledger"] = (None, {"ledger": ledgers_with_rows[len(ledgers_with_rows) // 2]})
        cand["halt"] = (None, {"ledger": ledgers_with_rows[-2]})
        cand["exports_nothing"] = (None, {"ledger": ledgers_with_rows[0]})
    if cand["drop_row"] is not None:
        d = cand["drop_row"][1]
        cand["drop_kind"] = (None, d)
        cand["unknown_tx_index"] = (None, {"ledger": d["ledger"]})
    return cand


def plant(rows_path, out_path, name, target):
    idx, d = target
    expect = {
        "drop_row": ("missing", "balance_change:missing"),
        "off_by_one": ("wrong_value", "balance_change:wrong_value:small_diff"),
        "int64_wrap": ("wrong_value", "balance_change:wrong_value:int64_wrap"),
        "duplicate_row": ("duplicate", "balance_change:duplicate"),
        "drop_muxed_participant": ("missing", "participant:missing:"),
        "credit_failed_tx": ("extra", "balance_change:extra:failed_tx"),
        "credit_non_sac_event": ("extra", "balance_change:extra:non_sac_contract"),
        "skip_ledger": ("skip", "ledger:skip"),
        "halt": ("halt", "ledger:halt"),
        "drop_entry": ("missing", "entry_change:missing:"),
        "duplicate_event": ("duplicate", "token_event:duplicate"),
        "exports_nothing": ("halt", "ledger:halt"),
        "drop_kind": ("missing", "participant:missing:"),
        "unknown_tx_index": ("extra", "balance_change:extra:unknown_tx"),
        "sac_contract_keyed_row": (None, None),
        "wrong_signer_key": ("wrong_value", "entry_change:wrong_value:account:signer_key"),
        "noop_field": ("extra", "entry_change:extra:noop:account:threshold"),
    }[name]
    extra = None
    if name == "credit_failed_tx":
        extra = {"kind": "balance_change", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                 "holder": d["address"], "asset": "native", "amount": "10000000"}
    if name == "credit_non_sac_event":
        extra = {"kind": "balance_change", "ledger": d["ledger"], "tx_hash": d["tx_hash"],
                 "holder": d["to"], "asset": d["contract"], "amount": d["amount"]}
    if name == "unknown_tx_index":
        extra = {"kind": "balance_change", "ledger": d["ledger"], "tx_index": 999999,
                 "holder": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "asset": "native",
                 "amount": "1"}
    with open(rows_path) as f, open(out_path, "w") as out:
        if name == "exports_nothing":
            return expect
        for i, line in enumerate(f):
            if name == "drop_kind" and '"kind":"participant"' in line:
                continue
            if name in ("skip_ledger", "halt"):
                led = json.loads(line)["ledger"]
                if (name == "skip_ledger" and led == d["ledger"]) or (name == "halt" and led >= d["ledger"]):
                    continue
            if name == "unknown_tx_index" and extra is not None and json.loads(line)["ledger"] == d["ledger"]:
                out.write(json.dumps(extra, separators=(",", ":")) + "\n")
                extra = None
            if i == idx:
                r = json.loads(line)
                if name == "sac_contract_keyed_row":
                    r["asset"] = d["contract"]
                    line = json.dumps(r, separators=(",", ":")) + "\n"
                if name in ("drop_row", "drop_muxed_participant", "drop_entry"):
                    continue
                if name == "off_by_one":
                    r["amount"] = str(int(r["amount"]) + 1)
                    line = json.dumps(r, separators=(",", ":")) + "\n"
                if name == "int64_wrap":
                    r["amount"] = str(wrap64(int(r["amount"])))
                    line = json.dumps(r, separators=(",", ":")) + "\n"
                if name == "wrong_signer_key":
                    # The key cut to its first 32 payload bytes (a fixed-width column).
                    r["field"] = r["field"][:7 + 66]
                    if r["field"] == json.loads(line)["field"]:
                        r["field"] = r["field"][:-2] + ("00" if r["field"][-2:] != "00" else "01")
                    line = json.dumps(r, separators=(",", ":")) + "\n"
                if name == "noop_field":
                    # A second row restating the value as unchanged.
                    v = r.get("new") or r.get("old") or "0"
                    out.write(line)
                    line = json.dumps(dict(r, old=v, new=v), separators=(",", ":")) + "\n"
                if name in ("duplicate_row", "duplicate_event"):
                    out.write(line)
                if extra is not None:
                    out.write(line)
                    line = json.dumps(extra, separators=(",", ":")) + "\n"
            out.write(line)
    return expect


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", required=True)
    ap.add_argument("--facts", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    base = os.path.join(a.work, "rows.base.jsonl")
    cand = base_rows(a.facts, base)

    # The exporter's declared kinds, as a real rig would pass them.
    kinds = sorted({json.loads(l)["kind"] for l in open(base)})

    def verdicts(rows, tag, declare=True):
        out = os.path.join(a.work, f"verdicts.{tag}.jsonl")
        cmd = [a.judge, "verdict", "--facts", a.facts, "--rows", rows, "-o", out]
        if declare:
            cmd += ["--kinds", ",".join(kinds)]
        subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)
        return out

    results = []
    vb = verdicts(base, "base")
    counts = {}
    with open(vb) as f:
        for line in f:
            v = json.loads(line)["verdict"]
            counts[v] = counts.get(v, 0) + 1
    base_ok = set(counts) == {"ok"}
    results.append({"plant": "none", "caught": base_ok, "verdicts": counts})
    for name, target in cand.items():
        if target is None:
            results.append({"plant": name, "caught": None, "note": "no target in these facts"})
            continue
        rows = os.path.join(a.work, f"rows.{name}.jsonl")
        verdict, prefix = plant(base, rows, name, target)
        # "exports nothing" runs without declared kinds: an empty export must not pass.
        vp = verdicts(rows, name, declare=(name != "exports_nothing"))
        d = target[1]
        hit = []
        other = 0
        with open(vp) as f:
            for line in f:
                v = json.loads(line)
                if v["verdict"] == "ok":
                    continue
                if v["ledger"] == d["ledger"] and (v.get("tx_hash") == d.get("tx_hash") or "tx_hash" not in d) \
                        and v["verdict"] == verdict and v["class"].startswith(prefix):
                    hit.append(v["class"])
                else:
                    other += 1
        if verdict is None:
            # Negative control: the row is correct in another spelling; nothing may be flagged.
            results.append({"plant": name, "ledger": d["ledger"], "expect": "no verdict",
                            "caught": other == 0, "other_verdicts": other})
        else:
            results.append({"plant": name, "ledger": d["ledger"], "tx_hash": d.get("tx_hash"),
                            "expect": prefix, "caught": bool(hit), "classes": sorted(set(hit)),
                            "other_verdicts": other})
        os.remove(rows)
        os.remove(vp)
    with open(os.path.join(a.work, "mutation_result.json"), "w") as f:
        json.dump(results, f, indent=1)
    for r in results:
        print(json.dumps(r))
    ok = all(r["caught"] for r in results if r["caught"] is not None)
    missing_targets = [r["plant"] for r in results if r["caught"] is None]
    if missing_targets:
        print("no target for:", missing_targets, file=sys.stderr)
    sys.exit(0 if ok and not missing_targets else 1)


if __name__ == "__main__":
    main()
