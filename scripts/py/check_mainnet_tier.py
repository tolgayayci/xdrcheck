#!/usr/bin/env python3
"""The mainnet tier's files without its lake objects (the pull-request check; `make verify-mainnet` is the full one).

corpus/mainnet/tier.json against corpus/schema/mainnet-tier.schema.json, every line of corpus/mainnet/tier.jsonl
against corpus/schema/mainnet-tx.schema.json, and what the lines must say together: the header's sha256 of
tier.jsonl and its counts (transactions, ledgers, parts, part bytes, distinct tokens, transactions per protocol),
one line per transaction, each token on exactly one line, the lake key the lake gives the ledger, one object hash
and size per object, parts at distinct offsets, lines in the cover's order (rarity never decreasing); and, when the
tier sits in a corpus root, that corpus.json's tiers.mainnet and the tier half of evidence/results/mainnet-coverage.json
repeat the header's counts (`make verify-coverage` checks the curated half). Exit 1 on any failure.

    check_mainnet_tier.py [--tier DIR]
"""
import argparse
import collections
import hashlib
import json
import os
import sys

import jsonschema
from referencing import Registry, Resource

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SCHEMAS = os.path.join(ROOT, "corpus", "schema")


def lake_key(seq):
    p = seq // 64000 * 64000
    return f"{0xFFFFFFFF - p:08X}--{p}-{p + 63999}/{0xFFFFFFFF - seq:08X}--{seq}.xdr.zst"


def validator(name):
    s = json.load(open(os.path.join(SCHEMAS, f"{name}.schema.json")))
    reg = Registry().with_resource(s["$id"], Resource.from_contents(s))
    return jsonschema.Draft202012Validator(s, registry=reg)


def check(tier):
    bad = []
    header = json.load(open(os.path.join(tier, "tier.json")))
    for e in validator("mainnet-tier").iter_errors(header):
        bad.append(f"tier.json: {e.message[:200]}")
    raw = open(os.path.join(tier, "tier.jsonl"), "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    if header.get("lines", {}).get("sha256") != sha:
        bad.append(f"tier.jsonl: sha256 is {sha}, tier.json says {header.get('lines', {}).get('sha256')}")
    v = validator("mainnet-tx")
    owner, txs, objs = {}, set(), {}
    ledgers, protocols = set(), collections.Counter()
    parts = part_bytes = 0
    last_rarity = 0
    lines = raw.decode().splitlines()
    for n, text in enumerate(lines, 1):
        try:
            line = json.loads(text)
        except json.JSONDecodeError as e:
            bad.append(f"tier.jsonl:{n}: not JSON: {e}")
            continue
        errs = list(v.iter_errors(line))
        if errs:
            bad.append(f"tier.jsonl:{n}: {errs[0].message[:200]}")
            continue
        tx = (line["ledger"], line["tx_index"])
        if tx in txs:
            bad.append(f"tier.jsonl:{n}: transaction {tx} is on an earlier line too")
        txs.add(tx)
        ledgers.add(line["ledger"])
        protocols[str(line["protocol"])] += 1
        if line["lake_key"] != lake_key(line["ledger"]):
            bad.append(f"tier.jsonl:{n}: lake key {line['lake_key']} is not the lake's key for {line['ledger']}")
        obj = (line["object_sha256"], line["object_bytes"], line["blob_offset"])
        if objs.setdefault(line["lake_key"], obj) != obj:
            bad.append(f"tier.jsonl:{n}: object {line['lake_key']} has another hash, size or offset on an earlier line")
        if line["rarity"] < last_rarity:
            bad.append(f"tier.jsonl:{n}: rarity {line['rarity']} below the previous line's {last_rarity}")
        last_rarity = line["rarity"]
        if line["tokens"] != sorted(line["tokens"]):
            bad.append(f"tier.jsonl:{n}: tokens not sorted")
        for t in line["tokens"]:
            if t in owner:
                bad.append(f"tier.jsonl:{n}: token {t} is on line {owner[t]} too")
            owner.setdefault(t, n)
        names = [p[0] for p in line["parts"]]
        if names[:3] != ["env", "res", "meta"] or len(set(names)) != len(names):
            bad.append(f"tier.jsonl:{n}: parts are not env, res, meta, then fee and postfee changes")
        if len({p[3] for p in line["parts"]}) != len(line["parts"]):
            bad.append(f"tier.jsonl:{n}: two parts at one offset")
        parts += len(line["parts"])
        part_bytes += sum(p[4] for p in line["parts"])
    counts = header.get("counts", {})
    for what, got in [
        ("transactions", len(lines)),
        ("ledgers", len(ledgers)),
        ("tokens", len(owner)),
        ("parts", parts),
        ("part_bytes", part_bytes),
        ("object_bytes", sum(o[1] for o in objs.values())),
        ("per_protocol", dict(protocols)),
    ]:
        if counts.get(what) != got:
            bad.append(f"tier.json: counts.{what} is {counts.get(what)}, the lines give {got}")
    cj = os.path.join(os.path.dirname(os.path.abspath(tier)), "corpus.json")
    if os.path.exists(cj):
        t = json.load(open(cj)).get("tiers", {}).get("mainnet")
        if t is None:
            bad.append("corpus.json: no tiers.mainnet")
        else:
            for k in ("transactions", "ledgers", "tokens"):
                if t.get(k) != counts.get(k):
                    bad.append(f"corpus.json: tiers.mainnet.{k} is {t.get(k)}, tier.json says {counts.get(k)}")
    stmt = os.path.join(os.path.dirname(os.path.abspath(tier)), "..", "evidence", "results", "mainnet-coverage.json")
    if os.path.exists(cj) and os.path.exists(stmt):
        d = json.load(open(stmt))
        for what, got, want in [
            ("tokens", d.get("tokens"), counts.get("tokens")),
            ("mainnet_tier.tokens_held", d.get("mainnet_tier", {}).get("tokens_held"), len(owner)),
            ("mainnet_tier.transactions", d.get("mainnet_tier", {}).get("transactions"), len(lines)),
        ]:
            if got != want:
                bad.append(f"evidence/results/mainnet-coverage.json: {what} is {got}, the tier gives {want}")
    return bad, len(lines), len(owner)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tier", default=os.path.join(ROOT, "corpus", "mainnet"))
    a = ap.parse_args()
    bad, n, tokens = check(a.tier)
    print(f"mainnet tier: {n} lines, {tokens} distinct tokens, header and schema checked")
    for b in bad[:50]:
        print("FAIL", b)
    if len(bad) > 50:
        print(f"... {len(bad) - 50} more")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
