#!/usr/bin/env python3
"""Refresh apps/docs/data/cap-prevalence.json: mainnet prevalence of the union arms that only one or two corpus
entries hold.

This is the one step of the CAP pages that needs data outside the repository: a locate index built by
`xdrcheck-corpus scan locate-build` over a scan of pubnet history. Everything else on the CAP pages comes from the
committed corpus (`generate.py` reads `corpus/index.json` and `corpus/coverage.json` directly).

How an entry is joined to the scan, and why only this narrowly:

1. `xdrcheck-corpus coverage --arms --report FILE` walks every committed input in a fixed order (every manifest
   entry's variants first, then chain streams, then vendored lake objects) and lists, for each union arm reachable
   from `LedgerCloseMetaBatch`, how many inputs hold it (`curated`) and the first three that do (`by`).
2. Because entries are walked first, `by` names every entry that holds the arm whenever it has fewer than three
   labels or one of its labels is not an entry (a chain stream or a lake object). Only those arms are kept, so
   the arm-to-entry link is complete; an arm that three or more entries hold is common in the corpus and says
   nothing about one entry. Labels that are not entries are dropped from the list.
3. The arm `Type::ARM` is the scan's type-level token `T|arm|Type::ARM` (token grammar `xcc.shape/v1`), so the
   join is by exact name. `xdrcheck-corpus scan locate --summary` gives its occurrences, ledgers and first and last
   ledger; `scan locate --limit N` gives the first N (ledger, transaction) postings in ledger order (the
   transaction is `null` for a posting on the ledger itself, such as its header).

An arm the index does not know is recorded with `"seen": false` (the scan's token census holds no occurrence of it
in the scanned range) only when the index knows another arm of the same union, so the join itself is shown to work
for that union; otherwise the arm is left out. A failed lookup stops the run. Nothing else is inferred.

    python3 apps/docs/scripts/cap_prevalence.py --xdrcheck-corpus target/release/xdrcheck-corpus --index DIR

Light: one coverage walk of the corpus (well under a minute) and two index lookups per kept arm.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
OUT = os.path.join(ROOT, "apps", "docs", "data", "cap-prevalence.json")
BY_CAP = 3  # the `by` list of `coverage --arms` stops at three inputs
EXAMPLES = 3


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"cap_prevalence: {' '.join(cmd[:4])} … failed: {p.stderr.strip()[:400]}")
    return p.stdout


def tsv_rows(text: str) -> list[dict[str, str]]:
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    if not lines:
        return []
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:]]


def scan_range(index: str) -> tuple[int, int, str]:
    with open(os.path.join(index, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    first = int(re.search(r"~(\d+)-", meta["first_unit"]).group(1))
    last = int(re.search(r"-(\d+)$", meta["last_unit"]).group(1))
    return first, last, meta.get("format", "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--xdrcheck-corpus", required=True, help="an xdrcheck-corpus binary built from this tree")
    ap.add_argument("--index", required=True, help="a locate index directory (xdrcheck-corpus scan locate-build --out)")
    ap.add_argument("--corpus", default=os.path.join(ROOT, "corpus"))
    ap.add_argument("--network", default="pubnet", help="the network the index was built over")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    with open(os.path.join(args.corpus, "index.json"), encoding="utf-8") as f:
        entry_ids = {e["id"] for e in json.load(f)["entries"]}

    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "arms.json")
        run([args.xdrcheck_corpus, "coverage", "--arms", "--corpus", args.corpus, "--report", report,
             "--baseline", os.devnull])
        with open(report, encoding="utf-8") as f:
            arms = json.load(f)

    first, last, fmt = scan_range(args.index)
    known = set()
    with open(os.path.join(args.index, "tokens.tsv"), encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4 and parts[1] == "T" and parts[2] == "arm":
                known.add(parts[3])
    unions = {t.split("|", 2)[2].split("::", 1)[0] for t in known}
    rows, dropped = [], []
    for r in arms["rows"]:
        if r["kind"] != "arm" or not r["covered"]:
            continue
        holders = sorted(b for b in r["by"] if b in entry_ids)
        complete = len(r["by"]) < BY_CAP or any(b not in entry_ids for b in r["by"])
        if not holders or not complete:
            continue
        token = f"T|arm|{r['id']}"
        row = {"arm": r["id"], "class": r["class"], "corpus_inputs": r["curated"], "entries": holders}
        if token not in known:
            if r["id"].split("::", 1)[0] not in unions:
                dropped.append(r["id"])
                continue
            row["seen"] = False
        else:
            loc = [args.xdrcheck_corpus, "scan", "locate", "--corpus", args.corpus, "--index", args.index, "--token", token]
            summary = tsv_rows(run(loc + ["--summary"]))
            if not summary:
                sys.exit(f"cap_prevalence: no summary for {token}")
            s = summary[0]
            ex = tsv_rows(run(loc + ["--limit", str(EXAMPLES)]))
            row.update({
                "seen": True,
                "occurrences": int(s["occurrences"]),
                "ledgers": int(s["ledgers"]),
                "first_ledger": int(s["first_ledger"]),
                "last_ledger": int(s["last_ledger"]),
                "examples": [[int(e["seq"]), int(e["tx"]) if e["tx"].isdigit() else None] for e in ex[:EXAMPLES]],
            })
        rows.append(row)
    rows.sort(key=lambda x: x["arm"])

    out = {
        "schema": "xdrcheck.docs.cap-prevalence/v1",
        "about": "Mainnet prevalence of union arms that at most three committed corpus inputs hold; "
                 "written by apps/docs/scripts/cap_prevalence.py, read by apps/docs/scripts/generate.py.",
        "network": args.network,
        "scan_first_ledger": first,
        "scan_last_ledger": last,
        "index_format": fmt,
        "token_grammar": "xcc.shape/v1",
        "join": "T|arm|<Type::ARM> by exact name; arms whose holding entries the coverage walk lists completely",
        "arms": rows,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=False)
        f.write("\n")
    seen = sum(1 for r in rows if r["seen"])
    if dropped:
        print(f"cap_prevalence: left out (no arm of the union in the index): {', '.join(dropped)}")
    print(f"cap_prevalence: {len(rows)} arms ({seen} seen on {args.network}) -> {os.path.relpath(args.out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
