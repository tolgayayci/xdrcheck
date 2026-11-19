#!/usr/bin/env bash
# replay-etl: the whole curated corpus replayed against stellar-etl, every export stellar-etl has on every ledger,
# with the halt oracle on: one row per export per ledger saying how that export ended there (exit status,
# signal, runtime panic, timeout, peak memory). `scripts/replay-full.sh` runs it with XDRCHECK_REPLAY_ADAPTER=stellar-etl.
#
# Usage: scripts/replay-etl.sh [report dir]   (default reports/replay-etl)
#
# Commits: XDRCHECK_ETL_COMMITS (space-separated full commits), default pins.toml [pipelines.stellar_etl] commit. Each
# must already be built in the adapter's cache (a first run of the adapter without --offline builds it).
# Networks: pubnet and testnet (stellar-etl knows no other passphrase). Units run XDRCHECK_REPLAY_PARALLEL at a time
# (default 4).
#
# Writes <dir>/stellar-etl-<commit12>-<network>/{report.json,REPORT.md,logs/}, halt-oracle.ndjson beside it and
# <dir>/halt-oracle.md (exports × statuses). Fails when a run could not be made (xdrcheck replay exit 2, no report, a
# harness fault), when a ledger of a unit lacks a halt-oracle row for one of the exports, or when an export did not
# end ok on a ledger (a halt, crash or timeout of any export is a finding to triage, never noise).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out="${1:-reports/replay-etl}"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
parallel="${XDRCHECK_REPLAY_PARALLEL:-4}"
py() { python3 -I "$@"; }
pinned=$(py -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["stellar_etl"]["commit"])' "$root/pins.toml")
commits="${XDRCHECK_ETL_COMMITS:-$pinned}"

(cd go && go build -o bin/ ./cmd/xdrcheck ./adapters/stellaretl/cmd/stellaretl)
rm -rf "$out"
mkdir -p "$out"
export TMPDIR="$out/.tmp"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

status=0
for commit in $commits; do
  for network in pubnet testnet; do
    name="stellar-etl-${commit:0:12}-$network"
    dir="$out/$name"
    oracle="$out/$name.halt-oracle.ndjson"
    echo "replay-etl: stellar-etl ${commit:0:12} on $network, every export, $parallel units at a time"
    set +e
    go/bin/xdrcheck replay --corpus corpus --pins pins.toml --network "$network" --keep-going --parallel "$parallel" \
      --adapter "$root/go/bin/stellaretl --offline --halt-oracle $oracle" --target-version "$commit" \
      --report "$dir" >"$dir.rows.txt" 2>"$dir.log"
    rc=$?
    set -e
    echo "replay-etl: $name: xdrcheck replay exited $rc; $(tail -1 "$dir.log")"
    if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
      echo "replay-etl: xdrcheck replay could not make the run (exit $rc, log: $dir.log)" >&2
      status=1
    fi
  done
done

py - "$out" <<'PY' || status=1
import collections, glob, json, os, sys
out = sys.argv[1]
EXPORTS = ["export_ledgers", "export_transactions", "export_operations", "export_effects", "export_token_transfer",
           "export_contract_events", "export_trades", "export_ledger_entry_changes", "export_assets",
           "export_ledger_transaction"]
ok = True
lines = ["# stellar-etl halt oracle", "", "| run | export | " + " | ".join(["ok", "halted", "crashed", "timeout", "not_reached", "not_run"]) + " |",
         "|---|---|---|---|---|---|---|---|"]
problems = []
for rep in sorted(glob.glob(os.path.join(out, "stellar-etl-*/report.json"))):
    run = os.path.basename(os.path.dirname(rep))
    rows = json.load(open(rep))["rows"]
    faults = [r for r in rows if r["replay"]["class"] == "harness_fault"]
    for r in faults:
        problems.append(f"{run}: {r['entry']}: harness_fault {(r.get('evidence') or {}).get('fault', '')[:160]}")
    oracle = os.path.join(out, run + ".halt-oracle.ndjson")
    ho = [json.loads(l) for l in open(oracle)] if os.path.exists(oracle) else []
    per = collections.defaultdict(set)
    count = collections.Counter()
    for h in ho:
        per[(h["session"], h["range_start"], h["range_end"], h["ledger"])].add(h["export"])
        count[(h["export"], h["status"])] += 1
        if h["status"] not in ("ok",):
            problems.append(f"{run}: ledger {h['ledger']} ({h['session']}, {h['range_start']}..{h['range_end']}): "
                            f"{h['export']} {h['status']} exit={h.get('exit_code')} signal={h.get('signal', '')} "
                            f"panic={h.get('runtime_panic', False)} {h.get('stderr_tail', '')[-200:]!r}")
    for k, have in per.items():
        missing = [e for e in EXPORTS if e not in have]
        if missing:
            problems.append(f"{run}: ledger {k[3]} ({k[0]}): no halt-oracle row for {', '.join(missing)}")
    for e in EXPORTS:
        lines.append(f"| {run} | {e} | " + " | ".join(str(count[(e, s)]) for s in ["ok", "halted", "crashed", "timeout", "not_reached", "not_run"]) + " |")
    print(f"  {run}: {len(rows)} rows, {len(ho)} halt-oracle rows over {len(per)} (session, ledger) pairs, {len(faults)} harness faults")
    if not ho:
        problems.append(f"{run}: no halt-oracle rows")
with open(os.path.join(out, "halt-oracle.md"), "w") as f:
    f.write("\n".join(lines) + "\n")
    if problems:
        f.write("\n## Not ok\n\n" + "\n".join("- " + p for p in problems) + "\n")
for p in problems[:200]:
    print("  " + p + "  NOT OK")
sys.exit(1 if problems else 0)
PY
if [ $status -eq 0 ]; then
  echo "replay-etl: every export ended ok on every ledger of every run ($out/halt-oracle.md)"
else
  echo "replay-etl: FAILED ($out/halt-oracle.md)" >&2
fi
exit $status
