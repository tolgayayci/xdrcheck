#!/usr/bin/env bash
# replay-full: the whole curated corpus replayed against wallet-backend at its pinned current commit (pins.toml
# [pipelines.wallet_backend] current), once per input (XDRCHECK_REPLAY_INPUTS, default "sep54-s3 rpc"). It is a run
# of the findings check's required set (findings/required-runs.d/): the rows the pipeline findings rest on.
#
# Usage: scripts/replay-full.sh [report dir]   (`make replay-full` passes $(REPORTS)/replay-full)
#
# Writes <dir>/wallet-backend-<input>/{report.json,REPORT.md,describe.json,logs/} and <dir>/wallet-backend-<input>.log.
#
# The rows are judged elsewhere: an unexpected row needs a finding or a pending entry, which `make
# verify-findings` checks (xdrcheck replay's exit 1 is therefore not a failure here). This script fails when a run
# could not be made or is not whole:
#   - xdrcheck replay exits 2 (bad arguments, the adapter broke, a harness fault) or writes no report;
#   - a row is a harness_fault, or is not of the pinned commit, or not of the input asked for;
#   - an entry the corpus has, with a variant on a network the run covers, has no row;
#   - a container with the run's label or a temporary directory of the adapter is left behind.
#
# Needs what `make verify-replay` needs: go/bin/xdrcheck, docker with the pinned TimescaleDB and SeaweedFS images, and
# the adapter's cache. `wallet-backend-adapter fetch` completes the cache when the network is available and changes
# nothing when it is complete, so the run is offline once dependencies are fetched (`make replay-full OFFLINE=1`).
# Units run XDRCHECK_REPLAY_PARALLEL at a time (default 4, the adapter's declared maximum), each with its own adapter
# process and database container.
# XDRCHECK_REPLAY_ADAPTER=stellar-etl runs scripts/replay-etl.sh instead: the corpus against stellar-etl, every export
# on every ledger, with one halt-oracle row per export per ledger.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${XDRCHECK_REPLAY_ADAPTER:-wallet-backend}" = stellar-etl ]; then
  exec scripts/replay-etl.sh "${1:-reports/replay-etl}"
fi
root=$PWD
out="${1:-reports/replay-full}"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
inputs="${XDRCHECK_REPLAY_INPUTS:-sep54-s3 rpc}"
parallel="${XDRCHECK_REPLAY_PARALLEL:-4}"
# The adapter names and labels its containers with this prefix (label xdrcheck.owner). It carries this run's PID, so
# the leak check below sees only this run's containers, never those of a run another session has going.
prefix="${XDRCHECK_WB_NAME_PREFIX:-xdrcheck-rf}-run$$"
export XDRCHECK_WB_NAME_PREFIX="$prefix"
export XDRCHECK_OBJSTORE="${XDRCHECK_OBJSTORE:-binary}"
py() { python3 -I "$@"; }

xdrcheck="$root/go/bin/xdrcheck"
adapter="$root/go/bin/wallet-backend-adapter"
# Rebuild so a stale binary never judges the run.
(cd go && go build -o bin/xdrcheck ./cmd/xdrcheck) || { echo "replay-full: cannot build $xdrcheck" >&2; exit 1; }
(cd go && go build -o bin/ ./adapters/walletbackend/cmd/wallet-backend-adapter)

commit=$(py -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["wallet_backend"]["current"])' "$root/pins.toml")

rm -rf "$out"
mkdir -p "$out"
export TMPDIR="$out/.tmp"
mkdir -p "$TMPDIR"
leftovers() {
  docker ps -a --filter "label=xdrcheck.owner=$prefix" --format '{{.Names}}' 2>/dev/null || true
}
# The adapter removes its containers when each replay ends, but docker finishes a removal asynchronously, so a
# container can still be listed for a few seconds after its run. settled_leftovers waits (bounded:
# XDRCHECK_LEAK_WAIT seconds, default 30) for the label's containers to go; whatever is still there afterwards was
# not removed and is a leak.
settled_leftovers() {
  local left deadline=$((SECONDS + ${XDRCHECK_LEAK_WAIT:-30}))
  left=$(leftovers)
  while [ -n "$left" ] && [ $SECONDS -lt $deadline ]; do
    sleep 1
    left=$(leftovers)
  done
  printf '%s' "$left"
}
cleanup() {
  local left
  left=$(leftovers)
  [ -z "$left" ] || docker rm -f -v $left >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

"$adapter" fetch --pins "$root/pins.toml"

status=0
for input in $inputs; do
  dir="$out/wallet-backend-$input"
  echo "replay-full: wallet-backend ${commit:0:12} on $input, whole corpus, $parallel units at a time"
  start=$(date +%s)
  set +e
  "$xdrcheck" replay --corpus "$root/corpus" --pins "$root/pins.toml" \
    --adapter "$adapter --pins $root/pins.toml" --target-version "$commit" \
    --input "$input" --parallel "$parallel" --report "$dir" >"$dir.rows.txt" 2>"$dir.log"
  rc=$?
  set -e
  echo "replay-full: $input: xdrcheck replay exited $rc after $(( $(date +%s) - start )) s; $(tail -1 "$dir.log")"
  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
    echo "replay-full: xdrcheck replay could not make the run on $input (exit $rc, log: $dir.log)" >&2
    tail -5 "$dir.log" >&2
    status=1
  fi
  if [ ! -f "$dir/report.json" ]; then
    echo "replay-full: no report for $input" >&2
    status=1
    continue
  fi
  if ! py - "$root/corpus" "$dir/report.json" "$commit" "$input" <<'PY'
import collections, json, os, sys
corpus, report, commit, input_kind = sys.argv[1:]
with open(report) as f:
    rows = json.load(f)["rows"]
ok = True
def bad(msg):
    global ok
    print("  " + msg + "  NOT OK")
    ok = False
seen = set()
for r in rows:
    rep = r["replay"]
    if rep["class"] == "harness_fault":
        bad(f"{r['row_id']}: harness_fault ({(r.get('evidence') or {}).get('fault', '')[:120]})")
    if r["target"]["version"] != commit:
        bad(f"{r['row_id']}: target version {r['target']['version']}, want {commit}")
    if rep.get("input") not in (None, input_kind):
        bad(f"{r['row_id']}: input {rep.get('input')}, want {input_kind}")
    seen.add(r["entry"])
# Every entry the harness plans has a row: a `ledger` entry whose replay.indexer_scope is not `sdk-only`
# (docs/replay-harness.md), with a variant on a network.
want = set()
for dirpath, _, files in os.walk(os.path.join(corpus, "manifest")):
    for name in files:
        if name.endswith(".json"):
            with open(os.path.join(dirpath, name)) as f:
                e = json.load(f)
            if e.get("kind") != "ledger" or (e.get("replay") or {}).get("indexer_scope") == "sdk-only":
                continue
            if any(v.get("network") != "none" for v in e.get("variants") or []):
                want.add(e["id"])
for e in sorted(want - seen):
    bad(f"{e}: no row")
by = collections.Counter(r["replay"]["class"] + ("·" + r["replay"]["qualifier"] if r["replay"].get("qualifier") else "") for r in rows)
unexpected = sum(1 for r in rows if r["expectation"] != "expected")
print(f"  {len(rows)} rows over {len(seen)} entries ({', '.join(f'{k} {v}' for k, v in sorted(by.items()))}); "
      f"{unexpected} unexpected, judged by make verify-findings")
sys.exit(0 if ok else 1)
PY
  then
    status=1
  fi
done

left=$(settled_leftovers)
if [ -n "$left" ]; then
  echo "replay-full: containers left behind (still present after ${XDRCHECK_LEAK_WAIT:-30}s): $left" >&2
  status=1
fi
# This run's socket directories (<prefix>-<adapter pid>-<n>: the adapter names them with the run's prefix) and
# source trees of builds. Every adapter process of the run has exited by now, so any socket directory of its own
# prefix is left behind; directories of other runs, which may share the cache from another PID namespace, are
# not looked at.
base="${XDG_CACHE_HOME:-$HOME/.cache}"
# The directory of the kit's earlier name is used while the new one does not exist (as the adapter does).
if [ -d "$base/xdrcheck" ] || [ ! -d "$base/xcc" ]; then base="$base/xdrcheck"; else base="$base/xcc"; fi
cache="$base/adapters/wallet-backend"
for d in "$cache"/run/"$prefix"-* "$cache"/work/src-*; do
  [ -e "$d" ] || continue
  name=$(basename "$d")
  if [[ "$name" == src-* || "${name#"$prefix"-}" =~ ^[0-9]+-[0-9]+$ ]]; then
    echo "replay-full: left behind: $d" >&2
    status=1
  fi
done
if [ $status -eq 0 ]; then
  echo "replay-full: wallet-backend ${commit:0:12} replayed over the whole corpus on every input; nothing left behind"
else
  echo "replay-full: FAILED" >&2
fi
exit $status
