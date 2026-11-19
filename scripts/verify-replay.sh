#!/usr/bin/env bash
# replay-regression: the reference adapter reproduces wallet-backend#729, #731 and #716 at their pre-fix commits and
# passes at the fixed commits and at the current commit.
#
# Usage: scripts/verify-replay.sh [report dir]   (`make verify-replay` passes reports/replay-regression)
#
# For every acceptance pair in pins.toml ([pipelines.wallet_backend] acceptance) and for the current commit, it
# runs `xdrcheck replay --assert-known` with the wallet-backend adapter on the corpus entries that carry an executed
# known divergence (`observed: executed`) referencing that bug — found in the manifest, not listed here — once
# per input (XDRCHECK_REPLAY_INPUTS, default "sep54-s3 rpc").
#
# The exit code of xdrcheck replay is not enough on its own (a variant the harness did not run is reported
# not_applicable and still counts as expected), so the script reads each report.json and asserts row by row:
#   - every variant of each such entry at a protocol the commit's pinned SDK decodes (pins.toml: the
#     pre-v0.8.0 limit for the acceptance commits, protocol.max_supported for the current one) has a scored row;
#     a missing or not_applicable row fails;
#   - at a pre-fix commit the row is exactly the class·qualifier the executed divergence declares, and the row
#     names that divergence as in range;
#   - at a fixed commit and at the current commit the row is `pass`;
#   - no row of the run is unexpected.
# Finally nothing may be left behind: no container with the run's label, no temporary directory.
#
# Needs: go/bin/xdrcheck, docker with the pinned TimescaleDB and SeaweedFS images, and the adapter's cache (clone,
# per-commit binaries, Go toolchain and modules). The first step, `wallet-backend-adapter fetch`, completes that
# cache when the network is available and changes nothing when the cache is complete, so the check runs offline
# once dependencies are fetched (`make verify-replay OFFLINE=1`).
#
# The database runs in a container with no network that the adapter reaches through a Unix socket in a
# bind-mounted directory, and the object store as the pinned image's own `weed` executable (XDRCHECK_OBJSTORE=binary,
# the same digest), so both are reachable from inside the offline wrapper's private network namespace.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out="${1:-reports/replay-regression}"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
inputs="${XDRCHECK_REPLAY_INPUTS:-sep54-s3 rpc}"
# The adapter names and labels its containers with this prefix (label xdrcheck.owner). It carries this run's PID, so
# the leak check below sees only this run's containers, never those of a run another session has going.
prefix="${XDRCHECK_WB_NAME_PREFIX:-xdrcheck-vr}-run$$"
export XDRCHECK_WB_NAME_PREFIX="$prefix"
export XDRCHECK_OBJSTORE="${XDRCHECK_OBJSTORE:-binary}"
py() { python3 -I "$@"; }

xdrcheck="$root/go/bin/xdrcheck"
adapter="$root/go/bin/wallet-backend-adapter"
# Rebuild so a stale binary never judges the run.
(cd go && go build -o bin/xdrcheck ./cmd/xdrcheck) || { echo "verify-replay: cannot build $xdrcheck" >&2; exit 1; }
(cd go && go build -o bin/ ./adapters/walletbackend/cmd/wallet-backend-adapter)

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

# The plan: one JSON object per run, with the rows that run must produce.
py - "$root" >"$out/plan.ndjson" <<'PY'
import json, os, re, sys, tomllib
root = sys.argv[1]
with open(os.path.join(root, "pins.toml"), "rb") as f:
    pins = tomllib.load(f)
wb = pins["pipelines"]["wallet_backend"]

def declared(d):
    if d["outcome"] in ("halt", "crash", "hang", "wrong_value"):
        return "mishandled·" + (d.get("qualifier") or d["outcome"])
    if d["outcome"] == "dropped" and d.get("qualifier"):
        return "dropped·" + d["qualifier"]
    sys.exit(f"verify-replay: divergence {d['reference']} declares no exact class·qualifier")

def variant_key(e, v):
    if any(o["protocol"] != v["protocol"] for o in e["variants"]):
        return f"{v['network']}@{v['protocol']}"
    return v["network"]

by_bug = {}
for dirpath, _, files in os.walk(os.path.join(root, "corpus", "manifest")):
    for name in sorted(files):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(dirpath, name)) as f:
            e = json.load(f)
        for d in (e.get("conformance") or {}).get("known_divergences") or []:
            if d.get("target") != "stellar/wallet-backend" or d.get("level") != "replay" or d.get("observed") != "executed":
                continue
            m = re.search(r"wallet-backend/(?:pull|issues)/(\d+)$", d.get("reference", ""))
            if m:
                by_bug.setdefault(m.group(1), []).append((e, d))

def required(pairs, max_protocol, want):
    rows = []
    for e, d in pairs:
        for v in e["variants"]:
            if v["network"] != "none" and v["protocol"] <= max_protocol:
                rows.append({"entry": e["id"], "variant": variant_key(e, v), "ledger": v["ledger_seq"],
                             "result": want(d), "reference": d["reference"] if want(d) != "pass" else None})
    return rows

old = wb["max_decodable_protocol_before_a9bac8d2"]
current_rows, seen = [], set()
for a in wb["acceptance"]:
    pairs = by_bug.get(a["bug"])
    if not pairs:
        sys.exit(f"verify-replay: no corpus entry carries an executed replay divergence for wallet-backend#{a['bug']}")
    for role, commit, want in (("prefix", a["prefix"], declared), ("fixed", a["fixed"], lambda d: "pass")):
        rows = required(pairs, old, want)
        if not rows:
            sys.exit(f"verify-replay: wallet-backend#{a['bug']} has no variant at Protocol {old} or below")
        print(json.dumps({"bug": a["bug"], "role": role, "commit": commit, "rows": rows}))
    for r in required(pairs, pins["protocol"]["max_supported"], lambda d: "pass"):
        if (r["entry"], r["variant"]) not in seen:
            seen.add((r["entry"], r["variant"]))
            current_rows.append(r)
print(json.dumps({"bug": "all", "role": "current", "commit": wb["current"], "rows": current_rows}))
PY

status=0
while read -r run; do
  bug=$(py -c 'import json,sys; print(json.loads(sys.argv[1])["bug"])' "$run")
  role=$(py -c 'import json,sys; print(json.loads(sys.argv[1])["role"])' "$run")
  commit=$(py -c 'import json,sys; print(json.loads(sys.argv[1])["commit"])' "$run")
  entries=$(py -c 'import json,sys; print(",".join(sorted({r["entry"] for r in json.loads(sys.argv[1])["rows"]})))' "$run")
  for input in $inputs; do
    dir="$out/${commit:0:12}-$bug-$input"
    echo "verify-replay: wallet-backend ${commit:0:12} ($role, #$bug) on $input: $entries"
    set +e
    "$xdrcheck" replay --corpus "$root/corpus" --pins "$root/pins.toml" \
      --adapter "$adapter --pins $root/pins.toml" --target-version "$commit" \
      --entries "$entries" --input "$input" --assert-known --report "$dir" >"$dir.rows.txt" 2>"$dir.log"
    rc=$?
    set -e
    if [ $rc -ne 0 ]; then
      echo "verify-replay: xdrcheck replay exited $rc for ${commit:0:12} on $input (log: $dir.log)" >&2
      tail -5 "$dir.log" >&2
      status=1
    fi
    if [ ! -f "$dir/report.json" ]; then
      echo "verify-replay: no report for ${commit:0:12} on $input" >&2
      status=1
      continue
    fi
    if ! py - "$dir/report.json" "$run" "$input" <<'PY'
import json, sys
report, run, input_kind = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
with open(report) as f:
    rows = json.load(f)["rows"]
ok = True
for req in run["rows"]:
    got = [r for r in rows if r.get("entry") == req["entry"] and r.get("variant") == req["variant"]]
    if len(got) != 1:
        print(f"  {req['entry']} {req['variant']}: {len(got)} rows, want exactly 1  NOT OK")
        ok = False
        continue
    r = got[0]
    rep = r["replay"]
    res = rep["class"] + ("·" + rep["qualifier"] if rep.get("qualifier") else "")
    good = (res == req["result"] and r["expectation"] == "expected" and rep.get("input") == input_kind
            and (rep.get("range") or {}).get("start", -1) <= req["ledger"] <= (rep.get("range") or {}).get("end", -1))
    kd = r.get("known_divergence") or {}
    if req["reference"]:
        good = good and kd.get("in_range") is True and kd.get("reference") == req["reference"]
    elif kd.get("in_range"):
        good = False
    print(f"  {req['entry']} {req['variant']} ledger {req['ledger']} {input_kind}: {res} (required {req['result']})  {'ok' if good else 'NOT OK'}")
    ok = ok and good
for r in rows:
    if r["expectation"] != "expected":
        print(f"  unexpected row {r['row_id']}: {r['replay']['class']} {r['replay'].get('qualifier', '')}  NOT OK")
        ok = False
sys.exit(0 if ok else 1)
PY
    then
      status=1
    fi
  done
done <"$out/plan.ndjson"

left=$(settled_leftovers)
if [ -n "$left" ]; then
  echo "verify-replay: containers left behind (still present after ${XDRCHECK_LEAK_WAIT:-30}s): $left" >&2
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
    echo "verify-replay: left behind: $d" >&2
    status=1
  fi
done
# The run's own temporary directory is removed on exit. What is still in it here was written by tools that do
# not clean up after themselves (SeaweedFS's log files, the offline wrapper's empty resolv.conf); it is listed.
if [ -d "$TMPDIR" ] && [ -n "$(ls -A "$TMPDIR")" ]; then
  echo "verify-replay: note: removing temporary files written during the run: $(ls -A "$TMPDIR" | tr '\n' ' ')"
fi
if [ $status -eq 0 ]; then
  echo "verify-replay: every acceptance commit and the current commit gave its required result on every input; nothing left behind"
else
  echo "verify-replay: FAILED" >&2
fi
exit $status
