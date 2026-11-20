#!/usr/bin/env bash
# Nightly canary (docs/maintenance.md, section 5.3): how far the pins are behind what upstream has published, and
# what the newest SDK releases do on the curated corpus before anyone pins them. It reports drift and never
# fails because of it: a pin behind upstream, or a cell whose verdict moved, is a DRIFT line in the summary, and
# the job fails only when it could not look or could not run.
#
#   latest   `xdrcheck pins latest --json`: every pins.toml pin with a `# renovate:` annotation against the newest
#            stable published version (npm, PyPI, the Go module proxy, crates.io, git tags)
#   plan     scripts/nightly/canary.py plan: per SDK family (js, go, python, rust), whether the newest version is
#            already a pinned column or needs a canary column
#   columns  `xdrcheck conform fetch` and `build` of the pinned columns the canaries are compared with; canary.py
#            materialise into a throw-away directory outside the working tree (lock files resolved by each
#            family's package manager: network), then `make fetch build` in each canary column directory
#   run      `xdrcheck conform run --overlay <dir> --set canary` and the same entries through the pinned columns the
#            canaries were made from; canary.py rename; `xdrcheck conform diff <pinned> <canary>`
#
# Usage: scripts/nightly/canary.sh <out dir>
#   XDRCHECK_CANARY_PLAN=1     stop after plan: no package manager runs, no driver is built (needs the latest
#                         step's network, or XDRCHECK_CANARY_LATEST)
#   XDRCHECK_CANARY_LATEST=F   use F (an earlier `xdrcheck pins latest --json` output) instead of looking up; with
#                         XDRCHECK_CANARY_PLAN=1 the job needs no network at all
# The canary columns, their caches and reports live under ${XDRCHECK_CACHE:-~/.cache/xdrcheck}/canary (a conformance run
# with columns from outside the repository writes its report outside the working tree); the summary and the
# diff are copied to <out dir>/canary/. Exit 0 unless a part could not run.
source "$(dirname "$0")/lib.sh"
nightly_init canary "${1:?usage: canary.sh <out dir>}"
need_tool "$XDRCHECK_BIN"

report="$OUT/canary"
work="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/canary"
mkdir -p "$report" "$work"
# The networked steps drop the offline switches a CI job sets after its own fetch.
net() { env -u GOPROXY -u CARGO_NET_OFFLINE -u PIP_NO_INDEX "$@"; }

t0=$(date +%s)
if [ -n "${XDRCHECK_CANARY_LATEST:-}" ]; then
  cp "$XDRCHECK_CANARY_LATEST" "$report/latest.json"
  rc=0
  python3 -I -c 'import json, sys
rows = json.load(open(sys.argv[1]))
sys.exit(2 if any(r.get("error") for r in rows) else 1 if any(r.get("behind") for r in rows) else 0)' "$report/latest.json" || rc=$?
  echo "latest: read from $XDRCHECK_CANARY_LATEST" >"$report/latest.txt"
else
  set +e
  net "$XDRCHECK_BIN" pins latest --json "$report/latest.json" >"$report/latest.txt" 2>&1
  rc=$?
  set -e
fi
behind=$(python3 -I -c 'import json, sys
print(", ".join(r["key"] + " " + r["current"] + " -> " + r["latest"] for r in json.load(open(sys.argv[1])) if r.get("behind")))' "$report/latest.json" 2>/dev/null || true)
case $rc in
  0) result latest PASS $(($(date +%s) - t0)) "every tracked pin is the newest published version" ;;
  1) result latest DRIFT $(($(date +%s) - t0)) "behind: $behind" ;;
  *) result latest FAIL $(($(date +%s) - t0)) "a lookup failed (exit $rc); see $report/latest.txt"
     nightly_finish ;;
esac

python3 -I scripts/nightly/canary.py plan --root "$ROOT" --latest "$report/latest.json" --json "$work/plan.json" \
  | tee "$report/plan.txt"
cp "$work/plan.json" "$report/plan.json"
families=$(python3 -I -c 'import json, sys
print(" ".join(f["family"] for f in json.load(open(sys.argv[1]))["families"] if f["status"] == "canary"))' "$work/plan.json")
if [ -z "$families" ]; then
  result plan PASS 0 "the newest release of every SDK family is a pinned column; no canary to run"
  nightly_finish
fi
result plan PASS 0 "canary columns for: $families"
if [ -n "${XDRCHECK_CANARY_PLAN:-}" ]; then
  result columns SKIPPED 0 "XDRCHECK_CANARY_PLAN is set: plan only"
  nightly_finish
fi

t0=$(date +%s)
overlay="$work/overlay"
templates=$(python3 -I -c 'import json, sys
print(",".join(c["template"] for f in json.load(open(sys.argv[1]))["families"] if f["status"] == "canary" for c in f["columns"]))' "$work/plan.json")
rm -rf "$overlay"
set +e
# The pinned columns the canaries are compared with, then the canary columns themselves.
{ net "$XDRCHECK_BIN" conform fetch --columns "$templates" && "$XDRCHECK_BIN" conform build --columns "$templates"; } >"$report/columns.log" 2>&1
rc=$?
[ $rc != 0 ] || net python3 -I scripts/nightly/canary.py materialise --root "$ROOT" --plan "$work/plan.json" \
  --overlay "$overlay" --cache "$work/cache" >>"$report/columns.log" 2>&1 || rc=$?
if [ $rc = 0 ]; then
  for dir in "$overlay"/drivers/*/*/; do
    [ -f "$dir/Makefile" ] || continue
    name=$(basename "$(dirname "$dir")")-$(basename "$dir")
    net make -C "$dir" fetch build XDRCHECK_ROOT="$ROOT" XDRCHECK_CACHE_DIR="$work/cache/driver-$name" >>"$report/columns.log" 2>&1 || { rc=$?; break; }
  done
fi
set -e
if [ $rc != 0 ]; then
  result columns FAIL $(($(date +%s) - t0)) "a canary column did not build (exit $rc); see $report/columns.log"
  nightly_finish
fi
result columns PASS $(($(date +%s) - t0)) "built $(grep -c '^\[columns' "$overlay/drivers/sets.toml") canary column(s)"

t0=$(date +%s)
rm -rf "$work/report-canary" "$work/report-pinned"
set +e
offline "$XDRCHECK_BIN" conform run --overlay "$overlay" --set canary --report "$work/report-canary" >"$report/run-canary.txt" 2>&1
rc_c=$?
offline "$XDRCHECK_BIN" conform run --columns "$templates" --report "$work/report-pinned" >"$report/run-pinned.txt" 2>&1
rc_p=$?
set -e
if [ ! -f "$work/report-canary/matrix.json" ] || [ ! -f "$work/report-pinned/matrix.json" ]; then
  result run FAIL $(($(date +%s) - t0)) "a conformance run did not complete (canary exit $rc_c, pinned exit $rc_p); see $report/run-*.txt"
  nightly_finish
fi
python3 -I scripts/nightly/canary.py rename --plan "$work/plan.json" --matrix "$work/report-canary/matrix.json" \
  --out "$work/canary-as-pinned.json" >/dev/null
set +e
"$XDRCHECK_BIN" conform diff "$work/report-pinned/matrix.json" "$work/canary-as-pinned.json" >"$report/diff.txt" 2>&1
rc=$?
set -e
case $rc in
  0) result run PASS $(($(date +%s) - t0)) "the newest releases give the same verdict as the pinned columns on every cell" ;;
  1) result run DRIFT $(($(date +%s) - t0)) "$(grep -cv '^xdrcheck conform diff' "$report/diff.txt") cell(s) moved between the pinned and the newest releases; see $report/diff.txt" ;;
  *) result run FAIL $(($(date +%s) - t0)) "xdrcheck conform diff could not run (exit $rc); see $report/diff.txt" ;;
esac
nightly_finish
