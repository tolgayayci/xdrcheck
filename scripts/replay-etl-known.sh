#!/usr/bin/env bash
# replay-etl-known: the corpus entries that declare a stellar-etl replay divergence, replayed against stellar-etl at
# its pinned commit (pins.toml [pipelines.stellar_etl] commit) with --assert-known. It is a run of the findings
# check's required set (findings/required-runs.d/): the stellar-etl rows the public pipeline findings rest on, so a
# record whose evidence is a stellar-etl replay row is checked against a report like any other.
#
# Usage: scripts/replay-etl-known.sh [report dir]   (`make replay-etl-known` passes $(REPORTS)/replay-etl-known)
#
# Writes <dir>/stellar-etl-<commit>/{report.json,REPORT.md,describe.json,logs/}. Only entries with a declared
# stellar-etl divergence run (--assert-known); the whole-corpus run with the halt oracle is scripts/replay-etl.sh.
# Offline once the adapter's cache holds the pinned stellar-etl binary (a first networked run builds it, or
# `make fetch`). Fails when the run could not be made (exit 2, no report), when a row is not of the pinned commit,
# or when an asserted entry did not show its declared result (exit 1 under --assert-known).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out="${1:-reports/replay-etl-known}"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
py() { python3 -I "$@"; }

commit=$(py -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["stellar_etl"]["commit"])' "$root/pins.toml")
dir="$out/stellar-etl-$commit"

# Rebuild so a stale binary never judges the run.
(cd go && go build -o bin/ ./cmd/xdrcheck ./adapters/stellaretl/cmd/stellaretl) || { echo "replay-etl-known: cannot build the tools" >&2; exit 1; }

rm -rf "$dir"
mkdir -p "$dir"
export TMPDIR="$out/.tmp"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

echo "replay-etl-known: stellar-etl ${commit:0:12}, entries with a declared stellar-etl divergence"
rc=0
"$root/go/bin/xdrcheck" replay --corpus corpus --adapter "$root/go/bin/stellaretl" --target-version "$commit" \
  --assert-known --report "$dir" >"$dir.log" 2>&1 || rc=$?
grep -v '^unit ' "$dir.log" | tail -n 20 || true
if [ "$rc" -eq 2 ] || [ ! -s "$dir/report.json" ]; then
  echo "replay-etl-known: the run could not be made (exit $rc); see $dir.log" >&2
  exit 1
fi
py - "$dir/report.json" "$commit" <<'EOF'
import json, sys
rep, commit = json.load(open(sys.argv[1])), sys.argv[2]
rows = rep.get("rows", [])
bad = [r["row_id"] for r in rows if r.get("target", {}).get("version") != commit]
if not rows:
    sys.exit("replay-etl-known: the report has no rows (no entry declares a stellar-etl divergence at this commit?)")
if bad:
    sys.exit("replay-etl-known: rows not of the pinned commit: " + ", ".join(bad))
print(f"replay-etl-known: {len(rows)} rows at {commit[:12]}")
EOF
if [ "$rc" -ne 0 ]; then
  echo "replay-etl-known: an asserted entry did not show its declared result (exit $rc); see $dir/REPORT.md" >&2
  exit 1
fi
