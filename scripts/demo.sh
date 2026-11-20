#!/usr/bin/env bash
# The one-minute demo: an indexer with a bug, the replay that finds it, and what you get to fix it.
#
# Usage: scripts/demo.sh [report dir]   (default reports/demo)
#
# It builds xdrcheck and go/adapters/demo — the minimal adapter template (go/adapters/minimal) with one bug planted
# on purpose: its indexer skips failed transactions — and replays the CAP-15 (fee bump) and CAP-27 (muxed
# account) entries of the corpus through it from a plain directory (the sep54-dir input: no Docker, no network).
# It then prints the first failures as REPORT.md shows them: the entry, its CAPs, what the ledger holds against
# what the indexer held, and the command that replays that entry alone.
#
# Exits 0 when the replay finds the planted bug (the replay itself exits 1), 1 otherwise. Needs Go (mise) and
# the repository's corpus; nothing is fetched.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-reports/demo}"
entries='cap-0015/*,cap-0027/*'
shown=3 # failures printed in full; the rest are in REPORT.md

echo "demo: building xdrcheck and the demo adapter"
(cd go && go build -o bin/ ./cmd/xdrcheck ./adapters/demo)
rm -rf "$out"
mkdir -p "$out"

echo "demo: replaying $entries through go/adapters/demo, whose indexer skips failed transactions"
echo
set +e
go/bin/xdrcheck replay --adapter go/bin/demo --target-version demo --input sep54-dir --entries "$entries" --report "$out" 2> "$out/replay.log"
code=$?
set -e
grep '^xdrcheck replay' "$out/replay.log" || true
echo
if [ "$code" -ne 1 ] || ! grep -q '^## Failures' "$out/REPORT.md"; then
  echo "demo: the replay did not report the planted bug (exit $code); see $out/replay.log" >&2
  exit 1
fi

# The Failures section up to the (shown+1)th failure.
awk -v n="$shown" '/^## Failures/ {on=1} /^## Counts/ {on=0} on && /^### / {k++} on && k <= n {print}' "$out/REPORT.md"
total=$(grep -c '^### `' "$out/REPORT.md" || true)
if [ "$total" -gt "$shown" ]; then
  echo "… and $((total - shown)) more failures in $out/REPORT.md"
fi
echo
echo "demo: found. The planted bug is the block marked SEEDED BUG in go/adapters/demo/main.go; remove it and the"
echo "demo: same replay passes. To test your own indexer, copy go/adapters/minimal (see its README)."
