#!/usr/bin/env bash
# Nightly full regeneration: `xdrcheck-corpus gen --check --all` regenerates every scenario under corpus/scenarios/
# (every protocol and network each one declares) on the pinned stellar-core, with no network, and compares the
# result with the committed chains: equal header hashes, transaction hashes and results, and byte-equal ledgers
# after normalisation. The per-pull-request check (`make verify-generate`) runs the same comparison over
# corpus/scenarios/pr.list; this one also catches a scenario that is missing from that list.
#
# Usage: scripts/nightly/regenerate.sh <out dir>
# Writes <out>/regenerate.log (the generator's output) and <out>/regenerate.summary.txt. Exit 0 every chain
# regenerated identically, 1 a difference, 2 the tool could not run.
source "$(dirname "$0")/lib.sh"
nightly_init regenerate "${1:?usage: regenerate.sh <out dir>}"
need_tool "$CORPUS_BIN"

scenarios=$(find corpus/scenarios -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) | wc -l)
listed=$(grep -cv '^\s*\(#\|$\)' corpus/scenarios/pr.list || true)
echo "regenerate: $scenarios scenario files; $listed of them in pr.list"

t0=$(date +%s)
set +e
# Always offline, like `make verify-generate`: the generator must not need the network.
"$ROOT/scripts/offline-run.sh" "$CORPUS_BIN" gen --check --all >"$NIGHTLY_LOG" 2>&1
rc=$?
set -e
took=$(($(date +%s) - t0))
tail -n 5 "$NIGHTLY_LOG" | sed 's/^/  /'
case $rc in
  0) result gen-check-all PASS "$took" "$scenarios scenarios regenerated identically" ;;
  1) result gen-check-all FAIL "$took" "differences found; see $NIGHTLY_LOG" ;;
  *) result gen-check-all FAIL "$took" "the generator could not run (exit $rc); see $NIGHTLY_LOG" ;;
esac
nightly_finish
