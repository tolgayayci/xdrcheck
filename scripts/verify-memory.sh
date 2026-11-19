#!/usr/bin/env bash
# The replay harness's memory-bound test (`make verify-memory`; docs/replay-harness.md §10), in two steps:
#   1. the four memory tests (go/internal/replay/memtest): every `xdrcheck replay` runs in a memory-limited group of
#      its own (256 MiB, swap off) — T-mem-1 the baseline indexer over the sampled bulk tier as a stream repeated
#      once and ten times (peak growth under 16 MiB, ten times the rows), the tier's ledgers of a megabyte or more
#      as a stream of their own, and the corpus's largest ledger repeated a hundred times; T-mem-2 an adapter answering observe with a 512 MiB line; T-mem-3 the memory-hog seeded
#      indexer under a 128 MiB adapter group; T-mem-4 the corpus's deepest and largest ledgers. All must pass.
#   2. the negative control: T-mem-1's stream runs again with streaming switched off (the harness observes and
#      holds each unit whole). It must fail — otherwise the test could not tell a streaming harness from one
#      that is not.
#
# Usage: scripts/verify-memory.sh [OUT]   (default reports/memory)
# Needs go/bin/xdrcheck (`make build`) and the golden cache (`make fetch`). Builds the baseline adapter and the test
# from the module cache, so it runs offline (scripts/offline-run.sh). XDRCHECK_MEMTEST_ARGS adds memtest flags (for
# example `--sample 0` for the whole bulk tier).
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-reports/memory}"
test -x go/bin/xdrcheck || { echo "verify-memory: go/bin/xdrcheck is not built (make build)" >&2; exit 2; }
(cd go && GOFLAGS="${GOFLAGS:--mod=readonly}" go build -o bin/ ./adapters/baseline/cmd/baseline ./internal/replay/memtest/cmd/memtest)
mkdir -p "$out"
# shellcheck disable=SC2086 # XDRCHECK_MEMTEST_ARGS is a list of flags
go/bin/memtest --xdrcheck go/bin/xdrcheck --baseline go/bin/baseline --corpus corpus --out "$out" ${XDRCHECK_MEMTEST_ARGS:-}

neg="$out/negative-control"
mkdir -p "$neg"
set +e
# shellcheck disable=SC2086
go/bin/memtest --xdrcheck go/bin/xdrcheck --baseline go/bin/baseline --corpus corpus --out "$neg" --negative-control ${XDRCHECK_MEMTEST_ARGS:-} \
  >"$neg/memtest.log" 2>&1
rc=$?
set -e
case "$rc" in
  1)
    echo "verify-memory: negative control failed as intended (streaming off); the assertions it broke:"
    grep -F '| false |' "$neg/memory-negative-control.md" || true
    # Its replay runs were killed on purpose, so their reports are partial and are not evidence: keep only the
    # summary, so report scanners (xdrcheck findings check) never read them.
    find "$neg" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
    ;;
  0)
    echo "verify-memory: the negative control passed with streaming off, so the test cannot detect unbounded growth" >&2
    exit 1
    ;;
  *)
    echo "verify-memory: the negative control could not run (exit $rc):" >&2
    tail -20 "$neg/memtest.log" >&2
    exit 2
    ;;
esac
echo "verify-memory: ok — report $out/memory.md, negative control $neg/memory-negative-control.md"
