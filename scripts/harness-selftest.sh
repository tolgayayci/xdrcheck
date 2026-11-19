#!/usr/bin/env bash
# The replay harness's own test (`make harness-selftest`): every seeded-bug indexer — the baseline indexer with
# one deliberate defect switched on (`baseline --bug NAME`) — is replayed through `xdrcheck replay` and must land in
# the class·qualifier its row of go/adapters/baseline/bugs/table.json documents; the unmodified baseline must
# pass the whole corpus.
#
# It also checks the Go view path (conformance column go@v0.9.0:views): with a difference planted on the view
# side (XDRCHECK_GO_VIEWS_PLANT=tx-hash flips the first transaction hash the view extractor reports), the L1 cells of
# the corpus's ledger entries must turn into diverge cells, and without it they must not.
#
# Usage: scripts/harness-selftest.sh [OUT]   (default reports/selftest)
# Needs go/bin/xdrcheck (`make build`). Builds the baseline adapter and the checker from the module cache, so it runs
# offline (scripts/offline-run.sh). XDRCHECK_SELFTEST_STRICT=1 also fails on known harness holes and on bugs whose
# demonstrating entry is not in the corpus yet; XDRCHECK_SELFTEST_ONLY=a,b runs only those bugs. XDRCHECK_SELFTEST_VIEWS=0
# skips the view-path check (it needs the go@v0.9.0 driver's package cache, `xdrcheck conform fetch`).
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-reports/selftest}"
test -x go/bin/xdrcheck || { echo "harness-selftest: go/bin/xdrcheck is not built (make build)" >&2; exit 2; }
(cd go && GOFLAGS="${GOFLAGS:--mod=readonly}" go build -o bin/ ./adapters/baseline/cmd/baseline ./adapters/baseline/bugs/cmd/harness-selftest)
mkdir -p "$out"

if [ "${XDRCHECK_SELFTEST_VIEWS:-1}" != 0 ]; then
  make -s -C drivers/go/v0.9.0 build >/dev/null
  # The ledger entries of the first manifest group that has one (derived from the corpus, never hard-coded).
  group=$(python3 -I - corpus/manifest <<'PY'
import json, os, sys
root = sys.argv[1]
for g in sorted(os.listdir(root)):
    for name in sorted(os.listdir(os.path.join(root, g))):
        with open(os.path.join(root, g, name)) as f:
            e = json.load(f)
        if any(v.get("xdr_type") == "LedgerCloseMeta" for v in e.get("variants") or []):
            print(g)
            sys.exit(0)
sys.exit(1)
PY
)
  views() {
    go/bin/xdrcheck conform run --columns 'go@v0.9.0:views' --entries "$group/*" --levels L1 --report "$out/views-$1" \
      >"$out/views-$1.txt" 2>&1 || true
    python3 -I - "$out/views-$1/report.json" "$1" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))["rows"]
diverge = sum(1 for r in rows if (r.get("conform") or {}).get("verdict") == "diverge")
planted = sys.argv[2] == "planted"
print(f"harness-selftest: views {sys.argv[2]}: {len(rows)} L1 cells, {diverge} diverge")
sys.exit(0 if rows and ((diverge > 0) if planted else (diverge == 0)) else 1)
PY
  }
  views clean || { echo "harness-selftest: the view path disagrees with the full decode without a plant ($out/views-clean.txt)" >&2; exit 1; }
  XDRCHECK_GO_VIEWS_PLANT=tx-hash views planted || { echo "harness-selftest: the planted view-vs-full difference was not caught ($out/views-planted.txt)" >&2; exit 1; }
  # The planted run's rows are deliberate failures; keep its console log only, so the findings check that scans
  # the reports directory never reads them as defects.
  rm -r -- "$out/views-planted"
fi

exec go/bin/harness-selftest --xdrcheck go/bin/xdrcheck --baseline go/bin/baseline --corpus corpus --out "$out" \
  ${XDRCHECK_SELFTEST_ONLY:+--only "$XDRCHECK_SELFTEST_ONLY"}
