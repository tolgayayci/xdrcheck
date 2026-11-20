# shellcheck shell=bash
# Nightly golden part `bulk-oracle`: sourced by scripts/nightly/goldens.sh after nightly_init, which provides
# the lib.sh helpers, tag, goldens_root and tree. Not run on its own.
t0=$(date +%s)
if skipped bulk-oracle; then
  result bulk-oracle SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP names bulk-oracle"
else
  set +e
  offline "$CORPUS_BIN" verify --tier bulk --checks hashes,roundtrip,ag3 --goldens "$goldens_root" \
    --report "$OUT/bulk-verify.json" >"$OUT/bulk-verify.log" 2>&1
  rc=$?
  set -e
  grep -v '^FAIL ' "$OUT/bulk-verify.log" | sed 's/^/  bulk-oracle: /' | tail -n 8 || true
  case $rc in
    0) result bulk-oracle PASS $(($(date +%s) - t0)) "every golden of the bulk tier round-trips in the oracle" ;;
    1) result bulk-oracle FAIL $(($(date +%s) - t0)) "$(grep -c '^FAIL ' "$OUT/bulk-verify.log") failing rows; see $OUT/bulk-verify.log" ;;
    *) result bulk-oracle FAIL $(($(date +%s) - t0)) "xdrcheck-corpus verify could not run (exit $rc); see $OUT/bulk-verify.log" ;;
  esac
fi
