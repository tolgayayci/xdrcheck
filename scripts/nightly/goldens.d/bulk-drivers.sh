# shellcheck shell=bash
# Nightly golden part `bulk-drivers`: sourced by scripts/nightly/goldens.sh after nightly_init, which provides
# the lib.sh helpers, tag, goldens_root and tree. Not run on its own.
t0=$(date +%s)
if skipped bulk-drivers; then
  result bulk-drivers SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP names bulk-drivers"
else
  set_name=public
  report="$OUT/bulk-conform"
  if [ -n "${XDRCHECK_OVERLAY:-}" ]; then
    set_name=all
    report="$(overlay_reports bulk-conform)"
  fi
  mkdir -p "$report"
  set +e
  offline "$XDRCHECK_BIN" conform build --set "$set_name" >"$report/build.log" 2>&1
  rc=$?
  if [ $rc = 0 ]; then
    offline "$XDRCHECK_BIN" conform run --set "$set_name" --tier bulk --levels L0 --goldens "$goldens_root" \
      --report "$report" >"$report/cells.txt" 2>"$report/run.log"
    rc=$?
  fi
  set -e
  grep '^xdrcheck conform' "$report/build.log" "$report/run.log" 2>/dev/null | sed 's/^[^:]*:/  bulk-drivers: /' | tail -n 4 || true
  case $rc in
    0) result bulk-drivers PASS $(($(date +%s) - t0)) "set $set_name: every golden decodes and re-encodes in every driver" ;;
    1) result bulk-drivers FAIL $(($(date +%s) - t0)) "set $set_name: unexpected verdicts; see $report/matrix.md" ;;
    *) result bulk-drivers FAIL $(($(date +%s) - t0)) "set $set_name: the run could not complete (exit $rc); see $report/build.log, $report/run.log" ;;
  esac
fi
