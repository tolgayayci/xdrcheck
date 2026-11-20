#!/usr/bin/env bash
# Nightly differential run across SDK drivers (docs/maintenance.md, "Differential mode"): the curated corpus
# through every column of the widest column set this run may use, then the matrix checked against the
# divergences the manifest declares, the readiness view for the newest supported protocol, and, when a base
# matrix is given, the cells whose verdict changed.
#
#   set         `public` (drivers/sets.toml: every column a public job may run); `all` when XDRCHECK_OVERLAY names
#               the private overlay, and that run's report goes to $XDRCHECK_OVERLAY/reports/nightly/differential/
#   build/run   `xdrcheck conform build` and `xdrcheck conform run --set <set>` (offline with OFFLINE=1)
#   check       `xdrcheck conform check` in development mode (with the overlay when set): any undeclared divergence
#               that is not pending finding review fails
#   readiness   `xdrcheck conform readiness --protocol <pins.toml [protocol] max_supported>`
#   diff        `xdrcheck conform diff <XDRCHECK_DIFF_BASE> <matrix>` when XDRCHECK_DIFF_BASE names an earlier matrix.json
#
# Usage: scripts/nightly/differential.sh <out dir>
# Needs `make fetch` and `make fetch-nightly` (driver packages) first. The job log shows counts; the cells,
# matrices and readiness table are files in the report directory. Exit 0 every part passed, 1 otherwise.
source "$(dirname "$0")/lib.sh"
nightly_init differential "${1:?usage: differential.sh <out dir>}"
need_tool "$XDRCHECK_BIN"

set_name=public
report="$OUT/differential"
overlay_flag=()
if [ -n "${XDRCHECK_OVERLAY:-}" ]; then
  set_name=all
  report="$(overlay_reports differential)"
  overlay_flag=(--overlay "$XDRCHECK_OVERLAY")
fi
mkdir -p "$report"
protocol=$(pin protocol.max_supported)

# step <part> <log> <cmd>...: run a step offline, its output to <log>; prints the tool's own summary lines.
step() {
  local name="$1" log="$2" t0 rc
  shift 2
  t0=$(date +%s)
  set +e
  offline "$@" >"$log" 2>&1
  rc=$?
  set -e
  grep -E '^xdrcheck conform [a-z]+( \(.*\))?:' "$log" | sed "s/^/  $name: /" | tail -n 3 || true
  STEP_RC=$rc
  STEP_TOOK=$(($(date +%s) - t0))
}

step build "$report/build.log" "$XDRCHECK_BIN" conform build --set "$set_name"
if [ $STEP_RC != 0 ]; then
  result build FAIL $STEP_TOOK "set $set_name: drivers did not build (exit $STEP_RC); see $report/build.log"
  nightly_finish
fi
result build PASS $STEP_TOOK "set $set_name built offline"

t0=$(date +%s)
set +e
offline "$XDRCHECK_BIN" conform run --set "$set_name" --report "$report" >"$report/cells.txt" 2>"$report/run.log"
rc=$?
set -e
grep '^xdrcheck conform run' "$report/run.log" | sed 's/^/  run: /' || true
case $rc in
  0 | 1) result run PASS $(($(date +%s) - t0)) "set $set_name: every cell judged ($(wc -l <"$report/cells.txt") cells); verdicts are checked next" ;;
  *) result run FAIL $(($(date +%s) - t0)) "set $set_name: the run could not complete (exit $rc); see $report/run.log" ;;
esac

if [ -f "$report/matrix.json" ]; then
  step check "$report/check.log" "$XDRCHECK_BIN" conform check "${overlay_flag[@]}" "$report/matrix.json"
  if [ $STEP_RC = 0 ]; then
    result check PASS $STEP_TOOK "every divergence is declared or pending finding review"
  else
    result check FAIL $STEP_TOOK "undeclared or changed cells (exit $STEP_RC); see $report/check.log"
  fi

  set +e
  "$XDRCHECK_BIN" conform readiness --protocol "$protocol" "$report/matrix.json" >"$report/readiness-p$protocol.md" 2>&1
  rc=$?
  set -e
  if [ $rc = 0 ]; then
    result readiness PASS 0 "$(head -n 1 "$report/readiness-p$protocol.md")"
  else
    result readiness FAIL 0 "xdrcheck conform readiness exited $rc; see $report/readiness-p$protocol.md"
  fi

  if [ -n "${XDRCHECK_DIFF_BASE:-}" ]; then
    set +e
    "$XDRCHECK_BIN" conform diff "$XDRCHECK_DIFF_BASE" "$report/matrix.json" >"$report/diff.txt" 2>&1
    rc=$?
    set -e
    case $rc in
      0) result diff PASS 0 "no cell changed against $XDRCHECK_DIFF_BASE" ;;
      1) result diff FAIL 0 "$(grep -cv '^xdrcheck conform diff' "$report/diff.txt") cells changed against the base; see $report/diff.txt" ;;
      *) result diff FAIL 0 "xdrcheck conform diff could not run (exit $rc); see $report/diff.txt" ;;
    esac
  else
    result diff SKIPPED 0 "no XDRCHECK_DIFF_BASE matrix to compare with"
  fi
fi
nightly_finish
