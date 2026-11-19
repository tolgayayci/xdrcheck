#!/usr/bin/env bash
# Every conformance driver directory's own tests (`make -C drivers/<dir> test`), the directories side by side
# (`make test-drivers`; `make test` and `make test-fast` run it).
#
# Usage: scripts/test-drivers.sh [jobs]   (default: the number of CPUs)
#        XDRCHECK_TEST_DRIVERS=js,js16,go@v0.9.0 scripts/test-drivers.sh   only these (`make test-drivers DRIVERS=...`:
#        the CI splits the directories over several jobs). A name is a directory of drivers/, or DIR@VERSION for one
#        of the versions its Makefile lists in VERSIONS (`make -C drivers/DIR test VERSIONS=VERSION`, so the
#        versions of one directory can run side by side); anything else fails.
#
# Each directory under drivers/ with a Makefile, then each one under $XDRCHECK_OVERLAY/drivers/ (with
# XDRCHECK_ROOT set to this repository), runs its `test` target as `make test` always ran it; only the order
# changes: up to [jobs] directories at once, each one's versions still one after another. A directory's output
# goes to its own log, printed when it fails. Exit 0 when every directory passes, 1 when any fails.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
jobs="${1:-$(nproc)}"
logs="${XDRCHECK_TEST_DRIVERS_LOGS:-$root/target/test-drivers}"
rm -rf "$logs"
mkdir -p "$logs"

# Each item: a driver directory, optionally with @VERSION.
dirs=()
only=",${XDRCHECK_TEST_DRIVERS:-},"
if [ "$only" != ",," ]; then
  IFS=, read -ra names <<<"${XDRCHECK_TEST_DRIVERS}"
  for n in "${names[@]}"; do
    d=${n%%@*}
    [ -f "drivers/$d/Makefile" ] || { echo "test-drivers: drivers/$d is not a driver directory" >&2; exit 1; }
    if [ "$n" != "$d" ]; then
      v=${n#*@}
      grep -qE "^VERSIONS :?= (.* )?$v( |\$)" "drivers/$d/Makefile" ||
        { echo "test-drivers: $v is not among the VERSIONS of drivers/$d/Makefile" >&2; exit 1; }
      dirs+=("$root/drivers/$d@$v")
    else
      dirs+=("$root/drivers/$d")
    fi
  done
else
  for d in drivers/*/; do [ -f "$d/Makefile" ] && dirs+=("$root/${d%/}"); done
fi
if [ "$only" = ",," ] && [ -n "${XDRCHECK_OVERLAY:-}" ]; then
  for d in "$XDRCHECK_OVERLAY"/drivers/*/; do [ -f "$d/Makefile" ] && dirs+=("${d%/}"); done
fi
[ "${#dirs[@]}" -gt 0 ] || { echo "test-drivers: no driver directory has a Makefile" >&2; exit 1; }
echo "test-drivers: ${#dirs[@]} driver directories, $jobs at a time"

run_one() {
  local dir=$1 shown=${1#"$ROOT"/} log s rc=0 extra=()
  log="$LOGS/$(echo "${dir#"$ROOT"/}" | tr '/@' '__').log"
  case "$dir" in "$ROOT"/*) ;; *) extra=(XDRCHECK_ROOT="$ROOT") ;; esac
  case "$dir" in *@*) extra+=(VERSIONS="${dir##*@}"); dir=${dir%@*} ;; esac
  s=$SECONDS
  make -C "$dir" test "${extra[@]}" >"$log" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    printf 'PASS %4ds %s\n' $((SECONDS - s)) "$shown"
  else
    printf 'FAIL %4ds %s (exit %d)\n' $((SECONDS - s)) "$shown" "$rc"
    sed 's/^/    /' "$log"
    return 1
  fi
}
export -f run_one
export LOGS="$logs" ROOT="$root"
if ! printf '%s\0' "${dirs[@]}" | xargs -0 -n 1 -P "$jobs" bash -c 'run_one "$1"' _; then
  echo "test-drivers: FAIL (logs in $logs)" >&2
  exit 1
fi
echo "test-drivers: PASS, all ${#dirs[@]} driver directories"
