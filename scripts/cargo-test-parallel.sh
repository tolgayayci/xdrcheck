#!/usr/bin/env bash
# Every test of the Rust workspace, as `cargo test --locked --workspace` runs them, with the test binaries run side
# by side instead of one after another (`make test-fast`).
#
# Usage: scripts/cargo-test-parallel.sh [jobs]   (default: the number of CPUs)
#
# `cargo test` runs its test binaries one at a time, and most of the slow ones hold one or two tests that each use
# one core, so a run keeps a 4-vCPU machine mostly idle. This builds the same binaries (`cargo test --no-run`, the
# same profile and features), then runs each one the way cargo does: from its package's directory, with the
# package's CARGO_* variables, every test of the binary, nothing filtered or skipped; the documentation tests run
# first through `cargo test --doc`, as cargo runs them. A binary's output goes to its own log, printed when it
# fails. Exit 0 when every binary passes, 1 when any fails, 2 when the build fails.
#
# Scratch copies: the tests copy the corpus into target/tmp (CARGO_TARGET_TMPDIR, fixed when the test is built).
# When a binary has ended, the entries it named after its own process ID (`<name>-<pid>`, the copies that would
# otherwise pile up from run to run) are removed. With XDRCHECK_TEST_SCRATCH=clean (the default when CI is set) every
# entry of target/tmp this run created or changed is removed once all binaries have ended: about 6 GB, which the
# tests recreate on every run. Locally it is off by default, since another test run may be using target/tmp.
set -euo pipefail
cd "$(dirname "$0")/.."
jobs="${1:-$(nproc)}"
logs="${CARGO_TARGET_DIR:-target}/test-parallel"
rm -rf "$logs"
mkdir -p "$logs"
scratch="$PWD/target/tmp"
scratch_clean="${XDRCHECK_TEST_SCRATCH:-$([ -n "${CI:-}" ] && echo clean || echo keep)}"
touch "$logs/started"

# One line per test binary: package directory, package name, version, binary path, display name.
list="$logs/binaries.tsv"
if ! cargo test --locked --workspace --no-run --message-format=json-render-diagnostics >"$logs/build.json"; then
  echo "cargo-test-parallel: the test build failed" >&2
  exit 2
fi
python3 -I - "$logs/build.json" >"$list" <<'PY'
import json, os, sys
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("profile", {}).get("test") or not m.get("executable"):
        continue
    t = m["target"]
    pkg = os.path.dirname(m["manifest_path"])
    # package_id: "path+file:///dir#name@version", or "path+file:///name#version" when the directory is the name.
    tail = m["package_id"].rsplit("#", 1)[-1]
    name, version = tail.split("@", 1) if "@" in tail else (os.path.basename(pkg), tail)
    what = os.path.relpath(t["src_path"], pkg)
    if t["kind"][0] in ("lib", "bin"):
        what = "unittests " + what
    print("\t".join([pkg, name, version, m["executable"], name + " " + what]))
PY
n=$(wc -l <"$list")
[ "$n" -gt 0 ] || { echo "cargo-test-parallel: no test binaries were built" >&2; exit 2; }
echo "cargo-test-parallel: $n test binaries, $jobs at a time"

run_one() {
  local pkg=$1 name=$2 version=$3 exe=$4 shown=$5 log s rc
  log="$LOGS/$(basename "$exe").log"
  s=$SECONDS
  rc=0
  (cd "$pkg" && CARGO_MANIFEST_DIR="$pkg" CARGO_PKG_NAME="$name" CARGO_CRATE_NAME="${name//-/_}" \
    CARGO_PKG_VERSION="$version" exec "$exe") >"$log" 2>&1 &
  local pid=$!
  wait "$pid" || rc=$?
  # The binary's own scratch copies, named after its process ID.
  if [ -d "$SCRATCH" ]; then
    find "$SCRATCH" -mindepth 1 -maxdepth 2 \( -name "*-$pid" -o -name "*-$pid-*" \) -prune -exec rm -rf {} + 2>/dev/null || true
  fi
  if [ "$rc" -eq 0 ]; then
    printf 'PASS %4ds %s (%s)\n' $((SECONDS - s)) "$shown" "$(grep -h '^test result:' "$log" | tail -1 | sed 's/^test result: //; s/; 0 measured.*//')"
  else
    printf 'FAIL %4ds %s (exit %d)\n' $((SECONDS - s)) "$shown" "$rc"
    sed 's/^/    /' "$log"
    return 1
  fi
}
export -f run_one
export LOGS="$logs" SCRATCH="$scratch"
status=0
if ! cargo test --locked --workspace --doc >"$logs/doc-tests.log" 2>&1; then
  sed 's/^/    /' "$logs/doc-tests.log"
  echo "FAIL documentation tests (cargo test --doc)"
  status=1
else
  echo "PASS documentation tests ($(grep -o '[0-9]* passed' "$logs/doc-tests.log" | awk '{s += $1} END {print s + 0}') passed)"
fi
tr '\t\n' '\0\0' <"$list" | xargs -0 -n 5 -P "$jobs" bash -c 'run_one "$@"' _ || status=1
if [ "$scratch_clean" = clean ] && [ -d "$scratch" ]; then
  before=$(du -sm "$scratch" | cut -f1)
  find "$scratch" -mindepth 1 -maxdepth 1 -newer "$logs/started" -exec rm -rf {} +
  echo "cargo-test-parallel: removed the scratch copies this run made in target/tmp ($before MB before)"
fi
if [ "$status" -ne 0 ]; then
  echo "cargo-test-parallel: FAIL (logs in $logs)" >&2
  exit 1
fi
echo "cargo-test-parallel: PASS, all $n test binaries"
