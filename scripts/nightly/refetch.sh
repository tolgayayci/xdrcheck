#!/usr/bin/env bash
# Nightly refetch: every pinned download fetched again into an empty cache and checked, so an artefact that
# disappeared or changed upstream shows up before a contributor's fresh checkout needs it.
#
#   fetch         scripts/fetch.sh (`make fetch`) with the kit's caches pointed at a new empty directory
#   drivers       the public conformance columns' package caches (scripts/nightly/fetch.sh drivers), same cache
#   pins          `xdrcheck pins check`: every version the tools read comes from pins.toml
#   goldens       `xdrcheck-corpus verify --tier bulk --checks hashes` on the freshly fetched golden tree
#   lake          `xdrcheck-corpus refetch`: every vendored public-lake object fetched again and compared by hash (a
#                 perishable testnet object that is gone is reported, not failed)
#
# Usage: scripts/nightly/refetch.sh <out dir>
# Network: all of it; this job is the network check. The empty cache is XDRCHECK_CACHE, XDRCHECK_CACHE_DIR and
# XDG_CACHE_HOME (the wallet-backend adapter's binaries); it is a new directory under $HOME/.cache, removed
# afterwards unless XDRCHECK_REFETCH_KEEP=1. The language package caches (cargo registry, Go modules) and container
# images are shared with the machine, so on a workstation they are only re-verified; the CI job starts with
# every cache cold. Exit 0 every part passed, 1 otherwise.
source "$(dirname "$0")/lib.sh"
nightly_init refetch "${1:?usage: refetch.sh <out dir>}"

fresh=$(mktemp -d "$HOME/.cache/xdrcheck-refetch.XXXXXX")
# Go writes its module cache read-only; make it writable so the directory can be removed.
# The job's own exit status is kept.
cleanup() {
  local rc=$?
  chmod -R u+w "$fresh" 2>/dev/null || true
  rm -rf "$fresh" || true
  exit $rc
}
[ "${XDRCHECK_REFETCH_KEEP:-}" = 1 ] || trap cleanup EXIT
echo "refetch: empty cache $fresh"
# Keep the compiler caches; they hold build products, not downloads.
GOCACHE="$(go env GOCACHE)"
export GOCACHE XDRCHECK_CACHE="$fresh" XDRCHECK_CACHE_DIR="$fresh" XDG_CACHE_HOME="$fresh/xdg"

# part <name> <success text> <cmd>...: run one part, log its output, record the result.
part() {
  local name="$1" ok="$2" t0 rc
  shift 2
  t0=$(date +%s)
  echo "== $name: $*" >>"$NIGHTLY_LOG"
  set +e
  "$@" >>"$NIGHTLY_LOG" 2>&1
  rc=$?
  set -e
  if [ $rc = 0 ]; then
    result "$name" PASS $(($(date +%s) - t0)) "$ok"
  else
    result "$name" FAIL $(($(date +%s) - t0)) "exit $rc; see $NIGHTLY_LOG"
  fi
  return 0
}

part fetch "every pinned download fetched into the empty cache and hash-verified" scripts/fetch.sh
part drivers "public conformance columns fetched from their lock files" scripts/nightly/fetch.sh drivers
[ -x "$XDRCHECK_BIN" ] || (cd go && go build -o bin/ ./cmd/xdrcheck)
part pins "every version the tools read is in pins.toml" "$XDRCHECK_BIN" pins check
[ -x "$CORPUS_BIN" ] || cargo build --locked --release -p xdrcheck-corpus --target-dir "$ROOT/target"
part goldens "the fetched golden tree matches corpus/bulk/" \
  "$CORPUS_BIN" verify --tier bulk --checks hashes --goldens "$fresh/goldens" --report "$OUT/refetch-goldens.json"
part lake "every vendored public-lake object is unchanged" "$CORPUS_BIN" refetch
grep '^refetch: ' "$NIGHTLY_LOG" | sed 's/^/  lake: /' || true
nightly_finish
