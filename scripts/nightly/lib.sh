# Shared helpers for the nightly jobs (sourced, not run). Each job script calls `nightly_init <job> <out dir>`
# first; it changes to the repository root and sets:
#
#   ROOT, OUT (absolute; created), CORPUS_BIN, XDRCHECK_BIN, NIGHTLY_LOG (OUT/<job>.log), NIGHTLY_SUMMARY
#   (OUT/<job>.summary.txt: one line per part, what the job printed as its result)
#
# Environment the jobs share:
#   OFFLINE=1           wrap every run step in scripts/offline-run.sh (fetch steps are never wrapped)
#   XDRCHECK_OVERLAY=DIR     the private overlay; only jobs that can use it read it, and their reports then go to
#                       $XDRCHECK_OVERLAY/reports/nightly/ instead of OUT, because nothing a run with the overlay
#                       writes may land in the public working tree
#   XDRCHECK_NIGHTLY_SKIP    comma-separated parts to skip on purpose (reported SKIPPED, not a failure), e.g. ag2
#   XDRCHECK_DOCKER_PREFIX   prefix for the names of containers the jobs start (default xdrcheck-nightly)
set -euo pipefail

# The published next-protocol stellar-core image. The name is fixed to the public repository name, never derived
# from the repository a workflow runs in, so a digest pin taken in one repository holds in the other.
XDRCHECK_CORE_NEXT_IMAGE=ghcr.io/tolgayayci/xdrcheck-core-next

nightly_init() {
  NIGHTLY_JOB="$1"
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  cd "$ROOT"
  mkdir -p "$2"
  OUT="$(cd "$2" && pwd)"
  CORPUS_BIN="$ROOT/target/release/xdrcheck-corpus"
  XDRCHECK_BIN="$ROOT/go/bin/xdrcheck"
  NIGHTLY_LOG="$OUT/$NIGHTLY_JOB.log"
  NIGHTLY_SUMMARY="$OUT/$NIGHTLY_JOB.summary.txt"
  NIGHTLY_FAILED=0
  NIGHTLY_STARTED=$(date +%s)
  : >"$NIGHTLY_LOG"
  : >"$NIGHTLY_SUMMARY"
  echo "$NIGHTLY_JOB: started $(date -u +%FT%TZ); reports under $OUT"
}

# pin <dotted key>: one scalar from pins.toml.
pin() {
  python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$ROOT/pins.toml" "$1"
}

# need_tool <path>: fail the job (exit 2) when a tool is not built.
need_tool() {
  [ -x "$1" ] || { echo "$NIGHTLY_JOB: $1 is not built; run make build" >&2; exit 2; }
}

# offline <cmd>...: run a step without network when OFFLINE is set.
offline() {
  if [ -n "${OFFLINE:-}" ]; then "$ROOT/scripts/offline-run.sh" "$@"; else "$@"; fi
}

# skipped <part>: whether XDRCHECK_NIGHTLY_SKIP names the part.
skipped() {
  case ",${XDRCHECK_NIGHTLY_SKIP:-}," in *",$1,"*) return 0 ;; esac
  return 1
}

# overlay_reports <name>: the private report directory for a run with the overlay (outside the working tree).
overlay_reports() {
  local d="${XDRCHECK_OVERLAY%/}/reports/nightly/$1"
  mkdir -p "$d"
  (cd "$d" && pwd)
}

# result <part> <PASS|FAIL|BLOCKED|SKIPPED> <seconds> <text>: record one part's result.
result() {
  local line
  line=$(printf '%-8s %-24s %5ss  %s' "$2" "$1" "$3" "$4")
  echo "$line" | tee -a "$NIGHTLY_SUMMARY"
  case "$2" in FAIL | BLOCKED) NIGHTLY_FAILED=1 ;; esac
}

# nightly_finish: print the summary and exit 0 only when no part failed or was blocked.
nightly_finish() {
  local took=$(($(date +%s) - NIGHTLY_STARTED))
  echo "$NIGHTLY_JOB: summary ($took s; full log $NIGHTLY_LOG)"
  sed 's/^/  /' "$NIGHTLY_SUMMARY"
  if [ "$NIGHTLY_FAILED" = 0 ]; then
    echo "$NIGHTLY_JOB: passed"
    exit 0
  fi
  echo "$NIGHTLY_JOB: FAILED"
  exit 1
}
