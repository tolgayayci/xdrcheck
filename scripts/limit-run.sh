#!/usr/bin/env bash
# Run a command under a memory limit (and optionally a process-count limit).
# Usage: scripts/limit-run.sh <memory, e.g. 512M> [--pids N] -- <command> [args...]
# Mechanism, in order of preference:
#   1. systemd-run --user --scope with MemoryMax (a cgroup v2 limit: the kernel kills the group on overflow)
#   2. prlimit --as (an address-space limit; allocation fails instead of the process being killed)
# The mechanism used is printed on stderr so reports can record it.
set -euo pipefail
mem="${1:?memory limit}"; shift
pids=""
if [ "${1:-}" = "--pids" ]; then pids="$2"; shift 2; fi
[ "${1:-}" = "--" ] && shift
if [ "$#" -eq 0 ]; then echo "usage: $0 <mem> [--pids N] -- <command>" >&2; exit 2; fi
if [ "${XDRCHECK_LIMIT_MECHANISM:-}" != "rlimit" ] && command -v systemd-run >/dev/null && systemd-run --user --scope -q -p MemoryMax=64M true 2>/dev/null; then
  echo "limit-run: cgroup MemoryMax=$mem${pids:+ TasksMax=$pids}" >&2
  exec systemd-run --user --scope -q -p MemoryMax="$mem" -p MemorySwapMax=0 ${pids:+-p TasksMax="$pids"} -- "$@"
fi
bytes=$(numfmt --from=iec "$mem")
echo "limit-run: rlimit AS=$mem${pids:+ NPROC=$pids}" >&2
exec prlimit --as="$bytes" ${pids:+--nproc="$pids"} -- "$@"
