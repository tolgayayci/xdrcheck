#!/usr/bin/env bash
# Run CI workflow jobs on this machine the way a hosted runner would, from cold caches (scripts/ci/run_local.py has
# the details): a fresh clone per job, only the job's declared fetch parts and artifacts, 2 CPUs and 7 GiB per step,
# the workflow's run lines as written. `make ci-local TIER=pr|full [JOB=id]` calls this.
#
# Usage: scripts/ci/run-local.sh --tier pr|full [--job ID ...] [--sha REV] [--out DIR] [--parallel N] [--keep]
set -euo pipefail
cd "$(dirname "$0")/../.."
PY="${PY:-$( [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)}"
if ! "$PY" -c 'import yaml' 2>/dev/null; then
  echo "run-local: $PY has no PyYAML; run: python3 -m venv .venv && .venv/bin/pip install --require-hashes -r scripts/py/requirements.txt" >&2
  exit 2
fi
exec "$PY" scripts/ci/run_local.py "$@"
