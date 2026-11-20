# Local emulation of the CI workflows (scripts/ci/run_local.py): each job of .github/workflows/pr.yml (TIER=pr) or
# full.yml (TIER=full) from a fresh clone of SHA (default HEAD), with only its declared fetch parts and artifacts, on
# 2 CPUs and 7 GiB, from cold caches. JOB=<id> runs one job and the jobs it needs; PARALLEL=N runs N at a time;
# CI_LOCAL_OUT=<dir> keeps the logs, artifacts and summary.md there.
TIER ?= pr
JOB ?=
SHA ?= HEAD
PARALLEL ?= 1
CI_LOCAL_OUT ?=
ci-local: ## network: CI jobs (TIER=pr|full, JOB=id) run as on a cold hosted runner: fresh clone, declared fetch parts only, 2 CPUs, 7 GiB
	PY=$(PY) scripts/ci/run-local.sh --tier $(TIER) --sha $(SHA) --parallel $(PARALLEL) \
	  $(foreach j,$(JOB),--job $(j)) $(if $(CI_LOCAL_OUT),--out $(CI_LOCAL_OUT))
