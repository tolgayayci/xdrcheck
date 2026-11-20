# Make targets of the results data (evidence/results/README.md). The Makefile includes every mk/*.mk in name order;
# give each target a `## text` line so `make help` and docs/cli.md list it.
#
# results-conformance and results-replay read the report directories the runs wrote under $(REPORTS); with
# RESULTS_CHECK=1 they compare the committed file with that run instead of writing it. results-check is the cheap
# part, which needs no run (make repo-checks runs it).
RESULTS    := scripts/py/results.py
RESULTS_CHECK ?=
RESULTS_FLAG = $(if $(filter 1,$(RESULTS_CHECK)),--check)

results: results-findings results-known-defects results-conformance results-replay results-acceptance ## every file under evidence/results/ from the runs in $(REPORTS) (RESULTS_CHECK=1 compares instead of writing)

results-conformance: ## evidence/results/conformance-matrix.json from the runs of make verify-conformance and verify-conformance-public
	$(PY) $(RESULTS) conformance --pr $(REPORTS)/conformance --public $(REPORTS)/conformance-public $(RESULTS_FLAG)

results-replay: ## evidence/results/replay-summary.json from the runs of make replay-full, verify-replay, replay-etl-known and harness-selftest
	$(PY) $(RESULTS) replay --replay-full $(REPORTS)/replay-full --replay-regression $(REPORTS)/replay-regression \
	  --replay-etl-known $(REPORTS)/replay-etl-known --selftest $(REPORTS)/selftest $(RESULTS_FLAG)

results-acceptance: ## evidence/results/acceptance.json from the acceptance table of make verify-acceptance ($(REPORTS)/acceptance.json)
	$(PY) $(RESULTS) acceptance --table $(REPORTS)/acceptance.json $(RESULTS_FLAG)

results-findings: ## evidence/results/findings.json from the public finding records
	$(PY) $(RESULTS) findings $(RESULTS_FLAG)

results-known-defects: ## evidence/results/known-defects.json from the README's known upstream defects table
	$(PY) $(RESULTS) known-defects $(RESULTS_FLAG)

# TOKEN_TABLE: the token table of a mainnet scan (`xdrcheck-corpus scan token-census`, tokens.tsv or tokens.tsv.zst);
# it is not in the repository (evidence/mainnet-scan/README.md).
TOKEN_TABLE ?=
results-prevalence: tool-rust ## evidence/mainnet-scan/entry-prevalence.json: each corpus entry's rarest shape token and its mainnet count (TOKEN_TABLE=the scan's token table)
	@test -n "$(TOKEN_TABLE)" || { echo "results-prevalence: set TOKEN_TABLE to the scan's token table (scan token-census tokens.tsv)" >&2; exit 2; }
	mkdir -p $(REPORTS)
	$(RUN) $(CORPUS) scan entry-tokens --corpus corpus --out $(REPORTS)/entry-tokens.tsv
	$(PY) $(RESULTS) prevalence --entry-tokens $(REPORTS)/entry-tokens.tsv --token-table $(TOKEN_TABLE) $(RESULTS_FLAG)

results-check: ## the results data without a run: findings and known defects current, the run summaries consistent with the corpus and findings
	$(PY) $(RESULTS) check

# The cheap check is part of the repository checks.
repo-checks: results-check
