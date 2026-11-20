# The sibling matrix (findings/SIBLINGS.md, evidence/results/sibling-matrix.json): every SDK defect class the kit
# knows, against every SDK family, read from the level-resolved runs of make verify-conformance and the public set.
# results-siblings needs those runs in $(REPORTS) (RESULTS_CHECK=1 compares instead of writing); results-siblings-check
# is the cheap part, which needs no run (make repo-checks runs it).
SIBLINGS := scripts/py/sibling_matrix.py

results-siblings: ## evidence/results/sibling-matrix.json and findings/SIBLINGS.md from the runs of make verify-conformance and the public set
	$(PY) $(SIBLINGS) generate --pr $(REPORTS)/conformance --public $(REPORTS)/conformance-public $(RESULTS_FLAG)

results-siblings-refresh: ## the sibling matrix's record states, its not-applicable rulings (findings/siblings-not-applicable.json) and its page, without a run
	$(PY) $(SIBLINGS) refresh $(RESULTS_FLAG)

results-siblings-check: ## the sibling matrix without a run: consistent with conformance-matrix.json and findings/, the page its rendering
	$(PY) scripts/py/test_sibling_matrix.py
	$(PY) $(SIBLINGS) check

repo-checks: results-siblings-check

# make results refreshes the sibling matrix with the other results files (it reads the same conformance runs).
results: results-siblings
