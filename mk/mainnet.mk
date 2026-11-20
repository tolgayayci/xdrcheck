# The mainnet tier (corpus/mainnet/README.md): 6,158 pubnet transactions, located in their public-lake objects, that
# together hold every transaction-level shape token of the mainnet scan. The objects (about 1 GB) are not in the
# repository:
#
#   make mainnet-fetch      network: GET every object into $(XDRCHECK_CACHE)/mainnet/objects/ (hash-checked,
#                           resumable; a full cache makes no request); also `make fetch FETCH_ONLY=mainnet`
#   make verify-mainnet     from the cache only (OFFLINE=1 cuts the network): hash chain, cut, round trip, tokens
#
# The pull-request check of the tier's files without the objects is scripts/py/check_mainnet_tier.py, in
# `make repo-checks`.
.PHONY: mainnet-fetch verify-mainnet results-mainnet results-mainnet-check mainnet-tier-check

# Parallel GETs of mainnet-fetch, and ledgers checked in parallel by verify-mainnet.
MAINNET_FETCH_JOBS ?= 16
MAINNET_JOBS       ?= 4

mainnet-fetch: tool-rust ## network: the mainnet tier's public-lake objects (about 1 GB) into $(XDRCHECK_CACHE)/mainnet/, hash-checked; offline when the cache is full
	$(CORPUS) mainnet fetch --cache $(XDRCHECK_CACHE) --jobs $(MAINNET_FETCH_JOBS)

verify-mainnet: tool-rust ## the mainnet tier from the cache (make mainnet-fetch): every part's hash chain to its lake object, cut, round trip, and the 15,186 tokens
	mkdir -p $(REPORTS)
	$(RUN) $(CORPUS) mainnet check --cache $(XDRCHECK_CACHE) --jobs $(MAINNET_JOBS) --out $(REPORTS)/mainnet-check.tsv

# The coverage statement (evidence/results/mainnet-coverage.json): of the tier's tokens, how many the tier holds and
# how many a curated corpus entry's transaction holds. It moves when a corpus entry is added, so its check runs
# with the corpus checks (make verify-coverage).
results-mainnet: tool-rust ## evidence/results/mainnet-coverage.json: the tier's tokens held by the mainnet tier and by the curated corpus (RESULTS_CHECK=1 compares)
	$(RUN) $(CORPUS) mainnet coverage $(RESULTS_FLAG)

results-mainnet-check: tool-rust ## evidence/results/mainnet-coverage.json is current with the tier and the curated corpus
	$(RUN) $(CORPUS) mainnet coverage --check

verify-coverage: results-mainnet-check

# The tier's files without the objects: schemas, header hash and counts, cover order (seconds).
mainnet-tier-check: ## corpus/mainnet's files against their schemas and header, without the lake objects
	$(PY) scripts/py/check_mainnet_tier.py

repo-checks: mainnet-tier-check
