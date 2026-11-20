# The SDK CI recipes run as an SDK maintainer would use them (docs/use-in-sdk-ci.md §2): a scratch SDK repository per
# language with the recipe copied in and wired to the SDK's own tree, the workflow's own test step, offline. Needs the
# caches make fetch-sdk fills.
sdk-ci-recipes: ## each SDK CI recipe (examples/sdk-ci/<lang>/workflow.yml) end to end against the pinned SDK's tree, offline: passes as committed, fails on a new divergence
	$(RUN) $(PY) examples/sdk-ci/check_recipes.py $(SDKCI_LANGS)
