# JavaScript conformance drivers, v16 API generation (the LTS line, @stellar/js-xdr 4): one directory per pinned
# @stellar/stellar-sdk version (drivers/sets.toml columns js@16.*), each with its own committed package-lock.json,
# sharing the driver source in src/ and the tests in test/. The orchestrator calls the version directories
# directly (`make -C drivers/js16/<version> fetch|build`); this file runs a target over all of them, each with its
# own cache directory, as `xdrcheck conform` names it.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := 16.3.0 16.3.1 16.4.1
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)

.PHONY: fetch build test clean check

fetch build clean:
	for v in $(VERSIONS); do $(MAKE) -C $$v $@ XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-js16-$$v; done

# The shared source must parse; then each version's driver tests (after build).
test: check
	for v in $(VERSIONS); do $(MAKE) -C $$v test XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-js16-$$v; done

check:
	for f in src/*.mjs test/*.mjs; do node --check $$f; done
