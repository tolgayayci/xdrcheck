# JavaScript conformance drivers, v17 API generation: one directory per pinned @stellar/stellar-sdk version
# (drivers/sets.toml columns js@17.*), each with its own committed package-lock.json, sharing the driver source
# in src/ and the tests in test/. The orchestrator calls the version directories directly
# (`make -C drivers/js/<version> fetch|build`); this file runs a target over all of them, each with its own
# cache directory, as `xdrcheck conform` names it.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := 17.2.0 17.2.1 17.3.0 17.4.0
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)

.PHONY: fetch build test clean check

fetch build clean:
	for v in $(VERSIONS); do $(MAKE) -C $$v $@ XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-js-$$v; done

# The shared source must parse; then each version's driver tests (after build).
test: check
	for v in $(VERSIONS); do $(MAKE) -C $$v test XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-js-$$v; done

check:
	for f in src/*.mjs test/*.mjs; do node --check $$f; done
