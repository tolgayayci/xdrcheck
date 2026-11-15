# Python conformance drivers: one directory per pinned PyPI stellar-sdk version (drivers/sets.toml columns
# python@*), each with its own hash-pinned requirements.txt, sharing the driver source in src/ and the tests in
# test/. The orchestrator calls the version directories directly (`make -C drivers/python/<version>
# fetch|build`); this file runs a target over all of them, each with its own cache directory, as `xdrcheck conform`
# names it.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := 17.0.0 17.0.1
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)
PYTHON ?= python3

.PHONY: fetch build test clean check

fetch build clean:
	for v in $(VERSIONS); do $(MAKE) -C $$v $@ XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-python-$$v; done

# The shared source must compile; then each version's driver tests (after build).
test: check
	for v in $(VERSIONS); do $(MAKE) -C $$v test XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-python-$$v; done

check:
	$(PYTHON) -I -c 'import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' src/*.py test/*.py
