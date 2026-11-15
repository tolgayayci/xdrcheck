# Go conformance drivers: one module per pinned go-stellar-sdk version (columns go@<version> in
# ../sets.toml), all built from the shared package in driver/. The orchestrator calls each version directory
# on its own; this file runs a target over all of them, each with its own package cache, which is what the
# top-level `make test` uses.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := v0.7.1 v0.7.2 v0.7.3 v0.8.0 v0.9.0

.PHONY: fetch build test clean

fetch build test clean:
	for v in $(VERSIONS); do env -u XDRCHECK_CACHE_DIR $(MAKE) -C $$v $@; done
