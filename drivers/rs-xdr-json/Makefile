# The rs-xdr-json drivers: one directory per pinned crate version, one shared source tree (src/). xdrcheck conform
# calls the version directories themselves; this Makefile runs a target in each of them (the top-level make test).
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := 30.0.0 main
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)

.PHONY: fetch build test clean

fetch build test clean:
	for v in $(VERSIONS); do $(MAKE) -C $$v $@ XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-rs-xdr-json-$$v; done
