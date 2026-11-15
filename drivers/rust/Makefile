# The Rust stellar-xdr drivers: one directory per pinned crate version, one shared source tree (src/).
# xdrcheck conform calls the version directories themselves; this Makefile runs a target in each of them, which is
# what the top-level `make test` uses.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSIONS := 28.0.0 28.0.1 30.0.0
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)

.PHONY: fetch build test clean fmt

fetch build test clean:
	for v in $(VERSIONS); do $(MAKE) -C $$v $@ XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE)/conform/drivers-rust-$$v; done

fmt:
	cargo fmt --manifest-path 30.0.0/Cargo.toml
