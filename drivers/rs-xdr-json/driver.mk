# Rules shared by every rs-xdr-json driver directory (drivers/rs-xdr-json/<version>/Makefile includes this). They
# meet the driver directory contract in drivers/README.md:
#   fetch  (network allowed) fill $(XDRCHECK_CACHE_DIR) with the crates the committed Cargo.lock names; cargo checks
#          every .crate against the lock's sha256
#   build  (offline) build bin/xdrcheck-driver from the directory and $(XDRCHECK_CACHE_DIR) alone
#   test   (offline) clippy, then a describe and one json request against the built driver
#   clean  remove what build made
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION := $(notdir $(patsubst %/,%,$(CURDIR)))
XDRCHECK_CACHE_DIR ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)/conform/drivers-rs-xdr-json-$(VERSION)
XDRCHECK_ROOT ?= $(abspath $(CURDIR)/../../..)

CARGO_ENV := CARGO_HOME=$(XDRCHECK_CACHE_DIR)/cargo CARGO_TARGET_DIR=$(XDRCHECK_CACHE_DIR)/target
CARGO_OFFLINE := $(CARGO_ENV) CARGO_NET_OFFLINE=true cargo
RELEASE := $(XDRCHECK_CACHE_DIR)/target/release
BLOB := $(XDRCHECK_ROOT)/corpus/blobs/58/582e694b96bf69f894763909a1b058c1a2523d5634f2e0947393cee9765f4e0e.xdr

.PHONY: fetch build test clean

fetch:
	mkdir -p $(XDRCHECK_CACHE_DIR)/cargo
	$(CARGO_ENV) cargo fetch --locked --manifest-path Cargo.toml
	echo "fetched" > $(XDRCHECK_CACHE_DIR)/fetched

build:
	@test -f $(XDRCHECK_CACHE_DIR)/fetched || { echo "rs-xdr-json $(VERSION): $(XDRCHECK_CACHE_DIR) is empty; run xdrcheck conform fetch first" >&2; exit 1; }
	$(CARGO_OFFLINE) build --release --offline --locked --manifest-path Cargo.toml --bins
	mkdir -p bin
	install -m 0755 $(RELEASE)/xdrcheck-driver bin/

test: build
	$(CARGO_OFFLINE) clippy --release --offline --locked --manifest-path Cargo.toml --bins -- -D warnings
	out=$$(printf '%s\n' '{"xcc":"xcc.driver/1","id":1,"op":"describe"}' \
	  '{"xcc":"xcc.driver/1","id":2,"op":"run","entry":"t/t","level":"json","input":{"kind":"xdr","xdr_type":"LedgerCloseMeta","path":"$(BLOB)"}}' \
	  '{"xcc":"xcc.driver/1","id":3,"op":"shutdown"}' | bin/xdrcheck-driver); \
	  [[ "$$out" == *'"package":"stellar-xdr"'* && "$$out" == *'"roundtrip":"identical"'* && "$$out" == *'"schema":"valid"'* ]] \
	  || { echo "rs-xdr-json $(VERSION): unexpected driver output: $$out" >&2; exit 1; }

clean:
	rm -rf bin
	[ ! -d $(XDRCHECK_CACHE_DIR)/target ] || $(CARGO_ENV) cargo clean --manifest-path Cargo.toml
