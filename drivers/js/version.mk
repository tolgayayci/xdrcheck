# One @stellar/stellar-sdk version directory (drivers/js/<version>/Makefile includes this file). It meets the
# driver directory contract in drivers/README.md:
#   fetch  (network allowed) fill $(XDRCHECK_CACHE_DIR) from package-lock.json only: `npm ci` in a staging copy
#          inside the cache verifies every tarball against the lock's sha512 integrity; nothing else is written
#   build  (offline) `npm ci --offline` from that cache into node_modules/, then write bin/xdrcheck-driver, a
#          wrapper around the shared driver source in ../src/ with the node found at build time
#   test   (offline) the shared driver tests for this version (../test/), after build
#   clean  remove node_modules/ and bin/
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION := $(notdir $(CURDIR))
JSDIR := $(abspath $(CURDIR)/..)
XDRCHECK_CACHE_DIR ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)/conform/drivers-js-$(VERSION)
STAMP := $(XDRCHECK_CACHE_DIR)/fetched

# npm keeps its cache and logs inside the directory's cache; no install script ever runs.
NPM := npm_config_cache=$(XDRCHECK_CACHE_DIR)/npm npm_config_logs_dir=$(XDRCHECK_CACHE_DIR)/npm-logs \
  npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false npm
NPM_CI := ci --ignore-scripts --no-audit --no-fund --no-bin-links --loglevel=warn

.PHONY: fetch build test clean

fetch:
	mkdir -p $(XDRCHECK_CACHE_DIR)/stage
	cp package.json package-lock.json $(XDRCHECK_CACHE_DIR)/stage/
	cd $(XDRCHECK_CACHE_DIR)/stage && $(NPM) $(NPM_CI)
	rm -rf $(XDRCHECK_CACHE_DIR)/stage/node_modules
	sha256sum package-lock.json | cut -d' ' -f1 > $(STAMP)

build:
	@test -z "$${XDRCHECK_SDK_VERSION:-}" || test "$$XDRCHECK_SDK_VERSION" = "$(VERSION)" || { echo "js $(VERSION): XDRCHECK_SDK_VERSION is $$XDRCHECK_SDK_VERSION" >&2; exit 1; }
	@test -f $(STAMP) || { echo "js $(VERSION): $(XDRCHECK_CACHE_DIR) is empty; run xdrcheck conform fetch (or make fetch) first" >&2; exit 1; }
	@test "$$(cat $(STAMP))" = "$$(sha256sum package-lock.json | cut -d' ' -f1)" || { echo "js $(VERSION): the cache was filled from another package-lock.json; fetch again" >&2; exit 1; }
	$(NPM) $(NPM_CI) --offline
	@node=$$(command -v node) || { echo "js $(VERSION): node is not on PATH" >&2; exit 1; }; \
	  mkdir -p bin; sed "s|@NODE@|$$node|" $(JSDIR)/src/xdrcheck-driver.in > bin/xdrcheck-driver.tmp; \
	  chmod +x bin/xdrcheck-driver.tmp; mv bin/xdrcheck-driver.tmp bin/xdrcheck-driver
	out=$$(printf '%s\n' '{"xcc":"xcc.driver/1","id":1,"op":"describe"}' '{"xcc":"xcc.driver/1","id":2,"op":"shutdown"}' \
	  | bin/xdrcheck-driver); [[ "$$out" == *'"package":"@stellar/stellar-sdk","version":"$(VERSION)"'* ]] \
	  || { echo "js $(VERSION): the built driver does not describe @stellar/stellar-sdk $(VERSION)" >&2; exit 1; }

test: build
	@test -x bin/xdrcheck-driver || { echo "js $(VERSION): bin/xdrcheck-driver is missing; run make build first" >&2; exit 1; }
	node $(JSDIR)/test/run.mjs --driver bin/xdrcheck-driver --version $(VERSION)

clean:
	rm -rf bin node_modules
