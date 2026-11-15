# The core column's driver: stellar-core's own XDR decoder (the pinned release binary's offline print-xdr and
# dump-xdr), wrapped by a small Go program with no dependencies. It meets the driver directory contract in
# drivers/README.md:
#   fetch  (network allowed) put the pinned stellar-core package (pins.toml [stellar_core]) into
#          $(XDRCHECK_CACHE_DIR)/stellar-core/<version>/ with scripts/fetch.d/stellar-core.sh, which verifies every
#          download and the extracted binary; packages the shared cache already holds are reused
#   build  (offline) check the binary's sha256 against pins.toml and build bin/xdrcheck-driver
#   test   (offline) the driver's own checks (selftest_test.go), after build
#   clean  remove what build made
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

XDRCHECK_ROOT ?= $(abspath $(CURDIR)/../..)
XDRCHECK_PINS ?= $(XDRCHECK_ROOT)/pins.toml
# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)
XDRCHECK_CACHE_DIR ?= $(XDRCHECK_CACHE)/conform/drivers-core

pin = $(shell python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["stellar_core"][sys.argv[2]])' $(XDRCHECK_PINS) $(1))
CORE_VERSION := $(call pin,version)
CORE_BINARY_SHA256 := $(call pin,binary_sha256)
CORE_DIR := $(XDRCHECK_CACHE_DIR)/stellar-core/$(CORE_VERSION)
SHARED_DL := $(XDRCHECK_CACHE)/stellar-core/$(CORE_VERSION)/dl

# The Go build cache lives in the package cache; no module downloads (the module has no dependencies).
GOENV := GOCACHE=$(XDRCHECK_CACHE_DIR)/gocache GOMODCACHE=$(XDRCHECK_CACHE_DIR)/gomod GOFLAGS=-mod=readonly \
	GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOPROXY=off

.PHONY: fetch build test clean

fetch:
	mkdir -p $(CORE_DIR)/dl
	if [ -d $(SHARED_DL) ] && [ $(SHARED_DL) != $(CORE_DIR)/dl ]; then \
	  for f in $(SHARED_DL)/*.deb; do \
	    if [ -e "$$f" ]; then ln -f "$$f" $(CORE_DIR)/dl/ 2>/dev/null || cp -f "$$f" $(CORE_DIR)/dl/; fi; \
	  done; \
	fi
	XDRCHECK_CACHE=$(XDRCHECK_CACHE_DIR) XDRCHECK_PINS=$(XDRCHECK_PINS) $(XDRCHECK_ROOT)/scripts/fetch.d/stellar-core.sh
	echo "stellar-core $(CORE_VERSION)" > $(XDRCHECK_CACHE_DIR)/fetched

build:
	@test -f $(XDRCHECK_CACHE_DIR)/fetched || { echo "drivers/core: $(XDRCHECK_CACHE_DIR) is empty; run make fetch (xdrcheck conform fetch) first" >&2; exit 1; }
	echo "$(CORE_BINARY_SHA256)  $(CORE_DIR)/pkg/usr/bin/stellar-core" | sha256sum --check --quiet
	$(GOENV) go build -trimpath -buildvcs=false \
	  -ldflags "-X main.coreVersion=$(CORE_VERSION) -X main.defaultCacheDir=$(XDRCHECK_CACHE_DIR)" -o bin/xdrcheck-driver .

test: build
	test -z "$$(gofmt -l .)" || { gofmt -l .; echo "drivers/core: run gofmt" >&2; exit 1; }
	$(GOENV) go vet .
	mkdir -p $(XDRCHECK_CACHE_DIR)/tmp
	XDRCHECK_ROOT=$(XDRCHECK_ROOT) XDRCHECK_PINS=$(XDRCHECK_PINS) XDRCHECK_CACHE_DIR=$(XDRCHECK_CACHE_DIR) XDRCHECK_DRIVER_BIN=$(CURDIR)/bin/xdrcheck-driver \
	  TMPDIR=$(XDRCHECK_CACHE_DIR)/tmp $(GOENV) go test -count=1 -v . | grep -v '^=== RUN'

clean:
	rm -rf bin
