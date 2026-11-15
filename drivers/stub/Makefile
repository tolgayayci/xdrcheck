# The orchestrator's test driver. It meets the driver directory contract in drivers/README.md:
#   fetch  (network allowed) fill $(XDRCHECK_CACHE_DIR) from the lock files; here a Go module with no dependencies
#   build  (offline) build bin/xdrcheck-driver from $(XDRCHECK_CACHE_DIR) only
#   test   (offline) the driver's own checks
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

XDRCHECK_CACHE_DIR ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)/conform/drivers-stub
GOENV := GOMODCACHE=$(XDRCHECK_CACHE_DIR)/gomod GOFLAGS=-mod=readonly GOTOOLCHAIN=local

.PHONY: fetch build test clean

fetch:
	mkdir -p $(XDRCHECK_CACHE_DIR)/gomod
	$(GOENV) go mod download
	$(GOENV) go mod verify
	echo "fetched" > $(XDRCHECK_CACHE_DIR)/fetched

build:
	@test -f $(XDRCHECK_CACHE_DIR)/fetched || { echo "stub: $(XDRCHECK_CACHE_DIR) is empty; run xdrcheck conform fetch first" >&2; exit 1; }
	$(GOENV) GOPROXY=off go build -trimpath -o bin/xdrcheck-driver .

# The stub has no dependencies, so its own test needs no fetch.
test:
	$(GOENV) GOPROXY=off go vet ./...
	$(GOENV) GOPROXY=off go build -trimpath -o bin/xdrcheck-driver .
	printf '%s\n' '{"xcc":"xcc.driver/1","id":1,"op":"describe"}' '{"xcc":"xcc.driver/1","id":2,"op":"shutdown"}' \
	  | bin/xdrcheck-driver | grep -q '"ok":true,"op":"shutdown"'

clean:
	rm -rf bin
