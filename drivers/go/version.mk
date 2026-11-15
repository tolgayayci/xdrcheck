# Rules shared by every drivers/go/<version> directory (each Makefile there sets VERSION and includes this
# file). They meet the driver directory contract in drivers/README.md:
#   fetch  (network allowed) download the modules go.sum locks into $(XDRCHECK_CACHE_DIR)/gomod and verify them
#   build  (offline) build bin/xdrcheck-driver from this directory, ../driver and $(XDRCHECK_CACHE_DIR) alone
#   test   (offline) the driver's own checks against this SDK version, after build
#   clean  remove what build made
#
# Built from an SDK checkout (xdrcheck conform fetch|build --sdk PATH sets XDRCHECK_SDK_SOURCE, in a private copy of
# drivers/go): fetch points go.mod at the checkout with a replace directive and resolves the checkout's own
# dependencies (go mod tidy, network allowed); build is unchanged and leaves bin/xdrcheck-sdk-source naming the
# checkout. The copy's go.mod and go.sum change; the committed ones never do (the rules refuse to run on a
# directory inside the repository).
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

# The directory of the kit's earlier name (~/.cache/xcc) is used while ~/.cache/xdrcheck does not exist.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)
XDRCHECK_CACHE_DIR ?= $(XDRCHECK_CACHE)/conform/drivers-go-$(VERSION)
XDRCHECK_ROOT ?= $(abspath $(CURDIR)/../../..)
XDRCHECK_SDK_SOURCE ?=

# The module cache and the build cache both live in the directory's package cache; readonly: never edit go.mod
# or go.sum; local: never fetch a toolchain.
GOENV := GOMODCACHE=$(XDRCHECK_CACHE_DIR)/gomod GOCACHE=$(XDRCHECK_CACHE_DIR)/gocache GOFLAGS=-mod=readonly \
	GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
GO_OFFLINE := GOPROXY=off
PKG := github.com/tolgayayci/xdrcheck/drivers/go/driver
SDK_MODULE := github.com/stellar/go-stellar-sdk

.PHONY: fetch build test clean source-guard

# Refuse to rewrite go.mod in the repository itself: a checkout build runs in the copy xdrcheck conform makes.
source-guard:
	@if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  case "$(CURDIR)/" in "$(abspath $(XDRCHECK_ROOT))/"*) \
	    echo "drivers/go/$(VERSION): XDRCHECK_SDK_SOURCE builds only in a copy of the driver directory (xdrcheck conform fetch --sdk makes one), never in $(CURDIR)" >&2; exit 1;; esac; \
	  test -f "$(XDRCHECK_SDK_SOURCE)/go.mod" || { echo "drivers/go/$(VERSION): $(XDRCHECK_SDK_SOURCE) has no go.mod" >&2; exit 1; }; \
	fi

fetch: source-guard
	mkdir -p $(XDRCHECK_CACHE_DIR)/gomod
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  $(GOENV) go mod edit -replace $(SDK_MODULE)=$(XDRCHECK_SDK_SOURCE); \
	  $(GOENV) GOFLAGS=-mod=mod go mod tidy; \
	fi
	$(GOENV) go mod download
	$(GOENV) go mod verify
	echo "go-stellar-sdk $(VERSION) $(XDRCHECK_SDK_SOURCE)" > $(XDRCHECK_CACHE_DIR)/fetched

build: source-guard
	@test -f $(XDRCHECK_CACHE_DIR)/fetched || { echo "drivers/go/$(VERSION): $(XDRCHECK_CACHE_DIR) is empty; run make fetch (xdrcheck conform fetch) first" >&2; exit 1; }
	rm -f bin/xdrcheck-sdk-source
	$(GOENV) $(GO_OFFLINE) go build -trimpath -buildvcs=false -o bin/xdrcheck-driver .
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then echo "$(XDRCHECK_SDK_SOURCE)" > bin/xdrcheck-sdk-source; fi

test: build
	$(GOENV) $(GO_OFFLINE) go vet . $(PKG)
	XDRCHECK_ROOT=$(XDRCHECK_ROOT) XDRCHECK_DRIVER_BIN=$(CURDIR)/bin/xdrcheck-driver $(GOENV) $(GO_OFFLINE) go test -count=1 $(PKG)

clean:
	rm -rf bin
