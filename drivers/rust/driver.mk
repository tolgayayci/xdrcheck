# Rules shared by every Rust driver directory (drivers/rust/<stellar-xdr version>/Makefile includes this).
# They meet the driver directory contract in drivers/README.md:
#   fetch  (network allowed) fill $(XDRCHECK_CACHE_DIR) with the crates the committed Cargo.lock names; cargo
#          checks every .crate against the lock's sha256
#   build  (offline) build bin/xdrcheck-driver from the directory and $(XDRCHECK_CACHE_DIR) alone
#   test   (offline) the driver's own checks (src/selftest.rs), after build
#   clean  remove what build made
# One source tree (../src) is compiled against each crate version; the version's Cargo.toml selects the
# stellar-strkey API with the cargo feature strkey-1.
#
# Built from an SDK checkout (xdrcheck conform fetch|build --sdk PATH sets XDRCHECK_SDK_SOURCE, in a private copy of
# drivers/rust): fetch points the copy's stellar-xdr dependency at the checkout (path = XDRCHECK_SDK_SOURCE, same
# features), refreshes the copy's Cargo.lock for it (cargo update, network allowed) and fetches what the
# checkout needs; build is unchanged and leaves bin/xdrcheck-sdk-source naming the checkout. The copy's Cargo.toml
# and Cargo.lock change; the committed ones never do (the rules refuse to run on a directory inside the
# repository). describe then reports the checkout's own crate version.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION := $(notdir $(patsubst %/,%,$(CURDIR)))
XDRCHECK_CACHE_DIR ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)/conform/drivers-rust-$(VERSION)
XDRCHECK_ROOT ?= $(abspath $(CURDIR)/../../..)
XDRCHECK_SDK_SOURCE ?=

# The registry, the downloaded crates and the build output all live in the cache; the directory only gets bin/.
CARGO_ENV := CARGO_HOME=$(XDRCHECK_CACHE_DIR)/cargo CARGO_TARGET_DIR=$(XDRCHECK_CACHE_DIR)/target
CARGO_OFFLINE := $(CARGO_ENV) CARGO_NET_OFFLINE=true cargo
RELEASE := $(XDRCHECK_CACHE_DIR)/target/release

.PHONY: fetch build test clean source-guard

# Refuse to rewrite Cargo.toml in the repository itself: a checkout build runs in the copy xdrcheck conform makes.
source-guard:
	@if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  case "$(CURDIR)/" in "$(abspath $(XDRCHECK_ROOT))/"*) \
	    echo "rust $(VERSION): XDRCHECK_SDK_SOURCE builds only in a copy of the driver directory (xdrcheck conform fetch --sdk makes one), never in $(CURDIR)" >&2; exit 1;; esac; \
	  case "$(XDRCHECK_SDK_SOURCE)" in /*) ;; *) echo "rust $(VERSION): XDRCHECK_SDK_SOURCE must be an absolute path, got $(XDRCHECK_SDK_SOURCE)" >&2; exit 1;; esac; \
	  grep -qE '^name = "stellar-xdr"' "$(XDRCHECK_SDK_SOURCE)/Cargo.toml" 2>/dev/null || { echo "rust $(VERSION): $(XDRCHECK_SDK_SOURCE)/Cargo.toml is not the stellar-xdr crate" >&2; exit 1; }; \
	fi

# With XDRCHECK_SDK_SOURCE: the stellar-xdr line of the copy's Cargo.toml gets path = XDRCHECK_SDK_SOURCE in place of its
# version (or of an earlier path), keeping its features; cargo update then locks the checkout and whatever new
# dependencies it brings.
fetch: source-guard
	mkdir -p $(XDRCHECK_CACHE_DIR)/cargo
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  sed -E -i 's#^(stellar-xdr = \{ )(version|path) = "[^"]*"#\1path = "$(XDRCHECK_SDK_SOURCE)"#' Cargo.toml; \
	  grep -qF 'stellar-xdr = { path = "$(XDRCHECK_SDK_SOURCE)"' Cargo.toml || { echo "rust $(VERSION): could not point stellar-xdr at $(XDRCHECK_SDK_SOURCE) in Cargo.toml" >&2; exit 1; }; \
	  $(CARGO_ENV) cargo update --manifest-path Cargo.toml -p stellar-xdr; \
	fi
	$(CARGO_ENV) cargo fetch --locked --manifest-path Cargo.toml
	echo "stellar-xdr $(VERSION) $(XDRCHECK_SDK_SOURCE)" > $(XDRCHECK_CACHE_DIR)/fetched

build: source-guard
	@test -f $(XDRCHECK_CACHE_DIR)/fetched || { echo "rust $(VERSION): $(XDRCHECK_CACHE_DIR) is empty; run xdrcheck conform fetch first" >&2; exit 1; }
	rm -f bin/xdrcheck-sdk-source
	$(CARGO_OFFLINE) build --release --offline --locked --manifest-path Cargo.toml --bins
	mkdir -p bin
	install -m 0755 $(RELEASE)/xdrcheck-driver $(RELEASE)/xdrcheck-driver-selftest bin/
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then echo "$(XDRCHECK_SDK_SOURCE)" > bin/xdrcheck-sdk-source; fi

test: build
	$(CARGO_OFFLINE) clippy --release --offline --locked --manifest-path Cargo.toml --bins -- -D warnings
	bin/xdrcheck-driver-selftest bin/xdrcheck-driver $(VERSION) $(XDRCHECK_ROOT)

clean:
	rm -rf bin
	[ ! -d $(XDRCHECK_CACHE_DIR)/target ] || $(CARGO_ENV) cargo clean --manifest-path Cargo.toml
