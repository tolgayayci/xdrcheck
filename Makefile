# One target per check; the same commands run locally and in CI. `make help` lists them by who runs them.
# The fetch targets are the only ones that use the network. Everything else runs offline:
# `make verify OFFLINE=1` wraps each run step in scripts/offline-run.sh.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

PY       ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)
REPORTS  ?= reports
NIGHTLY_REPORTS ?= reports-nightly
OFFLINE  ?=
# Settings exported under the kit's earlier name still apply: every XCC_<NAME> from the environment whose
# XDRCHECK_<NAME> is not set is exported to every step as XDRCHECK_<NAME>. A variable of the new name always wins.
$(foreach v,$(filter XCC_%,$(.VARIABLES)),$(if $(filter environment%,$(origin $(v))),$(if $(filter undefined,$(origin XDRCHECK_$(patsubst XCC_%,%,$(v)))),$(eval export XDRCHECK_$(patsubst XCC_%,%,$(v)) := $$($(v))))))
# The per-user cache. Earlier versions of the kit kept it in ~/.cache/xcc; that directory is used while
# ~/.cache/xdrcheck does not exist, so an existing cache keeps working. Exported to every step and tool.
XDRCHECK_CACHE ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)
export XDRCHECK_CACHE
RUN      := $(if $(OFFLINE),$(CURDIR)/scripts/offline-run.sh,)

# The tools. Rust binaries always go to ./target, whatever CARGO_TARGET_DIR the shell exports, so these paths
# hold; `make build` also links every user-facing tool into ./bin.
CORPUS   := target/release/xdrcheck-corpus
MUTATE   := target/release/xdrcheck-mutate
XDRCHECK := go/bin/xdrcheck
XDRLINT  := lint/bin/xdrlint
CARGO_BUILD := cargo build --locked --release --workspace --target-dir $(CURDIR)/target
GO_TOOLS := ./cmd/... ./adapters/baseline/cmd/... ./adapters/walletbackend/cmd/... ./adapters/stellaretl/cmd/... ./adapters/minimal ./adapters/demo
# ./bin/<name> -> where the tool is built.
BIN_LINKS := xdrcheck-corpus:../$(CORPUS) xdrcheck-mutate:../$(MUTATE) xdrcheck:../$(XDRCHECK) xdrlint:../$(XDRLINT) \
             baseline:../go/bin/baseline wallet-backend-adapter:../go/bin/wallet-backend-adapter \
             stellaretl:../go/bin/stellaretl minimal:../go/bin/minimal demo:../go/bin/demo

# A target that runs a tool first brings it up to date through its tool-* prerequisite (cargo and go rebuild only
# what changed), so a stale binary never runs. A tool given on the command line (`make verify-findings
# XDRCHECK=/path/to/xdrcheck`) is used as it is, and must exist.
define need
	@test -x "$(1)" || { echo "$@: $(1) is not built yet (run make build)" >&2; exit 1; }
endef

.PHONY: help toolchain fetch fetch-replay fetch-sdk fetch-lint build tool-rust tool-xdrcheck \
        verify-static verify-corpus verify-generate test test-rust test-go test-drivers test-cli test-fast test-rust-fast test-go-fast \
        harness-selftest verify-memory \
        verify-replay verify-replay-pr replay-full replay-etl-known verify-conformance verify-conformance-js verify-conformance-public lint-fixtures lint-wallet-backend lint-before-after lint-selftest \
        lint-stellar-etl \
        lint-docs lint-plugin verify-lint verify-lint-pr \
        verify-guide verify-coverage verify-findings verify-findings-acceptance acceptance-report acceptance-report-pr verify verify-pr \
        verify-acceptance verify-goldens-nightly repo-checks overlay-audit release fetch-nightly nightly-regenerate \
        nightly-differential nightly-early-warning nightly-refetch mutate-sensitivity nightly-xdr-watch xdr-ceilings \
        dist-bin dist-image release-assets action-selftest

# `##@ Group` starts a group in `make help`; each target's `## text` is its one line there.
help:
	@awk 'BEGIN { FS = ":.*## " } \
	  /^##@ / { printf "\n%s\n", substr($$0, 5); next } \
	  /^[a-z][a-z0-9-]*:.*## / { printf "%-27s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo
	@echo "OFFLINE=1 runs a target's steps with the network cut. docs/cli.md describes every target."

tool-rust:
ifeq ($(origin CORPUS)$(origin MUTATE),filefile)
	$(CARGO_BUILD) --quiet
else
	$(call need,$(CORPUS))
endif

tool-xdrcheck:
ifeq ($(origin XDRCHECK),file)
	cd go && go build -o bin/xdrcheck ./cmd/xdrcheck
else
	$(call need,$(XDRCHECK))
endif

##@ Everyone
toolchain: ## check toolchains against pins.toml
	scripts/toolchain-check.sh

# FETCH_ONLY="PART..." fetches only those parts (scripts/fetch.sh lists them); each CI job names the ones its target needs.
FETCH_ONLY ?= all
fetch: ## network: everything every target needs (dependencies, goldens, images, driver packages, pipeline sources); pinned, hash-verified; FETCH_ONLY picks parts
	scripts/fetch.sh $(FETCH_ONLY)

build: ## build every tool and link them into ./bin
	$(CARGO_BUILD)
	cd go && go build -o bin/ $(GO_TOOLS)
	[ ! -f lint/go.mod ] || (cd lint && go build -o bin/ ./cmd/...)
	@mkdir -p bin
	@for l in $(BIN_LINKS); do ln -sfn "$${l#*:}" "bin/$${l%%:*}"; done
	@echo "build: tools in $(CURDIR)/bin: $$(cd bin && ls | tr '\n' ' ')"
	@echo 'export PATH="$$PWD/bin:$$PATH"'

demo: tool-xdrcheck ## the one-minute demo: an indexer with a planted bug, its failures and their repro commands
	scripts/demo.sh reports-demo

##@ Indexer authors
fetch-replay: ## network: build dependencies and the object-store image for xdrcheck replay
	scripts/fetch.sh replay

fetch-lint: ## network: build dependencies and golangci-lint with the xdrlint plugin
	scripts/fetch.sh lint

lint-plugin: ## the xdrlint module plugin loads under the pinned golangci-lint (built by make fetch-lint)
	$(RUN) lint/plugin/golangci.sh run

check-adapter-ts: tool-xdrcheck ## the TypeScript minimal adapter: selftest and a full replay
	c=$${XDRCHECK_CACHE:-$$HOME/.cache/xdrcheck}/conform/drivers-js-17.4.0/npm; \
	if [ -d "$$c" ]; then XDRCHECK_NPM_CACHE="$$c" examples/adapter-ts/check.sh $(REPORTS)/adapter-ts; \
	else examples/adapter-ts/check.sh $(REPORTS)/adapter-ts; fi

harness-selftest: tool-xdrcheck ## seeded-bug indexers land in their documented classes
	$(RUN) scripts/harness-selftest.sh $(REPORTS)/selftest

##@ SDK maintainers
fetch-sdk: ## network: build dependencies and every public conformance column's driver packages
	scripts/fetch.sh sdk

# The corpus loaders (docs/use-in-sdk-ci.md §1) against the repository's corpus; and the SDK CI recipes
# (examples/sdk-ci) against the pinned SDKs, from the caches make fetch-sdk fills (the Go module cache of the
# go-stellar-sdk driver, the Python driver's wheelhouse); the Rust ones need their crates in the cargo cache.
# The SDK versions the examples pin, whose driver caches hold their packages.
SDKCI_GO_SDK := $(shell awk '$$1 == "github.com/stellar/go-stellar-sdk" {print $$2}' examples/sdk-ci/go/go.mod)
SDKCI_PY_SDK := $(shell sed -n 's/^stellar-sdk==\([^ ]*\).*/\1/p' examples/sdk-ci/python/requirements.txt)
SDKCI_VENV   := $(or $(XDRCHECK_CACHE),$(HOME)/.cache/xdrcheck)/sdk-ci/python-venv
sdk-loaders: ## the corpus loaders for SDK tests (Go, Rust, Python, npm) against this corpus
	cd packages/go && $(RUN) env GOPROXY=off GOFLAGS=-mod=readonly go test -count=1 ./...
	cd packages/rust && $(RUN) cargo test --locked --offline --target-dir $(CURDIR)/target/sdk-loaders
	cd packages/python && $(RUN) $(PY) -I -m unittest discover -s tests
	cd packages/npm && $(RUN) node --test test/archive.test.mjs

sdk-ci-examples: ## the Go, Rust and Python SDK CI recipes (examples/sdk-ci) against the pinned SDKs, offline
	cd examples/sdk-ci/go && XDRCHECK_CORPUS=$(CURDIR)/corpus $(RUN) env GOPROXY=off GOFLAGS=-mod=readonly \
	  GOMODCACHE=$(or $(XDRCHECK_CACHE),$(HOME)/.cache/xdrcheck)/conform/drivers-go-$(SDKCI_GO_SDK)/gomod go test -count=1 ./...
	XDRCHECK_CORPUS=$(CURDIR)/corpus $(RUN) cargo test --locked --offline --manifest-path examples/sdk-ci/rust/Cargo.toml \
	  --target-dir $(CURDIR)/target/sdk-ci-examples
	rm -rf $(SDKCI_VENV) && $(PY) -I -m venv $(SDKCI_VENV)
	$(RUN) $(SDKCI_VENV)/bin/python -I -m pip install --isolated --disable-pip-version-check --quiet --no-index --require-hashes \
	  --find-links $(or $(XDRCHECK_CACHE),$(HOME)/.cache/xdrcheck)/conform/drivers-python-$(SDKCI_PY_SDK)/wheels -r examples/sdk-ci/python/requirements.txt
	$(RUN) $(SDKCI_VENV)/bin/python -I -m pip install --isolated --disable-pip-version-check --quiet --no-index --no-deps ./packages/python
	cd examples/sdk-ci/python && XDRCHECK_CORPUS=$(CURDIR)/corpus $(RUN) $(SDKCI_VENV)/bin/python -I -m unittest discover -v -s . -p test_corpus.py

# Over the public column set's run (make verify-conformance-public first), into its report directory: the
# readiness table (readiness.md, readiness.json) and the scoreboard page (scoreboard.html).
sdk-readiness: tool-xdrcheck ## which pinned SDK versions decode each protocol's shapes; the scoreboard page
	$(XDRCHECK) conform readiness --report $(REPORTS)/conformance-public > /dev/null
	$(XDRCHECK) conform scoreboard --report $(REPORTS)/conformance-public

# sdk-regression asserts the three JS acceptance defects; run writes the pr-set matrix (exit 1 = unexpected cells, which
# check then lists and decides on; exit 2 = the run itself failed); check fails on undeclared cells unless they
# are pending a finding (overlay records: CONFORM_CHECK_FLAGS="--overlay DIR" or XDRCHECK_OVERLAY; the committed list
# findings/pending/conformance.json); CONFORM_CHECK_FLAGS="--mode acceptance" makes pending cells fail.
# The columns `xdrcheck conform sdk-regression` asserts on (go/internal/conform/sdk_regression.go SDKRegressionColumns).
SDK_REGRESSION_COLUMNS := js@17.2.0,js@17.2.1,js@17.3.0
verify-conformance: tool-xdrcheck ## sdk-regression (cases js-1766, js-1785, js-1789) and the cross-SDK divergence matrix
	$(RUN) $(XDRCHECK) conform build --set pr
	mkdir -p $(REPORTS)/conformance
	$(RUN) $(XDRCHECK) conform sdk-regression --report $(REPORTS)/conformance
	$(RUN) $(XDRCHECK) conform run --set pr --report $(REPORTS)/conformance > $(REPORTS)/conformance/cells.txt || [ $$? -eq 1 ]
	$(RUN) $(XDRCHECK) conform check $(CONFORM_CHECK_FLAGS) $(REPORTS)/conformance/matrix.json

# The pull-request form of sdk-regression (.github/workflows/pr.yml): the same `xdrcheck conform sdk-regression` assertions on the same
# three JavaScript columns, without the pr-set matrix around them, which the full CI runs (make verify-conformance).
verify-conformance-js: tool-xdrcheck ## sdk-regression alone: the JS acceptance assertions on their three JS columns (pull-request CI)
	$(RUN) $(XDRCHECK) conform build --columns $(SDK_REGRESSION_COLUMNS)
	mkdir -p $(REPORTS)/conformance
	$(RUN) $(XDRCHECK) conform sdk-regression --report $(REPORTS)/conformance

# The same run and check on the widest public column set (drivers/sets.toml `public`: `pr` plus the JS 16.x line,
# the older Python release and stellar-core's own decoder), into its own report directory. Not part of the per-PR
# `verify`: it repeats every `pr` cell and takes about two minutes more. The acceptance findings check needs it,
# because some finding records' rows come only from these columns.
verify-conformance-public: tool-xdrcheck ## conformance on the public column set (acceptance and nightly)
	$(RUN) $(XDRCHECK) conform build --set public
	mkdir -p $(REPORTS)/conformance-public
	$(RUN) $(XDRCHECK) conform run --set public --report $(REPORTS)/conformance-public > $(REPORTS)/conformance-public/cells.txt || [ $$? -eq 1 ]
	$(RUN) $(XDRCHECK) conform check $(CONFORM_CHECK_FLAGS) $(REPORTS)/conformance-public/matrix.json

# The corpus release archive in dist/ (docs/release.md): built twice and compared, every file a manifest names
# checked to be in it, verified offline from an empty directory, and the npm package run against the pinned
# JavaScript SDK offline. Needs `make fetch-sdk` (or `make fetch`). VERSION=<MAJOR+1>.0.0-rc.N builds the -next
# channel instead (refused while the corpus has no next-protocol entry).
release: tool-rust ## the corpus release archive in dist/: built twice, verified offline, npm package checked
	scripts/release.sh all

##@ Corpus authors
SCENARIOS ?= corpus/scenarios/pr.list
# DOCS=0 skips the documentation repository's own checks in verify-guide; they run offline from what
# `make fetch` prepared (scripts/fetch.d/docs.sh).
DOCS      ?= 1

repo-checks: ## repository-level checks that need no product code (schemas, corpus data, IDs, leaks)
	$(PY) scripts/py/check_schemas.py
	$(PY) scripts/py/check_corpus.py
	$(PY) scripts/py/check_ids.py
	$(PY) scripts/py/check_fields.py
	$(PY) scripts/py/check_guide_claims.py
	$(PY) scripts/py/check_public.py
	$(PY) scripts/py/test_check_public.py
	$(PY) scripts/py/check_slug.py
	$(PY) scripts/py/check_slug.py --self-test
	$(PY) apps/docs/scripts/generate.py --check
	$(PY) apps/dashboard/scripts/build_data.py --check
	$(PY) apps/dashboard/scripts/test_site.py
	$(PY) scripts/py/check_guide_entries.py
	$(RUN) $(PY) scripts/py/check_text_refs.py
	scripts/ci/check-workflows.sh
	@# The generated files the corpus tool checks without any cache (the guide's field table, the coverage report
	@# with the golden mirror listing, the corpus index), when it is built; CI's verify-static, verify-guide and
	@# verify-coverage run them again with the tool built from the commit.
	@if [ -x "$(CORPUS)" ]; then \
	  set -x; $(CORPUS) guide-table --check && $(CORPUS) coverage --check && $(CORPUS) index --check; \
	else echo "repo-checks: $(CORPUS) is not built (make build); guide-table, coverage and index checks skipped"; fi

verify-static: repo-checks tool-rust tool-xdrcheck ## schemas, hashes, entry IDs, pins
	$(RUN) $(CORPUS) verify --checks schema,hashes,ids
	$(RUN) $(CORPUS) index --check
	$(RUN) $(XDRCHECK) pins check

verify-corpus: tool-rust ## roundtrip, golden-agreement (AG-1, AG-4)
	mkdir -p $(REPORTS)
	$(RUN) $(CORPUS) verify --tier curated --report $(REPORTS)/corpus-verify.json
	$(RUN) $(CORPUS) verify --tier curated --checks ag4 --report $(REPORTS)/corpus-verify-ag4.json

verify-generate: tool-rust ## regenerate the per-PR scenario list with no network and compare with the corpus
	$(CURDIR)/scripts/offline-run.sh $(CORPUS) gen --check --list $(SCENARIOS)

verify-coverage: tool-rust ## per-CAP coverage is current and every gap is explained
	$(RUN) $(CORPUS) coverage --check

verify-guide: tool-rust ## guide-table: the guide table and claims match their sources
	$(RUN) $(CORPUS) guide-table --check --report $(REPORTS)/guide-table.json
	$(RUN) $(CORPUS) guide-claims --check
	cd lint && $(RUN) go run ./cmd/xdrlint-docs --check
	$(RUN) $(PY) guide/review/build.py --check
	$(if $(filter 1,$(DOCS)),$(RUN) scripts/docs-check.sh,@echo "verify-guide: DOCS=0, skipping the documentation repository's own checks")

test: test-rust test-go test-drivers test-cli ## unit tests of every component: test-rust, test-go, test-drivers and test-cli

test-rust: ## the Rust workspace's tests (cargo test)
	$(RUN) cargo test --locked --workspace

# GO_MODULES picks the Go modules test-go and test-go-fast run (default both; the CI jobs run go and lint apart).
GO_MODULES ?= go lint
test-go: ## the Go tests of go/ and lint/
	for m in $(GO_MODULES); do [ ! -f $$m/go.mod ] || (cd $$m && $(RUN) go test ./...) || exit 1; done

test-cli: ## docs/cli.md against the built tools' help and make help (scripts/py/check_cli_reference.py)
	$(PY) scripts/py/check_cli_reference.py

# DRIVERS=js,js16 runs only those directories of drivers/ (the CI jobs split them; scripts/ci/check_workflows.py
# checks that each workflow's jobs together cover every directory).
DRIVERS ?=
test-drivers: ## every conformance driver directory's own tests (and the overlay's), the directories side by side; DRIVERS=a,b picks some
	XDRCHECK_TEST_DRIVERS=$(DRIVERS) scripts/test-drivers.sh

# The pull-request unit tier (.github/workflows/pr.yml): every Rust test, with the test binaries run side by side
# instead of one after another; the Go tests in -short mode (a test that checks testing.Short() skips: today only
# TestTemplateBuildsInItsOwnModule, which builds the minimal adapter's template as a module of its own); every
# driver directory's tests; the command-line reference check. `make test` runs the same tests without -short, in
# the full CI (.github/workflows/full.yml).
test-fast: test-rust-fast test-go-fast test-drivers test-cli ## the pull-request unit tier: every Rust test in parallel, Go tests with -short, every driver's tests, test-cli

test-rust-fast: ## every test of the Rust workspace, the test binaries side by side (scripts/cargo-test-parallel.sh)
	$(RUN) scripts/cargo-test-parallel.sh

test-go-fast: ## test-go with go test -short: tests that check testing.Short() skip their long part
	for m in $(GO_MODULES); do [ ! -f $$m/go.mod ] || (cd $$m && $(RUN) go test -short ./...) || exit 1; done

##@ Kit maintainers (acceptance, nightly)
verify-memory: tool-xdrcheck ## the replay harness memory-bound test and its negative control
	$(RUN) scripts/verify-memory.sh $(REPORTS)/memory

verify-replay: tool-xdrcheck ## replay-regression (cases wallet-backend-729, wallet-backend-731, wallet-backend-716) on the six pinned wallet-backend commits
	$(RUN) scripts/verify-replay.sh $(REPORTS)/replay-regression

# The pull-request form of replay-regression (.github/workflows/pr.yml): the same script and row-by-row assertions on one input,
# REPLAY_PR_INPUT; the full CI runs both (make verify-replay).
REPLAY_PR_INPUT ?= rpc
verify-replay-pr: tool-xdrcheck ## replay-regression on one input (REPLAY_PR_INPUT, default rpc): the pull-request CI's form of verify-replay
	XDRCHECK_REPLAY_INPUTS=$(REPLAY_PR_INPUT) $(RUN) scripts/verify-replay.sh $(REPORTS)/replay-regression

# The whole corpus against wallet-backend at its pinned current commit, on both inputs: a run of the findings
# check's required set (findings/required-runs.d/). Not part of the per-PR `verify`: about 8 minutes.
replay-full: tool-xdrcheck ## the whole corpus against wallet-backend at the pinned current commit (acceptance)
	$(RUN) scripts/replay-full.sh $(REPORTS)/replay-full

# The corpus entries that declare a stellar-etl replay divergence, against stellar-etl at its pinned commit: a run of
# the findings check's required set, so the stellar-etl rows the pipeline findings rest on are in a checked report.
replay-etl-known: tool-xdrcheck ## the declared stellar-etl replay divergences at the pinned commit (acceptance)
	$(RUN) scripts/replay-etl-known.sh $(REPORTS)/replay-etl-known

lint-fixtures: ## lint-fixtures: every rule fires on its seeded fixtures
	mkdir -p $(REPORTS)
	cd lint && $(RUN) go test -json ./... > $(abspath $(REPORTS))/lint-fixtures.jsonl || \
	  { grep -h '"Action":"fail"' $(abspath $(REPORTS))/lint-fixtures.jsonl >&2; echo "lint-fixtures: failed; test output in $(REPORTS)/lint-fixtures.jsonl" >&2; exit 1; }

# Each linter run then writes <target>.tally.json (xdrcheck findings tally): what a findings check takes from its
# reports, with no site in it. CI withholds a linter report that names a site pending finding review from its upload
# (scripts/ci/withhold-pending.py), and the findings checks downstream read the tally in its place. The tally is
# written after a failed run too, as long as the run left its reports; the target's exit status is the run's.
define lint_tally
	$(RUN) $(XDRCHECK) findings tally --make $@ $(REPORTS) || [ $$rc -ne 0 ]; exit $$rc
endef

lint-wallet-backend: tool-xdrcheck ## lint-current at the pinned current commit; the summary states whether xdrlint exits 0 (clean) (the script builds xdrlint)
	rc=0; PY=$(PY) $(RUN) scripts/lint-pipeline.sh current $(REPORTS) || rc=$$?; \
	$(lint_tally)

lint-before-after: tool-xdrcheck ## lint-current: each rule fires before its fix and is silent after (the script builds xdrlint)
	rc=0; PY=$(PY) $(RUN) scripts/lint-pipeline.sh before-after $(REPORTS) || rc=$$?; \
	$(lint_tally)

lint-stellar-etl: tool-xdrcheck ## xdrlint on the pinned stellar-etl commit, built with the Go toolchain stellar-etl requires
	rc=0; PY=$(PY) $(RUN) scripts/lint-stellar-etl.sh $(REPORTS) || rc=$$?; \
	$(lint_tally)

lint-selftest: ## lint-current can fail: an added finding, a new report in a suppressed function, a widened or stale suppression and a stale pending entry each turn the pinned run red
	PY=$(PY) $(RUN) scripts/lint-pipeline.sh selftest $(REPORTS)

lint-docs: ## the rule pages in lint/docs match the rule registry, fragments and fixtures
	cd lint && $(RUN) go run ./cmd/xdrlint-docs -check

verify-lint: lint-fixtures lint-wallet-backend lint-before-after lint-stellar-etl lint-selftest ## lint-fixtures, lint-current

# The pull-request form (.github/workflows/pr.yml): the fixtures and the pinned current wallet-backend commit; the
# before/after pairs, stellar-etl and the self-test run in the full CI (make verify-lint).
verify-lint-pr: lint-fixtures lint-wallet-backend ## lint-fixtures and the current wallet-backend commit of lint-current (pull-request CI)

verify-findings: tool-xdrcheck ## findings-linked, development mode (drafts allowed)
	$(RUN) $(XDRCHECK) findings check --mode development $(REPORTS)

# Acceptance reads every report under $(REPORTS); run verify-conformance-public first (verify-acceptance does) so
# the public column set's rows are among them.
# PENDING_OK=1: exit 0 when the only failure is rows awaiting finding review (the full CI on main; findings-linked stays not met
# and the acceptance table says so); every other failure still fails. Without it (a release tag) that fails too.
PENDING_OK ?=
verify-findings-acceptance: tool-xdrcheck ## findings-linked, acceptance mode (every finding filed or resolved)
	$(RUN) $(XDRCHECK) findings check --mode acceptance $(if $(filter 1,$(PENDING_OK)),--pending-ok) $(REPORTS)

acceptance-report: tool-xdrcheck ## the acceptance table: one row per check -> status -> artefact
	$(RUN) $(XDRCHECK) report acceptance $(REPORTS)

# The make targets whose reports only the full CI writes (.github/workflows/full.yml); the pull-request CI runs
# smaller forms of some of them (verify-replay-pr, verify-conformance-js, verify-lint-pr).
FULL_CI_ONLY := verify-replay,verify-conformance,lint-before-after,lint-stellar-etl
acceptance-report-pr: tool-xdrcheck ## the acceptance table of the pull-request CI: a check met there whose other runs only the full CI makes is "proven in full CI"
	$(RUN) $(XDRCHECK) report acceptance $(REPORTS) --full-ci $(FULL_CI_ONLY)

# The pre-push gate of SECURITY.md: needs the private overlay (XDRCHECK_OVERLAY) and skips without it.
overlay-audit: ## no trigger of an embargoed overlay record, and no row-trimmed copy of an overlay file, in the tree
	@if [ -z "$${XDRCHECK_OVERLAY:-}" ]; then echo "overlay-audit: XDRCHECK_OVERLAY is not set; skipped (it needs the private overlay)"; exit 0; fi; \
	  $(MAKE) --no-print-directory tool-xdrcheck; \
	  $(XDRCHECK) overlay audit --overlay "$$XDRCHECK_OVERLAY"

# Release assets (docs/release.md sections 8 to 10, docs/github-action.md). Everything is written under dist/;
# nothing is published. DIST_PLATFORMS picks platforms, DIST_STRICT=1 fails on one that cannot be built here.
dist-bin: ## prebuilt xdrcheck, xdrcheck-corpus, xdrlint per platform in dist/, with SHA256SUMS (network for crates and modules)
	scripts/dist.sh bin

dist-image: ## the container image from dist/ (corpus + Linux binaries), smoke-tested offline, then removed
	scripts/dist.sh image

release-assets: ## SHA256SUMS and provenance over every asset in dist/, verified, plus the image smoke test
	scripts/dist.sh assemble

action-selftest: ## the GitHub Action (action.yml) run step by step against a local release in dist/
	action/selftest.sh reports-action-selftest

verify: verify-static verify-corpus verify-generate harness-selftest verify-memory verify-replay verify-conformance verify-lint verify-guide verify-coverage verify-findings acceptance-report ## every section 1 check

# What the pull-request CI runs (.github/workflows/pr.yml), one job per target there; `verify` and `make test` are
# the full CI's (.github/workflows/full.yml).
verify-pr: verify-static verify-corpus verify-generate test-fast verify-replay-pr verify-conformance-js verify-lint-pr verify-guide verify-coverage verify-findings acceptance-report-pr ## every check of the pull-request CI, then its acceptance table

verify-acceptance: verify-static verify-corpus verify-generate harness-selftest verify-memory verify-replay replay-full replay-etl-known verify-conformance verify-conformance-public verify-lint verify-guide verify-coverage verify-findings-acceptance acceptance-report ## every acceptance check, then the acceptance table

# Nightly jobs (.github/workflows/nightly-goldens.yml, or by hand); none gates a pull request. Each one prints a summary with one line
# per part and writes its logs and reports under $(NIGHTLY_REPORTS), apart from
# $(REPORTS) so the findings checks and the acceptance report never read them. OFFLINE=1 runs their run steps without
# network; XDRCHECK_OVERLAY widens the conformance runs to the overlay-only set and sends those reports to the overlay.
fetch-nightly: ## network: what only the nightly jobs need (driver packages, the stellar-core test image)
	scripts/nightly/fetch.sh

nightly-regenerate: tool-rust ## regenerate every scenario, not only pr.list, with no network
	scripts/nightly/regenerate.sh $(NIGHTLY_REPORTS)

verify-goldens-nightly: tool-rust tool-xdrcheck ## golden-agreement: AG-2 and bulk AG-3 (needs the stellar-core test image)
	OFFLINE=$(OFFLINE) scripts/nightly/goldens.sh $(NIGHTLY_REPORTS)

nightly-differential: tool-xdrcheck ## the curated corpus across every public driver; check, readiness, diff
	OFFLINE=$(OFFLINE) scripts/nightly/differential.sh $(NIGHTLY_REPORTS)

mutate-sensitivity: tool-rust ## xdrcheck mutate re-finds known public findings (TestMutateSensitivity, never skipped; needs the public drivers)
	$(call need,$(MUTATE))
	cd go && XDRCHECK_MUTATE_REQUIRE=1 $(RUN) go test ./cmd/xdrcheck -run '^TestMutateSensitivity$$' -count=1 -v

nightly-early-warning: tool-rust tool-xdrcheck ## stellar-core's next-protocol goldens at master through the oracle, new arms named (fetch needs network)
	OFFLINE=$(OFFLINE) scripts/nightly/early-warning.sh $(NIGHTLY_REPORTS)

# The upgrade watch (docs/maintenance.md, "Watch list"): stellar-xdr main with every #ifdef on, its other branches
# and open pull requests, the standing lcm_v3 item and the XDR diffs of pending CAP documents, each diffed against
# the pinned definitions with `xdrcheck xdr diff`. Digests, the log and a patch of candidate corpus rows go to
# $(NIGHTLY_REPORTS)/xdr-watch. A finding never fails it.
nightly-xdr-watch: tool-xdrcheck ## network: diff unreleased XDR (main, branches, pull requests, CAP documents) against the pins; digests, candidate rows
	scripts/nightly/xdr-watch.sh $(NIGHTLY_REPORTS)

xdr-ceilings: tool-xdrcheck ## regenerate the drivers' enum ceilings from the pinned XDR definitions (make test fails when they drift)
	$(XDRCHECK) xdr ceilings --write

nightly-refetch: ## network: make fetch into an empty cache, then pins, golden and lake hashes
	scripts/nightly/refetch.sh $(NIGHTLY_REPORTS)

# Staying in sync with the networks and upstream releases (docs/maintenance.md, sections 5.2 to 5.4; workflows
# watch-*.yml and vnext-core.yml). Only maint-selftest runs offline.
.PHONY: watch-network nightly-canary vnext-core maint-selftest

watch-network: tool-xdrcheck ## network: Horizon roots and the status page against pins.toml (protocols, dated votes and resets)
	$(XDRCHECK) pins check --network

nightly-canary: tool-xdrcheck ## network: pins behind upstream releases, and the newest SDK releases as canary columns (reports drift, fails only when it cannot run)
	scripts/nightly/canary.sh $(NIGHTLY_REPORTS)

vnext-core: ## network, docker: next-protocol stellar-core build from master, cached by commit (VNEXT_PLAN=1 prints the plan)
	XDRCHECK_VNEXT_PLAN=$(VNEXT_PLAN) scripts/nightly/vnext-core.sh $(NIGHTLY_REPORTS)

maint-selftest: tool-xdrcheck ## offline: renovate.json, the canary and the next-protocol build scripts against fixtures
	scripts/nightly/maint-selftest.sh

# Make fragments by area (mk/*.mk), in name order.
include $(sort $(wildcard mk/*.mk))
