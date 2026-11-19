#!/usr/bin/env bash
# The only networked step. Every download is pinned in pins.toml and verified by hash. Run offline steps
# afterwards with OFFLINE=1.
#
# Usage: scripts/fetch.sh [PART...]   (default: all; `make fetch FETCH_ONLY="PART..."` passes the parts)
#   all       (`make fetch`) every part below: what every make target needs
#   replay    (`make fetch-replay`) deps and the pinned object-store image (SeaweedFS, by digest) the replay
#             harness serves the `sep54-s3` input from; the `sep54-dir` and `rpc` inputs need nothing else
#   sdk       (`make fetch-sdk`) deps, the Rust SDK CI example's crates, and every public conformance column's driver
#             packages, stellar-core's own decoder among them (scripts/fetch.d/conform.sh)
#   lint      (`make fetch-lint`) deps (xdrlint's Go modules among them) and golangci
# The parts, which CI jobs pick one by one (.github/workflows/pr.yml, full.yml) so that each fetches only what its target needs:
#   deps            py, cargo and gomod: the build dependencies, common to the groups above
#   py              the Python packages of the repository checks (.venv)
#   cargo           the Rust crates of the workspace (cargo fetch)
#   gomod           the Go modules of go/ and lint/
#   core            the pinned stellar-core package and its runtime libraries (scripts/fetch.d/stellar-core.sh)
#   goldens         stellar-core's golden tree at the pinned tag (scripts/fetch.d/goldens.sh); read by the
#                   ag1 and ag3 checks of a curated `verify` (`make verify-corpus`, `make test`), `make verify-memory`,
#                   the nightly bulk-tier checks and the release check
#   conform         the driver packages of the `public` conformance column set (scripts/fetch.d/conform.sh)
#   conform-pr      the driver packages of the `pr` column set only (`make verify-conformance`)
#   drivers         every driver directory's own packages (make -C drivers/<family> fetch): what `make test` runs,
#                   the spec and XDR-JSON drivers outside the column sets among them
#   driver:DIR      one driver directory, for example driver:go/v0.9.0 (`make harness-selftest`)
#   wallet-backend  the wallet-backend builds and images of the replay adapter (scripts/fetch.d/wallet-backend.sh)
#   replay-etl      the stellar-etl replay adapter's clone and its build at the pinned commit (`make
#                   replay-etl-known`; scripts/fetch.d/replay-etl.sh)
#   lint-sources    the pipeline source trees xdrlint runs on (scripts/fetch.d/lint-{wallet-backend,stellar-etl}.sh)
#   lint-sources-wb the wallet-backend half of lint-sources only (`make verify-lint-pr`)
#   docs            the documentation repository and its packages (scripts/fetch.d/docs.sh)
#   sdk-ci          the crates of the Rust SDK CI example (examples/sdk-ci/rust; `make sdk-ci-recipes`)
#   seaweedfs       the pinned SeaweedFS image (the object-store tests and the replay harness)
#   golangci        golangci-lint with the xdrlint module plugin (scripts/fetch.d/lint-golangci.sh); `make
#                   lint-plugin` only, which no CI job runs
#   mainnet         the mainnet tier's public-lake objects (about 1 GB) into $XDRCHECK_CACHE/mainnet/, each checked
#                   against corpus/mainnet/tier.jsonl (`make verify-mainnet`; the same as `make mainnet-fetch`).
#                   Not part of `all`: only the full CI's mainnet job and a user who runs that check need it
# A conformance part uses $XDRCHECK as it is when that names a built xdrcheck (as the Makefile does with a tool
# given to it), and builds go/bin/xdrcheck otherwise. docs/ci-timings.md lists the time and size of each part.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v mise >/dev/null && eval "$(mise env -s bash 2>/dev/null)"

py() {
  [ -x .venv/bin/python ] || python3 -m venv .venv
  .venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --requirement scripts/py/requirements.txt
}
cargo_deps() { [ ! -f Cargo.lock ] || cargo fetch --locked; }
sdk_ci() { cargo fetch --locked --manifest-path examples/sdk-ci/rust/Cargo.toml; }
gomod() {
  [ ! -f go/go.mod ] || (cd go && go mod download)
  [ ! -f lint/go.mod ] || (cd lint && go mod download)
}

# The pinned SeaweedFS image; the harness runs it as a container or extracts its `weed` executable from it.
seaweedfs_image() {
  local img
  img=$(python3 -I -c 'import tomllib; print(tomllib.load(open("pins.toml", "rb"))["images"]["seaweedfs"])')
  if ! command -v docker >/dev/null; then
    echo "fetch: no docker; the replay harness's sep54-s3 input needs $img (sep54-dir and rpc do not)" >&2
    return 0
  fi
  docker image inspect "$img" >/dev/null 2>&1 || docker pull --quiet "$img"
}

conform_pr() {
  local x=${XDRCHECK:-}
  if [ -z "$x" ] || [ ! -x "$x" ]; then
    (cd go && go build -o bin/ ./cmd/xdrcheck)
    x=go/bin/xdrcheck
  fi
  "$x" conform fetch --set pr
}

drivers() {
  local d
  for d in drivers/*/; do
    [ ! -f "$d/Makefile" ] || make -C "$d" fetch
  done
}

# $CORPUS, when it names a built xdrcheck-corpus, is used as it is (as the Makefile does); otherwise cargo builds it.
mainnet() {
  local c=${CORPUS:-}
  if [ -z "$c" ] || [ ! -x "$c" ]; then
    cargo build --locked --release --quiet -p xdrcheck-corpus
    c=target/release/xdrcheck-corpus
  fi
  "$c" mainnet fetch --jobs "${MAINNET_FETCH_JOBS:-16}"
}

driver() {
  [ -f "drivers/$1/Makefile" ] || { echo "fetch: no driver directory drivers/$1" >&2; exit 2; }
  make -C "drivers/$1" fetch
}

run_part() {
  case "$1" in
    all)
      py; cargo_deps; gomod; sdk_ci
      for f in scripts/fetch.d/*.sh; do bash "$f"; done
      drivers ;;
    replay) py; cargo_deps; gomod; seaweedfs_image ;;
    sdk) py; cargo_deps; gomod; sdk_ci; bash scripts/fetch.d/conform.sh ;;
    lint) py; cargo_deps; gomod; bash scripts/fetch.d/lint-golangci.sh ;;
    deps) py; cargo_deps; gomod ;;
    py) py ;;
    cargo) cargo_deps ;;
    gomod) gomod ;;
    core) bash scripts/fetch.d/stellar-core.sh ;;
    goldens) bash scripts/fetch.d/goldens.sh ;;
    conform) bash scripts/fetch.d/conform.sh ;;
    conform-pr) conform_pr ;;
    drivers) drivers ;;
    driver:*) driver "${1#driver:}" ;;
    wallet-backend) bash scripts/fetch.d/wallet-backend.sh ;;
    replay-etl) bash scripts/fetch.d/replay-etl.sh ;;
    lint-sources) bash scripts/fetch.d/lint-wallet-backend.sh; bash scripts/fetch.d/lint-stellar-etl.sh ;;
    lint-sources-wb) bash scripts/fetch.d/lint-wallet-backend.sh ;;
    docs) bash scripts/fetch.d/docs.sh ;;
    sdk-ci) sdk_ci ;;
    seaweedfs) seaweedfs_image ;;
    golangci) bash scripts/fetch.d/lint-golangci.sh ;;
    mainnet) mainnet ;;
    *) echo "usage: $0 [PART...]; parts: all replay sdk lint deps py cargo gomod core goldens conform conform-pr drivers driver:DIR wallet-backend replay-etl lint-sources lint-sources-wb docs sdk-ci seaweedfs golangci mainnet" >&2
       exit 2 ;;
  esac
}

[ "$#" -gt 0 ] || set -- all
for part in "$@"; do run_part "$part"; done
echo "fetch ($*): done"
