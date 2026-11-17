#!/usr/bin/env bash
# Build golangci-lint at the version pinned in pins.toml ([go] golangci_lint) with the xdrlint module plugin
# from this checkout, and run it on a linter fixture.
#
# Usage: lint/plugin/golangci.sh build   (network: installs golangci-lint, then `golangci-lint custom`)
#        lint/plugin/golangci.sh run     (no network: runs the custom binary on lint/testdata/xdr1xx/xdr102
#                                          and checks that the xdrlint reports come out)
#
# Everything is kept under ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/tools/golangci-lint-<version>/:
#   bin/golangci-lint       the stock binary, from `go install`
#   golangci-lint-xdrlint   the custom binary with the plugin, from `golangci-lint custom`
#   plugin.sha256           a hash of the plugin's sources the custom binary was built from; `run` refuses a
#                           binary built from other sources (rebuild with `build`, which `make fetch` runs)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lint="$(cd "$here/.." && pwd)"
root="$(cd "$lint/.." && pwd)"
version="$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["go"]["golangci_lint"])' "$root/pins.toml")"
dir="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/tools/golangci-lint-$version"
custom="$dir/golangci-lint-xdrlint"
export GOTOOLCHAIN=local

sources_hash() {
  (cd "$lint" && find . -name '*.go' -not -path './testdata/*' -not -path './bin/*' -print0 | sort -z |
    xargs -0 sha256sum; sha256sum go.mod go.sum profiles/*.yml) | sha256sum | cut -d' ' -f1
}

case "${1:-}" in
build)
  mkdir -p "$dir/bin"
  if [ ! -x "$dir/bin/golangci-lint" ]; then
    GOBIN="$dir/bin" GOFLAGS= go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$version"
  fi
  want="$(sources_hash)"
  if [ -x "$custom" ] && [ "$(cat "$dir/plugin.sha256" 2>/dev/null)" = "$want" ]; then
    echo "golangci-lint $version with xdrlint: cached"
    exit 0
  fi
  work="$dir/build"
  rm -rf "$work"
  mkdir -p "$work/tmp"
  export TMPDIR="$work/tmp" # golangci-lint custom clones and builds in a temporary directory
  cat >"$work/.custom-gcl.yml" <<YML
version: $version
name: golangci-lint-xdrlint
destination: $dir
plugins:
  - module: github.com/tolgayayci/xdrcheck/lint
    import: github.com/tolgayayci/xdrcheck/lint/plugin
    path: $lint
YML
  (cd "$work" && GOFLAGS= "$dir/bin/golangci-lint" custom -v)
  echo "$want" >"$dir/plugin.sha256"
  rm -rf "$work"
  echo "golangci-lint $version with xdrlint: built $custom"
  ;;
run)
  [ -x "$custom" ] || { echo "golangci.sh: no $custom; run lint/plugin/golangci.sh build (make fetch)" >&2; exit 2; }
  if [ "$(cat "$dir/plugin.sha256" 2>/dev/null)" != "$(sources_hash)" ]; then
    echo "golangci.sh: $custom was built from other plugin sources; rebuild with lint/plugin/golangci.sh build" >&2
    exit 2
  fi
  "$custom" version
  mkdir -p "$dir/runs"
  out="$(mktemp -d "$dir/runs/run-XXXXXX")"
  trap 'rm -rf "$out"' EXIT
  cat >"$out/golangci.yml" <<'YML'
version: "2"
run:
  relative-path-mode: wd
linters:
  default: none
  enable: [xdrlint]
  settings:
    custom:
      xdrlint:
        type: module
        description: XDR ingestion mistakes (XDRCheck)
issues:
  max-issues-per-linter: 0
  max-same-issues: 0
YML
  rc=0
  (cd "$lint" && GOFLAGS=-mod=readonly GOPROXY=off "$custom" run --config "$out/golangci.yml" --output.text.path stdout \
      --output.sarif.path "$out/golangci.sarif" ./testdata/xdr1xx/xdr102/) >"$out/run.txt" 2>&1 || rc=$?
  cat "$out/run.txt"
  # No plugin settings: the package's own .xdrlint.yml is discovered (its account-key sink and normaliser), as
  # under `go vet -vettool`. The fixture's violations in bad.go come out as xdrlint reports (exit 1: issues
  # found), the compliant good.go has no XDR102 report, and the SARIF output names the linter.
  bad="$(grep -c 'xdr102/bad.go:.*XDR102 (error).*(xdrlint)' "$out/run.txt" || true)"
  good="$(grep -c 'xdr102/good.go:.*XDR102' "$out/run.txt" || true)"
  if [ "$rc" -ne 1 ] || [ "$bad" -eq 0 ] || [ "$good" -ne 0 ] || ! grep -q '"xdrlint"' "$out/golangci.sarif"; then
    echo "golangci.sh: exit $rc, $bad XDR102 reports in bad.go, $good in good.go; want exit 1, reports in bad.go only, and xdrlint in the SARIF" >&2
    exit 1
  fi
  echo "golangci.sh: golangci-lint $version loaded the xdrlint plugin: $bad XDR102 reports in lint/testdata/xdr1xx/xdr102/bad.go, none in good.go"
  ;;
*)
  echo "usage: $0 build|run" >&2
  exit 2
  ;;
esac
