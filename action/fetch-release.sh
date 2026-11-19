#!/usr/bin/env bash
# Download a pinned XDRCheck release and verify it: the pin helper for a CI job (docs/release.md section 9).
# Needs bash, curl, tar and sha256sum (or shasum on macOS). Runs on Linux and macOS.
#
# Usage:
#   fetch-release.sh --version VERSION [--sha256sums HEX] [--corpus] [--binaries PLATFORM|auto] [--npm]
#                    [--out DIR] [--repo OWNER/REPO | --base URL|DIR]
#
#   --version VERSION   the release, for example 30.0.0 (stable) or a -next release such as <N>.0.0-rc.1
#   --sha256sums HEX    the sha256 of the release's SHA256SUMS file. Pin it next to the version: then every
#                       downloaded byte is checked against a value from your own repository, not only against
#                       a checksum file fetched from the same place as the assets
#   --corpus            the corpus archive, extracted into DIR/xdrcheck-VERSION/ (corpus/, stress/)
#   --binaries P        the tools for platform P (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, or
#                       auto for this machine), extracted into DIR/xdrcheck-VERSION-P/bin/
#   --npm               the npm package xdrcheck-VERSION.tgz (stable releases), kept as a file
#   --out DIR           where to put everything (default: xdrcheck-VERSION)
#   --repo OWNER/REPO   the GitHub repository whose release (tag vVERSION) holds the assets
#                       (default: $XDRCHECK_REPO, else the project's own repository)
#   --base URL|DIR      read the assets from here instead of a GitHub release: a URL prefix or a local
#                       directory holding SHA256SUMS and the assets (a mirror, or dist/ of a local build)
#
# Prints, on stdout, lines for a GitHub Actions env file ($GITHUB_ENV) or `eval`:
#   XDRCHECK_VERSION=…  XDRCHECK_RELEASE=<release dir>  XDRCHECK_CORPUS=<release dir>/corpus  XDRCHECK_BIN=<dir>
#   XDRCHECK_NPM=<package file>
# Exit 0 when every requested asset is present and matches; 1 on a checksum mismatch or a missing asset;
# 2 on a usage error.
set -euo pipefail

DEFAULT_REPO_URL=https://github.com/tolgayayci/xdrcheck
version="" sums_pin="" want_corpus=0 binaries="" want_npm=0 out="" repo="${XDRCHECK_REPO:-}" base=""
die() { echo "fetch-release: $1" >&2; exit "${2:-1}"; }
usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:-}; shift 2 ;;
    --sha256sums) sums_pin=${2:-}; shift 2 ;;
    --corpus) want_corpus=1; shift ;;
    --binaries) binaries=${2:-}; shift 2 ;;
    --npm) want_npm=1; shift ;;
    --out) out=${2:-}; shift 2 ;;
    --repo) repo=${2:-}; shift 2 ;;
    --base) base=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    *) echo "fetch-release: unknown argument $1" >&2; usage ;;
  esac
done
echo "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$' ||
  die "--version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N, got '$version'" 2
[ -z "$sums_pin" ] || echo "$sums_pin" | grep -Eq '^[0-9a-f]{64}$' || die "--sha256sums must be 64 lowercase hex digits" 2
[ "$want_corpus$want_npm" != 00 ] || [ -n "$binaries" ] || die "nothing to fetch: give --corpus, --binaries or --npm" 2

if [ "$binaries" = auto ]; then
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) die "no binaries for $(uname -s)" 2 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "no binaries for $(uname -m)" 2 ;; esac
  binaries="$os-$arch"
fi
case "$binaries" in ""|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64) ;; *) die "unknown platform $binaries" 2 ;; esac

if [ -z "$base" ]; then
  if [ -n "$repo" ]; then base="https://github.com/$repo/releases/download/v$version"
  else base="$DEFAULT_REPO_URL/releases/download/v$version"; fi
fi
out=${out:-xdrcheck-$version}
mkdir -p "$out"
out=$(cd "$out" && pwd)

sha256() { if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # get NAME: the asset into $out/NAME
  if [ -d "$base" ]; then
    [ -f "$base/$1" ] || die "$1 is not in $base"
    cp "$base/$1" "$out/$1.part"
  else
    curl -fsSL --retry 3 --proto '=https' -o "$out/$1.part" "$base/$1" || die "could not download $base/$1"
  fi
  mv "$out/$1.part" "$out/$1"
}

get SHA256SUMS
if [ -n "$sums_pin" ]; then
  got=$(sha256 "$out/SHA256SUMS")
  [ "$got" = "$sums_pin" ] || die "SHA256SUMS has sha256 $got, the pin says $sums_pin"
  echo "fetch-release: SHA256SUMS matches the pinned sha256" >&2
fi

fetch_checked() { # fetch_checked NAME: download and check against SHA256SUMS
  local want got
  want=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$out/SHA256SUMS")
  [ -n "$want" ] || die "$1 is not listed in the release's SHA256SUMS"
  if [ -f "$out/$1" ] && [ "$(sha256 "$out/$1")" = "$want" ]; then
    echo "fetch-release: $1 already present and matches" >&2; return 0
  fi
  get "$1"
  got=$(sha256 "$out/$1")
  [ "$got" = "$want" ] || { rm -f "$out/$1"; die "$1 has sha256 $got, SHA256SUMS says $want"; }
  echo "fetch-release: $1 ok (sha256 $got)" >&2
}

echo "XDRCHECK_VERSION=$version"
if [ "$want_corpus" = 1 ]; then
  a="xdrcheck-$version.tar.gz"
  fetch_checked "$a"
  rm -rf "$out/xdrcheck-$version"
  tar --no-same-owner -xzf "$out/$a" -C "$out"
  # The archive's own list of every file it holds.
  (cd "$out/xdrcheck-$version" && if command -v sha256sum > /dev/null; then sha256sum -c --quiet SHA256SUMS; else shasum -a 256 -c --quiet SHA256SUMS; fi) ||
    die "the extracted corpus does not match its own SHA256SUMS"
  echo "XDRCHECK_RELEASE=$out/xdrcheck-$version"
  echo "XDRCHECK_CORPUS=$out/xdrcheck-$version/corpus"
fi
if [ -n "$binaries" ]; then
  a="xdrcheck-$version-$binaries.tar.gz"
  fetch_checked "$a"
  rm -rf "${out:?}/xdrcheck-$version-$binaries"
  tar --no-same-owner -xzf "$out/$a" -C "$out"
  echo "XDRCHECK_BIN=$out/xdrcheck-$version-$binaries/bin"
fi
if [ "$want_npm" = 1 ]; then
  a="xdrcheck-$version.tgz"
  fetch_checked "$a"
  echo "XDRCHECK_NPM=$out/$a"
fi
