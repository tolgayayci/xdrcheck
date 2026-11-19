#!/usr/bin/env bash
# The package works in an SDK's CI without the network: in an empty directory, install the pinned
# @stellar/stellar-sdk (pins.toml [js] stellar_sdk, from the conformance driver's committed lock file and its
# package cache) and the packed package from its local tarball, then run entries through the SDK. Every step after
# the copy runs inside scripts/offline-run.sh (no network, loopback only).
#
# Usage: packages/npm/check.sh PACKAGE_TGZ [ENTRY_GLOB]   (default: every entry of the release's corpus/ root)
#
# The whole corpus/ root must pass against the pinned SDK: every variant conforms, or shows the outcome a known
# divergence the entry records for that SDK version predicts (the runner's baseline).
#
# Needs the npm cache that `make fetch` (`xdrcheck conform fetch`) fills for the JavaScript driver of that version, and
# Node at pins.toml [js] node.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
[ "$#" -ge 1 ] || { echo "usage: $0 PACKAGE_TGZ [ENTRY_GLOB]" >&2; exit 2; }
tgz=$(realpath "$1")
entries=()
[ -z "${2:-}" ] || entries=(--entries "$2")

pin() { python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["js"][sys.argv[2]])' "$root/pins.toml" "$1"; }
sdk_version=$(pin stellar_sdk)
node_version=$(pin node)
[ "$(node --version)" = "v$node_version" ] || { echo "check: node is $(node --version), pins.toml says $node_version" >&2; exit 2; }
lock="$root/drivers/js/$sdk_version/package-lock.json"
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/conform/drivers-js-$sdk_version/npm"
[ -f "$lock" ] || { echo "check: no conformance driver lock file for @stellar/stellar-sdk $sdk_version" >&2; exit 2; }
[ -d "$cache" ] || { echo "check: $cache is empty; run make fetch first" >&2; exit 2; }

w="$root/dist/.npm-check"
rm -rf "$w"
mkdir -p "$w/ci"
cp "$tgz" "$w/"
cp "$lock" "$w/ci/package-lock.json"
printf '{\n  "name": "sdk-ci-example",\n  "private": true,\n  "dependencies": {\n    "@stellar/stellar-sdk": "%s"\n  }\n}\n' \
  "$sdk_version" > "$w/ci/package.json"

export npm_config_cache="$cache" npm_config_logs_dir="$w/npm-logs" npm_config_update_notifier=false \
  npm_config_fund=false npm_config_audit=false
cd "$w/ci"
set -x
"$root/scripts/offline-run.sh" npm ci --offline --ignore-scripts --loglevel=warn
"$root/scripts/offline-run.sh" npm install --offline --ignore-scripts --no-save --loglevel=warn "../$(basename "$tgz")"
"$root/scripts/offline-run.sh" ./node_modules/.bin/xdrcheck-corpus-run "${entries[@]}"
{ set +x; } 2>/dev/null
cd "$root"
rm -rf "$w"
echo "npm check: ok"
