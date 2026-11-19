#!/usr/bin/env bash
# Fetch stellar-core's golden LedgerCloseMeta tree at the pinned tag into the cache
# ($XDRCHECK_CACHE_DIR or $HOME/.cache/xdrcheck, under goldens/<tag>/) and verify it against the committed
# bulk index corpus/bulk/core-<tag>-<tier>.sha256. Set XDRCHECK_STELLAR_CORE_REPO to a local clone
# holding the tag to read it from there instead of a shallow fetch from GitHub.
set -euo pipefail
cd "$(dirname "$0")/../.."
version=$(awk -F'"' '/^\[stellar_core\]/{s=1;next} /^\[/{s=0} s && $1 ~ /^version *= */{print $2; exit}' pins.toml)
[ -n "$version" ] || { echo "goldens: no [stellar_core] version in pins.toml" >&2; exit 2; }
# $CORPUS, when it names a built xdrcheck-corpus, is used as it is (as the Makefile does); otherwise cargo builds it.
if [ -n "${CORPUS:-}" ] && [ -x "$CORPUS" ]; then
  "$CORPUS" fetch-goldens "v$version"
else
  cargo run --locked --release --quiet -p xdrcheck-corpus -- fetch-goldens "v$version"
fi
