# shellcheck shell=bash
# maint-selftest case group `vnext`: sourced by scripts/nightly/maint-selftest.sh, which provides ROOT,
# XDRCHECK, tmp (a scratch directory, with the shared fixture tmp/tracked.json) and ok/bad (record one case).
# Not run on its own.
commit=0123456789abcdef0123456789abcdef01234567
max=$(python3 -I -c 'import tomllib; print(tomllib.load(open("pins.toml", "rb"))["protocol"]["max_supported"])')
if XDRCHECK_CACHE="$tmp/cache" XDRCHECK_VNEXT_PLAN=1 XDRCHECK_VNEXT_COMMIT=$commit scripts/nightly/vnext-core.sh "$tmp/out" >"$tmp/vnext.log" 2>&1 &&
  grep -q -- '--enable-next-protocol-version-unsafe-for-production' "$tmp/out/vnext-core/plan.txt" &&
  grep -q "checkout --detach $commit" "$tmp/out/vnext-core/plan.txt" &&
  python3 -I -c 'import json, sys; p = json.load(open(sys.argv[1])); assert p["commit"] == sys.argv[2] and "@sha256:" in p["build_image"]' \
    "$tmp/out/vnext-core/plan.json" $commit; then
  ok "vnext: the plan builds the given commit with the next-protocol flag in the pinned build image"
else
  bad "vnext: plan (log: $(tail -n 5 "$tmp/vnext.log"))"
fi
cached() { # <ledger protocol>
  local d="$tmp/cache/stellar-core-vnext/$commit"
  mkdir -p "$d/pkg/usr/bin"
  printf '#!/bin/sh\n' >"$d/pkg/usr/bin/stellar-core"
  chmod +x "$d/pkg/usr/bin/stellar-core"
  printf '{"schema": "xcc.vnext-core/v1", "commit": "%s", "ledger_protocol": %s}\n' $commit "$1" >"$d/manifest.json"
  XDRCHECK_CACHE="$tmp/cache" XDRCHECK_VNEXT_COMMIT=$commit scripts/nightly/vnext-core.sh "$tmp/out" >"$tmp/vnext.log" 2>&1
}
if cached $((max + 1)) && grep -q "PASS     build .*cached build" "$tmp/vnext.log" && grep -q "PASS     inspect" "$tmp/vnext.log"; then
  ok "vnext: a cached build of the commit is reused and inspected"
else
  bad "vnext: cached build (log: $(tail -n 5 "$tmp/vnext.log"))"
fi
if ! cached "$max" && grep -q "FAIL     inspect .*not a next-protocol build" "$tmp/vnext.log"; then
  ok "vnext: a build at protocol $max is refused as not a next-protocol build"
else
  bad "vnext: inspect accepted protocol $max"
fi
