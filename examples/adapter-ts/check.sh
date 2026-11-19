#!/usr/bin/env bash
# Checks the TypeScript adapter: installs its one dependency from package-lock.json, runs the harness's
# selftest on it, then replays the whole corpus through it on the SEP-54 directory input. Exits non-zero when
# either fails.
#
# Usage: examples/adapter-ts/check.sh [report dir]   (default reports/adapter-ts)
#
# Needs node 24 and go/bin/xdrcheck (make build). npm installs from the network, or offline from
# XDRCHECK_NPM_CACHE when set (the JS conformance driver's cache holds the same lock: make fetch fills
# ~/.cache/xdrcheck/conform/drivers-js-17.4.0/npm).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:-$root/reports/adapter-ts}"
xdrcheck="$root/go/bin/xdrcheck"
test -x "$xdrcheck" || { echo "adapter-ts: $xdrcheck is not built (make build)" >&2; exit 2; }

npm_flags=(--ignore-scripts --no-audit --no-fund --loglevel=warn)
if [ -n "${XDRCHECK_NPM_CACHE:-}" ]; then
  (cd "$here" && npm_config_cache="$XDRCHECK_NPM_CACHE" npm_config_update_notifier=false npm ci --offline "${npm_flags[@]}")
else
  (cd "$here" && npm_config_update_notifier=false npm ci "${npm_flags[@]}")
fi

cd "$root"
adapter="node examples/adapter-ts/adapter.ts"
"$xdrcheck" replay --adapter "$adapter" --selftest
mkdir -p "$out"
"$xdrcheck" replay --adapter "$adapter" --target-version 0.1.0 --input sep54-dir --report "$out" > "$out/rows.txt"
echo "adapter-ts: selftest and replay passed (one line per row: $out/rows.txt; report: $out/REPORT.md)"
