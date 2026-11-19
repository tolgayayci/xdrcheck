#!/usr/bin/env bash
# Fetch the package caches of every public conformance column (`xdrcheck conform fetch --set public`), so the pull
# request, acceptance and nightly conformance runs find them offline. Idempotent: cached packages are kept.
# $XDRCHECK, when it names a built xdrcheck, is used as it is; otherwise go/bin/xdrcheck is built first.
set -euo pipefail
cd "$(dirname "$0")/../.."
x=${XDRCHECK:-}
if [ -z "$x" ] || [ ! -x "$x" ]; then
  (cd go && go build -o bin/ ./cmd/xdrcheck)
  x=go/bin/xdrcheck
fi
"$x" conform fetch --set public
