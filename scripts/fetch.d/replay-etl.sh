#!/usr/bin/env bash
# Fetch what `make replay-etl-known` needs offline: the stellar-etl replay adapter's cache (a blob-less clone of
# stellar-etl and its binary built at the pinned commit, pins.toml [pipelines.stellar_etl] commit, with the Go
# toolchain that commit's go.mod names), under ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/adapters/stellar-etl/.
# The adapter fills its cache on its first networked run (go/adapters/stellaretl/README.md), so this script makes
# that run: the entries that declare a stellar-etl divergence, into a temporary report directory it then removes.
# Idempotent: with the binary cached the run only replays (a few seconds). Network: this script only.
set -euo pipefail
cd "$(dirname "$0")/../.."
commit=$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["stellar_etl"]["commit"])' pins.toml)
(cd go && go build -o bin/ ./cmd/xdrcheck ./adapters/stellaretl/cmd/stellaretl)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0
go/bin/xdrcheck replay --corpus corpus --adapter go/bin/stellaretl --target-version "$commit" --assert-known \
  --report "$tmp/report" >"$tmp/replay.log" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] || [ ! -s "$tmp/report/report.json" ]; then
  tail -n 30 "$tmp/replay.log" >&2
  echo "replay-etl: the adapter could not prepare stellar-etl ${commit:0:12} (exit $rc)" >&2
  exit 1
fi
echo "replay-etl: stellar-etl ${commit:0:12} built and cached for the replay adapter"
