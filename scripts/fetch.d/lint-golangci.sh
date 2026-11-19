#!/usr/bin/env bash
# Build golangci-lint at the pinned version ([go] golangci_lint in pins.toml) with the xdrlint module plugin from
# this checkout, for `make lint-plugin`. Network: `go install` and `golangci-lint custom`, which clones
# golangci-lint at that tag. Idempotent: nothing is rebuilt while the plugin's sources are unchanged.
set -euo pipefail
cd "$(dirname "$0")/../.."
lint/plugin/golangci.sh build
