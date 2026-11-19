#!/usr/bin/env bash
# Fetch what the wallet-backend replay adapter needs offline: the pinned repository, a build of each
# acceptance commit and the current commit, their Go toolchain and modules, and the database and object-store
# images by digest. Idempotent: nothing changes when everything is cached.
set -euo pipefail
cd "$(dirname "$0")/../.."
(cd go && go build -o bin/ ./adapters/walletbackend/cmd/wallet-backend-adapter)
go/bin/wallet-backend-adapter fetch --pins pins.toml
