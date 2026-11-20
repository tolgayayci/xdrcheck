#!/usr/bin/env bash
# Nightly golden agreement (golden-agreement; docs/architecture.md, 'What "reproducible" and "agrees with the goldens" mean'):
#
# One part per file in scripts/nightly/goldens.d/ (sourced in this order, then any other part in name order):
#
#   ag2           AG-2 emission proof: the pinned stellar-core test image (pins.toml [stellar_core] test_image)
#                 re-runs core's own `[tx]` tests with `--rng-seed 12345 --check-lcm` against the golden tree
#                 `make fetch` cached. Runs in a container with no network.
#   bulk-oracle   AG-3 on the bulk tier: `xdrcheck-corpus verify --tier bulk --checks hashes,roundtrip,ag3` decodes,
#                 re-encodes and JSON-round-trips every golden ledger in the oracle.
#   bulk-drivers  AG-3 across SDK drivers: `xdrcheck conform run --tier bulk --levels L0` over the same goldens, on the
#                 `public` column set, or on `all` when XDRCHECK_OVERLAY names the private overlay (that run's report
#                 then goes to the overlay, never under the working tree).
#
# Usage: scripts/nightly/goldens.sh <out dir>
# Needs `make fetch` (goldens, stellar-core) and `make fetch-nightly` (driver packages, the test image) first.
# A missing test image makes ag2 BLOCKED, which fails the job like a failed check; XDRCHECK_NIGHTLY_SKIP (comma-separated
# part names: ag2, bulk-oracle, bulk-drivers) skips parts on purpose. Exit 0 every part passed, 1 otherwise.
source "$(dirname "$0")/lib.sh"
nightly_init goldens "${1:?usage: goldens.sh <out dir>}"
need_tool "$CORPUS_BIN"
need_tool "$XDRCHECK_BIN"

tag="v$(pin stellar_core.version)"
goldens_root="${XDRCHECK_GOLDENS:-${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/goldens}"
tree="$goldens_root/$tag"

# The parts, each a file in goldens.d/: the three above in their order, then any other part in name order.
parts_dir="$ROOT/scripts/nightly/goldens.d"
for part in ag2 bulk-oracle bulk-drivers $(cd "$parts_dir" && ls *.sh | sed 's/\.sh$//' | grep -vxE 'ag2|bulk-oracle|bulk-drivers' || true); do
  # shellcheck source=/dev/null
  source "$parts_dir/$part.sh"
done

nightly_finish
