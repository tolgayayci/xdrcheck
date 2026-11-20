#!/usr/bin/env bash
# Offline self-test of the maintenance jobs' scripts (docs/maintenance.md, sections 5.3 and 5.4); one case group per
# file in scripts/nightly/selftest.d/, sourced in name order. No network, no
# docker, no package manager: every networked step is replaced by a fixture.
#
#   renovate   the regex manager in renovate.json, run with Node's regular expressions over pins.toml, finds
#              exactly the pins `xdrcheck pins latest --list` tracks, with the same current values
#   canary     scripts/nightly/canary.sh with XDRCHECK_CANARY_PLAN=1 and a fixture `xdrcheck pins latest` output: a family
#              whose newest version is pinned needs no canary; one whose newest version is not gets a canary
#              column per profile of its newest pinned column; canary.py rename maps them back
#   vnext      scripts/nightly/vnext-core.sh with XDRCHECK_VNEXT_PLAN=1 and a fixed commit prints the next-protocol
#              build; a cached build is reused, and passes the inspect step only when its ledger protocol is
#              above protocol.max_supported
#
# Usage: scripts/nightly/maint-selftest.sh   (needs go/bin/xdrcheck and node; `make maint-selftest` builds xdrcheck)
# Exit 0 every case passed; 1 otherwise.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
XDRCHECK="$ROOT/go/bin/xdrcheck"
[ -x "$XDRCHECK" ] || { echo "maint-selftest: $XDRCHECK is not built; run make build" >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
ok() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; failed=1; }

# Shared fixture: the pins `xdrcheck pins latest` tracks ($tmp/tracked.json).
"$XDRCHECK" pins latest --list --json "$tmp/tracked.json" >/dev/null

# Every case group in selftest.d/, in name order: each is sourced, shares tmp, ok and bad, and adds its
# own cases. A new self-test adds a file there and edits nothing else.
for group in "$ROOT"/scripts/nightly/selftest.d/*.sh; do
  # shellcheck source=/dev/null
  source "$group"
done

if [ $failed = 0 ]; then
  echo "maint-selftest: passed"
else
  echo "maint-selftest: FAILED"
fi
exit $failed
