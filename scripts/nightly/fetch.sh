#!/usr/bin/env bash
# The networked step of the nightly jobs, on top of `make fetch`: what only the nightly checks need, pinned.
#
#   images    the stellar-core test image (pins.toml [stellar_core] test_image), pulled by digest, for AG-2
#   drivers   `xdrcheck conform fetch --set public`: the package caches of every public conformance column, from each
#             driver's lock file, so the drivers build and run offline
#
# Usage: scripts/nightly/fetch.sh [images] [drivers]   (no argument: both)
# XDRCHECK_NIGHTLY_SKIP=ag2 skips the image (it is several hundred megabytes). Idempotent: an image already present
# is not pulled again, and the driver caches are filled only where their lock files changed.
set -euo pipefail
cd "$(dirname "$0")/../.."
parts=("$@")
[ ${#parts[@]} -gt 0 ] || parts=(images drivers)

for part in "${parts[@]}"; do
  case "$part" in
    images)
      case ",${XDRCHECK_NIGHTLY_SKIP:-}," in
        *,ag2,*)
          echo "fetch-nightly: XDRCHECK_NIGHTLY_SKIP names ag2; not pulling the stellar-core test image"
          continue
          ;;
      esac
      image=$(python3 -I scripts/ci/pins.py images stellar_core.test_image)
      if docker image inspect "$image" >/dev/null 2>&1; then
        echo "fetch-nightly: have ${image%%@*}"
      else
        echo "fetch-nightly: pulling ${image%%@*} by digest"
        docker pull --quiet "$image"
      fi
      ;;
    drivers)
      [ -x go/bin/xdrcheck ] || (cd go && go build -o bin/ ./cmd/xdrcheck)
      # This is a networked step: drop the offline switches a CI job sets after its own fetch (GOPROXY=off,
      # CARGO_NET_OFFLINE, PIP_NO_INDEX), so the package managers can download what the lock files pin.
      env -u GOPROXY -u CARGO_NET_OFFLINE -u PIP_NO_INDEX go/bin/xdrcheck conform fetch --set public
      ;;
    *)
      echo "usage: scripts/nightly/fetch.sh [images] [drivers]" >&2
      exit 2
      ;;
  esac
done
echo "fetch-nightly: done"
