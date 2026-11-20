#!/usr/bin/env bash
# Keep pinned container images in a CI cache directory, so jobs do not pull them on every run.
# Usage: scripts/ci/images.sh load <dir>
#        scripts/ci/images.sh save <dir> <pins.toml image key>...
# `load` imports every saved archive. `make fetch` then pulls by digest whatever is still missing, so a cache
# that does not restore an image's digest costs a pull, never correctness.
# `save` writes one archive per image, and only when every requested image is present: a partial set would
# be cached under the full set's key and never refreshed.
set -euo pipefail
cd "$(dirname "$0")/../.."
cmd="${1:?usage: images.sh load|save <dir> [keys...]}"
dir="${2:?cache directory}"
shift 2
case "$cmd" in
  load)
    shopt -s nullglob
    for tar in "$dir"/*.tar; do
      echo "images: loading $(basename "$tar")"
      docker load --quiet --input "$tar"
    done
    ;;
  save)
    mapfile -t refs < <(python3 -I scripts/ci/pins.py images "$@")
    for ref in "${refs[@]}"; do
      if ! docker image inspect "$ref" >/dev/null 2>&1; then
        echo "images: $ref is not present after make fetch; not caching any image"
        rm -rf "$dir"
        exit 0
      fi
    done
    mkdir -p "$dir"
    for ref in "${refs[@]}"; do
      echo "images: saving $ref"
      docker save --output "$dir/${ref##*@sha256:}.tar" "$ref"
    done
    ;;
  *)
    echo "usage: images.sh load|save <dir> [keys...]" >&2
    exit 2
    ;;
esac
