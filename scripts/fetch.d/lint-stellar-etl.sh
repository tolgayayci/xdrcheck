#!/usr/bin/env bash
# Fetch what `make lint-stellar-etl` needs offline: the source tree of the pinned stellar-etl commit, the Go
# toolchain its go.mod requires (pins.toml [pipelines.stellar_etl] go_toolchain), and the Go modules the tree and
# xdrlint need to load under that toolchain.
#
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/stellar-etl.git          blobless bare clone of the pinned repository
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/stellar-etl/<commit>/    `git archive` of the commit, with .complete
#
# The toolchain and the modules go to the Go module cache (`go env GOMODCACHE`), so a run with GOPROXY=off finds
# them. Idempotent: a complete tree is skipped. Network: this script only.
set -euo pipefail
cd "$(dirname "$0")/../.."
pins="${XDRCHECK_PINS:-pins.toml}"
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint"

pin() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$pins" "$1"; }

repo="$(pin pipelines.stellar_etl.repo)"
commit="$(pin pipelines.stellar_etl.commit)"
toolchain="go$(pin pipelines.stellar_etl.go_toolchain)"
dir="$cache/stellar-etl/$commit"

# The toolchain the tree requires, and xdrlint's own modules under it.
GOTOOLCHAIN="$toolchain" go version >/dev/null
(cd lint && GOTOOLCHAIN="$toolchain" GOFLAGS=-mod=readonly go list -deps ./cmd/xdrlint >/dev/null)

if [ -f "$dir/.complete" ]; then
  echo "lint-stellar-etl: $commit cached"
  exit 0
fi
git_dir="$cache/stellar-etl.git"
if [ ! -f "$git_dir/HEAD" ]; then
  mkdir -p "$cache"
  rm -rf "$git_dir.part"
  git clone --quiet --bare --filter=blob:none "$repo" "$git_dir.part"
  mv "$git_dir.part" "$git_dir"
fi
git --git-dir "$git_dir" cat-file -e "$commit^{commit}" 2>/dev/null || git --git-dir "$git_dir" fetch --quiet "$repo" "$commit"
rm -rf "$dir"
mkdir -p "$dir"
git --git-dir "$git_dir" archive --format=tar "$commit" | tar -x -C "$dir"
(cd "$dir" && GOTOOLCHAIN="$toolchain" GOFLAGS=-mod=readonly go list -deps ./... >/dev/null)
echo "$commit" >"$dir/.complete"
echo "lint-stellar-etl: $commit extracted, toolchain $toolchain and modules fetched"
