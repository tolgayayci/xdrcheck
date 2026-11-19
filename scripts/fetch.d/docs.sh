#!/usr/bin/env bash
# Fetch what `scripts/docs-check.sh` needs offline: the documentation repository at the commit pinned in
# pins.toml [docs], with the dependencies its own lockfile pins installed.
#
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs/stellar-docs.git   blobless bare clone of the pinned repository
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs/<commit>/          worktree at the pinned commit, node_modules installed
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs/<commit>.complete  written when the worktree is ready
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs/tooling/           HOME for the docs tooling (pnpm store, corepack, mint)
#
# pnpm is the version the repository's `packageManager` field names, fetched by corepack (through a shim in that
# HOME) and checked against the hash in that field; `pnpm install --frozen-lockfile` installs exactly what
# pnpm-lock.yaml pins. Git hooks are not installed (HUSKY=0). The documentation commands are run once here, so that anything they fetch on first use is
# cached before the check runs offline. Idempotent: nothing is fetched while the worktree is complete.
# Network: this script only; read-only and anonymous.
set -euo pipefail
cd "$(dirname "$0")/../.."
pins="${XDRCHECK_PINS:-pins.toml}"
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs"

pin() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$pins" "$1"; }

repo="$(pin docs.repo)"
commit="$(pin docs.commit)"
tree="$cache/$commit"
if [ -f "$tree.complete" ]; then
  echo "docs: $commit cached"
  exit 0
fi

git_dir="$cache/stellar-docs.git"
mkdir -p "$cache"
if [ ! -f "$git_dir/HEAD" ]; then
  rm -rf "$git_dir.part"
  git clone --quiet --bare --filter=blob:none "$repo" "$git_dir.part"
  mv "$git_dir.part" "$git_dir"
fi
git --git-dir "$git_dir" cat-file -e "$commit^{commit}" 2>/dev/null ||
  git --git-dir "$git_dir" fetch --quiet "$repo" "$commit"

rm -rf "$tree" "$tree.complete"
git --git-dir "$git_dir" worktree prune
git --git-dir "$git_dir" worktree add --quiet --detach "$tree" "$commit"

# The docs tooling keeps its caches under HOME; give it one inside the cache, so the check finds them offline.
mkdir -p "$cache/tooling"
export HOME="$cache/tooling" COREPACK_HOME="$cache/tooling/corepack" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 HUSKY=0
unset XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME
# A corepack shim first on PATH, so that the `pnpm` the package scripts call is the pinned version too.
mkdir -p "$HOME/bin"
corepack enable --install-directory "$HOME/bin" pnpm
export PATH="$HOME/bin:$PATH"
(cd "$tree" && pnpm install --frozen-lockfile --reporter=silent)
# Warm whatever the commands fetch on first use; their verdict on the untouched tree does not matter here.
(cd "$tree" && pnpm -s validate >/dev/null 2>&1) || true
(cd "$tree" && pnpm -s check:links >/dev/null 2>&1) || true
git -C "$tree" reset --quiet --hard "$commit"
date -u +%FT%TZ >"$tree.complete"
echo "docs: $commit checked out, dependencies installed"
