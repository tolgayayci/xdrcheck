#!/usr/bin/env bash
# Fetch what `make lint-wallet-backend` and `make lint-before-after` need offline: the source tree of every
# wallet-backend commit the linter is run on, and the Go modules those trees need to load.
#
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/wallet-backend.git        blobless bare clone of the pinned repository
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/wallet-backend/<commit>/  `git archive` of each commit, with .complete
#
# The commits are pins.toml [pipelines.wallet_backend] current plus every commit named in
# lint/expected/wallet-backend/plan.json. Modules go to the Go module cache (`go env GOMODCACHE`), loaded with
# the same package patterns the run uses, so a run with GOPROXY=off finds everything. Idempotent: a commit
# whose tree is complete is skipped. Network: this script only.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
pins="${XDRCHECK_PINS:-pins.toml}"
plan=lint/expected/wallet-backend/plan.json
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint"

pin() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$pins" "$1"; }

repo="$(pin pipelines.wallet_backend.repo)"
current="$(pin pipelines.wallet_backend.current)"
mapfile -t commits < <(python3 -I -c 'import json, sys
plan = json.load(open(sys.argv[1]))
seen = [sys.argv[2]]
for c in plan["commits"]:
    if c not in seen: seen.append(c)
print("\n".join(seen))' "$plan" "$current")
mapfile -t patterns < <(python3 -I -c 'import json, sys; print("\n".join(json.load(open(sys.argv[1]))["packages"]))' "$plan")

git_dir="$cache/wallet-backend.git"
need_fetch=0
for c in "${commits[@]}"; do
  [ -f "$cache/wallet-backend/$c/.complete" ] || need_fetch=1
done
if [ "$need_fetch" = 1 ]; then
  if [ ! -f "$git_dir/HEAD" ]; then
    mkdir -p "$cache"
    rm -rf "$git_dir.part"
    git clone --quiet --bare --filter=blob:none "$repo" "$git_dir.part"
    mv "$git_dir.part" "$git_dir"
  fi
  for c in "${commits[@]}"; do
    git --git-dir "$git_dir" cat-file -e "$c^{commit}" 2>/dev/null || git --git-dir "$git_dir" fetch --quiet "$repo" "+refs/heads/*:refs/heads/*"
  done
fi

export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
for c in "${commits[@]}"; do
  dir="$cache/wallet-backend/$c"
  if [ -f "$dir/.complete" ]; then
    echo "lint-wallet-backend: $c cached"
    continue
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  git --git-dir "$git_dir" archive --format=tar "$c" | tar -x -C "$dir"
  # Load the packages the run loads (go list downloads exactly the modules they need).
  present=()
  for p in "${patterns[@]}"; do [ -d "$dir/${p%/...}" ] && present+=("$p"); done
  (cd "$dir" && go list -deps "${present[@]}" >/dev/null)
  echo "$c" >"$dir/.complete"
  echo "lint-wallet-backend: $c extracted, modules fetched"
done
cd "$root"
