#!/usr/bin/env bash
# Run the documentation repository's own checks with the guide pages in place (`make verify-guide`).
#
# The repository is the one pinned in pins.toml [docs], prepared by `make fetch` (scripts/fetch.d/docs.sh) under
# ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs/<commit>; this script needs no network. It resets that checkout to the pinned
# commit, places the pages where they would be published and applies guide/docs-nav.patch to docs.json:
#
#   guide/indexer-hardening.mdx -> docs/data/indexers/build-your-own/indexer-hardening.mdx
#   guide/checklist.mdx         -> docs/data/indexers/build-your-own/indexer-hardening/checklist.mdx
#
# then runs the three commands the repository asks of a new page, each a failure of its own:
#
#   1. `pnpm format:mdx` changes nothing in our pages (it rewrites the files; we compare them with ours);
#   2. `pnpm check` passes (prettier check, component-tag padding, RPC docs check, `mint validate`);
#   3. `pnpm check:links` reports no broken link that the repository at the pinned commit does not already report.
#      The repository's own CI lets this command fail on known broken links, so the comparison is with the same
#      command on the untouched checkout (cached beside it, per commit).
#
# The checkout is reset again on exit. Exit 0 when all three pass, 1 when one fails, 2 when the checkout is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
pins="${XDRCHECK_PINS:-pins.toml}"
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/docs"
commit="$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["docs"]["commit"])' "$pins")"
tree="$cache/$commit"
if [ ! -f "$tree.complete" ]; then
  echo "docs-check: no prepared checkout of the documentation repository at $commit; run \`make fetch\` first" >&2
  exit 2
fi

dest=docs/data/indexers/build-your-own
pages=("guide/indexer-hardening.mdx:$dest/indexer-hardening.mdx" "guide/checklist.mdx:$dest/indexer-hardening/checklist.mdx")
placed=()
for p in "${pages[@]}"; do placed+=("${p#*:}"); done

# The same HOME the fetch used, so the tooling finds its caches.
export HOME="$cache/tooling" COREPACK_HOME="$cache/tooling/corepack" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 HUSKY=0
# pnpm 11 checks the installed packages before every script and, when it judges them stale, tries to reinstall
# (offline here, so the script fails). The fetch installed exactly the lockfile, so that check is switched off.
export pnpm_config_verify_deps_before_run=false
unset XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME
export PATH="$HOME/bin:$PATH" # the corepack shim: pnpm at the version the repository pins, also inside its scripts
pnpm() { (cd "$tree" && command pnpm "$@"); }

exec 9>"$tree.lock"
flock 9
reset() {
  git -C "$tree" reset --quiet --hard "$commit"
  git -C "$tree" clean --quiet -fdx -e node_modules
}
place() {
  for p in "${pages[@]}"; do
    mkdir -p "$(dirname "$tree/${p#*:}")"
    cp "$root/${p%%:*}" "$tree/${p#*:}"
  done
  git -C "$tree" apply "$root/guide/docs-nav.patch"
  # The padding check lists files with `git ls-files`.
  git -C "$tree" add --intent-to-add -- "${placed[@]}"
}

out="$(mktemp -d "$cache/run.XXXXXX")"
trap 'reset; rm -rf "$out"' EXIT
fail=0

# Baseline for the link check: the untouched checkout, once per commit.
baseline="$tree.links-baseline"
if [ ! -f "$baseline" ]; then
  reset
  pnpm -s check:links >"$out/links" 2>&1 || true
  mv "$out/links" "$baseline"
fi

reset
place
echo "docs-check: stellar-docs at $commit with ${placed[*]} and the docs.json navigation patch"

# 1. format:mdx leaves our pages unchanged.
if ! pnpm -s format:mdx >"$out/format" 2>&1; then
  cat "$out/format"
  echo "FAIL pnpm format:mdx: the command failed"
  fail=1
else
  changed=0
  for p in "${pages[@]}"; do
    if ! diff -u --label "${p%%:*}" --label "${p#*:} after format:mdx" "$root/${p%%:*}" "$tree/${p#*:}"; then
      changed=1
    fi
  done
  if [ "$changed" -eq 1 ]; then
    echo "FAIL pnpm format:mdx: it changes our pages (diff above)"
    fail=1
  else
    echo "ok   pnpm format:mdx: our pages unchanged"
  fi
fi
reset
place

# 2. check.
if pnpm -s check >"$out/check" 2>&1; then
  echo "ok   pnpm check"
else
  cat "$out/check"
  echo "FAIL pnpm check"
  fail=1
fi

# 3. check:links, compared with the untouched checkout as "file: link" pairs. The tool prints each file, then
# each broken link in it on a line indented with no-break spaces and a "⎿"; spinner and summary lines differ
# between runs and are dropped.
status=0
pnpm -s check:links >"$out/links" 2>&1 || status=$?
links() {
  sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g; s/\xc2\xa0/ /g' "$1" |
    awk '/^[^ ].*\.mdx?$/ { f = $0; next } /^ *⎿ / { sub(/^ *⎿ */, ""); print f ": " $0 }' | sort -u
}
new="$(comm -13 <(links "$baseline") <(links "$out/links"))"
if [ "$status" -eq 0 ]; then
  echo "ok   pnpm check:links: no broken links"
elif [ -n "$new" ]; then
  echo "FAIL pnpm check:links: broken links that the repository at $commit does not already report:"
  printf '%s\n' "$new"
  fail=1
else
  echo "ok   pnpm check:links: no new broken links (the repository at $commit already reports $(links "$baseline" | wc -l))"
fi

exit "$fail"
