#!/usr/bin/env bash
# Nightly early warning on the next protocol (docs/maintenance.md, "Watch list"): fetch stellar-core's golden
# LedgerCloseMeta for the next protocol (`test-lcm-next/`) at the tip of an unpinned branch, then decode, re-encode
# and JSON-round-trip every ledger in the oracle (`xdrcheck-corpus verify --tier bulk-next --checks roundtrip`). A failure
# means the pinned XDR library cannot read what the next stellar-core emits: the next protocol upgrade needs work
# before the corpus can take those goldens.
#
# The oracle refuses ledgers above pins.toml [protocol] max_supported; for this check only, the gate is raised to
# the protocol the tier's index.json declares (`xdrcheck-corpus verify --tier bulk-next --max-protocol N`), since reading
# those ledgers is the point.
#
# Parts, so a red run says which kind of failure it is:
#   fetch   network or git: the sparse checkout of stellar-core could not be made
#   layout  the checkout has no test-lcm-<tier>/*.xdr, or its index.json files give no single protocol:
#           stellar-core moved or renamed its goldens; the job needs updating, the oracle may be fine
#   arms    the union arms and optional states stellar-core's XDR (its src/protocol-curr/xdr submodule at that
#           commit, every feature on) has and the pinned definitions lack, named (`xdrcheck xdr diff`); the job's
#           own diff is <out>/early-warning/next-xdr.{json,md}
#   decode  the pinned oracle cannot read the goldens: the next upgrade needs work; the arms part says what is new
#
# Usage: scripts/nightly/early-warning.sh <out dir>
# Network: the fetch, and the arms part's read-only fetch of the stellar-xdr commit. The decode step runs
# offline with OFFLINE=1. Because the branch is not pinned, the decode part prints counts only; the per-file
# detail stays in <out>/early-warning/verify.log and is not published. No xdrcheck.report file is written, so the
# findings checks over the reports directory never see rows about an unpinned branch.
#   XDRCHECK_EARLY_WARNING_REF   branch or tag to read (default master)
#   XDRCHECK_EARLY_WARNING_TIER  next (default) or current
#   XDRCHECK_STELLAR_CORE_REPO   a local clone to read from instead of GitHub
# Exit 0 every part passed; 1 a part failed (the summary says which).
source "$(dirname "$0")/lib.sh"
nightly_init early-warning "${1:?usage: early-warning.sh <out dir>}"
need_tool "$CORPUS_BIN"

ref="${XDRCHECK_EARLY_WARNING_REF:-master}"
tier="${XDRCHECK_EARLY_WARNING_TIER:-next}"
origin="${XDRCHECK_STELLAR_CORE_REPO:-https://github.com/stellar/stellar-core.git}"
clone="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/early-warning/stellar-core"
work="$OUT/early-warning"

# --- fetch (network) ---
t0=$(date +%s)
fetch() {
  if [ ! -f "$clone/.git/HEAD" ]; then
    rm -rf "$clone"
    mkdir -p "$(dirname "$clone")"
    git clone --quiet --depth 1 --filter=blob:none --no-checkout --branch "$ref" "$origin" "$clone"
    git -C "$clone" sparse-checkout set --no-cone "/test-lcm-$tier/"
    git -C "$clone" checkout --quiet --detach HEAD
  else
    git -C "$clone" remote set-url origin "$origin"
    git -C "$clone" sparse-checkout set --no-cone "/test-lcm-$tier/"
    git -C "$clone" fetch --quiet --depth 1 --filter=blob:none origin "$ref"
    git -C "$clone" checkout --quiet --detach FETCH_HEAD
  fi
}
rm -rf "$work"
mkdir -p "$work"
if ! fetch >>"$NIGHTLY_LOG" 2>&1; then
  result fetch FAIL $(($(date +%s) - t0)) "network or git: could not fetch stellar-core $ref; see $NIGHTLY_LOG"
  nightly_finish
fi
commit=$(git -C "$clone" rev-parse HEAD)
result fetch PASS $(($(date +%s) - t0)) "stellar-core $ref at ${commit:0:12}"

# --- layout: the fetched tree still has the shape this job reads; a failure here is stellar-core moving or
# renaming its goldens, not a decode problem ---
t0=$(date +%s)
files=$(find "$clone/test-lcm-$tier" -name '*.xdr' 2>/dev/null | wc -l)
if [ "$files" = 0 ]; then
  result layout FAIL $(($(date +%s) - t0)) "golden layout changed: $ref at ${commit:0:12} has no test-lcm-$tier/*.xdr"
  nightly_finish
fi
# The protocol the tier was captured at, from the header key every index.json carries.
if ! protocol=$(python3 -I -c 'import json, pathlib, sys
ps = set()
for p in pathlib.Path(sys.argv[1]).glob("*/index.json"):
    try:
        ps.add(json.loads(p.read_text())["!cfg protocol version"])
    except (ValueError, KeyError) as e:
        sys.exit(f"{p.name}: no \"!cfg protocol version\" ({e})")
if len(ps) != 1: sys.exit(f"index.json files disagree on the protocol or are missing: {sorted(ps)}")
print(ps.pop())' "$clone/test-lcm-$tier" 2>>"$NIGHTLY_LOG"); then
  result layout FAIL $(($(date +%s) - t0)) "golden layout changed: test-lcm-$tier index.json files give no single protocol (see $NIGHTLY_LOG)"
  nightly_finish
fi
result layout PASS $(($(date +%s) - t0)) "test-lcm-$tier: $files files, protocol $protocol"

# --- arms (network): the arms stellar-core's next build can emit that the pinned definitions lack, by name:
# stellar-core's XDR submodule at this commit, every feature on (what its vnext build compiles), diffed
# against the pinned stellar-xdr commit with `xdrcheck xdr diff`. A decode failure below is explained by these. ---
t0=$(date +%s)
if skipped arms; then
  result arms SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP"
elif [ ! -x "$XDRCHECK_BIN" ]; then
  result arms BLOCKED 0 "$XDRCHECK_BIN is not built (make build)"
elif ! xdr_commit=$(git -C "$clone" ls-tree HEAD src/protocol-curr/xdr | awk '$2 == "commit" { print $3 }') || [ -z "$xdr_commit" ]; then
  result arms FAIL $(($(date +%s) - t0)) "layout: stellar-core at ${commit:0:12} has no src/protocol-curr/xdr submodule"
elif "$XDRCHECK_BIN" xdr diff pinned "$xdr_commit" --base-features none --head-features all \
  --json "$work/next-xdr.json" --md "$work/next-xdr.md" >/dev/null 2>>"$NIGHTLY_LOG"; then
  arms=$(python3 -I -c 'import json, sys
a = [x["id"] for x in json.load(open(sys.argv[1]))["new_arms"]["LedgerCloseMetaBatch"]]
print(f"{len(a)} new: " + ", ".join(a) if a else "none new")' "$work/next-xdr.json")
  result arms PASS $(($(date +%s) - t0)) "stellar-core's XDR ${xdr_commit:0:12} against the pins: arms $arms"
else
  result arms FAIL $(($(date +%s) - t0)) "network or git: could not diff stellar-core's XDR ${xdr_commit:0:12} (see $NIGHTLY_LOG)"
fi

# --- decode (offline) ---
# A throwaway corpus root that holds only a bulk tier: the fetched files, indexed by their own hashes.
t0=$(date +%s)
mkdir -p "$work/corpus/bulk" "$work/goldens"
label="$ref-${commit:0:12}"
ln -s "$clone" "$work/goldens/$label"
(cd "$clone" && find "test-lcm-$tier" -name '*.xdr' -print0 | sort -z | xargs -0 sha256sum) >"$work/corpus/bulk/index.sha256"
python3 -I -c 'import json, sys
json.dump({"tiers": {"bulk-next": {"ref": sys.argv[1], "path": sys.argv[2],
           "file_index": "bulk/index.sha256", "source": sys.argv[3], "commit": sys.argv[4]}}},
          open(sys.argv[5], "w"), indent=1)' "$label" "test-lcm-$tier" "$origin" "$commit" "$work/corpus/corpus.json"
set +e
offline "$CORPUS_BIN" --corpus "$work/corpus" verify --tier bulk-next --max-protocol "$protocol" --checks roundtrip \
  --goldens "$work/goldens" >"$work/verify.log" 2>&1
rc=$?
set -e
# Counts only: the summary lines, never the per-file FAIL lines.
grep -v '^FAIL ' "$work/verify.log" | sed 's/^/  /' | tail -n 6 || true
failed=$(grep -c '^FAIL ' "$work/verify.log" || true)
case $rc in
  0) result decode PASS $(($(date +%s) - t0)) "every ledger of protocol $protocol round-trips in the pinned oracle" ;;
  1) result decode FAIL $(($(date +%s) - t0)) "$failed of $files files do not round-trip in the pinned oracle (protocol $protocol); see the arms line for what is new" ;;
  *)
    why=$(grep -m 1 -o 'max_protocol [0-9]* is above [0-9]*' "$work/verify.log" || true)
    if [ -n "$why" ]; then
      result decode BLOCKED $(($(date +%s) - t0)) "the oracle build refuses the tier's protocol ($why); the goldens were not read"
    else
      result decode FAIL $(($(date +%s) - t0)) "xdrcheck-corpus verify could not run (exit $rc)"
    fi
    ;;
esac
nightly_finish
