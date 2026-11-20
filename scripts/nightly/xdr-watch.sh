#!/usr/bin/env bash
# Nightly XDR watch (docs/maintenance.md, "Watch list"): `xdrcheck xdr watch` diffs every source of unreleased XDR
# against the pinned definitions (stellar-xdr main with every #ifdef on, every other branch and open pull
# request against its merge base, the XDR diff of every pending CAP document, and the standing items such as
# the lcm_v3 branch), then `xdrcheck xdr candidates` turns main's and the CAP documents' new shapes into candidate
# rows for corpus/caps.toml, arms.toml and plan.json, written as a patch. Nothing in the working tree changes.
#
#   <out>/xdr-watch/digest-p<N>.md    one per upcoming protocol: the body of that protocol's tracking issue
#   <out>/xdr-watch/digest.md         all of them
#   <out>/xdr-watch/watch-log.jsonl   every earlier run's lines, then this run's, one per source
#   <out>/xdr-watch/diffs/            each source's diff, JSON and Markdown
#   <out>/xdr-watch/candidates.patch  the candidate rows as a patch against corpus/ (empty when there are none)
#
# The log is carried between runs in XDRCHECK_XDR_WATCH_LOG (default $XDRCHECK_CACHE/xdr-watch/watch-log.jsonl, XDRCHECK_CACHE
# defaulting to ~/.cache/xdrcheck): read as the previous run's, replaced by this run's. A source that cannot be read
# is listed as blocked in the digest; findings never fail the job, only a tool that cannot run does.
#
# Usage: scripts/nightly/xdr-watch.sh <out dir>
# Network: read-only git fetches of stellar/stellar-xdr and stellar/stellar-protocol, and one GitHub API listing
# of stellar-xdr's open pull requests (GH_TOKEN or GITHUB_TOKEN is sent when set, for the rate limit).
source "$(dirname "$0")/lib.sh"
nightly_init xdr-watch "${1:?usage: xdr-watch.sh <out dir>}"
need_tool "$XDRCHECK_BIN"
work="$OUT/xdr-watch"
rm -rf "$work"
mkdir -p "$work"
log="${XDRCHECK_XDR_WATCH_LOG:-${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/xdr-watch/watch-log.jsonl}"
mkdir -p "$(dirname "$log")"

t0=$(date +%s)
prev=()
[ -f "$log" ] && prev=(--previous "$log")
if "$XDRCHECK_BIN" xdr watch --out "$work" "${prev[@]}" >"$work/watch.txt" 2>>"$NIGHTLY_LOG"; then
  cp "$work/watch-log.jsonl" "$log"
  sed 's/^/  /' "$work/watch.txt"
  summary=$(tail -n 1 "$work/watch.txt")
  new=$(grep -c ' (new)' "$work/watch.txt" || true)
  result watch PASS $(($(date +%s) - t0)) "${summary#xdrcheck xdr watch: }; $new changed since the previous run"
else
  cat "$work/watch.txt" >>"$NIGHTLY_LOG" 2>/dev/null || true
  result watch FAIL $(($(date +%s) - t0)) "xdrcheck xdr watch could not run (see $NIGHTLY_LOG)"
  nightly_finish
fi

# Candidate rows: applied to a copy of the three corpus files, then written as a patch against corpus/.
t0=$(date +%s)
copy="$work/candidates-corpus"
mkdir -p "$copy"
cp corpus/caps.toml corpus/arms.toml corpus/plan.json "$copy/"
if "$XDRCHECK_BIN" xdr candidates --corpus "$copy" --caps-info "$work/caps.json" --from "$work/candidates.txt" --write \
  >"$work/candidates.txt.out" 2>>"$NIGHTLY_LOG"; then
  : >"$work/candidates.patch"
  for f in caps.toml arms.toml plan.json; do
    diff -u --label "a/corpus/$f" --label "b/corpus/$f" "corpus/$f" "$copy/$f" >>"$work/candidates.patch" || [ $? -eq 1 ]
  done
  rm -rf "$copy"
  rows=$(sed -n 's/^xdrcheck xdr candidates: added \([0-9]*\) rows.*/\1/p' "$work/candidates.txt.out")
  result candidates PASS $(($(date +%s) - t0)) "$rows candidate rows (xdr-watch/candidates.patch)"
else
  result candidates FAIL $(($(date +%s) - t0)) "xdrcheck xdr candidates could not run (see $NIGHTLY_LOG)"
fi
nightly_finish
