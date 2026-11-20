#!/usr/bin/env bash
# Publish the nightly XDR watch's results to this repository (the xdr-watch job of .github/workflows/nightly-xdr-watch.yml
# runs it after `make nightly-xdr-watch`):
#
#   issues <dir>    one tracking issue per upcoming protocol, titled "Protocol N: XDR watch": its body is
#                   <dir>/digest-p<N>.md, rewritten every night; created when no open issue has that title
#   draft-pr <dir>  when <dir>/candidates.patch is not empty, a draft pull request from the branch
#                   xdr-watch/candidate-rows that applies it on top of the checked-out branch; the branch is
#                   rewritten every night and the pull request's body updated, so there is at most one
#
# <dir> is the xdr-watch directory the watch wrote (reports-nightly/xdr-watch). Needs the GitHub CLI with
# GH_TOKEN (the job's token: issues, pull requests and contents write). XDRCHECK_PUBLISH_DRY_RUN=1 prints every
# command that would change something on GitHub instead of running it, and reads nothing from GitHub.
# Findings never fail this step; only a command that fails does.
set -euo pipefail
cd "$(dirname "$0")/../.."

mode="${1:?usage: xdr-publish.sh issues|draft-pr <dir>}"
dir="${2:?usage: xdr-publish.sh issues|draft-pr <dir>}"
dry="${XDRCHECK_PUBLISH_DRY_RUN:-}"
branch="xdr-watch/candidate-rows"
limit=60000 # GitHub caps an issue or pull-request body at 65536 characters

run() {
  if [ -n "$dry" ]; then
    printf 'dry run:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

# body <file> <out>: the file, cut to the body limit with a pointer to the run's artefact.
body() {
  if [ "$(wc -c <"$1")" -le "$limit" ]; then
    cp "$1" "$2"
  else
    head -c "$limit" "$1" >"$2"
    printf '\n\n(cut at %d characters; the full text is in the run'"'"'s xdr-watch artefact)\n' "$limit" >>"$2"
  fi
}

case "$mode" in
issues)
  shopt -s nullglob
  digests=("$dir"/digest-p*.md)
  [ "${#digests[@]}" -gt 0 ] || { echo "xdr-publish: no digest-p*.md in $dir" >&2; exit 2; }
  for d in "${digests[@]}"; do
    title=$(head -n 1 "$d" | sed 's/^# //')
    b=$(mktemp)
    body "$d" "$b"
    if [ -n "$dry" ]; then
      echo "xdr-publish: would create or update the open issue titled \"$title\" with $d"
      run gh issue create --title "$title" --body-file "$d"
      rm -f "$b"
      continue
    fi
    n=$(gh issue list --state open --search "\"$title\" in:title" --json number,title \
      --jq "map(select(.title == \"$title\")) | first | .number // empty")
    if [ -n "$n" ]; then
      gh issue edit "$n" --body-file "$b" >/dev/null
      echo "xdr-publish: updated issue #$n \"$title\""
    else
      gh issue create --title "$title" --body-file "$b"
      echo "xdr-publish: created the issue \"$title\""
    fi
    rm -f "$b"
  done
  ;;
draft-pr)
  patch="$dir/candidates.patch"
  if [ ! -s "$patch" ]; then
    echo "xdr-publish: no candidate rows; no pull request"
    exit 0
  fi
  base="${XDRCHECK_PR_BASE:-${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}}"
  title="Candidate corpus rows from the XDR watch"
  b=$(mktemp)
  {
    echo "Candidate rows the nightly XDR watch derived from stellar-xdr main and the pending CAP documents"
    echo "(\`xdrcheck xdr candidates\`). Every row is marked CANDIDATE: confirm each arm's class and reason, the CAP's"
    echo "wording, and how each planned entry will be produced, or delete the row. Arm records validate only"
    echo "once the pinned XDR definitions include their arms, so \`make verify-coverage\` fails on this branch"
    echo "until the pins move; that is expected for a draft."
    echo
    echo "Rewritten every night from the latest watch; edits pushed to this branch are overwritten."
    echo
    sed -n '/^## New arms per source/,/^## CAP documents/p' "$dir"/digest-p*.md | grep -v '^## CAP documents' || true
  } >"$b"
  if [ -n "$dry" ]; then
    echo "xdr-publish: would apply $patch on $base as $branch and open or update a draft pull request"
    git apply --check "$patch"
    run git push --force origin "HEAD:refs/heads/$branch"
    run gh pr create --draft --base "$base" --head "$branch" --title "$title" --body-file "$b"
    rm -f "$b"
    exit 0
  fi
  gh auth setup-git
  git switch --quiet -C "$branch"
  git apply "$patch"
  git add corpus/caps.toml corpus/arms.toml corpus/plan.json
  git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "add candidate corpus rows from the XDR watch"
  git push --quiet --force origin "HEAD:refs/heads/$branch"
  n=$(gh pr list --state open --head "$branch" --json number --jq 'first | .number // empty')
  if [ -n "$n" ]; then
    gh pr edit "$n" --body-file "$b" >/dev/null
    echo "xdr-publish: updated draft pull request #$n"
  else
    gh pr create --draft --base "$base" --head "$branch" --title "$title" --body-file "$b"
  fi
  rm -f "$b"
  ;;
*)
  echo "usage: xdr-publish.sh issues|draft-pr <dir>" >&2
  exit 2
  ;;
esac
