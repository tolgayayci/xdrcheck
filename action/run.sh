#!/usr/bin/env bash
# The GitHub Action's one run step (action.yml at the repository root; docs/github-action.md). It reads its
# inputs from INPUT_* variables, downloads the pinned release and checks it against SHA256SUMS
# (action/fetch-release.sh), runs one mode, writes SUMMARY.md and the job summary, and sets the step outputs.
#
# Modes:
#   replay    xdrcheck replay of the release's corpus/ root through INPUT_ADAPTER, then the expected-failure list and
#             the all-read check (action/replay_expect.py) when asked
#   conform   xdrcheck conform fetch, build and run for INPUT_COLUMNS, from the action's own checkout (it holds the
#             driver tree); the expected-failure list and --require-all-read are xdrcheck conform's own
#   lint      xdrlint over INPUT_LINT_PATHS in INPUT_WORKING_DIRECTORY, with a SARIF file for code scanning
#
# Exit 0 pass, 1 the check failed, 2 the action could not run. Outputs are written either way, so the report
# is uploaded on failure too.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
action_root=$(dirname "$here")
mode=${INPUT_MODE:-}
code=2
fail() { echo "::error title=XDRCheck::$*"; echo "xdrcheck: $*" >&2; code=2; exit 2; }
out() { [ -z "${GITHUB_OUTPUT:-}" ] || echo "$1=$2" >> "$GITHUB_OUTPUT"; }
# The result output is written once, on the way out, whatever the exit path.
trap 'out result "$([ "$code" = 0 ] && echo pass || echo fail)"' EXIT
truthy() { case "${1:-}" in true|True|TRUE|1|yes) return 0 ;; *) return 1 ;; esac; }

case "$mode" in replay|conform|lint) ;; *) fail "input mode must be replay, conform or lint, got '$mode'" ;; esac

# The version: the input, else the action's own ref when it names a full release (uses: …@v30.0.0).
version=${INPUT_CORPUS_VERSION:-}
if [ -z "$version" ]; then
  ref=${XDRCHECK_ACTION_REF:-}
  if echo "$ref" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then version=${ref#v}
  else fail "set corpus-version (for example 30.0.0): the action ref '${ref:-none}' does not name one release"; fi
fi
version=${version#v}

tmp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
report=${INPUT_REPORT_DIR:-$tmp/xdrcheck-$mode}
mkdir -p "$report"
report=$(cd "$report" && pwd)
artifact=${INPUT_ARTIFACT_NAME:-xdrcheck-$mode}
out report-dir "$report"
out artifact-name "$artifact"

workdir=${INPUT_WORKING_DIRECTORY:-.}
workdir=$(cd "${GITHUB_WORKSPACE:-.}" && cd "$workdir" && pwd)
abs() { case "$1" in "") ;; /*) echo "$1" ;; *) echo "$workdir/$1" ;; esac; }
expected=$(abs "${INPUT_EXPECTED_FAILURES:-}")
[ -z "$expected" ] || [ -f "$expected" ] || fail "expected-failures: no file $expected"

# Download and verify. The release's repository: the input, else the action's own, else the workflow's.
repo=${INPUT_REPOSITORY:-${XDRCHECK_ACTION_REPOSITORY:-${GITHUB_REPOSITORY:-}}}
fetch=("$here/fetch-release.sh" --version "$version" --out "$tmp/xdrcheck-release-$version" --binaries auto)
[ -z "${INPUT_RELEASE_BASE:-}" ] || fetch+=(--base "$INPUT_RELEASE_BASE")
[ -n "${INPUT_RELEASE_BASE:-}" ] || [ -z "$repo" ] || fetch+=(--repo "$repo")
[ -z "${INPUT_SHA256SUMS:-}" ] || fetch+=(--sha256sums "$INPUT_SHA256SUMS")
[ "$mode" != replay ] || fetch+=(--corpus)
env_lines=$("${fetch[@]}") || fail "the release $version could not be downloaded and verified (see above)"
XDRCHECK_BIN="" XDRCHECK_CORPUS="" XDRCHECK_RELEASE=""
while IFS='=' read -r k v; do
  case "$k" in XDRCHECK_BIN|XDRCHECK_CORPUS|XDRCHECK_RELEASE) printf -v "$k" '%s' "$v" ;; esac
done <<< "$env_lines"
[ -n "$XDRCHECK_BIN" ] || fail "the release has no binaries for this runner"
export PATH="$XDRCHECK_BIN:$PATH"
if [ "$mode" != lint ] && [ ! -x "$XDRCHECK_BIN/xdrcheck" ]; then
  fail "mode $mode needs xdrcheck, which this release has no binary of for this runner"
fi

summary="$report/SUMMARY.md"
code=0
case "$mode" in
replay)
  [ -n "${INPUT_ADAPTER:-}" ] || fail "mode replay needs the adapter input (your adapter's command line)"
  args=(replay --corpus "$XDRCHECK_CORPUS" --adapter "$INPUT_ADAPTER"
        --target-version "${INPUT_TARGET_VERSION:-${GITHUB_SHA:-unknown}}" --report "$report")
  [ -z "${INPUT_INPUT:-}" ] || args+=(--input "$INPUT_INPUT")
  [ -z "${INPUT_ENTRIES:-}" ] || args+=(--entries "$INPUT_ENTRIES")
  set +e
  (cd "$workdir" && xdrcheck "${args[@]}") 2> "$report/replay.log"
  rc=$?
  set -e
  grep '^xdrcheck replay' "$report/replay.log" || tail -20 "$report/replay.log" >&2
  [ "$rc" -le 1 ] && [ -f "$report/report.json" ] || { tail -40 "$report/replay.log" >&2; fail "xdrcheck replay could not run (exit $rc)"; }
  check=""
  if [ -n "$expected" ] || truthy "${INPUT_REQUIRE_ALL_READ:-}"; then
    cargs=(check "$report/report.json" --corpus "$XDRCHECK_CORPUS")
    [ -z "$expected" ] || cargs+=(--expected "$expected")
    truthy "${INPUT_REQUIRE_ALL_READ:-}" && cargs+=(--require-all-read)
    [ -z "${INPUT_ENTRIES:-}" ] || cargs+=(--entries "$INPUT_ENTRIES")
    set +e
    check=$(python3 -I "$here/replay_expect.py" "${cargs[@]}")
    crc=$?
    set -e
    echo "$check"
    [ "$crc" -le 1 ] || fail "the expected-failure check could not run"
    # With a list, the list decides; without one, the replay's own result stands as well.
    if [ -n "$expected" ]; then code=$crc; else code=$(( rc > crc ? rc : crc )); fi
  else
    code=$rc
  fi
  {
    echo "## XDRCheck replay: $([ "$code" = 0 ] && echo pass || echo fail)"
    echo
    echo "Corpus $version, adapter \`$INPUT_ADAPTER\`."
    echo
    grep '^xdrcheck replay' "$report/replay.log" | sed 's/^/    /' || true
    if [ -n "$check" ]; then echo; echo '```text'; echo "$check" | head -60; echo '```'; fi
    echo
    # The report's Failures section: entry, CAPs, expected against observed, and the repro command.
    awk '/^## Failures/ {on=1} /^## Counts/ {on=0} on' "$report/REPORT.md" | head -150
    echo
    echo "Full report: \`REPORT.md\` and \`report.json\` in the \`$artifact\` artifact."
  } > "$summary"
  ;;
conform)
  [ -n "${INPUT_COLUMNS:-}" ] || fail "mode conform needs the columns input, for example 'js@17.4.0'"
  [ -f "$action_root/drivers/sets.toml" ] || fail "mode conform runs from the action's own checkout, which has no drivers/sets.toml"
  have=$(python3 -I -c 'import json,re,sys; print(re.sub(r"-dev$","",json.load(open(sys.argv[1]))["corpus_version"]))' "$action_root/corpus/corpus.json")
  [ "$have" = "$version" ] || echo "::warning title=XDRCheck::conform runs the corpus of the action's checkout ($have); corpus-version is $version"
  cols=(--columns "$INPUT_COLUMNS")
  (cd "$action_root" && xdrcheck conform fetch "${cols[@]}" && xdrcheck conform build "${cols[@]}") 2>&1 | tail -20 ||
    fail "xdrcheck conform fetch/build failed for $INPUT_COLUMNS (does the runner have the driver's toolchain?)"
  args=(conform run "${cols[@]}" --report "$report")
  [ -z "$expected" ] || args+=(--expected-failures "$expected")
  truthy "${INPUT_REQUIRE_ALL_READ:-}" && args+=(--require-all-read)
  [ -z "${INPUT_ENTRIES:-}" ] || args+=(--entries "$INPUT_ENTRIES")
  set +e
  (cd "$action_root" && xdrcheck "${args[@]}") > "$report/cells.txt" 2> "$report/conform.log"
  rc=$?
  set -e
  tail -5 "$report/conform.log"
  [ "$rc" -le 1 ] || { tail -40 "$report/conform.log" >&2; fail "xdrcheck conform run could not run (exit $rc)"; }
  if [ -n "$expected" ]; then
    code=$rc
  else
    # No list of its own: the corpus's declared divergences are the baseline (xdrcheck conform check).
    set +e
    (cd "$action_root" && xdrcheck conform check "$report/matrix.json") > "$report/check.txt" 2>&1
    code=$?
    set -e
    cat "$report/check.txt"
    [ "$code" -le 1 ] || fail "xdrcheck conform check could not run"
  fi
  {
    echo "## XDRCheck conformance: $([ "$code" = 0 ] && echo pass || echo fail)"
    echo
    echo "Corpus $have, columns \`$INPUT_COLUMNS\`."
    echo
    echo '```text'
    tail -20 "$report/conform.log"
    [ -n "$expected" ] || tail -20 "$report/check.txt"
    echo '```'
    if [ -f "$report/SUMMARY.md" ]; then echo; head -150 "$report/SUMMARY.md"; fi
  } > "$summary.tmp"
  mv "$summary.tmp" "$summary"
  ;;
lint)
  command -v go > /dev/null || fail "mode lint needs Go on the runner (xdrlint loads your packages with it): add actions/setup-go first"
  read -r -a paths <<< "${INPUT_LINT_PATHS:-./...}"
  read -r -a extra <<< "${INPUT_LINT_ARGS:-}"
  sarif="$report/xdrlint.sarif"
  if [ -z "${XDRLINT_DOCS_BASE:-}" ] && [ -n "$repo" ]; then
    export XDRLINT_DOCS_BASE="https://github.com/$repo/blob/v$version/lint/docs/{rule}.md"
  fi
  set +e
  (cd "$workdir" && xdrlint -sarif "$sarif" ${extra[@]+"${extra[@]}"} "${paths[@]}") > "$report/xdrlint.txt" 2>&1
  code=$?
  set -e
  cat "$report/xdrlint.txt"
  [ "$code" -le 1 ] || fail "xdrlint could not run (exit $code; see xdrlint.txt)"
  [ -f "$sarif" ] && out sarif "$sarif"
  {
    echo "## XDRCheck xdrlint: $([ "$code" = 0 ] && echo pass || echo fail)"
    echo
    echo "xdrlint $version on \`${INPUT_LINT_PATHS:-./...}\` in \`${INPUT_WORKING_DIRECTORY:-.}\`."
    echo
    echo '```text'
    head -120 "$report/xdrlint.txt"
    echo '```'
    echo
    echo "SARIF for code scanning: \`xdrlint.sarif\` in the \`$artifact\` artifact (the action's \`sarif\` output)."
  } > "$summary"
  ;;
esac

[ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$summary" >> "$GITHUB_STEP_SUMMARY"
[ "$code" = 0 ] || echo "::error title=XDRCheck::$mode failed; see the job summary and the $artifact artifact"
exit "$code"
