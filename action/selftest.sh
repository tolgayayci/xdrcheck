#!/usr/bin/env bash
# Self-test of the GitHub Action (action.yml): each case runs the action's steps exactly as written, through
# action/simulate.py (a local stand-in for the runner), against the release built in dist/ (`make release` and
# `make dist-bin`), read through the release-base input so nothing is downloaded. It checks the step outcome,
# the outputs, the uploaded artifact and the job summary of every mode: replay (pass, a planted bug, the
# expected-failure list and each way it fails, the all-read check), lint (SARIF), the checksum guard (a
# corrupted asset, a wrong SHA256SUMS pin), and, when SELFTEST_CONFORM=1 and the driver is fetched, conform.
#
# Usage: action/selftest.sh [OUT_DIR]   (default reports-action-selftest)
# Exit 0 when every case behaves as expected, 1 otherwise. Linux only (the replay harness is).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out=${1:-reports-action-selftest}
mkdir -p "$out"
out=$(cd "$out" && pwd)
PY=${PY:-$([ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)}
"$PY" -c 'import yaml' 2> /dev/null || { echo "action selftest: $PY has no PyYAML (python3 -m venv .venv && .venv/bin/pip install --require-hashes -r scripts/py/requirements.txt)" >&2; exit 2; }

read -r version _ <<< "$(scripts/release.sh version)"
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo "action selftest: unsupported machine" >&2; exit 2 ;; esac
for f in SHA256SUMS "xdrcheck-$version.tar.gz" "xdrcheck-$version-linux-$arch.tar.gz"; do
  [ -f "dist/$f" ] || { echo "action selftest: dist/$f is missing; run make release and make dist-bin first" >&2; exit 2; }
done
scripts/dist.sh verify dist
dist="$root/dist"
sums=$(sha256sum dist/SHA256SUMS | cut -d' ' -f1)
entries='cap-0015/*,cap-0027/*'

pass=0 failed=0
ok() { echo "  ok: $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $*"; failed=$((failed + 1)); }
# run_case NAME WANT(success|failure) INPUT=VALUE...: run the action, compare the conclusion and the result output.
run_case() {
  local name=$1 want=$2; shift 2
  echo "case $name"
  set +e
  "$PY" action/simulate.py . "$out/$name" corpus-version="$version" release-base="$dist" "$@" > "$out/$name.log" 2>&1
  set -e
  rm -rf "$out/$name/runner-temp/xdrcheck-release-$version" # the downloaded release; the reports stay
  local got result
  got=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["conclusion"])' "$out/$name/result.json" 2> /dev/null || echo "no result")
  result=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["outputs"]["result"])' "$out/$name/result.json" 2> /dev/null || echo "")
  if [ "$got" = "$want" ]; then ok "conclusion $got, result output '$result'"; else bad "conclusion $got, want $want (log: $out/$name.log)"; tail -15 "$out/$name.log"; fi
  case "$want" in
    success) [ "$result" = pass ] || bad "result output is '$result', want pass" ;;
    failure) [ "$result" = fail ] || bad "result output is '$result', want fail" ;;
  esac
}
has() { # has FILE PATTERN WHAT
  if grep -Eq "$2" "$1" 2> /dev/null; then ok "$3"; else bad "$3: no /$2/ in $1"; fi
}

run_case replay-minimal success mode=replay adapter=minimal entries="$entries" sha256sums="$sums" artifact-name=replay-minimal
has "$out/replay-minimal/step-summary.md" '^## XDRCheck replay: pass' "job summary says pass"
for f in REPORT.md SUMMARY.md report.json; do
  [ -f "$out/replay-minimal/artifacts/replay-minimal/$f" ] && ok "artifact has $f" || bad "artifact lacks $f"
done
has "$out/replay-minimal.log" 'SHA256SUMS matches the pinned sha256' "the SHA256SUMS pin is checked"

run_case replay-demo failure mode=replay adapter=demo target-version=demo entries="$entries" artifact-name=replay-demo
has "$out/replay-demo/step-summary.md" '^## Failures' "job summary carries the Failures section"
has "$out/replay-demo/step-summary.md" 'xdrcheck replay --adapter' "job summary carries the repro command"
[ -f "$out/replay-demo/artifacts/replay-demo/REPORT.md" ] && ok "the report is uploaded on failure" || bad "no artifact on failure"

# The expected-failure list: written from the failing run, it makes the same run pass.
list="$out/demo.failures"
"$PY" action/replay_expect.py write "$out/replay-demo/artifacts/replay-demo/report.json" > "$list"
n=$(grep -cv '^#' "$list" || true)
[ "$n" -gt 0 ] && ok "the list holds $n failing entry variants" || bad "the written list is empty"
run_case replay-demo-listed success mode=replay adapter=demo target-version=demo entries="$entries" expected-failures="$list"
has "$out/replay-demo-listed.log" "$n still as listed, 0 new failures" "every listed failure is still there"

grep -v '^#' "$list" | tail -n +2 > "$out/demo.short"
run_case replay-demo-new-failure failure mode=replay adapter=demo target-version=demo entries="$entries" expected-failures="$out/demo.short"
has "$out/replay-demo-new-failure/step-summary.md" '^NEW-FAILURE ' "an unlisted failure is NEW-FAILURE"

passing=$("$PY" -c '
import json, sys
for r in json.load(open(sys.argv[1]))["rows"]:
    if not r.get("failure") and (r.get("replay") or {}).get("class") == "pass":
        print(r["entry"], r.get("variant") or "-"); break' "$out/replay-demo/artifacts/replay-demo/report.json")
{ cat "$list"; echo "$passing"; } > "$out/demo.extra"
run_case replay-demo-unexpected-pass failure mode=replay adapter=demo target-version=demo entries="$entries" expected-failures="$out/demo.extra"
has "$out/replay-demo-unexpected-pass/step-summary.md" "^UNEXPECTED-PASS +$passing" "a listed entry that passes is UNEXPECTED-PASS"

{ cat "$list"; echo "cap-0015/no-such-entry -"; } > "$out/demo.stale"
run_case replay-demo-not-run failure mode=replay adapter=demo target-version=demo entries="$entries" expected-failures="$out/demo.stale"
has "$out/replay-demo-not-run/step-summary.md" '^NOT-RUN +cap-0015/no-such-entry' "a stale line is NOT-RUN"

# The all-read check: an entry the minimal adapter declares out of its envelope is unread until listed.
read_entries='cap-0003/*,cap-0015/*'
run_case replay-unread failure mode=replay adapter=minimal entries="$read_entries" require-all-read=true
has "$out/replay-unread/step-summary.md" '^NEW-UNREAD +cap-0003/' "an unread entry variant fails the all-read check"
"$PY" action/replay_expect.py write "$out/replay-unread/runner-temp/xdrcheck-replay/report.json" --unread > "$out/minimal.unread"
run_case replay-unread-listed success mode=replay adapter=minimal entries="$read_entries" require-all-read=true expected-failures="$out/minimal.unread"

# The checksum guard: a corrupted asset and a wrong SHA256SUMS pin stop the action before anything runs.
bad_dist="$out/bad-dist"
rm -rf "$bad_dist"; mkdir -p "$bad_dist"
cp dist/SHA256SUMS "dist/xdrcheck-$version-linux-$arch.tar.gz" "$bad_dist/"
cp "dist/xdrcheck-$version.tar.gz" "$bad_dist/"
printf 'x' | dd of="$bad_dist/xdrcheck-$version.tar.gz" bs=1 seek=1000 conv=notrunc status=none
run_case tampered failure mode=replay adapter=minimal entries="$entries" release-base="$bad_dist"
has "$out/tampered.log" "xdrcheck-$version.tar.gz has sha256 [0-9a-f]+, SHA256SUMS says" "a corrupted asset is refused"
[ ! -f "$out/tampered/runner-temp/xdrcheck-replay/report.json" ] && ok "nothing ran on the corrupted release" || bad "the replay ran on a corrupted release"
run_case wrong-pin failure mode=replay adapter=minimal entries="$entries" sha256sums="$(printf '0%.0s' {1..64})"
has "$out/wrong-pin.log" 'SHA256SUMS has sha256 .* the pin says' "a wrong SHA256SUMS pin is refused"

# lint: xdrlint over the minimal adapter's package (a module that imports go-stellar-sdk's xdr package).
if command -v go > /dev/null; then
  run_case lint success mode=lint working-directory=go lint-paths=./adapters/minimal artifact-name=lint
  sarif=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["outputs"]["sarif"])' "$out/lint/result.json")
  if "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["version"]=="2.1.0" and d["runs"][0]["tool"]["driver"]["name"]' "$sarif" 2> /dev/null; then
    ok "the sarif output is a SARIF 2.1.0 log"; else bad "no SARIF log at '$sarif'"; fi
  [ -f "$out/lint/artifacts/lint/xdrlint.sarif" ] && ok "the artifact has xdrlint.sarif" || bad "the artifact lacks xdrlint.sarif"
  has "$out/lint/step-summary.md" '^## XDRCheck xdrlint: pass' "job summary says pass"
else
  echo "case lint: skipped (no Go toolchain)"
fi

# The workflow examples in docs/github-action.md, with `uses: OWNER/REPO@…` pointed at this action.yml, through
# the pinned actionlint (scripts/ci/check-workflows.sh fetches it): it checks the action's metadata and every
# input the examples pass.
echo "case docs-examples"
al_version=$(sed -n 's/^ACTIONLINT_VERSION=//p' scripts/ci/check-workflows.sh)
al_sha=$(sed -n 's/^ACTIONLINT_SHA256=\([0-9a-f]*\).*/\1/p' scripts/ci/check-workflows.sh)
al_tar="${XDG_CACHE_HOME:-$HOME/.cache}/xdrcheck-ci/actionlint-$al_version/actionlint_${al_version}_linux_amd64.tar.gz"
if [ "$arch" = amd64 ] && [ -f "$al_tar" ] && echo "$al_sha  $al_tar" | sha256sum --check --quiet --strict - 2> /dev/null; then
  proj="$out/docs-examples"
  rm -rf "$proj"; mkdir -p "$proj/.github/workflows" "$proj/.git"
  cp action.yml "$proj/"
  tar --no-same-owner -xzf "$al_tar" -C "$proj" actionlint
  n=$("$PY" - docs/github-action.md "$proj/.github/workflows" <<'PY'
import os, re, sys
blocks = re.findall(r"```yaml\n(.*?)```", open(sys.argv[1], encoding="utf-8").read(), re.S)
head = "name: example\non: [push]\npermissions:\n  contents: read\n"
for i, b in enumerate(blocks):
    b = re.sub(r"OWNER/REPO@v[0-9][0-9.]*", "./", b)
    open(os.path.join(sys.argv[2], "example-%d.yml" % i), "w").write(b if b.startswith("name:") else head + b)
print(len(blocks))
PY
)
  if (cd "$proj" && ./actionlint -shellcheck= -pyflakes= .github/workflows/*.yml); then
    ok "actionlint passes the $n workflow examples against action.yml"
  else
    bad "actionlint rejects a workflow example in docs/github-action.md"
  fi
else
  echo "  skipped: no pinned actionlint in the cache (scripts/ci/check-workflows.sh fetches it)"
fi

# conform needs the driver's packages (make fetch-sdk) and its toolchain; opt in with SELFTEST_CONFORM=1.
if [ "${SELFTEST_CONFORM:-}" = 1 ]; then
  run_case conform success mode=conform columns='js@17.4.0' entries='cap-0015/*' artifact-name=conform
  has "$out/conform/step-summary.md" '^## XDRCheck conformance: pass' "job summary says pass"
  [ -f "$out/conform/artifacts/conform/matrix.json" ] && ok "the artifact has matrix.json" || bad "the artifact lacks matrix.json"
else
  echo "case conform: skipped (SELFTEST_CONFORM=1 runs it; it needs make fetch-sdk)"
fi

echo
echo "action selftest: $pass checks passed, $failed failed (cases under $out)"
[ "$failed" = 0 ]
