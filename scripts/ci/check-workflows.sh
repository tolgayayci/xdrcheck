#!/usr/bin/env bash
# Validate the CI files locally: actionlint over .github/workflows, then the repository's own rules
# (scripts/ci/check_workflows.py: actions pinned by commit SHA with a version comment, versions only from
# pins.toml, read-only tokens, a timeout on every job, one documented make target per job), and the self-test of
# the local CI emulation's --reuse (scripts/ci/run_local.py).
# actionlint is a pinned release binary, verified by sha256 and kept in $HOME/.cache.
set -euo pipefail
cd "$(dirname "$0")/../.."

ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 # linux_amd64.tar.gz

if [ "$(uname -sm)" != "Linux x86_64" ]; then
  echo "check-workflows: the pinned actionlint binary is for Linux x86_64 only" >&2
  exit 2
fi
cache="${XDG_CACHE_HOME:-$HOME/.cache}/xdrcheck-ci/actionlint-$ACTIONLINT_VERSION"
tarball="$cache/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
mkdir -p "$cache"
if [ ! -f "$tarball" ]; then
  url="https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION/$(basename "$tarball")"
  curl -fsSL --retry 3 -o "$tarball.part" "$url"
  mv "$tarball.part" "$tarball"
fi
# Verify on every run, not only after the download: the cache directory is writable by anything.
if ! echo "$ACTIONLINT_SHA256  $tarball" | sha256sum --check --quiet --strict -; then
  echo "check-workflows: $tarball does not match the pinned sha256; delete it and retry" >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar --no-same-owner -xzf "$tarball" -C "$work" actionlint

PY="${PY:-$( [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)}"
if ! "$PY" -c 'import yaml' 2>/dev/null; then
  echo "check-workflows: $PY has no PyYAML; run: python3 -m venv .venv && .venv/bin/pip install --require-hashes -r scripts/py/requirements.txt" >&2
  exit 2
fi

status=0
# shellcheck and pyflakes integrations are off so the result does not depend on what else is installed.
"$work/actionlint" -shellcheck= -pyflakes= .github/workflows/*.yml && echo "actionlint $ACTIONLINT_VERSION: no problems" || status=1
"$PY" scripts/ci/check_workflows.py || status=1
"$PY" scripts/ci/check_workflows.py --self-test || status=1
"$PY" scripts/ci/run_local.py --self-test || status=1
exit $status
