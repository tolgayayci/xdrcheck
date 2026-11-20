#!/usr/bin/env bash
# Show, in the job log, that scripts/offline-run.sh leaves a command no way out: list the interfaces inside the
# namespace, then require a canary TCP connect and a name lookup to fail. This is the per-job evidence that the
# run steps are offline (docs/ci-isolation.md); it fails the job if either probe succeeds.
set -euo pipefail
cd "$(dirname "$0")/../.."
# Hosted Ubuntu 24.04 runners restrict unprivileged user namespaces through AppArmor. Lift that restriction on
# the throwaway runner when it is in force, so the same wrapper runs in CI and on a workstation.
if ! unshare --user --map-root-user --net true 2>/dev/null; then
  if [ "${CI:-}" = "true" ] && [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    echo "offline-check: allowing unprivileged user namespaces on this runner"
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  fi
fi
scripts/offline-run.sh bash -c '
  echo "offline-check: interfaces inside the namespace:"
  ip -brief link 2>/dev/null || cat /proc/net/dev
  if timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
    echo "offline-check: FAIL: a TCP connect to 1.1.1.1:443 succeeded" >&2
    exit 1
  fi
  echo "offline-check: TCP connect to 1.1.1.1:443 failed, as required"
  if timeout 5 getent hosts github.com >/dev/null 2>&1; then
    echo "offline-check: FAIL: github.com resolved" >&2
    exit 1
  fi
  echo "offline-check: name lookup of github.com failed, as required"
'
