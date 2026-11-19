#!/usr/bin/env bash
# Run a command with no network access: private network and mount namespaces with only a loopback interface.
# Usage: scripts/offline-run.sh <command> [args...]
# Name lookups are cut too: on hosts using systemd-resolved, glibc's `resolve` module talks to the resolver over a
# Unix socket that a network namespace does not cover, so /run/systemd/resolve is hidden and /etc/resolv.conf
# emptied inside the mount namespace.
# Mechanism, in order of preference:
#   1. unshare --user --map-root-user --net --mount (unprivileged; works where user namespaces are allowed)
#   2. XDRCHECK_OFFLINE_FALLBACK=docker: run inside a pinned toolbox container with --network none
set -euo pipefail
if [ "$#" -eq 0 ]; then echo "usage: $0 <command> [args...]" >&2; exit 2; fi
# A container's ports are not reachable from the private network namespace, so the replay harness's object
# store runs as the pinned image's own `weed` executable (same digest) unless the caller chose otherwise.
export XDRCHECK_OBJSTORE="${XDRCHECK_OBJSTORE:-binary}"
if [ "${XDRCHECK_OFFLINE_FALLBACK:-}" = "docker" ]; then
  img="${XDRCHECK_TOOLBOX_IMAGE:?set XDRCHECK_TOOLBOX_IMAGE to a pinned image for the docker fallback}"
  exec docker run --rm --network none -e XDRCHECK_OBJSTORE -v "$PWD:$PWD" -w "$PWD" -u "$(id -u):$(id -g)" "$img" "$@"
fi
if ! unshare --user --map-root-user --net --mount true 2>/dev/null; then
  echo "offline-run: unprivileged user namespaces are not available here; set XDRCHECK_OFFLINE_FALLBACK=docker" >&2
  exit 3
fi
exec unshare --user --map-root-user --net --mount -- bash -c '
  ip link set lo up 2>/dev/null || true
  [ -d /run/systemd/resolve ] && mount -t tmpfs none /run/systemd/resolve 2>/dev/null || true
  empty=$(mktemp); mount --bind "$empty" /etc/resolv.conf 2>/dev/null || true
  exec "$@"' bash "$@"
