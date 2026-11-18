#!/bin/bash
# Run one scenario inside a fresh, empty network namespace (only loopback): no outbound connection is possible.
HERE="$(cd "$(dirname "$0")" && pwd)"
exec unshare -rn bash -c 'ip link set lo up && exec "$0" "$@"' "$HERE/run.sh" "$@"
