#!/bin/bash
# one chain inside a fresh, empty network namespace (only loopback): own ports, no stale node, no outbound connection
HERE="$(cd "$(dirname "$0")" && pwd)"
exec unshare -rn bash -c 'ip link set lo up && exec "$0" "$@"' "$HERE/run.sh" "$@"
