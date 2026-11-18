# Offline and memory isolation

For anyone running the kit's checks in CI or on a workstation who needs to know that a run used no network and
stayed within a memory bound. Two wrappers enforce this. Both were exercised on Debian 13, kernel 6.12, cgroup v2.
Add `OFFLINE=1` to a `make` target to run it under the network wrapper.

## No network: `scripts/offline-run.sh`

Runs a command in a private network namespace with only a loopback interface
(`unshare --user --map-root-user --net`). Local servers (stellar-core's HTTP port, the mock RPC, the object store)
keep working on loopback; nothing can reach the internet. Verified: an HTTPS request fails to connect, and a
socket binds on 127.0.0.1.

A container's published ports are not on that loopback, so the wrapper sets `XDRCHECK_OBJSTORE=binary` unless the
caller set it: the replay harness's object store then runs as the pinned SeaweedFS image's own `weed` executable
(same digest) inside the namespace.

Fallback where unprivileged user namespaces are disabled: `XDRCHECK_OFFLINE_FALLBACK=docker` with a pinned toolbox
image runs the command in a container with `--network none`.

Dependencies are fetched beforehand by `make fetch`, the only networked step.

## Memory: `scripts/limit-run.sh`

Runs a command under a memory limit.

| Mechanism | When | Behaviour on overflow | Verified |
|---|---|---|---|
| cgroup v2 `MemoryMax` via `systemd-run --user --scope` | default when available | the kernel kills the group (exit 137) | a 200 MiB allocation under a 64 MiB limit was killed; an 8 MiB one succeeded |
| `prlimit --as` (address space) | `XDRCHECK_LIMIT_MECHANISM=rlimit`, or no user systemd | allocation fails inside the process (`MemoryError`, `ENOMEM`) | a 200 MiB allocation under 64 MiB raised `MemoryError` |

The two behave differently on purpose: the memory-bound test runs under the cgroup limit (what a container
runtime does), and negative vectors with huge length prefixes are also run under the address-space limit, where
an implementation that pre-allocates fails visibly instead of being killed. Reports record which mechanism was
used.

Limits: the wrappers are verified on the machine above, not yet on hosted CI runners. The network namespace
needs unprivileged user namespaces; where they are disabled, use the Docker fallback.
