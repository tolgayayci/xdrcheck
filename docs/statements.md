# Infrastructure, user tracking and decentralisation

For SDK maintainers and indexer operators deciding whether to run the kit on their machines or in their CI. It
states what the kit reaches over the network, what it records, what it depends on, and how to check each statement
yourself.

## Infrastructure

| Statement | How to check |
|---|---|
| The kit is command-line tools and files. It runs on your own machine or CI runner: Linux on x86-64, with Docker for the replay checks | [README.md](../README.md#requirements), Requirements |
| The project operates **no hosted service**: no server, API, database, website backend or package mirror | There is nothing to deploy in the repository; every command in [cli.md](cli.md) runs locally |
| The project itself uses a public git repository and that host's CI runners (`ubuntu-24.04`), and nothing else | `.github/workflows/*.yml` |
| External reads happen only in the fetch step: public package registries (crates.io, the Go module proxy, npm, PyPI, Maven Central), the stellar-core package and container images, the stellar-core repository at a pinned tag, wallet-backend and stellar-etl at pinned commits, and the public Stellar data lake (anonymous read). Each is pinned by version and hash or digest in `pins.toml` and lock files | `scripts/fetch.sh` and `scripts/fetch.d/`; `pins.toml`; `xdrcheck pins check` |
| Every check runs with the network unreachable once `make fetch` has run | `make <target> OFFLINE=1` runs each check inside a network namespace with loopback only ([ci-isolation.md](ci-isolation.md)); the CI jobs of both tiers (pull-request and full) run that way |
| No account, sign-up, API key or credential is needed to run any part of the kit | No job in `.github/workflows/` uses a secret; the adapters pass dummy credentials to local emulators only |
| No key with funds is used. Generated transactions are signed with keys derived from public labels on private standalone networks | [README.md](../README.md#keys-and-networks); scenario files under `corpus/scenarios/` |

## User tracking

| Statement | How to check |
|---|---|
| The tools collect **no data about their users**: no telemetry, no analytics, no crash reporting, no update checks | The run steps work with no network at all (`OFFLINE=1`), so nothing can be sent; the source is public |
| Telemetry in third-party components the kit starts is switched off (the TimescaleDB image used by the wallet-backend adapter registers a telemetry job by default; the adapter disables it) | `go/adapters/walletbackend/db.go` |
| Reports contain what the run observed about the reader under test, the tool versions and the pins. They are written to local files and uploaded only by your own CI | `corpus/schema/report.schema.json`; `xdrcheck report redact` removes evidence strings before a report is shared |
| The package registries and the git host keep their own standard download and access logs. That is outside the project's control; the project receives nothing from them beyond public download counts | — |

## Decentralisation

| Statement | How to check |
|---|---|
| There is nothing to operate: anyone can run every check from a clone, offline, with no service, account or key provided by the project | [cli.md](cli.md); `make <target> OFFLINE=1` |
| The corpus is plain files (JSON, raw XDR, zstd) with published hashes and a JSON Schema. It can be mirrored freely and read without any tool from this repository | [manifest.md](manifest.md); `corpus/schema/` |
| The project depends on no infrastructure of its own. Its upstream inputs are public and pinned, and history entries are vendored, so the corpus stays complete if a public source disappears (for example after a testnet reset) | `corpus/objects/`; [maintenance.md §8](maintenance.md) |
| You can test your own indexer or SDK without involving the project: the adapter and driver protocols are documented and need no source, schema or credentials from the indexer | [adapter-protocol.md](adapter-protocol.md); [driver-protocol.md](driver-protocol.md) |

## Stack, licence and openness

| Statement | How to check |
|---|---|
| Built against the stable Stellar stack current at the time of pinning: stellar-core 30.0.0, the XDR definitions at v30.0, rs-stellar-xdr 30.0.0, go-stellar-sdk v0.9.0, js-stellar-sdk 17.4.0, stellar-rpc and Galexie v30.0.1 (Protocol 30) | `pins.toml`; `xdrcheck pins check` |
| The steps for following a protocol upgrade are written down, each with its outputs | [maintenance.md §5](maintenance.md) |
| Licensed Apache-2.0; third-party material and its licences are listed | `LICENSE`, `NOTICE` |
| The history, the checks and the CI results are public; changes are recorded in the changelog | [CHANGELOG.md](../CHANGELOG.md); `.github/workflows/` |
