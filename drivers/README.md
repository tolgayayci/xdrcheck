# Conformance drivers

A **driver** is a small program that wraps exactly one SDK at exactly one version and answers the conformance
orchestrator (`xdrcheck conform`) over the driver protocol `xcc.driver/1`: one JSON object per line on stdin and
stdout, validated against `corpus/schema/driver-protocol.schema.json`. A driver reports what the SDK did
(`ok`, `diverge`, `reject`, `crash`, `n_a` with a typed reason); it never sees expected values and never reads
the manifest. The orchestrator judges. The `api` argument and result vocabulary, the facts an accepted cell must
carry and the judging rules are specified in [`docs/conformance-protocol.md`](../docs/conformance-protocol.md).

| Path | What |
|---|---|
| `sets.toml` | The named column sets (`required`, `acceptance`, `pr`, `public`, `all` and the sets below) |
| `sets.d/<family>.toml` | The conformance columns of one SDK family (SDK, pinned version, decode profile, driver directory, run command), loaded after `sets.toml` in name order; `[extend]` appends members to a set of `sets.toml` |
| `<lang>/<version>/` | One driver directory per pinned SDK version, with its committed lock files |
| `stub/` | The orchestrator's own test driver: canned outcomes, no SDK (column `stub@0.1.0`, set `selftest`) |
| `soroban-spec/<version>/` | Rust `soroban-spec`, the contract-spec reader of the Soroban Rust SDK and stellar-cli: the spec level only |
| `rs-xdr-json/<version>/` | rs-stellar-xdr's XDR-JSON (SEP-51) converter: the json level only (`levels = ["json"]` in `sets.d/json.toml`) |

## Columns and sets

A column ID is `<sdk>@<version>`, or `<sdk>@<version>:<profile>` when one SDK version runs under several decode
profiles (Rust: `limits-default`, `limits-none`; Go: `views`; such columns share one driver directory). Every `sdk` column's
version must be listed in `pins.toml` `[conformance.columns]`, and the `core` column's version must be the
pinned stellar-core version; every `xdrcheck conform` command checks this before doing anything.

| Set | Columns | Used by |
|---|---|---|
| `required` | JS 17.4.0; Go v0.9.0; Rust 30.0.0 (both profiles) | the minimum |
| `acceptance` | `required` + JS 17.2.0, 17.2.1, 17.3.0 | the minimum that still shows the three JS acceptance defects |
| `pr` | `acceptance` + Go v0.7.1, v0.7.2, v0.7.3, v0.8.0; Rust 28.0.0, 28.0.1 (both profiles); Python 17.0.1 | every pull request; the default |
| `public` | `pr` + JS 16.3.0, 16.3.1, 16.4.1; Python 17.0.0; the stellar-core column | the widest set a public scheduled job runs |
| `all` | `public`, plus the columns a private overlay adds with `[extend]` | the same as `public` without an overlay; the `views`, `spec`, `json` and `selftest` sets are not in it |
| `views` | Go v0.8.0, v0.9.0 under the decode profile `views` | the Go view path: the bytes through go-stellar-sdk's zero-copy XDR views and view-based ingest extractors (`ExtractLedgerTxParts`, `EventsFromTxParts`, `FeesFromTxParts`, `LedgerTransactionViewRange`), each derived key compared with the full decode of the same SDK; a difference is a `diverge` cell (`drivers/go/views`) |
| `selftest` | the stub | the orchestrator's own tests |
| `spec` | Rust soroban-spec 29.0.1 and 30.0.0-rc.1; JS 17.4.0 and 16.3.0; Go v0.9.0; Python 17.0.1 | the contract-spec readers (`xdrcheck conform run --kind spec`) |
| `json` | rs-stellar-xdr 30.0.0 and main (`30.0.0+ebec5fb1c76e`) | the XDR-JSON converters (`xdrcheck conform run --level json`); not in any other set |

Select columns with `--set NAME` or `--columns GLOB[,GLOB…]` (`*` matches any characters).

A private overlay (`xdrcheck conform run --overlay DIR`, or `$XDRCHECK_OVERLAY`) may hold its own `drivers/sets.toml`, which
adds columns whose driver directories live under the overlay; such a column runs only with the overlay, and that run
writes its report outside the working tree. Public CI uses only `pr` and `public`.

## The driver directory contract

Each column's `dir` holds a `Makefile` with these targets. `xdrcheck conform fetch` runs `make -C <dir> fetch` and
`xdrcheck conform build` runs `make -C <dir> build`, once per directory, with:

| Variable | Value |
|---|---|
| `XDRCHECK_CACHE_DIR` | the directory's package cache: `$XDRCHECK_CACHE/conform/<dir with / as ->`, `XDRCHECK_CACHE` defaulting to `~/.cache/xdrcheck` |
| `XDRCHECK_COLUMNS` | the IDs of the selected columns this directory serves, space-separated |
| `XDRCHECK_SDK_VERSION` | the pinned SDK version |
| `XDRCHECK_PINS` | absolute path of the pins file |
| `XDRCHECK_ROOT` | absolute path of the repository root |
| `XDRCHECK_OFFLINE=1`, `GOPROXY=off`, `GOFLAGS=-mod=readonly`, `GOTOOLCHAIN=local`, `CARGO_NET_OFFLINE=true`, `npm_config_offline=true`, `PIP_NO_INDEX=1` | set for `build` only |

| Target | Network | Must |
|---|---|---|
| `fetch` | allowed; the only conformance step that may use it | fill `$XDRCHECK_CACHE_DIR` from the committed lock files only (`package-lock.json`, `go.sum`, `Cargo.lock`, hashed `requirements.txt`, a jar list with sha256), verifying every artefact's integrity; never resolve a version that is not locked; write nothing outside `$XDRCHECK_CACHE_DIR` |
| `build` | none: it runs inside a network namespace with loopback only | build the driver from the directory and `$XDRCHECK_CACHE_DIR` alone and fail if anything is missing; leave the command named by the column's `run` (by convention `bin/xdrcheck-driver`) inside the directory; change no committed file; be repeatable |
| `test` | none | the driver's own checks, after `build`; the top-level `make test` runs `make -C drivers/<name> test` for every `drivers/*/Makefile`, so a language directory holding several version directories provides a `Makefile` whose `test` runs each of them |
| `clean` | none | remove what `build` made |

The cache is keyed by directory, so CI caches can be keyed by the hash of the directory's lock files.

### Building from an SDK checkout (`--sdk`)

`xdrcheck conform fetch|build|run --sdk PATH` runs the selected columns (one SDK's: `--column go --sdk ../go-stellar-sdk`)
against an SDK checkout instead of the pinned package, so a maintainer tests an unreleased branch. The committed
directory is never touched: `fetch --sdk` copies the column's language directory (`drivers/go/`, `drivers/rust/`,
`drivers/python/`) afresh to `$XDRCHECK_CACHE/conform/source-<key>/`, keyed by the checkout's path, and runs the copy's
`fetch` with `XDRCHECK_SDK_SOURCE` set to the checkout's absolute path and a cache directory of its own
(`<dir>@source-<key>`); `build` and `run` use that copy. A Makefile that supports it reads `XDRCHECK_SDK_SOURCE`:

| Target | With `XDRCHECK_SDK_SOURCE` |
|---|---|
| `fetch` | refuses to run in a directory inside `XDRCHECK_ROOT`; points the build at the checkout (Go: a `replace` directive and `go mod tidy`; Rust: a `path` dependency and `cargo update -p stellar-xdr`; Python: a wheel of the checkout) and fetches what the checkout needs, network allowed |
| `build` | builds offline as usual and writes `bin/xdrcheck-sdk-source` holding the checkout's path; without the variable it removes that file |

`run` refuses a copy whose `bin/xdrcheck-sdk-source` names another checkout, and a selection of several SDKs or of a
driver whose Makefiles do not read `XDRCHECK_SDK_SOURCE` (JavaScript: use the npm runner's `--sdk`,
[docs/use-in-sdk-ci.md](../docs/use-in-sdk-ci.md)). `describe` may then report any `sdk.version` (the checkout's
own; Go reports `(devel)`); known divergences are still judged against the column's pinned version, so a bug the
checkout fixes shows as `unexpected-conform`. `matrix.json` records the checkout as the column's `source`, and
`SUMMARY.md` says which column was built from it.

### JavaScript from an SDK checkout

Planned: this section is written with the change that builds it.

### Head columns

Planned: this section is written with the change that builds it.

## Running a driver

`xdrcheck conform run` starts the column's `run` command with the driver directory as its working directory,
`XDRCHECK_COLUMN` and `XDRCHECK_CACHE_DIR` in its environment, and no network. Then:

1. It sends `{"xcc":"xcc.driver/1","id":1,"op":"describe"}`. The answer must validate, and its `sdk.ecosystem`,
   `sdk.package` and `sdk.version` — read from the installed package, never from the driver's own
   configuration — must equal the column's; a column with a `profile` must find it in `decode.profiles`.
   Otherwise the column's cells are not run and the command exits 2.
2. It sends one `run` request at a time (`entry`, `variant`, `level`, `profile`, `input`) and waits for exactly
   one response line echoing `id`, `entry`, `level` (and `variant`, `profile` when present). A level the
   driver did not declare in `describe.levels` is recorded `n_a` without a request.
3. At the end it sends `shutdown`; the driver answers `{"ok":true}` and exits.

One long-lived process serves a column's cells, serially; columns run in parallel (`--jobs`). Entries built to
stress a reader (the `limits/` group, and any entry with a known divergence of outcome `crash` or `hang`) run in
a fresh process each. Limits per driver process: `--timeout` per request (default 20 s, plus as much again per MiB of the input, so large ledgers get proportionally longer), `--memory-max`
(default 1 GiB: a cgroup v2 `memory.max` with swap off, or polled process-group RSS where no user cgroup is
available) and `--as-limit` (`RLIMIT_AS`; off by default, because Go, Node and JVM runtimes reserve far more
address space than they use). Core files are disabled.

What the orchestrator does with each answer:

| The driver… | Recorded as |
|---|---|
| answers with a valid response | its outcome and reason (`source: driver`) |
| dies, is killed at the timeout, or is killed at the memory cap before answering | `crash` with reason `process_died`, `timeout` or `out_of_memory`, exit status, signal and the driver's stderr since the request (`source: orchestrator`); the next cell starts a fresh process |
| answers with anything that breaks the protocol (not JSON, an unknown field, a missing or out-of-enum value, a wrong id or echo, a `protocol_error`, an accepted cell without the evidence its level requires, `n_a/op_not_supported` for an op it declares) | a protocol error: the response is not trusted, the cell is not judged, the process is replaced, and the command exits 2 |

A driver must therefore never catch a fault-class error (stack overflow, out of memory, a panic) and report it
as `reject`; it reports `crash` with a reason, or lets the process die.

### Per-column resource limits

Planned: this section is written with the change that builds it.

## Outputs

`xdrcheck conform run --report DIR` writes:

| File | Contents |
|---|---|
| `SUMMARY.md` | start here: only the rows that need a look (a new divergence, one not yet triaged, a known divergence, an SDK-against-SDK split), each with its CAPs, the entry's bug class (validity and flags), the expected value from the corpus, every wrong column's answer with its declared divergence or finding, and a repro command; then the entry variants a column never read |
| `matrix.json` | `xcc.conformance.matrix/v1`: columns, entries (with their validity and flags), every judged cell with its outcome, verdict and check, the cross-SDK comparison, known divergences the run did not assert (no selected column inside the range, or every cell inside it `n_a`), infrastructure problems, and counts |
| `matrix.md` | the matrix as Markdown: one table per entry group, one row per entry, variant and level, one column per conformance column |
| `cross-sdk.md` | where the latest column of each SDK disagrees on an entry, with its CAPs and bug class |
| `report.json` | `xcc.report/v1`: one row per judged cell, in entry, variant, column, level order whatever the scheduling; the comparable part carries no times or host names |
| `cells.ndjson` | every cell: the request, the driver's response line verbatim, the crash record or the protocol error, and timings |
| `describe.json` | each column's `describe` and its problems |

Each cell gets a **verdict**, the driver's outcome against the entry's reference: `conform`; `diverge` (accepted,
with bytes or values that differ from the manifest's); `accepts_invalid` (accepted what must be refused);
`reject_valid` (refused a valid input); `crash`; `n_a`. A variant that needs an XDR feature the column's `describe`
probes report absent, refused cleanly (an undeclared union arm or enum value), is `n_a`, and so are the L1 and L2
cells of a variant whose L0 cell is such a refusal or a known divergence. Each cell also gets a **check** against
the entry's known divergences for the column's target, version and profile: inside a declared range the declared
outcome (with its declared detail) is `known`, `conform` is `unexpected-conform` and any other result
`known-changed`; outside every range `conform` stays `conform` and anything else is `undeclared`. A known
divergence whose version range does not parse stops the run (exit 2).

A variant with no `requires` list is beyond reach only when its protocol is above the `xdr_schema.protocol` the
column's driver reports, so a driver reports no more than it can prove. Each SDK driver reports 30 when every
Protocol 30 probe passes and 29 when one fails, and reports no protocol at all when the SDK declares a member
above the Protocol 30 definitions in one of a fixed set of enums (`ContractCostType`, `ConfigSettingID`,
`LedgerEntryType`, `OperationType`, `SCValType` and others; the table is in each driver's `reach` module): such
an SDK's XDR is newer than the driver's probes, and its refusals are judged, never excused. The stellar-core
column reports the ledger protocol the binary prints in `stellar-core version`. Each driver's tests assert the
protocol every pinned version reports, so pinning an SDK with newer XDR fails them until the driver learns the
next protocol's probes and enum ceiling.

| Command | Does |
|---|---|
| `xdrcheck conform check DIR/matrix.json` | exit 1 if any cell is `undeclared`, `unexpected-conform` or `known-changed`; 2 if the run had infrastructure problems |
| `xdrcheck conform diff A B` | list cells whose verdict or check changed, or that exist on one side only; exit 1 if any |
| `xdrcheck conform readiness --protocol N [matrix.json]` | the matrix restricted to entries introduced at Protocol N and to the latest column of each SDK major line |

`--tier bulk` runs stellar-core's golden files instead of the curated corpus, one cell per ledger at L0: the
files listed in the tier's hash index (`corpus.json` `tiers.bulk`) are read from the golden cache (`--goldens
DIR`, else `$XDRCHECK_GOLDENS`, else `~/.cache/xdrcheck/goldens`, as `<DIR>/<tag>/<file>`) and refused unless their hashes
match. `--entries` then selects files (`bulk/current/<TestName>/*`). The default timeout is 120 s.

`XDRCHECK_SETS` names a sets file other than `drivers/sets.toml` (the tests use it).
