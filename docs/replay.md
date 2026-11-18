# `xdrcheck replay --target`: any target, any version, any ledger

For SDK maintainers and pipeline operators who want to run one SDK or pipeline, at any version, over chosen real
ledgers: a ledger range, one transaction, a named set, the ledgers of a CAP, or a known issue before and after its
fix.

`xdrcheck replay` has three forms:

| Form | Selected by | Runs | Writes |
|---|---|---|---|
| corpus | `--adapter` ([replay-harness.md](replay-harness.md)) | corpus entries through an indexer adapter, judged against the entries' expected values | a report |
| target (this page) | any of `--target`, `--issue`, `--tx`, `--ledgers`, `--set`, `--cap`, `--ledger-file` | **real ledgers** (mainnet, testnet or corpus) through **one target at one version** | a run directory ([run-directory.md](run-directory.md)) |
| rig | `--rig wallet-backend\|stellar-etl\|horizon` ([Pipeline targets](#pipeline-targets)) | one service rig directly | the rig's raw output, not a run directory |

`xdrcheck replay --help` prints the three usage lines; `xdrcheck replay --target T --help` and
`xdrcheck replay --rig R --help` print the flags of the other two forms.

```
xdrcheck replay --target TARGET --version VERSION  SELECTION...  [--out DIR] [--network pubnet|testnet]
           [--dataset DIR] [--lake DIR] [--corpus DIR] [--offline] [--rebuild] [--force]
           [--dispositions FILE] [--issues-overlay FILE] [--fail-on DISPOSITION]
```

## Selection

| Flag | Selects |
|---|---|
| `--ledgers 30941181,30941857` or `--ledgers 100-200` or `--ledgers @file` | whole ledgers |
| `--tx 30941181:51` | one transaction: the ledger and the 0-based position of the transaction in the ledger's apply order (the order of its transaction results). Repeatable. Rows of the other transactions of that ledger are dropped |
| `--tx <64-hex hash>` (with `--ledgers`) | a transaction by hash, searched in the selected ledgers |
| `--set NAME` | a named set of the dataset ([data.md](data.md), `xdrcheck data sets`) |
| `--cap 38` | the corpus ledgers of every entry that names CAP 38, on `--network` |
| `--issue js-stellar-sdk#1766` | a known issue from `issues.json`: its ledger, its transaction, its target, and by default its pre-fix version (`--fixed` for the fixed one) |
| `--ledger-file FILE` | a ledger object you have: a zstd `LedgerCloseMetaBatch` (a lake object) or a raw `LedgerCloseMeta` named `SEQ.xdr` |

Ledgers that no local lake holds are downloaded from the public lake into the ledger cache first (size and MD5
checked, as `xdrcheck data fetch` does), unless `--offline`.

## Targets and versions

| Target | What runs | `--version` |
|---|---|---|
| `go` | the Go sweep against `github.com/stellar/go-stellar-sdk`: codec, txnbuild parse, hash, re-encode, operation and transaction rebuild, every `ingest.LedgerTransaction` helper, byte-presence checks, token-transfer modes, `VerifyEvents`, Stellar Asset Contract events | a tag (`v0.9.0`), a commit, a branch (`main`), or a local checkout (a `replace` directive) |
| `js` | the JS sweep against `@stellar/stellar-sdk`: codec, parse, hash, re-encode, operation and transaction rebuild, JSON round trip, `Operation.fromXDRObject`, `scValToNative` | an npm version, a commit or branch of `stellar/js-stellar-sdk`, or a local checkout |
| `python` | the Python sweep against `stellar-sdk`: codec, parse, hash, re-encode, JSON round trip | a PyPI version, a commit or branch of `StellarCN/py-stellar-base`, or a local checkout |
| `rust` | the Rust sweep against `stellar-xdr`: codec, transaction extraction, serde JSON round trip | a crates.io version, a commit or branch of `stellar/rs-stellar-xdr`, or a local checkout |
| `wallet-backend`, `stellar-etl`, `horizon` | the pipeline's rig ingests the ledgers into its database and exports rows; the judge compares the rows with facts it computes from the ledger itself | whatever the rig accepts (a commit or tag) |

The sweep programs are embedded in the `xdrcheck` binary. Each (target, version) is built once into
`$XDRCHECK_CACHE/targets/<target>/<version>/` (default `~/.cache/xdrcheck`) and reused; a tag or full commit is never
rebuilt, a branch is re-resolved on every run (pass `--offline` to use the cached build), and a changed sweep
program is rebuilt. The run manifest records both the version asked for and the version built (for `main`, the Go
pseudo-version or the package version and ref).

The SDK sweeps need the target's own toolchain: Go for `go`, Node.js 22.15 or newer and npm for `js`, Python 3
and the `zstd` command for `python`, Rust for `rust`. A missing toolchain is reported as `not available: <tool>
missing`, with status `unavailable` and no rows; it is never a pass.

### Pipeline targets

Pipeline targets run through two programs:

| Program | Found as | Called as |
|---|---|---|
| rig | this binary's `xdrcheck replay --rig <target>` (the service rigs), or the command in `$XDRCHECK_RIG_WALLET_BACKEND` (`_STELLAR_ETL`, `_HORIZON`) | `RIG --ledgers @LIST --commit V --lake LAKE --network P --fetch none --out DIR`; it builds the pipeline at V, ingests the listed ledgers (ascending) from the lake-layout directory into one database and writes `DIR/rows.jsonl` in the judge's row schema; it also writes `DIR/status.jsonl` (`ingested`, `halted`, `skipped` or `harness_fault` per ledger); exit 0 every ledger was ingested, 1 a ledger halted or was skipped (rows are still judged), 2 a harness fault |
| judge | `$XDRCHECK_JUDGE`, else `xdrcheck-judge` on `PATH` | `JUDGE facts --root LAKE --list LEDGERS --network P -o FACTS.jsonl`, then `JUDGE verdict --facts FACTS.jsonl --rows ROWS.jsonl -o VERDICTS.jsonl` |

Every judge verdict other than `ok` becomes a row with check `judge-<kind>` and the judge's class; `unknown` (the
judge's truth is incomplete) has verdict `error`, the others (`missing`, `extra`, `wrong_value`, `duplicate`,
`skip`, `halt`) `fail`.

A pipeline run whose rig did not ingest every ledger is `partial`: its rows are still judged (the judge turns a halt
into a row, so a known halt stays visible to clusters and run comparison), and the summary message counts the
ledgers not ingested (see `work/rig/status.jsonl`). A run whose rig wrote no `status.jsonl`, or ingested every
ledger and wrote an empty `rows.jsonl`, is `failed`.

## Run states and exit codes

The run directory's `summary.json` has one of four states ([run-directory.md](run-directory.md)):

| State | Meaning | Exit |
|---|---|---|
| `complete` | the run ran over every selected ledger (whatever it found) | 0, or 1 with `--fail-on D` when a cluster has disposition D |
| `partial` | a pipeline rig did not ingest every ledger; the rows of the run are judged but do not cover every ledger | 2 |
| `failed` | the run could not run: a build or run failure, a ledger that could not be fetched or is not local with `--offline`, a rig without per-ledger status, or no rows from fully ingested ledgers | 2 |
| `unavailable` | the target is not available on this machine (a missing toolchain); no rows, never a pass | 3 |

Bad arguments also exit 2, before any run directory is written. The rig form (`--rig`) exits as the rig does
(0, 1 or 2, above).

## Worked example: a known issue, before and after its fix

```
$ xdrcheck replay --issue js-stellar-sdk#1766 --out runs/1766-prefix
built js 17.2.0 (~/.cache/xdrcheck/targets/js/17.2.0)
xdrcheck js@17.2.0: complete (rows limited to the selected transactions; tested counts cover whole ledgers); 2 rows in 2 clusters -> runs/1766-prefix
  candidate            1  op-decode|Error:Assets are not in lexicographic order
  candidate            1  tx-parse|Error:Assets are not in lexicographic order

$ xdrcheck replay --issue js-stellar-sdk#1766 --fixed --out runs/1766-fixed
built js 17.2.1 (~/.cache/xdrcheck/targets/js/17.2.1)
xdrcheck js@17.2.1: complete (rows limited to the selected transactions; tested counts cover whole ledgers); 1 rows in 1 clusters -> runs/1766-fixed
  builder-default      1  tx-rebuild|rebuild-throws:TimeBounds has to be set or you must call setTimeout(TimeoutInfinite).

$ xdrcheck runs compare runs/1766-prefix runs/1766-fixed
A js@17.2.0
B js@17.2.1
-      1      0  op-decode|Error:Assets are not in lexicographic order
+      0      1  tx-rebuild|rebuild-throws:TimeBounds has to be set or you must call setTimeout(TimeoutInfinite).
-      1      0  tx-parse|Error:Assets are not in lexicographic order
```

The issue's ledger is testnet 5521432 from the corpus entry `cap-0038/pool-issuers-order-by-bytes-not-strkey`;
the pool-share trustline in its transaction 2 has issuers whose strkey text order is the reverse of their byte
order. The fixed version parses it; the builder default that remains on both is noise by disposition.

The same transaction on mainnet-style input, any version:

```
xdrcheck replay --target go --version v0.9.0 --tx 30941181:51
xdrcheck replay --target go --version main   --tx 30941181:51
xdrcheck replay --target go --version ../go-stellar-sdk --ledgers 30941100-30941199
```

## `issues.json`

`go/internal/hunt/issues/issues.json` (schema `schemas/issues.schema.json`) maps a public issue to its target, the
version before and after the fix, the corpus entry or ledger that shows it, the transaction, and the expected
check and class. Only public issues belong there. A private overlay in the same format, given by
`--issues-overlay FILE` or `$XDRCHECK_ISSUES`, adds more without touching the tree.
