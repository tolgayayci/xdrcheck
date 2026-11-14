# stellar-etl adapter

For stellar-etl operators and for authors of batch-export indexers: how the stellar-etl adapter builds and drives an
unmodified [stellar-etl](https://github.com/stellar/stellar-etl) binary at the version under test through
`xcc.adapter/1`, how it decides a status without a cursor, and how export rows become facts. Executed results:
`evidence/stellar-etl/`.

## Build and run

```sh
cd go && go build -o bin/ ./adapters/stellaretl/cmd/stellaretl ./cmd/xdrcheck
bin/xdrcheck replay --corpus ../corpus --adapter bin/stellaretl --target-version 7e3fc9af95359dad6ba939fa88791f49cdf531ae \
  --assert-known --report ../reports/stellar-etl
```

`--target-version` takes a tag (`v2.8.35`, the release `pins.toml` `[pipelines.stellar_etl]` pins) or a full commit.
Options of the adapter itself:

| Option | Meaning |
|---|---|
| `--cache-dir DIR` | cache root when `prepare` names none (default: the user cache directory's `xdrcheck/adapters`, the one `xdrcheck replay` passes) |
| `--repo DIR` | use an existing stellar-etl clone instead of `<cache>/stellar-etl/repo.git` |
| `--etl-binary FILE` | use a prebuilt stellar-etl for every target instead of building one (tests, CI) |
| `--offline` | never clone, fetch or build; use what the cache holds |
| `--halt-oracle FILE` | append one JSON line per export per ledger of every ingest: how that export ended there (`ok`, `halted`, `crashed`, `timeout`, `not_reached`, `not_run`, with exit status, signal, runtime panic, wall time and peak memory). The ledger a failed export stopped at is the first one it fails on when rerun alone on one ledger, from its last rows upward (`failing_ledger_by: probe`, reruns logged to `logs/<export>.probe.log`); when none fails alone or the deadline leaves no time, the ledger after its last rows, else the range start (`failing_ledger_by: rows`) |
| `--export-memory-max BYTES` | memory cap per export command; a command killed at the cap is a crash |

## What it does per session

1. **`prepare`** resolves the target in a blob-less clone of stellar-etl (`<cache>/stellar-etl/repo.git`, cloned on
   first use), builds `bin/stellar-etl-<commit>` once with the Go toolchain the commit's `go.mod` names and cgo on
   (stellar-etl links go-stellar-xdr-json, a cgo wrapper), and answers `resolve_ranges`: `A..B` is every commit
   from A to B on B's first-parent history, `..B` everything up to B. A cold build needs the network once (the
   clone, Go modules, the toolchain); later runs work offline.
2. **`ingest`** serves the harness's `sep54-dir` layout through a GCS-compatible emulator on loopback
   (fake-gcs-server's library, the emulator go-stellar-sdk's own datastore tests use) and runs every export
   stellar-etl has — `export_ledgers`, `export_transactions`, `export_operations`, `export_effects`,
   `export_token_transfer`, `export_contract_events`, `export_trades`, `export_ledger_entry_changes`,
   `export_assets` and `export_ledger_transaction` — over the range, one after the other (a failed export does not
   stop the ones after it), each with `-o <session>/out/<command>/ --datastore-path xdrcheck/lake` and the network flag
   (`--testnet`, `--futurenet`, none for pubnet), in a scrubbed environment (`PATH`, `HOME` and
   `STORAGE_EMULATOR_HOST` only).
3. **`observe`** reads the JSON Lines back and maps them (below).
4. **`teardown`** removes the session's folders.

stellar-etl reads ledgers only from a GCS datastore (the type is fixed in its code, at v2.8.34 and at the pinned
v2.8.35 alike), so `sep54-dir` is the only input declared; the emulator is the adapter's, and the indexer is
pointed at it exactly as it would be pointed at a bucket. Other passphrases than pubnet, testnet and futurenet cannot be configured in stellar-etl and are
answered with `unsupported_input`.

## Status

stellar-etl is a batch tool with no cursor. The adapter's progress marker is the highest ledger in the ledgers
export once every command has exited 0; status rests on exit codes, signals and rows, never on log text.

| Facts | Status |
|---|---|
| every command exited 0 and the ledgers export reaches `range.end` | `completed` |
| a command was still running at the deadline | `timeout` |
| a command ended by a signal, or exited 2 with a Go runtime panic on stderr (`runtime_panic: true`) | `crashed` |
| any other non-zero exit | `halted`: `failing_ledger` is the ledger after the last one the failing command wrote rows for, `rows_for_failing_ledger` counts every export's rows for it |

## Envelope

`sdk_limit`, from the go-stellar-sdk version the target's `go.mod` pins: v0.8.x (including the v0.8.1
pseudo-versions of v2.8.33 and v2.8.34) → `max_protocol` 30; v0.7.x → 29. Without a local clone at `describe` time,
or for any other SDK version, nothing is declared (`enforcement: none`). The pinned v2.8.35 pins go-stellar-sdk
v0.9.0, which the adapter does not classify yet, so at the pin no envelope is declared.

## Row mapping

One stored row is one fact; nothing is derived or repaired.

| Kind | From | Mapping |
|---|---|---|
| receipts | transactions, operations and contract-events exports | the number of rows held for the ledger (`transactions`, `operations`); `events`: the contract-events rows that are operation events (`operation_id` set) or transaction-level fee events (first topic `fee`), never the diagnostic rows the same table holds |
| transactions | transactions export | `transaction_hash`; `index` from the TOID (`id`); `successful`; `transaction_result_code` → XDR-JSON name (`TransactionResultCodeTxFeeBumpInnerSuccess` → `tx_fee_bump_inner_success`), the label kept as `native_label`; `fee_charged` as its token; `inner_transaction_hash`; operation result codes from the operations export (`PaymentResultCodePaymentSuccess` → `payment.success`) |
| participants | transactions (`account`, `fee_account`), operations (`source_account`), effects (`address`), trades (`selling_account_address`, `buying_account_address`, located by `history_operation_id`) | the column as `address`; its `_muxed` column, when set, as `on_chain_form` |
| state changes | effects export | `account_created`, `account_removed`; `account_credited`/`account_debited` → `balance_changed` (amount as `delta_as_stored`); `trustline_created`, `trustline_removed`, `trustline_updated` → `trustline_limit_changed`, `trustline_flags_updated` → `trustline_flags_changed`; `signer_created`/`removed`/`updated` → `signer_added`/`removed`/`changed`; `account_thresholds_updated` → `thresholds_changed`; `sequence_bumped`. Other effect types are not mapped |
| movements | token-transfer export, topics `transfer`, `mint`, `burn`, `clawback` | `amount_raw` as `amount` (the float `amount` only as `amount_as_stored` when there is no raw value); asset `CODE:ISSUER`, `native`, or the emitting contract; `to_muxed` as `to.on_chain_form` and `to_muxed_id` as a `u64` routing ID, exactly as written. Fee rows are not mapped: a refund is a `fee` row with a negative amount |
| addresses | — | not provided: most addresses sit inside per-type detail columns |

`export_ledger_entry_changes`, `export_assets` and `export_ledger_transaction` are mapped onto no fact: they are
judged on how they end (status table above, and the halt oracle). `scripts/replay-etl.sh` (`XDRCHECK_REPLAY_ADAPTER=stellar-etl
scripts/replay-full.sh`) replays the whole corpus with the halt oracle on and fails on any export that did not end ok.

Effects and operations carry no transaction hash; their TOIDs (`ledger<<32 | order<<12 | op`) locate them through
the transactions export.

## Service rig (`xdrcheck replay --rig stellar-etl`)

- **Network and path.** stellar-etl has no passphrase flag: `--testnet` / `--futurenet` / none pick the passphrase and
  the datastore suffix (`<--datastore-path>/<testnet|futurenet|pubnet>`); the layout is fixed at one ledger per file,
  64,000 files per partition. Standalone ledgers closed with the testnet passphrase are exact under `--testnet`. A
  wrong network flag still exits 0 with rows (transaction hashes then come from the wrong passphrase), so the rig
  derives the flag from the lake's passphrase and refuses others.
- **Absent ledgers** are fatal in stellar-etl (exit 1, "ledger object … is missing"), not an empty export. The rig
  passes an absolute output directory (each export runs with its working directory in the segment folder) and
  calls a command that reports successful transforms but wrote no file a harness fault.
- **Status.** `ingested`, `halted`, `skipped`, `harness_fault`, and `dropped`: every export exited 0 but a drop check
  failed (`drop_checks_failed` names them). Nonce entries are left out of the contract-data check (stellar-etl
  discards them by design).
- **Judge rows.** `ledger`, `token_event` and `balance_change` go to the judge: balance changes are derived from
  `export_token_transfer` rows of classic assets (fees included; use `--balance-scope net`), never from effects,
  which have no credit or debit for trades, pool legs, creation and merges. Pass
  `--kinds ledger,balance_change,token_event`: entry changes are compacted per ledger without a transaction
  (`ledger_entry_change`), transactions give only source and fee account, and `approve` is not exported.

## Tests

- `observe_test.go` — the mapping on rows stellar-etl wrote for ledger 64558277 (`testdata/out`), and the harness's
  matcher on them: the mint in that ledger is a wrong routing value.
- `gcs_test.go` — go-stellar-sdk's GCS datastore, the reader stellar-etl uses, reads a layout from the emulator.
- `adapter_test.go` — the protocol selftest, completed and halted ingests, the passphrase refusal and commit ranges,
  with a stand-in for stellar-etl that reads the ledger from the emulator and writes the fixture rows.
- `real_test.go` — with `XDRCHECK_STELLAR_ETL_CACHE` pointing at a cache that holds the clone and the binary of the
  pinned commit: the real stellar-etl over every entry declaring a stellar-etl replay divergence
  (`--assert-known`); skipped otherwise.
