# Horizon rig

For Horizon operators and contributors: how to run real ledgers through an unmodified
[stellar-horizon](https://github.com/stellar/stellar-horizon), export what it stored as rows the judge reads, and
what the rig cannot see. Horizon is fed by its own history reingestion with the datastore ledger backend, so no
captive core, no history archive and no network are involved.

## Build and run

```sh
cd go && go build -o bin/ ./adapters/horizon/cmd/horizon-rig
bin/horizon-rig --lake LAKE --ledgers list.txt --version v30.0.1 --horizon-src stellar-horizon-clone \
  --out runs/x --shards 8
```

| Option | Meaning |
|---|---|
| `--lake DIR` | ledgers in the SEP-54 lake layout (one ledger per `.xdr.zst` file, 64,000 files per partition); mounted read-only |
| `--ledgers FILE` / `--range S-E` | ledgers to run (first field of each line; other lines are ignored) |
| `--version V --horizon-src CLONE` | tag, branch or commit, built once into `--bin-dir` as `stellar-horizon-<commit>` (static, `CGO_ENABLED=0`, release version string) |
| `--horizon-bin FILE` | a prebuilt static binary instead |
| `--shards N` | parallel workers, one Horizon database each |
| `--group single\|contiguous` | one `db reingest range` per ledger (default), or one per run of consecutive ledgers (`--max-group`) |
| `--passphrase P` | network passphrase (default pubnet); passed as a custom network, with an archive URL that is never contacted |
| `--timeout D` | per reingest call; a timeout is a halt |

`horizon-rig rows --out rows.jsonl [--commit C] RUN/tables` re-exports the common rows from a run's raw dumps.

## What it does

1. Starts Postgres and one long-lived container for the static Horizon binary on an internal Docker network (no
   egress), creates one database per shard and runs `db init` in each.
2. Ledgers whose file is not in the lake are `skipped` and never sent to Horizon. The rest are planned into
   segments and spread over the shards. Each segment is one
   `stellar-horizon db reingest range S E --ledgerbackend datastore --datastore-config <Filesystem datastore>
   --network-passphrase P --history-archive-urls <unused> --db-url <shard>`.
3. A segment that exits 0 marks its ledgers `ingested`. A failing single-ledger segment is `halted` with the error
   Horizon logged. A failing multi-ledger segment commits nothing and its error need not name the ledger, so every
   ledger of it is rerun alone: each becomes `ingested` or `halted` on its own (`attempt: probe`), and
   `stopped_at` keeps the last ledger the backend returned before the segment stopped.
4. Every status is cross-checked against the shard's `history_ledgers`; a mismatch is a harness fault (exit 3), and
   so is a failure of the rig's environment before Horizon reads the ledger (status `harness_fault`). History-archive
   caching is off: concurrent calls in one container otherwise race on Horizon's shared bucket-cache directory.
5. `dump.sql` dumps every history table Horizon fills, with internal ids resolved to addresses, assets, pool and
   claimable-balance ids, into `tables/<table>.jsonl.zst`; `rows.jsonl` maps them to the common rows.

## Run directory

```
manifest.json        version, commit, binary sha256, lake, counts, shards, segment mode, images, command
status.jsonl         one line per requested ledger: ingested | halted | skipped | harness_fault, segment, shard, error, error_ledger, stopped_at
tables/*.jsonl.zst   raw history tables (integers with every digit; parse them as exact numbers)
rows.jsonl           common rows, sorted by ledger
summary.json         status counts, harness faults, rows per table and kind, setup / ingest / export time, time per ledger
logs/                Horizon's output of every failed call
```

## Common rows

Rows are what the judge (`crates/xdrcheck-judge`, `verdict --rows`) reads, plus the rig row fields: `kind`,
`pipeline` (`horizon`), `commit`, `source` (the table), `ledger`, `tx_index` / `op_index` (0-based apply order;
Horizon's are 1-based), `tx_hash` (outer hash for a fee bump), `exact` (always true), amounts as integer strings in
the smallest unit. Run the judge with `--balance-scope nofee` and `--kinds` limited to what Horizon exports.

| Table | Kind |
|---|---|
| `history_ledgers` | `ledger` |
| `history_transactions` | `tx` (`result_code` decoded from the stored result) |
| `history_operations` | `operation`; each `asset_balance_changes` entry of an `invoke_host_function` → `token_event` (`contract` = the asset's SAC id) |
| `history_effects` | `balance_change` for every amount-bearing effect (`reason` = effect name, signed from the holder's side; `contract_credited` / `contract_debited` → the contract; `liquidity_pool_trade`, deposits and withdrawals → the pool's reserves too; claimable-balance effects → the balance entry `B…`; the taker-side `trade` effects of a path payment are skipped because its debit and credit effects already carry it; `fee` false), `entry_change` (`created` / `updated` / `removed`, `entry_key` = base64 LedgerKey XDR, one per operation, key and change) where the effect states an entry's lifecycle; this is a subset of the entry changes, not all of them |
| `history_transaction_participants` | `participant` (`holder`), one per transaction and account |
| `history_trades`, `history_trades_60000`, `history_operation_participants`, claimable-balance and liquidity-pool link tables | `other` (verbatim) |

## Limits

- `db reingest range` runs Horizon's transaction (history) processors only. The state tables (`accounts`,
  `accounts_data`, `accounts_signers`, `trust_lines`, `offers`, `liquidity_pools`, `claimable_balances`,
  `claimable_balance_claimants`, `asset_contracts`, `contract_asset_balances`, `contract_asset_stats`,
  `exp_asset_stats`) stay empty; they need history-archive checkpoint ingestion, which this rig does not run. The
  1-minute trade aggregation `history_trades_60000` is filled and dumped (as `other` rows).
- History reingestion needs no neighbours: a ledger ingested alone gives the same rows as the same ledger inside a
  dense range, so sparse ledgers are fine.
- Horizon has no fee effects, so its balance changes never include a transaction's fee (`fee` is always false).
- Horizon emits `account_credited` / `account_debited` for an issuer moving its own asset; the judge holds no balance
  for an issuer, so those rows read as extra. A path payment whose source is also a maker of one of its hops loses
  that maker side.
- A Horizon release stops on a ledger whose protocol is newer than the one it supports; that is a `halted` status
  with Horizon's message, not a harness fault.
