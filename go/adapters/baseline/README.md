# Baseline indexer and adapter

For indexer authors who want to see what a correct reader extracts from a `LedgerCloseMeta`, or who are adding
observation kinds to their own adapter. The baseline is a minimal ledger reader built on go-stellar-sdk v0.9.0, plus
the adapter that lets `xdrcheck replay` drive it. It has two jobs:

- **Reference reader.** It shows what a correct reader extracts from a `LedgerCloseMeta`, and from where. Every
  replayable corpus entry must match it with no missing or wrong facts. When it fails, either the baseline or the
  entry is wrong, and the entry is blocked until that is settled.
- **Complete example adapter.** It maps every observation kind, so it shows how each fact is derived and reported.
  To adapt your own indexer, start from the template [`../minimal`](../minimal) (receipts and transactions,
  about 150 lines) and come here for the kinds you add. Both are built on the public package
  [`adapterkit`](../../adapterkit), which holds the protocol types, the stdio transport and the test helpers;
  neither the template nor this adapter's protocol code imports anything under `internal/`. The contract stays
  the two schemas `corpus/schema/adapter-protocol.schema.json` and `observation.schema.json`, so an adapter in
  another language needs nothing from this repository ([`examples/adapter-ts`](../../../examples/adapter-ts)).

## Build and run

```sh
cd go && go build -o bin/ ./cmd/xdrcheck ./adapters/baseline/cmd/baseline && cd ..
go/bin/xdrcheck replay --adapter go/bin/baseline --target-version 0.1.0 --input sep54-dir --report reports/baseline
```

The one binary has two roles:

- `baseline [--max-protocol N] [--max-lcm-version N] [--min-protocol-with-transactions N]` is the adapter. It
  speaks `xcc.adapter/1`: one JSON request per line on stdin, one response per line on stdout, logs on stderr.
- `baseline index …` is the indexer. The adapter starts it for each `ingest`.

The gate flags lower the indexer's limits for testing, and `describe` always declares exactly the limits the
indexer enforces.

## What the indexer extracts, and from where

| Fact | Source in the ledger | Never from |
|---|---|---|
| receipts | transaction processing list, envelopes, meta: transactions, operations, consensus events, entry changes | — |
| transactions | hash recomputed from the envelope with the pass's passphrase (by the SDK's transaction reader); result pair; result codes in XDR-JSON names (`tx_success`, `set_options.success`) | — |
| participants | owners of every ledger entry changed in fee processing, transaction-level changes and operation changes; the fee payer; the source whose sequence number moved | envelope destinations, memos, Soroban authorization entries |
| muxed identity | a muxed ID only where the ledger carries a u64: a `MuxedAccount` in the envelope of an account the meta already made a participant, or a `to_muxed_id` of type u64 in an event; always an alias beside the base address | text or hash memos; `to_muxed_id` of type string or bytes |
| state changes | created / updated / removed / restored entries, classified by entry type and by diffing before and after (balances, signers, thresholds, flags, limits, sponsorship); the operation type only labels `cause` | effects inferred from operation type alone |
| movements | token-shaped contract events (`transfer`, `mint`, `burn`, `clawback`), each keyed on the contract that emitted it; fees and refunds from fee processing; balance deltas only when the ledger carries no classic events | envelope amounts; an asset named in an event's topics by a contract that is not that asset's contract |
| addresses | every address above, stored as its full strkey text | — |

**Events are trusted only as far as their emitter** (rule M-7 in `docs/manifest.md` §6.7):

- An event is a movement of a classic asset only when the emitting contract is that asset's Stellar Asset Contract
  under the pass's network.
- An event from any other contract that names a classic asset in its topics is a forged claim. Nothing is recorded,
  and the address it names does not become a participant.
- An event that names no classic asset is that contract's own token movement.

The derivation is in `indexer/derive.go` and `indexer/events.go`. Each step is a separate function (`feeStep`,
`txLevelStep`, `opChangesStep`, `eventsStep`, `balanceDeltaStep`, `aliasStep`), so a seeded-bug variant can
replace one step and nothing else. The envelope's claims (source, destinations, memo) are stored beside the facts
under `claimed` and are never mapped to facts.

## Gates (`enforcement: indexer_gate`)

| Gate | Default | Refusal |
|---|---|---|
| `max_protocol` | 30 | the header's protocol is higher |
| `ledger_close_meta_version` | 0–2 | the `LedgerCloseMeta` arm is newer |
| `min_protocol_with_transactions` | 10 | a ledger below it carries transactions |

A gate is checked before anything is written for the ledger. A refusal:

- exits with code 3;
- leaves `exit.json` naming the gate and the observed value;
- leaves the cursor below the refused ledger.

Any other stop:

- a fetch, decode or persist error exits with code 1 and an `exit.json` naming the phase;
- a Go runtime panic exits with code 2.

Every ledger is written whole (to a temporary file renamed into place) before the cursor moves past it, so a stop
never leaves a partial ledger.

## The store

The indexer has no database. Each session's store is `<workdir>/store/`:

- `ledgers/<seq>.json`: one document per ledger, holding its facts in the protocol's neutral vocabulary (one
  record per fact) and the `claimed` block;
- `cursor`: the last ledger stored;
- `exit.json`: written when a run stops on a ledger.

`observe` reads the documents back and sorts the facts by transaction index, operation index and JSON text. The
indexer reads no clock, so two sessions over the same unit give byte-identical observation sets.

## Writing your own adapter

Copy [`../minimal`](../minimal) and follow its README. When your indexer is a separate program with a store of
its own, as here, this adapter's protocol handler (`adapter.go`, on `adapterkit.Serve`) is the pattern:

1. **`describe`**: keep `Describe` constant. Declare only the inputs, units and observation kinds your indexer
   really has. Declare its real gates, or `enforcement: none`.
2. **`prepare`**: create an empty store for the session. Refuse a store you did not create.
3. **`ingest`**: start your indexer against the loopback input and range you are given, with a scrubbed
   environment. Read its progress marker and its own structured exit record, never its log text. Report the facts
   behind the status (`ingestResult` shows the order of the rules).
4. **`observe`**: map one stored record to one fact. Pass stored values through as `as_stored`, and do not clean
   them.
5. **`teardown`**: remove the session's store.
6. **Check it**: run `xdrcheck replay --adapter "<your command>" --selftest`.

The tests in this directory do the same: `adapter.Selftest`, then plan → serve → adapter → match over every
replayable corpus entry, on the SEP-54 directory, mock RPC and (where the object store can run) S3 inputs.
