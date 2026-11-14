# Minimal adapter: the template

For authors of an indexer written in Go. After this page you have run the adapter template against the corpus,
copied it into your own module, and connected it to your indexer so that `xdrcheck replay` can judge what your
indexer stores.

`main.go` is the smallest useful replay adapter. It lets `xdrcheck replay` drive an indexer over the corpus through
the protocol `xcc.adapter/1` ([docs/adapter-protocol.md](../../../docs/adapter-protocol.md)), and reports two
observation kinds:

- **receipts**: how many transactions and operations the indexer holds per ledger;
- **transactions**: each transaction's hash, apply-order index, success and fee charged.

With those two kinds the harness catches an indexer that drops a ledger or a transaction, crashes, hangs or halts.
The complete example, with every kind, is [`../baseline`](../baseline).

The adapter imports only go-stellar-sdk and the public package
[`adapterkit`](../../adapterkit) (`github.com/tolgayayci/xdrcheck/go/adapterkit`): the
protocol types, the stdio transport (`adapterkit.Main`), error codes, and `kittest` for your own `go test`.
Nothing under `internal/` is needed; a test copies `main.go` and `protocol_test.go` into a module of their own
and builds, vets and tests them there.

## Try it

From the repository's `go/` directory:

```sh
go build -o bin/ ./cmd/xdrcheck ./adapters/minimal
cd .. && go/bin/xdrcheck replay --adapter go/bin/minimal --selftest
go/bin/xdrcheck replay --adapter go/bin/minimal --target-version 0.1.0 --input sep54-dir --report reports/minimal
```

The selftest checks the protocol without scoring anything. The replay runs every entry of the corpus from a
plain directory (no Docker) in a few seconds and must pass. `make demo` (`scripts/demo.sh`) runs the same template
with one planted bug and shows what the report says about it.

## Copy it

1. Copy `main.go` and `protocol_test.go` into your own module and require the kit:

   ```sh
   go mod init example.com/my-indexer-adapter
   go get github.com/tolgayayci/xdrcheck/go@<commit>   # or a replace to a local checkout
   go mod tidy && go test ./... && go build -o my-adapter .
   ```

2. Work through the places marked `REPLACE`:
   - **Describe**: your adapter's name, the inputs your indexer reads (`sep54-dir`, `sep54-s3`, `rpc`), and its
     envelope: `indexer_gate` if it refuses ledgers on purpose, `sdk_limit` for the protocols its SDK decodes,
     or `none`. Declare only the kinds you map.
   - **Prepare**: create a fresh, empty store under `p.Workdir`; refuse one that already holds data.
   - **Ingest**: start your indexer on `p.Input` and `p.Range` (`adapterkit.RunChild` runs a separate program
     with a deadline), read its own progress marker and exit record, never its log text, and report the status
     the facts justify (adapter-protocol.md §4.3).
   - **Observe**: one query per kind, one fact per stored record, values exactly as stored. A ledger you hold
     nothing for is left out: that is how a drop is seen.
   - **Teardown**: drop the store.

3. Check it: `go test ./...` (in-process protocol checks), then
   `xdrcheck replay --adapter ./my-adapter --selftest`, then a replay with `--report DIR`. `DIR/REPORT.md` lists each
   failure with what the ledger holds, what your indexer held, and the command that replays that entry alone.

4. Add kinds as you go: participants, state changes, movements, addresses. Each switches on that kind's
   expectations for every entry; `../baseline` shows how each is derived.

An indexer in another language speaks the same JSON over stdin/stdout: see
[`examples/adapter-ts`](../../../examples/adapter-ts) for the TypeScript twin of this template.

## When it fails

| Symptom | Cause | Fix |
|---|---|---|
| `--selftest` fails | a response does not match the protocol schema | the message names the method and field; compare with `corpus/schema/adapter-protocol.schema.json` |
| every row `harness_fault` | the adapter exits, writes to stdout outside the protocol, or returns an error | write logs to stderr only; its stderr is in the report directory's `logs/` |
| rows `dropped · silent` on entries your indexer handles | `observe` reads the wrong store, or `prepare` reused a store | give each session a fresh store under `p.Workdir` |
| `mishandled · hang` everywhere | `ingest` never sees the progress marker reach `range.end` | read the marker your indexer writes, and set a deadline with `adapterkit.RunChild` |

What each class means: [replay-harness.md §7](../../../docs/replay-harness.md). Every message and status rule:
[adapter-protocol.md](../../../docs/adapter-protocol.md).

## Limits

- The harness judges only the kinds you declare in `describe`. An indexer that stores participants wrongly passes
  until you add the `participants` kind.
- `xdrcheck replay` runs on Linux only.
