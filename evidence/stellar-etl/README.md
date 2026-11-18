# stellar-etl through a GCS emulator (2026-11-12)

stellar-etl **v2.8.34** (`2b24ec89ddce7fc0beb7795de982c93e6895eaf3`), the release pinned when this run was made,
unmodified, run over captured pubnet ledgers served from a GCS-compatible emulator on loopback, first by hand and then
through the replay harness with the stellar-etl adapter (`go/adapters/stellaretl`). The transcripts in this folder
are the evidence and record that version; `reproduce.sh` rebuilds the same commit so they compare. The pin is now
v2.8.35 (`7e3fc9af95359dad6ba939fa88791f49cdf531ae`, `pins.toml`); the five entries below also record a run at that
commit with the same result (`conformance.known_divergences`, `observed: executed`).

| What | Ledger / transaction | Result at v2.8.34 |
|---|---|---|
| Emulator path: export commands read a SEP-54 (Galexie) layout from fake-gcs-server | 64558277 (382 transactions) | every export exits 0: 1 ledger, 382 transactions, 649 operations, 615 effects, 970 token-transfer rows |
| stellar-etl#450: a text or hash `to_muxed_id` becomes an `M…` address with muxed ID 0 | 64558277 `6591994c…` (mint, text `psp:160886906`) | `to_muxed` `MBN32NH6…ATXO`, `to_muxed_id` `"0"`; replay: **mishandled · wrong_value**, the only differing fact |
| the same | 65437006 `7f2aaed8…` (five transfers, text `Daily 2026-11-12`) | five transfers with `to_muxed_id` `"0"`; **mishandled · wrong_value** |
| the same | 65437006 `c31dd894…` (transfer, 32 MEMO_HASH bytes) | `to_muxed_id` `"0"`; **mishandled · wrong_value** |
| the same, beside a correct one | 65437006 `425dacc1…` (op 1 to a muxed destination, op 0 with the text memo) | op 1 correct (`23144059716`); op 0 `"0"`; **mishandled · wrong_value** |
| go-stellar-sdk#6043: `support/contractevents` parses only the four-topic (pre-CAP-67) SAC mint, so the three-topic mint gets no effect | 64558277 `b35be42e…` (KALE mint by `invoke_host_function`) | no participant and no `balance_changed` for the recipient `GB237VS5…`; replay: **dropped · partial** (`cap-0067/sac-mint-three-topics`) |

In the effects export of 64558277, none of the 34 SAC mints made by `invoke_host_function` has a credited effect,
while all 101 mints made by classic payments have one; the token-transfer export records every mint. The cause is in
go-stellar-sdk (finding F-0038), which stellar-etl links; stellar-etl's effects table is the affected consumer.

Every other fact the four #450 entries state (all transactions with result codes, operation result codes and fees,
receipts, participants, the other movements) matched. The four entries carry the divergence as
`conformance.known_divergences` (target `stellar/stellar-etl`, level `replay`, versions
`2b24ec89…..2b24ec89…` and `7e3fc9af…..7e3fc9af…`, `observed: executed`), and `xdrcheck replay --assert-known` reports each as expected.

## Versions

- stellar-etl `2b24ec89ddce7fc0beb7795de982c93e6895eaf3` (tag v2.8.34), built with the toolchain its `go.mod` names
  (`go 1.27.3`) and cgo on (it links go-stellar-xdr-json, a cgo wrapper), `go build -trimpath`; binary sha256
  `bf0d60839c98536f39d9adae1b139fb2f212cf85d0bc3387bed3787850d104b2`. Its `go.mod` pins go-stellar-sdk
  `v0.8.1-0.20261106081502-e31e3b146d00`.
- fake-gcs-server v1.49.2 (the version go-stellar-sdk's datastore tests use): the binary for the by-hand check, the
  library inside the adapter.
- Lake objects: `corpus/objects/pubnet/64558277/FC26EB3A--64558277.xdr.zst` (sha256 `ec9d2e73…031d82`) and
  `corpus/objects/pubnet/65437006/`, unchanged from the public data lake.

## How stellar-etl reads ledgers here

- v2.8.34 reads ledgers only through go-stellar-sdk's datastore with the type fixed to `GCS`; there is no
  filesystem or S3 option. The Google storage client honours `STORAGE_EMULATOR_HOST` and then sends no credentials.
- The datastore path is `--datastore-path` plus `/pubnet` (or `/testnet`, `/futurenet` with the network flags), so
  objects live at `<bucket>/<prefix>/pubnet/<partition>/<object>.xdr.zst`, with the layout's `.config.json` beside
  the partitions.
- The client downloads through the XML API path `/<bucket>/<object, slashes as %2F>`. fake-gcs-server routes that
  path only when its `-public-host` equals the `Host` the client sends (`127.0.0.1:<port>`); with the default it
  treats the host as a bucket name and answers 404, which stellar-etl reports as `file does not exist`.
- Each export reads the ledger object once (four requests: bucket, list, `.config.json`, the object) and writes
  JSON Lines to `<out>/<start>-<end>-<name>.txt`. Nothing leaves loopback.

## Files

- `emulator-check.txt` — the by-hand run: fake-gcs-server, the five exports over ledger 64558277, the emulator's
  request log, and the token-transfer row of the #450 mint.
- `replay-assert-known.txt` — `xdrcheck replay --assert-known` with the adapter over every entry that declares a
  stellar-etl replay divergence (the four #450 entries and `cap-0067/sac-mint-three-topics`), and every missing or wrong fact per row (`report_facts.py`).
- `reproduce.sh` — regenerates the two transcripts into a scratch folder and compares them with these. `report_facts.py` — the helper it uses.

## Reproduce

```bash
go install github.com/fsouza/fake-gcs-server@v1.49.2   # network once, or set FAKE_GCS
# the adapter builds stellar-etl into its cache on first use (network once), or set STELLAR_ETL
bash evidence/stellar-etl/reproduce.sh                 # offline from then on
```

The script writes its transcripts to a scratch folder (`$WORK/transcripts`) and prints how they differ from the
committed ones; it never overwrites the files in this folder.

The linter half of stellar-etl#450 runs with `make fetch` once and then `make lint-stellar-etl OFFLINE=1`: xdrlint,
built with the Go toolchain stellar-etl's `go.mod` requires (`pins.toml` `[pipelines.stellar_etl] go_toolchain`),
reports XDR101 at the two `SetID` calls in `internal/transform/token_transfer.go`, matched by the frozen lists in
`lint/expected/stellar-etl/` to finding F-0015.
