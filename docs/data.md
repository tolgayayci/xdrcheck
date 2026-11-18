# `xdrcheck data`: the dataset and the ledger cache

The dataset is what the mainnet scan derived: the shape census per level and kind, the greedy covers, the token
census and its leads, the kept-ledger index, the locate index, the value tags, the corpus entries and the public
findings, plus named ledger sets. `xdrcheck find` and `xdrcheck replay` resolve their selections through it. A
dataset directory holds one `manifest.json` (schema `schemas/dataset-manifest.schema.json`, `xcc.dataset/v1`) that
**points at** those files with their size and sha256; large files are never copied.

```
xdrcheck data status   [--dataset DIR] [--verify]
xdrcheck data sets     [--dataset DIR] [--show NAME]
xdrcheck data fetch    (--ledgers LIST | --set NAME) [--out DIR] [--network pubnet|testnet] [--parallel N] [--rate R] [--from-local=false]
xdrcheck data manifest --root NAME=PATH... [--out DIR] [--version V] [--corpus DIR] [--findings DIR] [--no-hash]
xdrcheck data update   [--dataset DIR] [--to LEDGER]
```

The dataset directory is `--dataset`, else `$XDRCHECK_DATASET`, else `~/.local/share/xdrcheck/dataset`. The ledger cache is
`--lake`, else `$XDRCHECK_LAKE`, else `<dataset>/lake`.

## The manifest

| Key | What |
|---|---|
| `version`, `tip_ledger`, `network`, `created` | the dataset version and the newest ledger its census counted |
| `roots` | named directories: `derived` (census, covers, tokens, leads, kept-ledger index), `kept` (a lake-layout directory of kept ledgers), `scan` (the full scan's per-block Parquet), `hunt` (locate index, value tags, generated ledgers). `$XDRCHECK_DATASET_ROOT_<NAME>` moves a root, so one manifest serves machines whose data lives elsewhere |
| `lakes` | read-only lake-layout directories searched for a ledger before the cache |
| `tables` | per table: format (`tsv` with a header line, optionally zstd; `parquet`; `locate-index`), its files as `${root}/path` with bytes and sha256, or a glob whose checksums are the scan's own `MANIFEST.json` files, columns taken from file names, or `missing` with the reason (the producer has not run) |
| `sets` | per named set: a file of ledgers (`unit: ledger`) or of `ledger<TAB>tx_index` (`unit: tx`), its count |

Tables: `shapes` (every distinct shape per level G0–G3 and kind, with occurrences and first/last ledger),
`census_summary`, `census_facts`, `tokens`, `covers`, `cover_summary`, `rare_tokens`, `value_extremes`,
`event_signatures`, `rare_results`, `rare_change_cells`, `kept_ledgers`, `kept_tx_shapes`, `kept_components`,
`scan_occurrences`, `scan_tx_shapes`, `scan_components`, `locate`, `tags`, `tag_summary`, `corpus_entries`,
`findings`.

Sets: `controls`, `kept`, `token-cover`, `g0-cover`, `cap-<n>` (the corpus ledgers of each CAP captured from the network's history), and
`never-seen-generated` (ledgers a local stellar-core closed for arms mainnet has not shown).

## Worked example

```
$ xdrcheck data manifest --out ~/.local/share/xdrcheck/dataset --version 2026-11-17.1 \
    --root derived=/srv/xdrcheck/derived --root kept=/srv/xdrcheck/kept --root scan=/srv/xdrcheck/scan --root hunt=/srv/xdrcheck/hunt
dataset 2026-11-17.1, tip 65505999: 22 tables, 25 sets -> ~/.local/share/xdrcheck/dataset/manifest.json

$ xdrcheck data status
dataset   2026-11-17.1 (2026-11-17T13:36:23Z)
network   pubnet
tip       ledger 65505999
…
tables:
  kept_tx_shapes     tsv       1 files  715.8 MB  size-ok
  locate             missing: the locate index has not been built (xdrcheck-corpus scan locate-build)
  shapes             tsv      32 files    1.9 GB  size-ok
  tags               tsv       1 files  113.5 MB  size-ok
  tokens             tsv       1 files  616.3 KB  size-ok
…
$ xdrcheck data sets
cap-38                         2 tx      corpus examples of CAP 38 from pubnet history
controls                      21 ledger  control ledgers: each holds a property a check must flag
g0-cover                   98594 ledger  the fewest ledgers that show every G0 shape at least once
never-seen-generated           -  not available: the core generator has not produced ledgers
token-cover                 8116 tx      the fewest transactions that show every token at least once
…
$ xdrcheck find --class 'V|u64band' --limit 5 --format ledgers > ledgers.txt
$ xdrcheck data fetch --ledgers @ledgers.txt --out ./lake --from-local=false
5 ledgers into ./lake in 0.8s: map[ok:5], 158.9 KB downloaded
$ xdrcheck data fetch --ledgers @ledgers.txt --out ./lake
5 ledgers into ./lake in 0.0s: map[have:5], 0 B downloaded
```

`fetch` writes the lake layout (`<partition>/<object>.xdr.zst`) and an `index.tsv` (`seq path size md5`). Each
download is checked against `Content-Length` and the `ETag` (the public lake's objects are single-part, so the
ETag is their MD5); a mismatch is retried with back-off and then reported, never written. At most 256 requests
are in flight (`--parallel`, default 64) and `--rate` caps requests per second (default 200). It is resumable: a
ledger already in the cache with its recorded size and MD5 is kept. With `--from-local` (default) a ledger a
read-only lake of the dataset holds is copied, not downloaded.

## Keeping the data current: `xdrcheck data update`

`update` prints the plan of a top-up from the tip and runs nothing. The dataset is append-only: a top-up adds one
new block of every table for the ledgers after the tip (scan, census, token census, cover additions, locate, value
tags) and writes a new manifest version that lists the old files unchanged plus the new ones. A run directory
records the dataset version and the manifest's sha256 it resolved its selection through, and old versions' files
never change, so old runs stay reproducible.
