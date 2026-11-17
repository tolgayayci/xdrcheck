# Vendored public-lake objects

Each directory `<network>/<ledger sequence>/` holds one object copied **byte for byte** from the public
Stellar data lake (SEP-54 layout, AWS Open Data bucket `aws-public-blockchain`) and its provenance,
`capture.json`. Objects are never re-encoded or recompressed. Testnet objects are perishable: testnet resets
(next on 2026-12-16) and the vendored copy may become the only one.

Written by `xdrcheck-corpus capture <network> <ledger> [--tx HASH] [--entry ID]`; checked against the lake by
`xdrcheck-corpus refetch [--network testnet|pubnet]`.

## Where an object comes from

- Stores (`pins.toml` `[public_lake]`): `s3://aws-public-blockchain/v1.1/stellar/ledgers/pubnet` and the
  current testnet epoch `…/testnet/2025-12-18`. One ledger per object, 64,000 objects per partition.
- Key of ledger `s`, with `p = s / 64000 * 64000`:
  `printf '%08X--%d-%d/%08X--%d.xdr.zst' $((0xFFFFFFFF-p)) $p $((p+63999)) $((0xFFFFFFFF-s)) $s`.
- Transport: anonymous HTTPS through `curl` at
  `https://aws-public-blockchain.s3.us-east-2.amazonaws.com/<store path>/<key>`; a `HEAD` for the object's
  user metadata, `Last-Modified` and `ETag`, then a `GET`. No credentials. `capture.json.refetch` is the
  command that fetches the same bytes.

## `capture.json` (`"schema": "xcc.capture/v1"`)

| Field | Meaning |
|---|---|
| `network`, `passphrase`, `ledger_seq` | The ledger |
| `store`, `key`, `url` | Where the object is: the `s3://` store root as manifests record it, the key under it, the HTTPS URL |
| `object_file` | The vendored object in this directory (the base name of the key) |
| `object_sha256`, `object_bytes` | The object as served (zstd) |
| `decompressed_sha256`, `decompressed_bytes` | After zstd decompression: the XDR `LedgerCloseMetaBatch` |
| `batch_index`, `blob_offset`, `blob_sha256`, `blob_bytes` | The ledger inside the batch: bytes `[blob_offset, blob_offset + blob_bytes)` of the decompressed object are one `LedgerCloseMeta`, the blob a manifest variant names. With one ledger per object, `batch_index` is 0 and `blob_offset` 12 (two sequence numbers and the array length) |
| `written_by` | `<core-version>; exporter <version>` from the object metadata |
| `regenerated` | `true` if the object was written by a stellar-core newer than the ledger's protocol era (rule below) |
| `perishable` | `true` for testnet |
| `object_metadata` | The object's user metadata (`x-amz-meta-*` without the prefix), as served |
| `object_last_modified`, `object_etag` | `Last-Modified` (UTC) and `ETag` of the object |
| `ledger` | Facts read from the blob: `protocol` (header), `protocol_upgrade` (new version, if the ledger upgrades the protocol), `ledger_close_meta_version`, `header_hash`, `close_time`, `close_time_utc`, `tx_count`, `transaction_meta_versions` (count per arm), `tx_hashes_recomputed` (every result's transaction hash was recomputed from its envelope under `passphrase`) |
| `captured_at`, `captured_with` | When and how the vendored object was first downloaded |
| `verified_at` | When a capture last confirmed the lake serves the same bytes |
| `refetch` | Command that fetches the same object |
| `shapes`, `shapes_note` | Research notes on shapes found in the ledger, carried over verbatim from the first capture (optional) |

A capture checks the object against itself before writing: the batch decodes under explicit limits and
re-encodes byte-exactly, the ledger is the requested sequence, the metadata's passphrase, ledger range and
protocol agree with the bytes, and every transaction hash is recomputed from its envelope. Re-capturing a
vendored ledger whose lake object now has other bytes fails (exit 1) and keeps the vendored copy.

**`regenerated`.** A core of major version N implements protocols up to N, and a network at protocol P runs
cores P and, before the vote to P + 1, P + 1. With `W` the writer's major version and `P` the header protocol:
`W > P + 1` is regenerated; `W = P + 1` is regenerated when the object was written (`Last-Modified`) more than
one day after the ledger closed, or when that time is unknown; `W ≤ P` is not regenerated. The pubnet lake's
Protocol 1–22 ledgers (written by core 23.0.1 in September 2025) are regenerated, and so is pubnet ledger
58762517 (Protocol 23, written by core 24.1.0 three months after it closed). A regenerated object is real core
output for that ledger, but not the bytes a node emitted when it closed: such ledgers carry TransactionMeta v4
and backfilled events whatever their protocol.

## History-archive objects

`<network>/history-archive/<checkpoint>/` holds objects copied byte for byte from a public stellar-core history
archive, for `history-archive` sources (`docs/manifest.md` §4.4): the checkpoint's History Archive State (HAS, the
JSON that names the bucket list) and the bucket file as served (`bucket-<hash>.xdr.gz`), with `capture.json`
(`"schema": "xcc.capture.history-archive/v1"`). `capture` does not fetch from archives; each object was fetched
with one anonymous `curl` GET whose response headers are recorded.

| Field | Meaning |
|---|---|
| `network`, `passphrase`, `checkpoint` | The archive's network and the checkpoint ledger of the HAS |
| `store`, `has` | The archive root URL; the HAS's key, URL, vendored file, sha256, size, writer (`server`), `Last-Modified` and `ETag` |
| `object`, `url`, `object_file` | The bucket's key under the root (the manifest's `source.object`), its URL and the vendored file |
| `object_sha256`, `object_bytes`, `compression` | The object as served (gzip) |
| `decompressed_sha256`, `decompressed_bytes`, `bucket_hash` | After gzip decompression; for a bucket the sha256 equals its hash in the HAS |
| `bucket_level`, `bucket_slot`, `record_count` | Where the HAS lists the bucket, and how many record-marked records it holds |
| `object_last_modified`, `object_etag`, `captured_at`, `captured_with`, `refetch`, `perishable` | As for lake objects |
| `records[]` | The records cut into blobs: `entry`, `record_index`, `byte_offset` (of the 4-byte record mark in the decompressed bucket, the manifest's `source.byte_offset`), `record_mark`, `blob_offset`, `blob_sha256`, `blob_bytes` |

The chain is: `object_sha256` → gzip decompress → `decompressed_sha256` (the bucket hash) → the record mark at
`byte_offset` → its body is the blob. For the vendored testnet bucket:

```sh
O=corpus/objects/testnet/history-archive/4378879/bucket-ab140ae5757d5bef1ff43fe364099d9d55b1477d2f17130e18485308fdada404.xdr.gz
sha256sum "$O"                                              # fe43c8fe…ed87578 = object_sha256
gzip -dc "$O" | sha256sum                                   # ab140ae5…fdada404 = the bucket hash
gzip -dc "$O" | tail -c +4483097 | head -c 116 | sha256sum  # bffde983…7393d6c0 = the blob at byte_offset 4483092
```

## Earlier layouts

The first 38 captures were written by hand before the tool existed, in two layouts: one with
`sha256_compressed`, `downloaded_utc`, `s3_head_object` and `commands`, and one with `object_sha256`,
`captured_at`, `captured_by` and no object metadata. Both were normalised to the format above by
re-capturing every ledger (all 38 objects were identical to the lake's); the first download time and the
shape notes were kept, and the two captures that had no metadata got it from the lake. `capture` still
reads both layouts.
