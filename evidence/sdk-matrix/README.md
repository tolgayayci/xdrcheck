# Cross-SDK divergence probe (throwaway, research only — 2026-11-12)

Not product code. Executes 111 vectors (10 groups) through 19 SDK/version/config columns and writes a divergence matrix.

## Re-run everything (one command)

```sh
cd evidence/sdk-matrix
bash run.sh                 # installs anything missing, builds probes, regenerates vectors, runs all, writes results/matrix.md
bash run.sh "python 17.0.1" # optional substring filter on "<sdk> <version>"
```

Outputs: `results/<sdk>_<version>.jsonl` (one JSON line per vector: `{vector,sdk,version,p30,outcome,got,detail}`),
`results/depth_boundaries.jsonl` (bisected depth limit), `results/extra_as_limit.jsonl` (memory vectors under `prlimit --as=1GiB`),
`results/matrix.md` (generated table; do not edit). Inspect one file quickly: `python3 -I show.py results/go_v0.8.0.jsonl`.

The result files are not committed: `run.sh` writes them under `results/` (ignored by git), and the corpus entries
cite the probe vectors and the `xcc conform` commands that reproduce each divergence instead. The drivers' self-tests
compare their driver with the result files when a run has written them (or with `$XCC_OVERLAY/evidence/sdk-matrix/results/`
when `XCC_OVERLAY` is set), and `XCC_OVERLAY=… python3 -I make_matrix.py` writes the table there.

A single probe can be run by hand with a vector ID, e.g.
`node js/probe.mjs js/17.2.0 vectors/vectors.json 1c` · `go/v0.7.1/probe vectors/vectors.json 9I1` ·
`rust/target-x30_0_0/release/probe vectors/vectors.json none 6h` · `py/venv-17.0.1/bin/python -I py/probe.py vectors/vectors.json 3a`.

## Layout

| path | what |
|---|---|
| `vectors/gen_vectors.py` → `vectors/vectors.json` | every vector hand-encoded in plain Python (own XDR + SEP-23 encoder, no SDK); each has `expect` and `why` (core/spec justification). sha256 of vectors.json: `bf7a2ec7e1b1a51266282a9f9cf6f67ee19ec040ee11f3a1d4092c67ec722527` |
| `data/` | real bytes: testnet tx envelope `0126748091…346f` (copied from `../js-1766/`), Galexie objects for testnet ledgers 5540313 (P30 upgrade ledger) and 5540314 (first SIGNED_MS ledger) |
| `js/probe.mjs` + `js/<ver>/` | one npm install per version; one probe handles v16 and v17 APIs |
| `go/common/main.go` + `go/<ver>/` | one Go module per SDK version (main.go symlinked), go-xdr as pinned by the SDK's go.mod |
| `rust/common/main.rs` + `rust/x<ver>/` | one crate per stellar-xdr version; mode arg `limits` = `Limits{depth:500,len:input.len()}`, `none` = `Limits::none()` |
| `py/probe.py` + `py/venv-<ver>/` | one venv per stellar-sdk version |
| `run_all.py`, `depth_bisect.py`, `make_matrix.py` | runner (crash isolation: a vector whose process dies is re-run alone and recorded `crash`), depth bisection, table |

Outcome codes: `ok` accepted and value matches expectation · `reject` clean error · `wrong` accepted invalid input or produced a different value ·
`crash` process abort / panic / stack overflow / OOM · `n/a` API absent (reason in `detail`). Memory vectors (group 6h) run one per process in
`systemd-run --user --scope -p MemoryMax=1G -p MemorySwapMax=0`; peak RSS (ru_maxrss of the child) is appended to `detail`. `/usr/bin/time` is not installed.

## Toolchains

Node v24.19.0, npm 11.17.0 · go1.25.14 linux/amd64 · rustc/cargo 1.98.1 (release profile) · Python 3.13.16 (mise; system python3 lacks ensurepip) ·
Linux 6.12, 8 MiB main-thread stack (`ulimit -s 8192`).

## Pinned packages (registry integrity)

| ecosystem | package@version | integrity |
|---|---|---|
| npm | @stellar/stellar-sdk@16.3.0 | sha512-pnB1t4bdnkN8M7tRIcLXnNboq+Hof62NzPMnQrl5MWBNC/d1vUbdrzXgy7yw8I+0hbfz5YN64uVb84BqzIpYiQ== |
| npm | @stellar/stellar-sdk@16.3.1 | sha512-PPM1JA51NChSPyMkh+T9sHxJtP/v9e9Gcyc2BMNvnGvbZwqoKJclRSdPgmalLDAmTnTewGs7VMM9nRxDeCzzgQ== |
| npm | @stellar/stellar-sdk@16.4.1 | sha512-0kT+ShOUE6dc0smLEsajuizss1hvlGDsCooM88FqgxNOCKpY8IuQPzCs75RNKMSMITz+dX7KZ5qGhQ2EWGMTTg== |
| npm | @stellar/stellar-sdk@17.2.0 | sha512-hGdbvhnOMFwAe+QOAUVPrtLf8U+arO2XG+0osEeY87Ti5scj1R52YSw8HW828gf6UG4PW/jtAlfnyaGCj8t6UA== |
| npm | @stellar/stellar-sdk@17.2.1 | sha512-kIyfnZ2zCOqV8SUJcsk9buBOvhH1wsLU7KAzqAJyY7AgmD+KdvLTMpI1gcYdhGSakuDG5s6xSO4EN9HZTxpm8g== |
| npm | @stellar/stellar-sdk@17.3.0 | sha512-E9olNBk1FDTYSdGphd+U4EMlbRdkCQfveuK7/fhEtlEBl7GIoXtHHr0Hh6WcxIiO0/sRutsgapZDhhGpdd/Bqg== |
| npm | @stellar/stellar-sdk@17.4.0 | sha512-IX6gi62yWQ+6Oz56LsVEEeSViSOWJL3BkttftwVmVsu+62nLTWNVsCmTWEzwgNLT/q5HGP25OnlU+hhy2E4wwA== |
| npm | @stellar/js-xdr@4.0.0 (all 16.x) | sha512-+NmNa7Tk5BI5XFdy/6xGTqAN4J9a9KgCrCGhj2uEUTCBhLkch0M+QbKzNH8zEnejWe0p8w+0q5hUVX6L3OzoVA== |
| npm | @stellar/js-xdr@5.0.0 (all 17.x) | sha512-HBDNKnxr+ecdaEmbZ0mcKkirOF8tXXEbWSw34P3wT40Tn3g+u+cCH17xAWZymzscq8cojHB8340pR8QNVaD32w== |
| Go | github.com/stellar/go-stellar-sdk v0.7.1 | h1:28z6JuMtXoE5W535ekcUOUPAgfrxof3yc6gM700W2I4= (go-xdr v0.0.0-20260529210834-0bf8f4956364 h1:gOKrfuWdZ92LFlv0TAwgZ7OsWKeBsOMDlGLyFgduI1w=) |
| Go | … v0.7.2 | h1:LTO860ulPKRmsKgxGTAf8APL2nFtVvRKClhw2unGhyY= |
| Go | … v0.7.3 | h1:r4kKiiTOuNdJrEjKYs5ykLSLWKpq9fp6HnIXUs4TiuI= |
| Go | … v0.8.0 | h1:PU0iM2deEly7qs60BGnm2L+lE3WtrvED3WT/MIjet5A= (v0.7.2–v0.8.0 all pin go-xdr v0.0.0-20260806060815-dc590f17552a h1:40YIhQusSioBKDW5Tr+YdjoXphcVeu7eXUS2ibMQBTs=) |
| crates.io | stellar-xdr 28.0.0 / 28.0.1 / 30.0.0 | sha256 f93d09ff8b9f919b084f664003c4c546ac66a76affd5429460dbe29f4b326f8e / 52599dcc4daa661c19d912f5ad55322772515a198c0da3c985ef3922f7f40b77 / 56f2fb2008b42fc746c0f6b46e375600068dd91f07748e9f1737c6341a2255f2 (default features off; `std,base64,hex`) |
| crates.io | stellar-strkey 1.0.0 (latest; used by xdr 30) / 0.0.13 (what xdr 28.x pins, `version = "0.0.13"`) | sha256 5038ed2bf4e11842210d118f65791d8ca4747622daddd222338b3d06b6051bc1 / ee1832fb50c651ad10f734aaf5d31ca5acdfb197a6ecda64d93fcdb8885af913 |
| PyPI | stellar-sdk 17.0.0 / 17.0.1 (wheel) | sha256 4d40daa8a6b88e1d6dcb7f4ed0df389a5e704a8e18ca9e0da6a800ed9a159240 / 04adf81710417833e852965bdbb8f9b44c9b6aa9a404a737598a6c0bea534b78 |
| PyPI | xdrlib3 0.1.1 (both) | sha256 175c0645f347c64e76bb374c2109480007eb2ff04ad08acfe885a130d2b0877d |

Python 17.0.0 is the last release before the issuer-order fix: py-stellar-base fix commit `2c7b1ea7e24dbe3e865a184417208cc2b4ce4731` (#1247) is not an ancestor of tag 17.0.0 (`8400be52…`) and is an ancestor of 17.0.1 (`3d722d01…`).

## Data provenance

| file | source | sha256 |
|---|---|---|
| `data/FFAB7625--5540314.xdr.zst` | `s3://aws-public-blockchain/v1.1/stellar/ledgers/testnet/2025-12-18/FFAC03FF--5504000-5567999/FFAB7625--5540314.xdr.zst` (anonymous; object metadata `protocol-version 30`, `core-version stellar-core 30.0.0 (0e49751a…)`) | 969df29d…b568 (zst), 79caf2c4…f1b4 (decompressed, 168376 B) |
| `data/FFAB7626--5540313.xdr.zst` | same partition, ledger 5540313 (upgrade ledger, header version 30, StellarValue ext still `SIGNED`) | 74303ad4…9113 (zst), 6cfd958e…e9aa |
| `data/testnet-tx-0126748091.envelope.b64` | copy of `../js-1766/` (Horizon testnet) | 16291676…81df1 |

## JS v16 vs v17 API differences the probe had to bridge

`fromXDR`/`toXDR` (v16) vs `fromXdr`/`toXdr` (v17; v17.2+ still also has `fromXDR`) · union arm `u.switch().name` + `u.value()` (v16; int-discriminant unions return a bare number from `switch()`) vs `u.type` + `u.value` (v17) ·
struct fields are methods in v16 (`e.key()`), properties in v17 · `LedgerCloseMetaBatch.ledgerCloseMeta()` (v16) vs `.ledgerCloseMetas` (v17) · `TransactionBuilder.fromXDR`/`Operation.fromXDRObject`/`Memo.fromXDRObject` vs `…Xdr…` ·
`Buffer` (v16) vs `Uint8Array` (v17) — and note `scvSortedMap` ordering of bytes keys differs by input class on ≤17.2.0/16.x (see note) · `scValToNative` of non-UTF-8 `scvString`/`scvSymbol` returns a mangled `string` in v16, a `Uint8Array` in v17 ·
`StrKey.decodeMuxedContract`/`encodeMuxedContract` exist only from 17.3.0 (v16.4.x decodes P30 XDR but `Address` throws on muxed contracts).
