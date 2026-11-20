# Findings report: SDKs and XDR libraries

The divergences the conformance runner found between the SDKs and XDR libraries it drives and what stellar-core
accepts, and where each stands upstream. Every failure cell of the runs below resolves to a finding record under
`findings/`; the records are the source of truth and this page summarises them. One SDK's fix is every other SDK's
regression test: where several projects had the same defect, the table at the end shows them side by side. State as
of 2026-11-20 (upstream states checked on 2026-11-20).

Findings still under coordinated disclosure, if any, are not represented in this report.
Divergences our runs found that are not yet reported upstream are pending finding review: the public tree lists only
which cells they account for (`findings/pending/conformance.json`: entry, variant, column, level) and describes
nothing about them (`findings/README.md`).

## How to reproduce

```sh
make fetch && make build
make verify-conformance OFFLINE=1     # set pr: builds every driver, asserts the acceptance cells, checks the matrix
go/bin/xdrcheck conform build --set public
scripts/offline-run.sh go/bin/xdrcheck conform run --set public --report reports/conformance-public   # adds js 16.x, python 17.0.0, core
make verify-findings OFFLINE=1        # every failure row carries a finding ID that resolves to a record
```

One cell: `xdrcheck conform run --columns '<column>' --entries '<entry>' --report <dir>`. The protocol, levels and
verdicts are in [`docs/conformance-protocol.md`](../docs/conformance-protocol.md).

## Columns

| SDK or library | Versions (columns) | In set |
|---|---|---|
| js-stellar-sdk (with js-xdr) | 17.4.0, 17.3.0, 17.2.1, 17.2.0; 16.4.1, 16.3.1, 16.3.0 | 17.x `pr`; 16.x `public` |
| go-stellar-sdk (with go-xdr) | v0.9.0, v0.8.0, v0.7.3, v0.7.2, v0.7.1 | `pr` |
| rs-stellar-xdr (with rs-stellar-strkey) | 30.0.0, 28.0.1, 28.0.0, each under two decode profiles, `limits-default` and `limits-none` | `pr` |
| py-stellar-base | 17.0.1; 17.0.0 | 17.0.1 `pr`; 17.0.0 `public` |
| stellar-core (reference column) | 30.0.0 | `public` |

## Results by run (development mode)

| Run | Cells | Failure cells | With a finding | Pending finding review |
|---|---|---|---|---|
| `make verify-conformance` (set `pr`, 16 columns) | 36304 | 162 | 162 | 0 |
| `xdrcheck conform run --set public` (21 columns) | 47649 | 296 | 296 | 0 |

Each column runs the same 2,269 cells (one per entry, variant and level), so the cell counts are the column counts of
the `pr` and `public` sets in `drivers/sets.toml` times 2,269; the cells pending finding review are the ones listed in
`findings/pending/conformance.json`. `xdrcheck conform check` passes both in development mode (no undeclared cell
without a finding or a pending entry).

## Findings

All are public upstream. Most were already recorded upstream (`duplicate-of`); F-0034, F-0036, F-0037, F-0043, F-0045,
F-0046, F-0053, F-0056, F-0058 to F-0061, F-0063, F-0064, F-0075 to F-0085 and F-0089 to F-0093 were found by this kit and reported by the maintainers of this kit
(`filed`). The records marked "executed by hand" have no report row: no run of the kit compares that
behaviour, and each was re-run by hand from its public issue.

| Record | Project | Defect | Versions affected (executed) | Fixed in | Upstream | State |
|---|---|---|---|---|---|---|
| F-0016 | js-stellar-sdk | Pool asset order and ScVal map key order compared as strkey text, not XDR bytes | 16.3.0, 17.0.0–17.2.0 (asset order); 16.x and 17.2.0 (map keys) | 17.2.1, 16.3.1 | [PR #1766](https://github.com/stellar/js-stellar-sdk/pull/1766), fixed | `duplicate-of` |
| F-0017 | js-stellar-sdk | Offer and muxed-account IDs accept unsafe, empty, hex and negative input and encode another value | 16.3.0–16.4.1, 17.2.0–17.2.1 | 17.3.0 | [issue #1785](https://github.com/stellar/js-stellar-sdk/issues/1785), fixed | `duplicate-of` |
| F-0018 | js-stellar-sdk | `scValToNative` merges map keys that convert to the same native key and drops entries | 16.3.0–16.4.1, 17.2.0–17.2.1 | 17.3.0 | [issue #1789](https://github.com/stellar/js-stellar-sdk/issues/1789), fixed | `duplicate-of` |
| F-0019 | js-stellar-sdk | The 16.x StrKey decoder checks the checksum but not the per-type payload rules | 16.3.0–16.4.1 | 17.2.0 (17.x line) | [PR #1580](https://github.com/stellar/js-stellar-sdk/pull/1580) (v17 line); the signed-payload framing part is [PR #1588](https://github.com/stellar/js-stellar-sdk/pull/1588) | `duplicate-of` |
| F-0020 | js-stellar-sdk | `Address.fromScAddress` on 16.x refuses a muxed contract address (Protocol 30) | 16.4.1 | 17.3.0 | [PR #1811](https://github.com/stellar/js-stellar-sdk/pull/1811), fixed | `duplicate-of` |
| F-0021 | js-xdr | A union with a float discriminant encodes bytes it cannot decode (custom schemas only) | 4.0.0, 5.0.0 | merged, not released | [issue #162](https://github.com/stellar/js-xdr/issues/162), closed | `duplicate-of` |
| F-0022 | js-xdr | Default decode depth 200 refuses valid deeply nested values and ledgers | 4.0.0 (SDK 16.x) | 5.0.0 (SDK 17.x) | [PR #155](https://github.com/stellar/js-xdr/pull/155), fixed | `duplicate-of` |
| F-0023 | go-stellar-sdk | Liquidity pool asset order compared as strkey text | v0.7.1 | v0.7.2 (v0.6.1 backport) | [PR #5974](https://github.com/stellar/go-stellar-sdk/pull/5974), fixed | `duplicate-of` |
| F-0024 | go-stellar-sdk | `strkey.Decode` accepts payloads that break the per-type length and padding rules | v0.7.1 | v0.7.2 | [PR #5977](https://github.com/stellar/go-stellar-sdk/pull/5977), fixed | `duplicate-of` |
| F-0025 | go-stellar-sdk | `strkey.Encode` emits a signed-payload strkey for an empty payload | v0.7.1–v0.9.0 | — | [issue #5981](https://github.com/stellar/go-stellar-sdk/issues/5981), **open** | `duplicate-of` |
| F-0026 | go-xdr | A length prefix larger than the input is allocated before reading | as pinned by go-stellar-sdk v0.7.1 | go-stellar-sdk v0.7.2 | [PR #34](https://github.com/stellar/go-xdr/pull/34), fixed | `duplicate-of` |
| F-0027 | py-stellar-base | Liquidity pool asset order compared as strkey text | 17.0.0 | 17.0.1 | [issue #1246](https://github.com/StellarCN/py-stellar-base/issues/1246), fixed | `duplicate-of` |
| F-0028 | java-stellar-sdk | Liquidity pool asset order compared as strkey text | 6.0.0 | merged 2026-11-05, not released | [PR #832](https://github.com/lightsail-network/java-stellar-sdk/pull/832) | `duplicate-of`; **release request drafted** |
| F-0029 | rs-stellar-strkey | An empty signed payload encodes to a strkey the library's own parser refuses | 0.0.13 (stellar-xdr 28.0.x) | 0.0.17 | [PR #107](https://github.com/stellar/rs-stellar-strkey/pull/107), fixed | `duplicate-of` |
| F-0030 | rs-stellar-xdr | Serde deserialisation accepts a vector longer than its declared maximum | 28.0.0 | 28.0.1 | [GHSA-3xhm-p452-9wjh](https://github.com/stellar/rs-stellar-xdr/security/advisories/GHSA-3xhm-p452-9wjh), fixed | `duplicate-of` |
| F-0034 | js-stellar-sdk | `StrKey.encodeSignedPayload` encodes a signed payload outside 1 to 64 bytes (empty or 65 bytes) | 16.3.0–17.4.0 | — | [issue #1899](https://github.com/stellar/js-stellar-sdk/issues/1899), **open** | `filed` |
| F-0035 | rs-stellar-strkey | A 65-byte signed payload encodes to a strkey the library's own parser refuses | 0.0.13 (stellar-xdr 28.0.x) | 0.0.17 | [PR #107](https://github.com/stellar/rs-stellar-strkey/pull/107), fixed | `duplicate-of` |
| F-0036 | go-stellar-sdk | `strkey.Decode` with the claimable-balance version byte accepts an unknown type byte (SEP-23 invalid vector 15) | v0.7.1–v0.9.0 | — | [issue #6042](https://github.com/stellar/go-stellar-sdk/issues/6042), **open** | `filed` |
| F-0037 | rs-stellar-xdr | A bool encoded as 2 decodes as false, while stellar-core reads it as true | 28.0.0–30.0.0 | merged (`2f72a6a5`), not released | [issue #622](https://github.com/stellar/rs-stellar-xdr/issues/622), closed | `filed` |
| F-0043 | rs-stellar-xdr | Under `Limits::none()`, `BytesM`, `StringM` and `VecM<u8>` allocate the length a prefix claims before reading (aborts under a 1 GiB address-space cap) | 28.0.0–30.0.0 | — | [issue #623](https://github.com/stellar/rs-stellar-xdr/issues/623), **open** (hardening) | `filed` |
| F-0045 | js-stellar-sdk | `LedgerCloseMetaBatch.fromXDR` refuses a ledger whose failed transaction has a 493-level authorization tree (no corpus entry yet) | 17.4.0 | — | [issue #1901](https://github.com/stellar/js-stellar-sdk/issues/1901), **open** (fix PR #1902 open) | `filed` |
| F-0046 | go-stellar-sdk | The token transfer processor credits the admin of a legacy `[mint, admin, to]` event (pubnet 64870500, 64870521; executed by hand) | v0.9.0 | — | [issue #6044](https://github.com/stellar/go-stellar-sdk/issues/6044), **open** | `filed` |
| F-0047 | py-stellar-base | `scval.to_native` merges map keys that convert to the same native key and drops entries | 17.0.0–17.0.1 | merged (PR #1252), not released | [issue #1250](https://github.com/StellarCN/py-stellar-base/issues/1250), closed | `duplicate-of` |
| F-0048 | py-stellar-base | Muxed-account and offer IDs outside their valid range are encoded instead of refused (wrapped modulo 2^64, or a negative offer ID as is) | 17.0.0–17.0.1 | merged (PR #1253), not released | [issue #1251](https://github.com/StellarCN/py-stellar-base/issues/1251), closed | `duplicate-of` |
| F-0063 | py-stellar-base | A signed-payload signer with an empty or 65-byte payload is encoded into a P strkey the SDK's own decoder refuses | 17.0.0–17.0.1 | merged (PR #1265), not released | [issue #1256](https://github.com/StellarCN/py-stellar-base/issues/1256), closed | `filed` |
| F-0064 | py-stellar-base | StrKey decodes a signed-payload key whose padding bytes are not zero | 17.0.0–17.0.1 | merged (PR #1261), not released | [issue #1258](https://github.com/StellarCN/py-stellar-base/issues/1258), closed | `filed` |
| F-0053 | js-stellar-sdk | `Transaction` drops an explicit `minSeqNum` of 0; `cloneFrom` and `assembleTransaction` rebuild without it (the rebuild fact on `cap-0021/precond-v2-min-seq-num-zero`, L1) | 17.1.0–17.4.0 (kit: 17.2.0–17.4.0) | — | [issue #1904](https://github.com/stellar/js-stellar-sdk/issues/1904), **open** | `filed` |
| F-0056 | go-stellar-sdk | `txnbuild.TransactionFromXDR` drops `SorobanTransactionData` from `ExtendFootprintTtl` and `RestoreFootprint` (the rebuild fact on a mainnet `RestoreFootprint` and a testnet `ExtendFootprintTtl`, L1) | v0.7.1–v0.9.0 | — | [issue #6045](https://github.com/stellar/go-stellar-sdk/issues/6045), **open** | `filed` |
| F-0058 | rs-stellar-xdr | Top-level `Int64` and `Uint64` serialize to JSON numbers and reject strings, unlike SEP-51 (executed by hand) | 30.0.0 | merged (`d65093af`), not released | [issue #625](https://github.com/stellar/rs-stellar-xdr/issues/625), closed | `filed` |
| F-0059 | rs-stellar-xdr | JSON schema `$ref` values contain unencoded `<` and `>`, so strict validators refuse the schemas (executed by hand) | 30.0.0 | merged (`f6c69ff0`), not released | [issue #626](https://github.com/stellar/rs-stellar-xdr/issues/626), closed (as a duplicate) | `filed` |
| F-0060 | java-stellar-sdk | `Sep45Challenge.readChallengeAuthorizationEntries` throws `IllegalArgumentException` instead of `InvalidSep45ChallengeException` for some malformed input (executed by hand) | 6.0.0 | — | [issue #834](https://github.com/lightsail-network/java-stellar-sdk/issues/834), **open** | `filed` |
| F-0061 | js-stellar-sdk | `scValToNative` and `humanizeEvents` drop the `ScErrorType` of every non-contract error (the native error fact on `cap-0046/scval-error-*`, L3) | 16.3.0–17.4.0 | — | [issue #1905](https://github.com/stellar/js-stellar-sdk/issues/1905), **open** | `filed` |
| F-0075 | go-stellar-sdk | `txnbuild.NewFeeBumpTransaction` refuses a Soroban inner transaction parsed with `TransactionFromXDR` unless the base fee also covers its resource fee, and then counts the resource fee again (executed by hand) | v0.7.1–v0.9.0 | — | [issue #6051](https://github.com/stellar/go-stellar-sdk/issues/6051), **open** | `filed` |
| F-0076 | go-stellar-sdk | `txnbuild` parses time bounds of 2^63 and above as negative values, so `NewTransaction` refuses to rebuild the transaction (executed by hand) | v0.7.1–v0.9.0 | — | [issue #6052](https://github.com/stellar/go-stellar-sdk/issues/6052), **open** | `filed` |
| F-0077 | go-stellar-sdk | The `LedgerTransaction` Soroban fee accessors and `ledger.SorobanFeeWrite1Kb` read only TransactionMeta v3 and LedgerCloseMeta v1, so they return `(0, false)` on every protocol 23+ ledger (executed by hand on pubnet ledger 65437014) | v0.9.0 | — | [issue #6053](https://github.com/stellar/go-stellar-sdk/issues/6053), **open** | `filed` |
| F-0078 | go-stellar-sdk | `ContractCodeHashFromSorobanFootprint` and `ContractIdFromTxEnvelope` stop at the first footprint key of another type, and the three footprint helpers panic on classic transactions (executed by hand on pubnet ledger 65437014) | v0.9.0 | — | [issue #6054](https://github.com/stellar/go-stellar-sdk/issues/6054), **open** | `filed` |
| F-0079 | go-stellar-sdk | `ingest.ChangeCompactor` writes the merged TTL into the caller's `LedgerCloseMeta` when two transactions extend the same TTL entry (CAP-63; executed by hand, also on the stellar-core golden `cap-0063/parallel-phase-stages-and-clusters-golden.b959dfeef765fbb2`) | v0.9.0 | — | [issue #6055](https://github.com/stellar/go-stellar-sdk/issues/6055), **open** | `filed` |
| F-0080 | go-stellar-sdk | `SorobanInclusionFeeCharged` and `InclusionFeeCharged` return minus the resource fee when the fee account is muxed (executed by hand) | v0.9.0 | — | [issue #6056](https://github.com/stellar/go-stellar-sdk/issues/6056), **open** | `filed` |
| F-0081 | go-stellar-sdk | `txnbuild.NewFeeBumpTransaction` over a v0 inner transaction returns a fee bump whose inner transaction is nil, so `Base64()` and `Hash()` panic; a v0 transaction without time bounds is refused (executed by hand) | v0.7.1–v0.9.0 | — | [issue #6057](https://github.com/stellar/go-stellar-sdk/issues/6057), **open** | `filed` |
| F-0082 | go-stellar-sdk | The token transfer processor's `NewEventsProcessor` drops the issuer's burn when a revocation redeems pool shares and the other leg rounds to 0 (CAP-38; executed by hand on a local stellar-core 30.0.0 ledger) | v0.9.0 | — | [issue #6058](https://github.com/stellar/go-stellar-sdk/issues/6058), **open** | `filed` |
| F-0092 | go-stellar-sdk | `ingest.FeesFromTxParts` counts a failed Soroban transaction as a classic fee when stellar-core runs without `EMIT_SOROBAN_TRANSACTION_META_EXT_V1`, its default (executed by hand, also on the stellar-core golden `cap-0046/contract-error-return-values-golden.38db1ab5b5b4c24b`) | v0.9.0 | — | [issue #6060](https://github.com/stellar/go-stellar-sdk/issues/6060), **open** | `filed` |
| F-0083 | js-stellar-sdk | `TransactionBuilder.buildFeeBumpTransaction` throws for a v0 inner transaction without time bounds, which stellar-core converts to `PRECOND_NONE` with the same hash (executed by hand on mainnet transaction `eef91974…`) | 17.4.0 | — | [issue #1911](https://github.com/stellar/js-stellar-sdk/issues/1911), **open** | `filed` |
| F-0084 | js-stellar-sdk | `contract.Spec` decodes a struct map by entry position instead of by key, so a missing `Option` field (CAP-86 sparse unpacking) shifts values and an extra key throws (executed by hand) | 17.4.0 | — | [issue #1912](https://github.com/stellar/js-stellar-sdk/issues/1912), **open** | `filed` |
| F-0085 | js-stellar-sdk | `rpc.Server.getLedgerEntries` drops the `extXdr` field, so the sponsor of an entry (CAP-33) cannot be read (executed by hand) | 17.4.0 | — | [issue #1913](https://github.com/stellar/js-stellar-sdk/issues/1913), **open** | `filed` |
| F-0090 | py-stellar-base | `SorobanServer.get_ledger_entries` drops the `extXdr` field, so the sponsor of an entry (CAP-33) cannot be read; the sibling of F-0085 (executed by hand) | 17.0.1 | — | [issue #1278](https://github.com/StellarCN/py-stellar-base/issues/1278), **open** | `filed` |
| F-0091 | rs-stellar-rpc-client | `get_ledger_entries` and `get_full_ledger_entries` drop the `extXdr` field, so the sponsor of an entry (CAP-33) cannot be read, also through `stellar ledger entry fetch`; the sibling of F-0085 (executed by hand) | 30.0.0; stellar-cli 30.0.1 | — | [issue #124](https://github.com/stellar/rs-stellar-rpc-client/issues/124), **open** | `filed` |
| F-0093 | js-stellar-sdk | `contract.Spec` cannot convert a `#[contracterror]` argument or a nested `soroban_sdk::Error` value: `funcArgsToScVals` and `funcResToNative` throw (executed by hand) | 17.4.0 | — | [issue #1915](https://github.com/stellar/js-stellar-sdk/issues/1915), **open** | `filed` |
| F-0089 | stellar-cli | `contract invoke` panics with "not yet implemented" on a result holding a `soroban_sdk::Error` and cannot pass a `#[contracterror]` argument; the sibling of F-0093 in `soroban-spec-tools` (executed by hand against a local network) | 30.0.1 | — | [issue #2897](https://github.com/stellar/stellar-cli/issues/2897), **open** | `filed` |
| F-0051 | js-stellar-sdk | `Spec.fromWasm` uses the first `contractspecv0` section and ignores the others | 16.3.0–16.4.1, 17.2.0–17.2.1 | 17.3.0 | [issue #1826](https://github.com/stellar/js-stellar-sdk/issues/1826), fixed | `duplicate-of` |
| F-0032 | dotnet-stellar-sdk | Liquidity pool asset order compared as strkey text (read from the source; no driver) | 17.0.0 (source reading) | open PR #272 | [issue #257](https://github.com/Beans-BV/dotnet-stellar-sdk/issues/257), **open** | `duplicate-of`; evidence comment drafted, not posted |

The 16.x line of js-stellar-sdk is a maintenance line that receives critical security fixes only (its
`SECURITY.md`); its gaps are recorded as known divergences and no backport request is drafted unless a maintainer
decides to ask for one.

### Not a defect

| Record | What | Why |
|---|---|---|
| F-0041 | py-stellar-base 17.0.0 and 17.0.1 read a bool encoded as 2 as true | stellar-core 30.0.0 reads the same bytes the same way (`evidence/core-print-xdr/out/bool-2.txt`); the SDK shows the value the network applies. Declared `wont_fix` on `xdr-strict/bool-value-2` |
| F-0049 | go-stellar-sdk v0.7.1–v0.7.3 refuse contract specs with UDT names over 60 bytes | Built on XDR definitions before v30, whose UDT name bound is 60 bytes; v30 raised it to 1024 ([stellar-xdr PR #312](https://github.com/stellar/stellar-xdr/pull/312)) and v0.8.0 decodes the same specs |
| F-0050 | js-stellar-sdk 16.3.0–16.3.1 and 17.2.0–17.2.1 refuse contract specs with UDT names over 60 bytes | The same pre-v30 bound; 16.4.0 and 17.3.0 decode the same specs |

## One defect, several SDKs

Liquidity-pool asset order (CAP-38: stellar-core orders a pool's two assets by their XDR bytes; for two assets with
the same code that means the raw issuer key, which can sort differently from its strkey text):

| SDK | Shows it on | Fixed | Record | What remains |
|---|---|---|---|---|
| js-stellar-sdk | 16.3.0, 17.2.0 (and earlier 17.x) | 16.3.1, 17.2.1 (#1766) | F-0016 | — |
| go-stellar-sdk | v0.7.1 | v0.7.2 (#5974) | F-0023 | — |
| py-stellar-base | 17.0.0 | 17.0.1 (#1246) | F-0027 | — |
| java-stellar-sdk | 6.0.0 | merged on master (#832), not released | F-0028 | a release; request drafted |
| dotnet-stellar-sdk | 17.0.0 (source reading) | open PR #272 | F-0032 | evidence comment on #257 drafted |
| rs-stellar-xdr | not exercised (no object layer at these levels) | — | — | — |

The cells: `cap-0038/pool-issuers-order-by-bytes-not-strkey` (a testnet history ledger) and its local twins
`cap-0038/pool-issuers-order-by-bytes-not-strkey-local-twins` at L1, and `cap-0038/api-liquidity-pool-issuer-ordering.*`
at L4. Every fixed version passes them; every affected version fails them with the same reason (`ordering`).

Signed-payload strkey on encode with a payload outside 1 to 64 bytes (SEP-23): on `strkey/api-encode-signed-payload-empty`,
go-stellar-sdk (F-0025, #5981, open), rs-stellar-strkey (F-0029, #107, fixed), js-stellar-sdk (F-0034, #1899, open) and
py-stellar-base (F-0063, #1256, fix merged, not released); on `strkey/api-encode-signed-payload-65-bytes`, js-stellar-sdk
(F-0034), rs-stellar-strkey (F-0035, #107, fixed) and py-stellar-base (F-0063).

ScMap keys that convert to the same native key (`cap-0046/scval-map-keys-collide-three-types.*`, L3): js-stellar-sdk
(F-0018, #1789, fixed in 17.3.0) and py-stellar-base (F-0047, #1250, fix merged, not released). Muxed-account and offer IDs outside the
field's range on encode (`cap-0027/api-muxed-account-id-encoding.*`, `classic/api-offer-id-encoding.*`, L4): js-stellar-sdk
(F-0017, #1785, fixed in 17.3.0) and py-stellar-base (F-0048, #1251, fix merged, not released).

Fee bump over a v0 inner transaction: go-stellar-sdk (F-0081, #6057, open: `NewFeeBumpTransaction` returns a fee bump
whose inner transaction is nil) and js-stellar-sdk (F-0083, #1911, open: `buildFeeBumpTransaction` refuses a v0
inner transaction without time bounds), both executed by hand; no conformance fact fee-bumps a parsed transaction.

The `extXdr` field of an RPC `getLedgerEntries` result, which holds the entry's sponsor (CAP-33): js-stellar-sdk (F-0085,
#1913, open), py-stellar-base (F-0090, #1278, fixed by the maintainer) and rs-stellar-rpc-client (F-0091, #124, open, also seen through
stellar-cli's `ledger entry fetch`) drop it, all executed by hand; no corpus entry drives an RPC client.

Error values outside a `Result` (a `#[contracterror]` argument, or a `soroban_sdk::Error` nested in a struct or a vec):
js-stellar-sdk's `contract.Spec` (F-0093, #1915, open) throws, and stellar-cli's `soroban-spec-tools` (F-0089, #2897, open)
panics on the value and refuses the argument; both executed by hand, no corpus entry converts an error value through a
contract spec.

### The sibling matrix

[`SIBLINGS.md`](SIBLINGS.md) (generated by `make results-siblings` into `evidence/results/sibling-matrix.json`)
looks for every SDK defect class of the public records in every SDK family the kit knows, from the executed
conformance runs of the `pr` and `public` column sets: 34 classes × 9 families, with 38 cells that reproduce, 1 not
a defect, 23 shown by a public record outside the runs, 43 not affected and 201 not run (no driver, or no applicable
cell). The classes come from the records (shared `defect_group`, `siblings` links, or the same failing cell), not
from a hand-made list.

## Drafts

| Record | Kind | Command (printed by `xdrcheck conform siblings`, never run) |
|---|---|---|
| F-0028 | release request | `gh issue create --repo lightsail-network/java-stellar-sdk --title "Release request: …" --body-file findings/F-0028/issue-java-stellar-sdk.md` |
| F-0032 | evidence comment | `gh issue comment 257 --repo Beans-BV/dotnet-stellar-sdk --body-file findings/F-0032/issue-dotnet-stellar-sdk.md` |

Each waits for a maintainer's approval of that exact draft and channel; [`findings/drafts/README.md`](drafts/README.md)
has the full commands.

## Status against the acceptance check

`make verify-findings` (development mode) passes. The records marked "executed by hand" are exempt from the orphan
check and listed as such. `make verify-findings-acceptance` stays red until every failure row
resolves to a record in a terminal state: it fails on the cells pending finding review, which wait for maintainer review. F-0032 is
`duplicate-of` the open upstream issue; observed by source reading only on an SDK without a driver column, it is
exempt from the orphan check and listed as such.
