# Reproduction: js-stellar-sdk#1766 (issuer order by strkey text, not key bytes)

A hand-run reproduction (2026-11-12), separate from the kit's own check of the same issue (`make verify-conformance`,
check `sdk-regression`, case js-1766); kept as the dated record, its scripts are not part of the kit.

## What it shows
Two issued assets with the same code `USD` whose issuers sort one way as `G…` text and the other way as raw ed25519 key bytes (the order stellar-core uses):

| | strkey | key bytes (first byte) |
|---|---|---|
| A | `GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL` | `e305f885…` |
| B | `GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO` | `f7a4c0e5…` |

Text: B < A (`'3'`=0x33 < `'R'`=0x52). Bytes: A < B (0xe3 < 0xf7). These are the reserves of the live testnet pool `c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e`, created by testnet tx `0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f` (ledger 5521432, 2026-11-02T14:46:40Z, successful). The envelope (from Horizon testnet, 2026-11-12) is saved as `testnet-tx-0126748091.envelope.b64`; op[2] is the pool-share ChangeTrust.

## Versions
- `prefix/`: `@stellar/stellar-sdk@17.2.0` (tag v17.2.0, 7cfd51a98bc9f12bd56abee48c13b7b99f8be4fb)
- `fixed/`: `@stellar/stellar-sdk@17.2.1` (tag v17.2.1, b4893496f69116d9db2a4a90214a7236831b6656; fix c103c9b3e7dc9ea1e47abc01b3a07011ce62af88)
- Both resolve `@stellar/js-xdr@5.0.0`. Node v24.19.0, npm 11.17.0, Linux.

## Commands
```sh
cd evidence/js-1766
for d in prefix:17.2.0 fixed:17.2.1; do
  mkdir -p ${d%%:*} && (cd ${d%%:*} && echo '{"name":"repro","private":true,"type":"module"}' > package.json \
    && npm install --ignore-scripts --no-audit --no-fund @stellar/stellar-sdk@${d##*:})
done
curl -s https://horizon-testnet.stellar.org/transactions/0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["envelope_xdr"])' > testnet-tx-0126748091.envelope.b64
node repro.mjs prefix > transcript-prefix.txt 2>&1
node repro.mjs fixed  > transcript-fixed.txt  2>&1
```
`repro.mjs <dir>` loads the SDK from `<dir>/node_modules`, so the same script runs against both installs.

## What a reviewer sees (diff of the two transcripts)
| check | 17.2.0 (pre-fix) | 17.2.1 (fixed) | core |
|---|---|---|---|
| `Asset.compare(A,B)` | `1` | `-1` | A < B |
| `new LiquidityPoolAsset(A,B,30)` | throws "Assets are not in lexicographic order" | OK | valid |
| `new LiquidityPoolAsset(B,A,30)` | OK (wrong) | throws | invalid |
| `getLiquidityPoolId(A,B)` | throws | `c2a73012…2d5e` (= live testnet pool ID) | `c2a73012…2d5e` |
| `getLiquidityPoolId(B,A)` | `c1324f87…9fdb` (a pool that cannot exist) | throws | invalid |
| `Operation.changeTrust({asset: LP(A,B)})` | throws | OK | valid |
| `xdr.TransactionEnvelope.fromXdr(env)` (raw XDR) | OK, round-trips | OK, round-trips | — |
| `TransactionBuilder.fromXdr(env, TESTNET)` | **throws** | OK, hash `01267480…346f`, pool ID matches | accepted on-chain |
| `Operation.fromXdrObject(op[2])` | **throws** | OK | — |
| `scvSortedMap(bytes 0x0a, bytes 0x09)` | `0a, 09` | `09, 0a` | `09, 0a` |
| `scvSortedMap(symbol "a", string "b")` | symbol first | string first | string (type 14) before symbol (15) |
| `nativeToScVal({10:…, 9:…})`, u32 keys | `10, 9` | `9, 10` | `9, 10` |

So the pre-fix SDK fails both to **build** the pool trustline and to **decode** the core-accepted transaction at the SDK object layer (`Transaction`/`Operation`); the raw `xdr` layer decodes it fine. The ScVal map half of #1766 is encode-only (builder sorting).

## Core-emitted LedgerCloseMeta (answers "decode or only build?")
`FFABBFE7--5521432.xdr.zst` is the Galexie object for testnet ledger 5521432 (protocol 29), copied unchanged from the public data lake:
`aws s3 cp --no-sign-request s3://aws-public-blockchain/v1.1/stellar/ledgers/testnet/2025-12-18/FFAC03FF--5504000-5567999/FFABBFE7--5521432.xdr.zst .`
(sha256 of .zst `9aa845398f6ae4aa478ceb19cc24be0b3d9a0d06fc1cd889422311f3fbe7926a`, of the decompressed `LedgerCloseMetaBatch` `ef639c7c3f30f48419851c25f1f42eff68b9a6236643485325a54f18439c40d3`, 131640 bytes).

```sh
zstd -d FFABBFE7--5521432.xdr.zst -o lcm.xdr
node decode-lcm.mjs prefix lcm.xdr > transcript-lcm-prefix.txt 2>&1
node decode-lcm.mjs fixed  lcm.xdr > transcript-lcm-fixed.txt  2>&1
```
| | 17.2.0 | 17.2.1 |
|---|---|---|
| `xdr.LedgerCloseMetaBatch.fromXdr` | OK, byte-exact round trip | OK, byte-exact round trip |
| `TransactionBuilder.fromXdr` on the 19 tx-set envelopes | 18/19; tx `01267480…346f` throws "Assets are not in lexicographic order" | 19/19 |

So a corpus entry built from this ledger catches #1766 **only** if the JS driver parses envelopes through the SDK object layer (`TransactionBuilder.fromXdr` / `Operation.fromXdrObject`), not just the generated `xdr` codec.
