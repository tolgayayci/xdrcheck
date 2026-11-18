# Reproduction: js-stellar-sdk#1789 (scValToNative drops colliding map keys)

A hand-run reproduction (2026-11-12), separate from the kit's own check of the same issue (`make verify-conformance`,
check `sdk-regression`, case js-1789); kept as the dated record, its scripts are not part of the kit.

## Versions
- `prefix/`: `@stellar/stellar-sdk@17.2.1` (tag v17.2.1, b4893496f69116d9db2a4a90214a7236831b6656)
- `fixed/`: `@stellar/stellar-sdk@17.3.0` (tag v17.3.0, 0f2fd40ba6db761390e3e5e4eb5c432234696a61; fix PR #1778, merge 91bd61d2f8ffae138f2d27a94015ec3bfe042383)
- `@stellar/js-xdr@5.0.0` in both. Node v24.19.0, npm 11.17.0.

## Commands
```sh
cd evidence/js-1789
for d in prefix:17.2.1 fixed:17.3.0; do
  mkdir -p ${d%%:*} && (cd ${d%%:*} && echo '{"name":"repro","private":true,"type":"module"}' > package.json \
    && npm install --ignore-scripts --no-audit --no-fund @stellar/stellar-sdk@${d##*:})
done
node repro.mjs prefix > transcript-prefix.txt 2>&1
node repro.mjs fixed  > transcript-fixed.txt  2>&1
```

## Input
ScVal XDR (hex), hand-assembled from the XDR spec (synthetic, not captured from a network):
```
00000011 00000001 00000002  00000003 00000001 00000003 0000000a  0000000f 00000001 31000000 00000003 00000014
scvMap   present  2 entries key u32 1         val u32 10         key sym "1"                val u32 20
```
Keys are in Soroban host order (U32 before Symbol), so a contract can return or emit this map.

## What a reviewer sees
| check | 17.2.1 (pre-fix) | 17.3.0 (fixed) |
|---|---|---|
| `xdr.ScVal.fromXdr(hex)` | 2 entries, round-trips | 2 entries, round-trips |
| `scValToNative(decoded)` | `{"1":20}`: **one entry silently lost** | `TypeError: scvMap has more than one key that converts to "1"` |
| control (`u32 1`, `symbol "a"`) | `{"1":10,"a":20}` | same |

This is a decode-to-native defect: the raw XDR decode is correct, the SDK's native conversion is wrong. A corpus entry catches it only if its manifest carries the expected native/JSON conversion (or "must error"), not just the XDR round trip.

Not fixed on the v16 LTS line: v16.4.1 `src/base/scval.ts:452` still returns `Object.fromEntries(...)` with no collision check (source check, not run).
