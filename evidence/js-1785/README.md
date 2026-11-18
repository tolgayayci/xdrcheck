# Reproduction: js-stellar-sdk#1785 (muxed account IDs and offer IDs encode a different ID)

A hand-run reproduction (2026-11-12), separate from the kit's own check of the same issue (`make verify-conformance`,
check `sdk-regression`, case js-1785); kept as the dated record, its scripts are not part of the kit.

## Versions
- `prefix/`: `@stellar/stellar-sdk@17.2.1` (tag v17.2.1, b4893496f69116d9db2a4a90214a7236831b6656)
- `fixed/`: `@stellar/stellar-sdk@17.3.0` (tag v17.3.0, 0f2fd40ba6db761390e3e5e4eb5c432234696a61; fix PR #1780, merge f9863aebfd81cd45fc211f27f4a965f0f6b2e9eb)
- `@stellar/js-xdr@5.0.0` in both. Node v24.19.0, npm 11.17.0.

## Commands
```sh
cd evidence/js-1785
for d in prefix:17.2.1 fixed:17.3.0; do
  mkdir -p ${d%%:*} && (cd ${d%%:*} && echo '{"name":"repro","private":true,"type":"module"}' > package.json \
    && npm install --ignore-scripts --no-audit --no-fund @stellar/stellar-sdk@${d##*:})
done
node repro.mjs prefix > transcript-prefix.txt 2>&1
node repro.mjs fixed  > transcript-fixed.txt  2>&1
```

## What a reviewer sees
| input | 17.2.1 (pre-fix) | 17.3.0 (fixed) |
|---|---|---|
| `new MuxedAccount(G, "0x10")` | OK, `id()` = `"0x10"`, M-address encodes 16 | throws "id is not a valid uint64 string" |
| `"016"` | OK, `id()` = `"016"` | OK, `id()` = `"16"` (canonicalised) |
| `" 16 "` | OK, `id()` = `" 16 "` | throws |
| `""` | OK, M-address with ID **0** | throws |
| `manageSellOffer offerId: 9007199254740993` (number) | OK, encodes **9007199254740992** | throws (not a safe integer) |
| `offerId: ""` | encodes **0** (= create a new offer) | throws |
| `offerId: "-5"` / `-5` | encodes -5 (network rejects) | throws |
| `offerId: "0x10"` | encodes 16 | throws |
| `offerId: "9007199254740993"` (string) | OK exact | OK exact (control) |
| `manageBuyOffer offerId: 9007199254740993` | encodes 9007199254740992 | throws |

This is a builder/validation defect only. Decoding a core-emitted M-address or offer ID is correct in both versions (`decodedId=16`). A corpus of XDR files cannot catch it; the conformance runner needs API-level vectors (input value → expected encoded bytes or expected rejection).

Not fixed on the v16 LTS line: v16.4.1 (`lts-16`) `src/base/operations/manage_sell_offer.ts:48` still does `xdr.Int64.fromString(opts.offerId.toString())` (source check, not run).
