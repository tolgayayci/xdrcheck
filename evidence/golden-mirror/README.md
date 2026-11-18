# golden-mirror probe (2026-11-12) — throwaway research repro, not product code

AG-4 "golden mirror" executed once: a local release stellar-core v30.0.0 replays the focus transaction of a
core golden (`--check-lcm` tree at tag v30.0.0) on the testnet, mainnet and core-test passphrases under several
meta-flag profiles; a structural skeleton of the transaction is compared with the golden's.
The transcripts and outputs in this folder are the evidence.

## Result in one table (`out/summary.tsv`, `out/{trust,muxed}/compare.txt`)

| pattern / golden frame | flag profile | testnet | mainnet | core-test `(V) (;,,;) (V)` |
|---|---|---|---|---|
| CAP-0073 SAC `trust` create, `4c437318f87437c5` frame 42 (L44) | `golden-trust` (= the test's own flags) | **identical** | **identical** | **identical** |
| CAP-0073 SAC `trust` repeat (no-op), frame 43 (L45) | `golden-trust` | **identical** | **identical** | **identical** |
| same two | `lake` (7 flags on) | 1 diff (`soroban_meta.ext` v1) | 1 | 1 |
| same two | `test-default` / `design-core-default` | 3 diffs (2 tx-level `fee` events missing) | 3 | 3 |
| CAP-0084 SAC transfer to `W…`, `f9e9d669f79493b3` frame 11 (L13) | `test-default` + `min_persistent_ttl=20` | **identical** | **identical** | **identical** |
| same | `test-default`, stock p30 testnet settings | 3 diffs (SAC instance TTL bump absent) | 3 | 3 |
| same | `lake` + `min_persistent_ttl=20` | 4 diffs (soroban ext v1 + 2 fee events) | 4 | — |

Skeleton hashes (sha256, ordered): trust create `14603d361d2bbd84…`, trust repeat `bc12323110472d0d…`,
muxed transfer `54292e6543145033…` — equal to the golden's in every "identical" cell, and stable over 3 testnet runs
(`out/skel/repeat-run{2,3}-L18.json`). Negative control: golden frame 42 vs 43 → 6 differences.

## Layout
- `golden/` — `git -C ../../_src/stellar-core show v30.0.0:test-lcm-current/InvokeHostFunctionTests/<hash>.xdr` for
  `4c437318f87437c5` (sha256 `20624d6d…fefeda`), `f9e9d669f79493b3` (`66d188e7…452193`), `08892c12cfbd6c32`
  (`8365a7b4…296437`, not mirrored) and that directory's `index.json`.
- `config/core.cfg.in` (the `../local-core/` template with `@FLAGS@`), `config/profiles.sh` (flag profiles, with source line refs),
  `config/enable.xdr`, `config/p30-testnet.xdr` (copied from `../local-core/config/upgrades/`),
  `config/p30-testnet-minttl20.{json,xdr}` (same, `state_archival.min_persistent_ttl` 120960 → 20).
- `driver/mirror_trust.mjs`, `driver/mirror_muxed.mjs` — Node 24 + `@stellar/stellar-sdk` 17.4.0 (symlinked
  `node_modules` from `../local-core/driver`). Helpers copied from `../wallet-backend-731/core/driver/scenario731.mjs`; keys derived like core's
  `getAccount()` (name padded with `.` to 32 bytes), root = sha256(passphrase), so on the core-test passphrase the
  accounts and SAC addresses equal the golden's (`CA6V62EK…VRR`, `GCQGMTQJ…EQG7`, `GCE4HENK…77CN`).
- `run.sh <testnet|mainnet|coretest> <profile> <driver> <dir>`; `run-offline.sh` = same inside `unshare -rn`
  (fresh netns with only `lo`; `run.sh` also refuses to start if 11626/11627 already answer). Core binary and
  stellar-xdr CLI are reused read-only from `../local-core/`.
- `scripts/frames.py` (the `../local-core/` RFC 5531 record-mark splitter), `split_decode.py` (split + decode + re-encode check),
  `txlist.py` (per-tx overview), `skeleton.py` (normaliser + skeleton + `diff`; algorithm in its docstring),
  `leafdiff.py` (value-level diff), `compare.sh` (all runs of a pattern vs a golden frame).
- `out/schema-LedgerCloseMeta.json` — `stellar-xdr types schema --type LedgerCloseMeta` (drives the typed walk).
- `out/golden-4c43/`, `out/golden-f9e9/` — golden frames (raw + JSON); `out/{trust,muxed}/<net>-<profile>[-minttl20]/`
  — run dirs (`meta.xdr`, `decoded/`, `driver.json`, `core.cfg`, logs); `out/skel/` — every skeleton;
  `out/unmirrored/compare.txt` — local-core L28 and wallet-backend-731 P28 L15 (lake-profile entries, not mirrored) vs the golden.

## Re-run (bash, from this directory; ≈1.4 s per chain, ≈5 s per compare)
```bash
X=../local-core/tools/bin/stellar-xdr
$X types schema --type LedgerCloseMeta > out/schema-LedgerCloseMeta.json
for net in testnet mainnet coretest; do
  for p in golden-trust lake test-default design-core-default; do
    ./run-offline.sh $net $p driver/mirror_trust.mjs out/trust/$net-$p; done
  for p in test-default lake golden-trust; do
    ./run-offline.sh $net $p driver/mirror_muxed.mjs out/muxed/$net-$p
    SETTINGS=p30-testnet-minttl20.xdr ./run-offline.sh $net $p driver/mirror_muxed.mjs out/muxed/$net-$p-minttl20; done
done
scripts/compare.sh trust golden/4c437318f87437c5.xdr 42-L44:L18 43-L45:L19
scripts/compare.sh muxed golden/f9e9d669f79493b3.xdr 11-L13:L17
# one skeleton / one diff by hand
python3 -I scripts/skeleton.py $X out/schema-LedgerCloseMeta.json out/golden-4c43/frame42-L44.json --out /dev/stdout
python3 -I scripts/skeleton.py diff out/skel/golden-4c43-42-L44.json out/skel/trust-testnet-lake-L18.json
python3 -I scripts/leafdiff.py out/golden-4c43/frame42-L44.json out/trust/coretest-golden-trust/decoded/frame16-L18.json
```
`NO_TIMEBOUNDS=0` keeps the SDK's time bounds (reproduces the `envelope.tx.cond` difference of the first attempt).

## Pins
- stellar-core `30.0.0 (0e49751aa9ddf892302cca02cea7f3f5d97df9f1)`, binary sha256 `dd24eb86…3eac` (the `../local-core/` .deb)
- stellar-xdr CLI `30.0.0 (3c2aa43d2ab54d429ae44aa5143d805bf5dba7e2)`, xdr `4f524bbac80c781c06e4fb5fc93a2d0d331d6705`
- goldens: stellar-core tag `v30.0.0`, `test-lcm-current/InvokeHostFunctionTests/`, `index.json` header
  `!cfg protocol version 30`, `!rng seed 12345`
