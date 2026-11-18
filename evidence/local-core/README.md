# local-core scenario probe (2026-11-12) — throwaway research repro, not product code

Standalone stellar-core v30.0.0 (release .deb, no docker), offline in an empty network namespace,
driven over HTTP `tx`/`manualclose` through a scenario that covers shapes a–h, on both real passphrases.
The transcripts and outputs in this folder are the evidence.

## Layout
- `dl/` — downloaded .debs + `SHA256SUMS` (the core sha256 matches apt.stellar.org noble `Packages`)
- `root/` — `dpkg-deb -x` of those .debs; binary `root/usr/bin/stellar-core`
  (sha256 `dd24eb86d322ca58345bcaa04dfe6bd5922f74fe49e4725cd36b92bc22ac3eac`)
- `tools/bin/stellar-xdr` — `cargo install --locked stellar-xdr --version 30.0.0 --features cli`
- `driver/scenario.mjs` — Node 24 + `@stellar/stellar-sdk` 17.4.0 driver (deterministic keys)
- `config/core.cfg.in` — node config template; `config/upgrades/` — Soroban settings upgrade sets
- `run.sh <testnet|mainnet> <dir>` — one clean run; `run-offline.sh` — same inside `unshare -rn`
- `analysis/{frames,analyze,compare,cause,shapes}.py` — record-mark parser, normaliser, comparisons
- `out/<net>/run-1/` — canonical run (meta.xdr, decoded/*.json, analysis.json, driver.json, core.cfg, logs)
- `out/<net>/run-{2,3}/` — hashes only (meta.sha256, analysis.json)
- `out/compare.txt`, `out/twin-diff.txt` — reproducibility table and twin diff
- `out/random-salt/` — the first 6 runs, before the settings-upgrade salt fix (shows header divergence)

## Re-run from scratch
```sh
cd evidence/local-core
mkdir -p dl root && cd dl
curl -O https://apt.stellar.org/pool/noble/s/st/stellar-core_30.0.0-3642.0e49751aa.noble_amd64.deb
B=http://archive.ubuntu.com/ubuntu/pool/universe/l/llvm-toolchain-20
for p in libc++1-20 libc++abi1-20 libunwind-20; do curl -O "$B/${p}_20.1.2-0ubuntu1~24.04.3_amd64.deb"; done
apt-get download libpq5          # Debian trixie 17.11-0+deb13u1 (any libpq5 works)
sha256sum -c SHA256SUMS
cd .. && for f in dl/*.deb; do dpkg-deb -x "$f" root; done
cargo install --locked stellar-xdr --version 30.0.0 --features cli --root "$PWD/tools"
(cd driver && npm install @stellar/stellar-sdk@17.4.0)
# settings upgrade sets: enable.xdr = stellar-rpc v30.0.0 docker/upgrades/enable.xdr (== quickstart
# settings_enable_upgrades.json); p30-testnet.xdr = stellar-xdr encode --type ConfigUpgradeSet of
# quickstart 35a3f46e local/core/etc/config-settings/p30/testnet.json
for net in testnet mainnet; do for n in 1 2 3; do
  ./run-offline.sh $net out/$net/run-$n && mkdir -p out/$net/run-$n/decoded &&
  python3 -I analysis/analyze.py "$PWD/tools/bin/stellar-xdr" out/$net/run-$n
done; done
python3 -I analysis/compare.py out      # reproducibility + twin table
python3 -I analysis/cause.py out/testnet # which normalisation step each raw difference needs
python3 -I analysis/shapes.py out/testnet/run-1
```
`RANDOM_SALT=1 ./run-offline.sh …` reproduces core's own (random-salt) settings-upgrade transactions.

## Pins
- stellar-core `30.0.0 (0e49751aa9ddf892302cca02cea7f3f5d97df9f1)`, deb sha256 `2c1eb74aa1dcf1c4799feeb91cfaf3eb50667232308910165e6b7f8ddff19c30`
- stellar-xdr CLI `30.0.0 (3c2aa43d2ab54d429ae44aa5143d805bf5dba7e2)`, xdr `4f524bbac80c781c06e4fb5fc93a2d0d331d6705`
- final (ledger 31) header hash — testnet `5c4d31594140c7650b6ee00db18325cd24a5c276c0f3e0d37052dca41e3e995a`,
  mainnet `6c38ac0b3ea5d97dfddfa072a2e328e9c0e82d57ccd7e62747726cb149f652be` (identical in all 3 runs each)
