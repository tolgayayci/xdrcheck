# wallet-backend#731 end-to-end repro (2026-11-12)

A hand-run reproduction, separate from the kit's own check of the same issue (`make verify-replay`, which runs the
reference adapter on the pinned pre-fix and fixed commits). It is kept as the dated record; its scripts are not part
of the kit.

A local stellar-core v30.0.0 chain **at protocol 28** (also 26, 27; mainnet twin) carrying a CAP-0073 SAC `trust`
(ledger 15, only tx in its ledger), ingested by wallet-backend at pre-fix `764a4f5b`, fixed `c152783c` and HEAD
`e967ce8b` through a SEP-54 lake on SeaweedFS and through a mock `getLedgers`. The transcripts and outputs in this folder are the evidence.

| commit | L15 `trust(B)` state_changes | exit / cursor |
|---|---|---|
| `764a4f5bcbff5abb0949d93da37f769063013ea0` (pre-fix) | only `BALANCE/DEBIT` (fee); **no TRUSTLINE/ADD, no BALANCE_AUTHORIZATION**; `trustline_balances` row present | ingests 2..24, cursor 24, alive, SIGTERM → 0 |
| `c152783c054c765c8b51fd26ed313fd1ebc1c50c` (fixed) | + `TRUSTLINE/ADD` (limit `922337203685.4775807`) + `BALANCE_AUTHORIZATION/SET flags=1` | same |
| `e967ce8b7362b79c277e700e789181d76fbb5967` (HEAD) | state_changes identical to fixed; participants drop the SAC `C…` address | same |

## Layout
- `core/` — driver `driver/scenario731.mjs` (adapted from `../local-core/driver/scenario.mjs`; `node_modules` is a
  symlink to `../local-core/driver/node_modules`, `@stellar/stellar-sdk` 17.4.0), `run.sh`, `run-offline.sh`
  (`unshare -rn`: fresh netns, own ports 11626/11627, no stale node), `config/core.cfg.in` (= `../local-core/`'s),
  `config/upgrades/{enable.xdr, p26,p27,p29-testnet.{json,xdr}}` (quickstart `35a3f46e` `local/core/etc/config-settings/pNN/testnet.json`, encoded with stellar-xdr 30.0.0).
  Binary and stellar-xdr CLI are **reused read-only** from `../local-core/` (core sha256 `dd24eb86…3eac`).
- `out/<pNN>-<net>/run-N/` — `meta.xdr` (canonical stream), `ledgers/<seq>.xdr` (raw LCM per ledger),
  `decoded/<seq>.json`, `summary.json`, `driver.json` (keys, steps, tx hashes), `core.cfg`, logs. `out/compare.txt`: per-ledger hashes, repro.
- `lake/<pNN>-<net>/` — SEP-54 layout (`.config.json` byte-identical to the public testnet lake's; key
  `FFFFFFFF--0-63999/%08X--<seq>.xdr.zst`, object = zstd(`LedgerCloseMetaBatch{S,S,[lcm]}`)).
- `analysis/` — `frames.py` , `split_decode.py`, `make_lake.py`. `gocheck/` — go-stellar-sdk v0.7.3 `SafeUnmarshal` check.
- `lib.sh`, `run_ingest.sh`, `observe.py`, `transcripts.sh`, `mock_rpc.py` (= `../wallet-backend-replay/`'s, unmodified).
- `transcript-{prefix,fixed,head}.txt` — 4 cases each (datastore chain 2..24, datastore only-L15, rpc chain, rpc only-L15). `diff-prefix-vs-fixed.txt`.
- `logs/` — every ingest log, `runs.tsv`, `obs-*.txt` row dumps, mock request logs, flags per SHA, gocheck output.
- `bin/` — the three wallet-backend binaries (rebuildable; safe to delete).

## Re-run (bash, from this directory)
```bash
# 1. chains (≈2 s each). PROTOCOL/SETTINGS default to 28 / p27-testnet.xdr (quickstart has no p28 dir)
core/run-offline.sh testnet out/p28-testnet/run-1
core/run-offline.sh mainnet out/p28-mainnet/run-1
PROTOCOL=26 SETTINGS=p26-testnet.xdr core/run-offline.sh testnet out/p26-testnet/run-1
PROTOCOL=27 SETTINGS=p27-testnet.xdr core/run-offline.sh testnet out/p27-testnet/run-1
for d in out/*/run-1; do python3 -I analysis/split_decode.py ../local-core/tools/bin/stellar-xdr $d; done
(cd gocheck && go run . $(ls ../out/p28-testnet/run-1/ledgers/*.xdr | sort -V))     # v0.7.3 decodes all 23
python3 -I analysis/make_lake.py out/p28-testnet/run-1 lake/p28-testnet "Test SDF Network ; September 2015"

# 2. wallet-backend binaries (worktrees in this dir; remove afterwards)
for s in 764a4f5bcbff5abb0949d93da37f769063013ea0 c152783c054c765c8b51fd26ed313fd1ebc1c50c e967ce8b7362b79c277e700e789181d76fbb5967; do
  git -C ../../_src/wallet-backend worktree add --detach $PWD/src-${s:0:8} $s
  (cd src-${s:0:8} && CGO_ENABLED=0 go build -trimpath -o ../bin/wallet-backend-${s:0:8} .); done

# 3. services (127.0.0.1 only): TimescaleDB 2.28.2-pg17 @sha256:909e2c75…, SeaweedFS 4.46 @sha256:08d51613…
source lib.sh
docker run -d --name xcc-g5-pg -p 127.0.0.1:55931:5432 -e POSTGRES_HOST_AUTH_METHOD=trust timescale/timescaledb:2.28.2-pg17 \
  postgres -c timescaledb.enable_chunk_skipping=on -c timescaledb.enable_sparse_index_bloom=on -c timescaledb.telemetry_level=off -c fsync=off
docker run -d --name xcc-g5-s3 -p 127.0.0.1:58343:8333 --entrypoint sh chrislusf/seaweedfs:4.46 -c \
 'weed server -dir=/data -s3 & until echo s3.bucket.list | weed shell -master localhost:9333 2>/dev/null | grep -q ledgers; do echo s3.bucket.create -name ledgers | weed shell -master localhost:9333 2>/dev/null; sleep 1; done; wait'
for s in 764a4f5b c152783c e967ce8b; do q postgres "create database tmpl_$s"
  env -i PATH=$PATH HOME=$HOME bin/wallet-backend-$s migrate up --database-url "$(dburl tmpl_$s)"
  q postgres "alter database tmpl_$s with allow_connections false is_template true"
  q postgres "select pg_terminate_backend(pid) from pg_stat_activity where datname='tmpl_$s'"; done
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
aws s3 cp --recursive --endpoint-url http://127.0.0.1:58343 lake/p28-testnet s3://ledgers/local/p28-testnet
K=FFFFFFFF--0-63999/FFFFFFF0--15.xdr.zst   # single-ledger lake: only .config.json + L15
aws s3 cp --endpoint-url http://127.0.0.1:58343 lake/p28-testnet/.config.json s3://ledgers/local/p28-testnet-only15/.config.json
aws s3 cp --endpoint-url http://127.0.0.1:58343 lake/p28-testnet/$K s3://ledgers/local/p28-testnet-only15/$K
python3 -I mock_rpc.py 58010 $(ls out/p28-testnet/run-1/ledgers/*.xdr | sort -V) 2>logs/mock-rpc-chain.log &
python3 -I mock_rpc.py 58011 out/p28-testnet/run-1/ledgers/15.xdr 2>logs/mock-rpc-only15.log &

# 4. runs: run_ingest.sh <sha8> <datastore|rpc> <label> <S> <E>  (seeds cursor S-1, waits for cursor >= E, SIGTERM)
bash run_ingest.sh 764a4f5b datastore pre-ds-chain 2 24 && python3 -I observe.py run_pre_ds_chain
BUCKETPATH=ledgers/local/p28-testnet-only15 bash run_ingest.sh c152783c datastore fix-only15 15 15 && python3 -I observe.py run_fix_only15 15
bash transcripts.sh 764a4f5b prefix; bash transcripts.sh c152783c fixed; bash transcripts.sh e967ce8b head
# mainnet twin: PASSPHRASE='Public Global Stellar Network ; September 2015' NETWORK=pubnet BUCKETPATH=ledgers/local/p28-mainnet bash run_ingest.sh …

# teardown
docker rm -f -v xcc-g5-pg xcc-g5-s3; kill %1 %2
for s in 764a4f5b c152783c e967ce8b; do git -C ../../_src/wallet-backend worktree remove --force $PWD/src-$s; done
```
`run_ingest.sh` passes `--network/--stellar-environment` except at `e967ce8b`, which has neither flag.
Single-ledger runs need a source that holds **only** that ledger (or a stop at cursor ≥ E): with the full lake the
process races past E within one 100 ms poll.

## Pins
- stellar-core `30.0.0 (0e49751aa9ddf892302cca02cea7f3f5d97df9f1)`, binary sha256 `dd24eb86d322ca58345bcaa04dfe6bd5922f74fe49e4725cd36b92bc22ac3eac`
- P28 testnet chain `meta.xdr` sha256 `108c358829bc9fd665ce7236d92bcb74652a150a66688144a90c6b5612067005` (raw bytes vary run to run; header hashes do not)
- L15 header hash testnet `c0f754e7c9a7a47a0969dbf88f861c89bf79ae0e97ffe464e90aaa8c292145b3`, mainnet `6f09aa250d53acb32af316152a905fb7689bd52f00daeb9714ba32d700ad4343`
- L15 tx testnet `8764718b70f14a572c9beb660460ba0485da1c7aa6f6960a8851f951e6be44e5`, mainnet `8decbdd50ac0e33a0382cc2e06c74b522a3280a86f93b3e2ace371cf13df35fc`
- final L24 header testnet `c18290b6285df333643c49386254f4b7f0f8241621f74962455fdfa9d999caa7`, mainnet `78a3f9adce2de48b7de4559fb1832c271c984f8ab6172e5682f03b311df26206`
