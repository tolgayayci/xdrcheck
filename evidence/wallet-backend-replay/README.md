# wallet-backend single-ledger replay probe (2026-11-12)

A hand-run reproduction, separate from the kit's own check of the same issues (`make verify-replay`); kept as the
dated record, its scripts are not part of the kit. It reproduces **wallet-backend#729** (CAP-40
signed-payload signer halts ingestion) and **#716** (the same signer silently truncated), using
real testnet ledger **4437357** (tx `d9f78749…9fed`). It feeds the ledger through **both** inputs
wallet-backend consumes: a SEP-54 lake on an S3 emulator, and a mock RPC (`getHealth` and `getLedgers`).
The transcripts and outputs in this folder are the evidence.

| Bug | Pre-fix | Fixed | Pre-fix behaviour | Fixed behaviour |
|---|---|---|---|---|
| #729 | `2a0a84ea12523b6c92e278c0c84b443041240095` | `2c873353c1f0f3c9b145e25a7d009023ad104a1c` | exit 2 (`panic: executing root command: …`) after 5 persist attempts (about 15.4 s), cursor stays 4437356, 0 rows | cursor 4437357; SIGNER/ADD row, `signer_account_id` 41 bytes → `PBCK2RYY…MS` |
| #716 | `79ea2acd1dc65a07166133cc04b12e76db314db0` | `bb0b162b072583c7dabffbdee664d1c117e5ba56` | cursor 4437357, exit 0 on SIGTERM; `signer_account_id` 33 bytes, which does not decode as a strkey | same as #729 fixed (rows byte-identical to `2c873353`) |

## Requirements (as used)

- Linux, docker 29.7.2, Go ≥ 1.25.9 (go1.25.14 used, `GOTOOLCHAIN=auto`), python3 (stdlib only), `zstd`, `jq`, `aws` CLI (only for the anonymous download and for uploading to the local emulator).
- Optional: `stellar` CLI 28.1.0, to decode the ledger and cross-check strkeys.
- Images:
  - `timescale/timescaledb:2.28.2-pg17` (`sha256:909e2c75…f1ce1a`). This is the tag pinned by `docker-compose.yaml` and the CI `go.yaml` at all four SHAs.
  - `chrislusf/seaweedfs:4.46` (`sha256:08d51613…625b62`). This is the tag HEAD's integration tests pin. The pre-fix SHAs reference `minio/minio:latest`, which **no longer exists** on Docker Hub ("pull access denied … repository does not exist", 2026-11-12), so SeaweedFS is used at every SHA.
- Ports: 55917 (Postgres), 58333 (S3), 58000 and 59000 (mock RPC), 58002–59401 (ingest servers). All bind to 127.0.0.1.

## Steps from a clean machine

All paths are relative to this directory. `lib.sh` holds the constants (`R`, ports, ledger, tx hash, lake key) and the helpers `q` (psql via `docker exec`), `fresh_db` and `cursor`. Use **bash**: zsh does not word-split, and it treats `$s:c…` as a modifier.

```bash
source lib.sh
# 1. Build one binary per SHA (≈23 s cold GOCACHE, ≈1.5 s warm; output is byte-identical across rebuilds)
git -C ../../_src/wallet-backend worktree add --detach $R/src-<sha> <sha>
(cd src-<sha> && CGO_ENABLED=0 go build -trimpath -o $R/bin/wallet-backend-<sha8> .)

# 2. Database: the compose file's two settings, plus telemetry off (no phone-home) and fsync=off (speed)
docker run -d --name xcc-g4-pg -p 127.0.0.1:55917:5432 -e POSTGRES_HOST_AUTH_METHOD=trust \
  timescale/timescaledb:2.28.2-pg17 postgres -c timescaledb.enable_chunk_skipping=on \
  -c timescaledb.enable_sparse_index_bloom=on -c timescaledb.telemetry_level=off -c fsync=off
#    one template per SHA (the image's template1 already has the timescaledb extension)
q postgres "create database tmpl_<sha8>"
bin/wallet-backend-<sha8> migrate up --database-url "$(dburl tmpl_<sha8>)"        # ≈0.2 s
#    the TimescaleDB per-DB scheduler stays connected to the template, so close it first:
q postgres "alter database tmpl_<sha8> with allow_connections false is_template true"
q postgres "select pg_terminate_backend(pid) from pg_stat_activity where datname='tmpl_<sha8>'"
#    per run: fresh_db <db> tmpl_<sha8> 4437357  (CREATE DATABASE … TEMPLATE … + cursor seed, ≈150 ms)

# 3a. Lake: SeaweedFS with the repo's own startup command, bucket "ledgers"
docker run -d --name xcc-g4-s3 -p 127.0.0.1:58333:8333 --entrypoint sh chrislusf/seaweedfs:4.46 -c \
 'weed server -dir=/data -s3 & until echo s3.bucket.list | weed shell -master localhost:9333 2>/dev/null | grep -q ledgers; do echo s3.bucket.create -name ledgers | weed shell -master localhost:9333 2>/dev/null; sleep 1; done; wait'
mkdir -p download && aws s3 cp --no-sign-request \
  s3://aws-public-blockchain/v1.1/stellar/ledgers/testnet/2025-12-18/$LAKEKEY download/FFBC4A92--4437357.xdr.zst
aws s3 cp --no-sign-request s3://aws-public-blockchain/v1.1/stellar/ledgers/testnet/2025-12-18/.config.json download/lake-config.json
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1   # local emulator only
aws s3 cp --endpoint-url http://127.0.0.1:58333 download/lake-config.json s3://ledgers/testnet/2025-12-18/.config.json
aws s3 cp --endpoint-url http://127.0.0.1:58333 download/FFBC4A92--4437357.xdr.zst s3://ledgers/testnet/2025-12-18/$LAKEKEY
#    The keys and bytes are identical to the public lake (sha256 of the object 24fc6077…aae4001b).

# 3b. Mock RPC: decompress, strip the 12-byte batch header (start, end, count=1), and serve the raw LCM
zstd -dc download/FFBC4A92--4437357.xdr.zst | tail -c +13 > download/lcm.xdr   # sha256 582e694b…765f4e0e
python3 -I mock_rpc.py 58000 download/lcm.xdr 2>logs/mock-rpc.log &

# 4–5. One ledger, observe, stop (run_ingest.sh prints the exact command line; observe.sh runs the queries)
bash run_ingest.sh 2a0a84ea datastore prefix-ds ; bash observe.sh run_prefix_ds
bash run_ingest.sh 2c873353 rpc fixed-rpc       ; bash observe.sh run_fixed_rpc
python3 -I strkey_roundtrip.py <signer_account_id hex> PBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSAAAAAAB55LN6AANMS
bash transcripts.sh      # re-runs all 8 cases and writes transcript-*.txt
bash bench.sh 2c873353 datastore 10   # per-entry cost loop

# Teardown
docker rm -f -v xcc-g4-pg xcc-g4-s3; kill %1
for d in src-*; do git -C ../../_src/wallet-backend worktree remove --force $R/$d; done
```

The ingest command that every run uses (flags rather than env; `env -i`, so no ambient AWS config leaks in):

```
wallet-backend ingest --database-url … --network testnet --network-passphrase "Test SDF Network ; September 2015" \
  --stellar-environment spike --ingestion-mode live --ledger-backend-type datastore|rpc \
  --archive-url http://127.0.0.1:1/ --ingest-server-port <free> --log-level INFO
  # datastore: --rpc-url http://127.0.0.1:1 --datastore-bucket-path ledgers/testnet/2025-12-18 --datastore-region us-east-1
  #            --datastore-endpoint-url http://127.0.0.1:58333 --datastore-buffer-size 1 --datastore-num-workers 1
  #            --datastore-retry-limit 1 --datastore-retry-wait 1s   + env AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
  # rpc:       --rpc-url http://127.0.0.1:58000 --get-ledgers-limit 1
```

## Files

| File | What it is |
|---|---|
| `lib.sh`, `run_ingest.sh`, `observe.sh`, `bench.sh`, `transcripts.sh` | the harness-in-miniature (bash) |
| `mock_rpc.py` | stdlib mock of `getHealth` + `getLedgers`; slices `headerXdr` out of the LCM; handles LCM v0/v1/v2 and the P30 StellarValue arms |
| `strkey_roundtrip.py` | stored bytes → SEP-23 strkey → strict decode, checked against the stellar CLI |
| `gocheck/` | 15-line Go program: the pinned go-stellar-sdk v0.7.3 `strkey` on the truncated value (what `AddressBytea.Scan` returns at `79ea2acd`) |
| `transcript-{prefix,fixed}-{datastore,rpc}.txt` | #729, all four combinations |
| `transcript-716-{prefix,fixed}-{datastore,rpc}.txt` | #716, all four combinations |
| `logs/` | raw process logs, mock request log (`mock-rpc*.log`), `runs.tsv`, benchmark output, flag lists per SHA |
| `download/`, `download-p30/` | lake objects: 4437357, 4437400 (P28) and 5540314 (P30, used for the "pinned SDK cannot decode" probe) |
| `bin/` | the four binaries (≈98 MB each; rebuildable, safe to delete) |

## Extra probes recorded in `logs/`

- `ingest-p30-prefix-{ds,rpc}.log`: a P30 ledger at the v0.7.3 pin. The decode fails. Datastore exits 2 after 1.2 s; RPC exits 2 after 151 s (10 fetch attempts).
- `ingest-missing-{ds,rpc}.log`: a ledger that is absent from the source. The process waits silently (alive at 30 s, cursor unchanged); SIGTERM exits 0.
- `ingest-prefix-ds-restart.log`: a restart on the halted DB resumes at 4437357 and fails the same way. A supervisor turns this into the crash loop.
- `ingest-reseed.log`: the same DB, cursor re-seeded forward to 4437399, then ledger 4437400 ingested in 238 ms.
- `ingest-fk-*.log`: ledger 4437493, which updates a pre-existing trustline, on a seeded empty DB. No FK error; `trustline_assets` is upserted.
- `ingest-tiny.log`, `ingest-fileurl.log`, `ingest-unseeded.log`: the `{1,1}` manifest schema works; `ARCHIVE_URL=file:///nonexistent` is accepted; an unseeded DB exits 2 after 60 ms on the archive fetch.
