#!/usr/bin/env bash
# re-run every #731 case for one commit and write transcript-<name>.txt. Usage: transcripts.sh <sha8> <name>
# Needs: xcc-g5-pg, xcc-g5-s3 with lake uploaded, mock_rpc.py on 58010 (whole chain) and 58011 (only L15).
set -u
source "$(dirname "$0")/lib.sh"; cd "$R"
SHA=$1; NAME=$2; F=transcript-$NAME.txt
trim() { sed 's/time="2026-[0-9-]*T//; s/ pid=[0-9]*//' "$1" | grep -E 'level=(warning|error|fatal)|Ingested ledger (1[3-9]|2[0-4]) |Starting ingestion|shutdown|^panic' | cut -c1-300; }
{
echo "# transcript: wallet-backend#731 ($NAME), wallet-backend $SHA, local stellar-core v30.0.0 chain at protocol 28, testnet passphrase"
echo "# date: $(date -u +%FT%TZ); go: $(go env GOVERSION); binary sha256: $(sha256sum bin/wallet-backend-$SHA | cut -c1-64)"
echo "# commit: $(git -C src-$SHA rev-parse HEAD)  go-stellar-sdk: $(grep 'stellar/go-stellar-sdk ' src-$SHA/go.mod | awk '{print $2}')"
echo "# chain: out/p28-testnet/run-1/meta.xdr sha256 $(cut -c1-64 out/p28-testnet/run-1/meta.sha256); trigger = L15 tx 8764718b70f14a572c9beb660460ba0485da1c7aa6f6960a8851f951e6be44e5 (SAC trust(B))"
echo "# ledgers of interest: 14 deploy SAC USDC:I | 15 SAC trust(B) | 16 SAC mint(B) | 17 control ChangeTrust(C) | 18 classic pay I->C | 19 SAC transfer B->C | 20 SAC trust(D) via D's address credentials (src A) | 21 J sets AUTH_REQUIRED | 22 deploy SAC EURT:J | 23 SAC trust(B) on EURT:J (flags 0) | 24 empty"
for case in "datastore chain ledgers/local/p28-testnet 2 24 58010" "datastore only15 ledgers/local/p28-testnet-only15 15 15 58010" "rpc chain - 2 24 58010" "rpc only15 - 15 15 58011"; do
  set -- $case; be=$1; kind=$2; bp=$3; S=$4; E=$5; port=$6; lb="tr-$NAME-$be-$kind"
  echo; echo "################ case: $be, $kind (cursor seeded to $((S-1)), wait for $E)"
  [ "$bp" != - ] && echo "# lake: s3://$bp (SEP-54, .config.json {ledgersPerBatch 1, batchesPerPartition 64000, zstd})" || echo "# mock getLedgers on 127.0.0.1:$port"
  BUCKETPATH=$bp RPCPORT=$port bash run_ingest.sh "$SHA" "$be" "$lb" "$S" "$E" 60
  echo "## process log (filtered: warnings/errors, per-ledger 'Ingested' lines 13-24, start/shutdown)"; trim "logs/ingest-$lb.log"
  echo "## observation (observe.py; addresses rendered by the harness, not by wallet-backend)"; python3 -I observe.py "run_${lb//-/_}" "$([ $S = 2 ] && echo 13 || echo $S)"
done
} > "$F" 2>&1
echo "wrote $F"
