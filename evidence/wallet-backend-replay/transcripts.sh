#!/usr/bin/env bash
# Re-run every case and write transcript-*.txt (commands + trimmed output).
set -u
source "$(dirname "$0")/lib.sh"
cd "$R"
trim() { sed 's/time="2026-[0-9-]*T//; s/ pid=[0-9]*//' "$1" | grep -vE 'Set chunk interval|^ +--|^Flags:|^Usage:|^  wallet-backend ingest|^ *-h, --help|^$|^goroutine|^github.com|^main.main|^\s+github.com|^\s+/' | cut -c1-600; }
one() { # <file> <sha8> <backend> <label> <bug>
  local f=$1 sha=$2 be=$3 lb=$4 bug=$5
  {
    echo "# wallet-backend replay transcript: $bug, wallet-backend $sha, ledger backend '$be', testnet ledger $LEDGER, tx $TXHASH"
    echo "# date: $(date -u +%FT%TZ); go: $(go env GOVERSION); binary sha256: $(sha256sum bin/wallet-backend-$sha | cut -c1-16)…"
    echo "# fresh DB = CREATE DATABASE run_x TEMPLATE tmpl_$sha; INSERT ingest_store latest=$((LEDGER-1)), oldest=$LEDGER"
    bash run_ingest.sh "$sha" "$be" "$lb" 400
    echo; echo "## process log (trimmed: usage text and goroutine trace removed)"; trim "logs/ingest-$lb.log"
    echo; echo "## exit status as seen by the shell: see 'rc=' above"
    echo; echo "## observation queries (observe.sh)"; bash observe.sh "run_${lb//-/_}"
    sig=$(q "run_${lb//-/_}" "SELECT encode(sc.signer_account_id,'hex') FROM state_changes sc JOIN transactions t ON sc.to_id=t.to_id WHERE t.hash=decode('$TXHASH','hex') AND sc.state_change_category='SIGNER'")
    if [ -n "$sig" ]; then echo; echo "## round-trip of stored signer_account_id"; echo "\$ python3 -I strkey_roundtrip.py $sig PBCK2RYY…MS"; python3 -I strkey_roundtrip.py "$sig" PBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSAAAAAAB55LN6AANMS; echo "rc=$?"; fi
  } > "$f" 2>&1
  echo "wrote $f"
}
one transcript-prefix-datastore.txt 2a0a84ea datastore tr-prefix-ds  "wallet-backend#729 pre-fix"
one transcript-fixed-datastore.txt  2c873353 datastore tr-fixed-ds   "wallet-backend#729 fixed"
one transcript-prefix-rpc.txt       2a0a84ea rpc       tr-prefix-rpc "wallet-backend#729 pre-fix"
one transcript-fixed-rpc.txt        2c873353 rpc       tr-fixed-rpc  "wallet-backend#729 fixed"
one transcript-716-prefix-datastore.txt 79ea2acd datastore tr716-prefix-ds "wallet-backend#716 pre-fix (truncation)"
one transcript-716-fixed-datastore.txt  bb0b162b datastore tr716-fixed-ds  "wallet-backend#716 fixed"
one transcript-716-prefix-rpc.txt       79ea2acd rpc       tr716-prefix-rpc "wallet-backend#716 pre-fix (truncation)"
one transcript-716-fixed-rpc.txt        bb0b162b rpc       tr716-fixed-rpc  "wallet-backend#716 fixed"
