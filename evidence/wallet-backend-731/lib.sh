# Helpers (adapted from ../wallet-backend-replay/lib.sh). Source from bash.
R=evidence/wallet-backend-731
PGC=xcc-g5-pg; S3C=xcc-g5-s3
PGPORT_HOST=55931
S3PORT=58343
RPCPORT=${RPCPORT:-58010}
PASSPHRASE=${PASSPHRASE:-'Test SDF Network ; September 2015'}
NETWORK=${NETWORK:-testnet}
CHAIN=${CHAIN:-$R/out/p28-testnet/run-1}
BUCKETPATH=${BUCKETPATH:-ledgers/local/p28-testnet}
q() { docker exec -i $PGC psql -U postgres -h 127.0.0.1 -v ON_ERROR_STOP=1 -qAt -d "$1" -c "$2"; }
qp() { docker exec -i $PGC psql -U postgres -h 127.0.0.1 -v ON_ERROR_STOP=1 -P pager=off -d "$1" -c "$2"; }
dburl() { echo "postgres://postgres@127.0.0.1:${PGPORT_HOST}/$1?sslmode=disable"; }
ms() { date +%s%3N; }
fresh_db() { # <db> <template> <startLedger>
  q postgres "DROP DATABASE IF EXISTS $1 WITH (FORCE)" >/dev/null
  q postgres "CREATE DATABASE $1 TEMPLATE $2" >/dev/null
  q "$1" "INSERT INTO ingest_store(key,value) VALUES ('latest_ingest_ledger','$(( $3 - 1 ))'),('oldest_ingest_ledger','$3') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null
}
cursor() { q "$1" "SELECT value FROM ingest_store WHERE key='latest_ingest_ledger'"; }
