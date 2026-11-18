# Throwaway helpers for the wallet-backend replay probe. Source from bash.
R=evidence/wallet-backend-replay
PGPORT_HOST=55917
S3PORT=58333
RPCPORT=${RPCPORT:-58000}
PASSPHRASE='Test SDF Network ; September 2015'
LEDGER=${LEDGER:-4437357}
TXHASH=d9f78749cd01297cd5f22c7f2c798c9eec93d56f399e1c4cc2f8977ca52b9fed
LAKEKEY='FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst'

# psql inside the container (no host psql). Usage: q <db> <sql>
q() { docker exec -i xcc-g4-pg psql -U postgres -h 127.0.0.1 -v ON_ERROR_STOP=1 -qAt -d "$1" -c "$2"; }
# pretty psql
qp() { docker exec -i xcc-g4-pg psql -U postgres -h 127.0.0.1 -v ON_ERROR_STOP=1 -P pager=off -d "$1" -c "$2"; }
dburl() { echo "postgres://postgres@127.0.0.1:${PGPORT_HOST}/$1?sslmode=disable"; }
ms() { date +%s%3N; }

# fresh DB from a per-SHA template, cursors seeded so live mode starts at $2
fresh_db() { # <db> <template> <startLedger>
  q postgres "DROP DATABASE IF EXISTS $1 WITH (FORCE)" >/dev/null
  q postgres "CREATE DATABASE $1 TEMPLATE $2" >/dev/null
  q "$1" "INSERT INTO ingest_store(key,value) VALUES ('latest_ingest_ledger','$(( $3 - 1 ))'),('oldest_ingest_ledger','$3') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null
}
cursor() { q "$1" "SELECT value FROM ingest_store WHERE key='latest_ingest_ledger'"; }
