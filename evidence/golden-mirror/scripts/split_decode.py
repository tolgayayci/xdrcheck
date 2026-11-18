"""split a record-marked LCM stream (own RFC 5531 parser), decode each LCM with stellar-xdr 30.0.0 to JSON,
re-encode check, and list every tx with its host-function name.
usage: python3 -I split_decode.py <stellar-xdr> <stream.xdr> <outdir>"""
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frames as F
X, SRC, OUT = sys.argv[1:4]
os.makedirs(OUT, exist_ok=True)
rows = []
for k, rec in enumerate(F.frames(SRC)):
    j = json.loads(subprocess.run([X, 'decode', '--type', 'LedgerCloseMeta', '--input', 'single', '--output', 'json'],
                                  input=rec, capture_output=True, check=True).stdout)
    re = subprocess.run([X, 'encode', '--type', 'LedgerCloseMeta', '--input', 'json', '--output', 'single'],
                        input=json.dumps(j).encode(), capture_output=True, check=True).stdout
    arm = next(iter(j)); v = j[arm]; seq = v['ledger_header']['header']['ledger_seq']
    open(f'{OUT}/frame{k:02d}-L{seq}.xdr', 'wb').write(rec)
    json.dump(j, open(f'{OUT}/frame{k:02d}-L{seq}.json', 'w'), indent=1)
    txs = []
    envs = {}
    # envelopes live in tx_set phases (v2) — map by position not needed; take from tx_processing order via hash lookup later
    for i, tp in enumerate(v.get('tx_processing', [])):
        res = tp['result']['result']['result']
        txs.append({'i': i, 'hash': tp['result']['transaction_hash'],
                    'result': res if isinstance(res, str) else next(iter(res))})
    rows.append({'frame': k, 'seq': seq, 'lcm': arm, 'proto': v['ledger_header']['header']['ledger_version'],
                 'bytes': len(rec), 'sha256': hashlib.sha256(rec).hexdigest(), 'rt': re == rec, 'txs': txs})
json.dump(rows, open(f'{OUT}/frames.json', 'w'), indent=1)
for r in rows:
    print(r['frame'], 'L%d' % r['seq'], r['lcm'], 'p%d' % r['proto'], r['bytes'], 'rt=%s' % r['rt'], [(t['hash'][:8], t['result']) for t in r['txs']])
