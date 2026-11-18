"""split meta.xdr into per-ledger LCM files, decode each with stellar-xdr 30.0.0, write a summary.
usage: python3 -I split_decode.py <stellar-xdr bin> <run dir>
writes <run>/ledgers/<seq>.xdr (raw LCM), <run>/decoded/<seq>.json, <run>/summary.json"""
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frames as F
X, RUN = sys.argv[1], sys.argv[2]
os.makedirs(RUN + '/ledgers', exist_ok=True); os.makedirs(RUN + '/decoded', exist_ok=True)
summ = []
for rec in F.frames(RUN + '/meta.xdr'):
    j = json.loads(subprocess.run([X, 'decode', '--type', 'LedgerCloseMeta', '--input', 'single', '--output', 'json'], input=rec, capture_output=True, check=True).stdout)
    arm = next(iter(j)); v = j[arm]
    hh = v['ledger_header']; seq = hh['header']['ledger_seq']
    open(f'{RUN}/ledgers/{seq}.xdr', 'wb').write(rec)
    json.dump(j, open(f'{RUN}/decoded/{seq}.json', 'w'), indent=1)
    # re-encode check
    re = subprocess.run([X, 'encode', '--type', 'LedgerCloseMeta', '--input', 'json', '--output', 'single'], input=json.dumps(j).encode(), capture_output=True, check=True).stdout
    sv_ext = hh['header']['scp_value']['ext']
    txs = []
    for tp in v.get('tx_processing', []):
        meta = tp['tx_apply_processing']; mv = next(iter(meta))
        res = tp['result']['result']['result']
        txs.append({'hash': tp['result']['transaction_hash'], 'result': res if isinstance(res, str) else next(iter(res)),
                    'fee_charged': tp['result']['result']['fee_charged'], 'tx_meta': mv,
                    'op_events': [len(o.get('events', [])) for o in meta[mv].get('operations', [])] if mv == 'v4' else None,
                    'op_changes': [[ (next(iter(c)), next(iter(c[next(iter(c))]['data'])) if next(iter(c)) != 'removed' else 'key') for c in o['changes']] for o in meta[mv].get('operations', [])]})
    summ.append({'seq': seq, 'lcm': arm, 'protocol': hh['header']['ledger_version'], 'header_hash': hh['hash'],
                 'close_time': hh['header']['scp_value']['close_time'],
                 'scp_ext': sv_ext if isinstance(sv_ext, str) else next(iter(sv_ext)), 'lcm_ext': (v.get('ext') if isinstance(v.get('ext'), str) else next(iter(v.get('ext', {'-': 0})))) if arm != 'v0' else None,
                 'bytes': len(rec), 'sha256': hashlib.sha256(rec).hexdigest(), 'reencode_exact': re == rec, 'txs': txs})
json.dump(summ, open(RUN + '/summary.json', 'w'), indent=1)
for s in summ:
    print(s['seq'], s['lcm'], 'p%d' % s['protocol'], s['scp_ext'], s['lcm_ext'], s['header_hash'][:16], s['bytes'], 'rt=%s' % s['reencode_exact'],
          [(t['hash'][:8], t['result'], t['tx_meta'], t['op_events'], t['op_changes']) for t in s['txs']])
