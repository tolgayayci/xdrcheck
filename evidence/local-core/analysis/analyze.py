"""Decode a meta stream per ledger, normalise like core's --check-lcm, write <run>/analysis.json.

Normalisation (equivalent, for equality purposes, to core's MetaUtils normalizeMeta +
zeroNonDeterministicDiagnostics at v30.0.0):
  1. every LedgerEntryChanges vector (any JSON list whose items are single-key objects with key in
     created/updated/removed/state/restored) is sorted by (change-type rank, canonical JSON of the change).
     Core sorts by (LedgerKey, type rank, sha256(change)); both are total orders over the same multiset,
     so two vectors are equal after one normalisation iff they are equal after the other.
  2. diagnostic/contract events whose topics are [sym core_metrics, sym invoke_time_nsecs] get data u64 0.
The normalised JSON is re-encoded to XDR with stellar-xdr 30.0.0 and hashed.
usage: python3 -I analyze.py <stellar-xdr bin> <run dir>
"""
import hashlib, json, subprocess, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frames as F

CHG = {'state': 0, 'created': 1, 'updated': 2, 'removed': 3, 'restored': 4}
X = sys.argv[1]
RUN = sys.argv[2]


def dec(b):
    p = subprocess.run([X, 'decode', '--type', 'LedgerCloseMeta', '--input', 'single', '--output', 'json'], input=b, capture_output=True, check=True)
    return json.loads(p.stdout)


def enc(j):
    p = subprocess.run([X, 'encode', '--type', 'LedgerCloseMeta', '--input', 'json', '--output', 'single'], input=json.dumps(j).encode(), capture_output=True, check=True)
    return p.stdout


canon = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'))
stats = {'sorted_vectors': 0, 'vectors_reordered': 0, 'zeroed_invoke_time': 0}


def is_changes(v):
    return isinstance(v, list) and v and all(isinstance(x, dict) and len(x) == 1 and next(iter(x)) in CHG for x in v)


def norm(v):
    if isinstance(v, dict):
        t = v.get('topics')
        if isinstance(t, list) and len(t) == 2 and t[0] == {'symbol': 'core_metrics'} and t[1] == {'symbol': 'invoke_time_nsecs'}:
            if v.get('data') != {'u64': '0'}:
                stats['zeroed_invoke_time'] += 1
            v = dict(v); v['data'] = {'u64': '0'}
        return {k: norm(x) for k, x in v.items()}
    if isinstance(v, list):
        v = [norm(x) for x in v]
        if is_changes(v):
            s = sorted(v, key=lambda c: (CHG[next(iter(c))], canon(c)))
            stats['sorted_vectors'] += 1
            if s != v:
                stats['vectors_reordered'] += 1
            return s
        return v
    return v


def walk(v, fn):
    fn(v)
    if isinstance(v, dict):
        for x in v.values(): walk(x, fn)
    elif isinstance(v, list):
        for x in v: walk(x, fn)


def code(r):
    """compact result: tx code + per-op codes"""
    res = r['result']
    if isinstance(res, str):
        return res
    (k, v), = res.items()
    if k in ('tx_fee_bump_inner_success', 'tx_fee_bump_inner_failed'):
        return k + '(' + code(v['result']) + ')'
    ops = []
    for o in v if isinstance(v, list) else []:
        if isinstance(o, str):
            ops.append(o); continue
        (ok, ov), = o.items()
        if ok == 'op_inner':
            (on, oc), = ov.items()
            ops.append(on + ':' + (oc if isinstance(oc, str) else next(iter(oc))))
        else:
            ops.append(ok)
    return k + '[' + ','.join(ops) + ']'


out = []
for idx, raw in enumerate(F.frames(os.path.join(RUN, 'meta.xdr'))):
    j = dec(raw)
    (ver, body), = j.items()
    hdr = body['ledger_header']
    before = dict(stats)
    n = norm(j)
    nb = enc(n)
    txs = []
    for tp in body.get('tx_processing', []):
        r = tp['result']
        (mv, m), = tp['tx_apply_processing'].items()
        txs.append({'hash': r['transaction_hash'], 'result': code(r['result']), 'fee_charged': r['result']['fee_charged'], 'tx_meta': mv})
    out.append({
        'frame': idx, 'lcm': ver, 'ledger': hdr['header']['ledger_seq'], 'protocol': hdr['header']['ledger_version'],
        'close_time': hdr['header']['scp_value']['close_time'], 'header_hash': hdr['hash'],
        'tx_set_hash': hdr['header']['scp_value']['tx_set_hash'], 'bucket_list_hash': hdr['header']['bucket_list_hash'],
        'raw_len': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
        'norm_sha256': hashlib.sha256(nb).hexdigest(), 'roundtrip_raw_ok': enc(j) == raw,
        'reordered_vectors': stats['vectors_reordered'] - before['vectors_reordered'],
        'zeroed_invoke_time': stats['zeroed_invoke_time'] - before['zeroed_invoke_time'],
        'txs': txs,
    })
    with open(os.path.join(RUN, 'decoded', f'{idx:02d}-L{hdr["header"]["ledger_seq"]}.json'), 'w') if os.path.isdir(os.path.join(RUN, 'decoded')) else open(os.devnull, 'w') as fh:
        json.dump(j, fh, indent=1)
json.dump({'stats': stats, 'ledgers': out}, open(os.path.join(RUN, 'analysis.json'), 'w'), indent=1)
print(RUN, len(out), 'ledgers', stats)
