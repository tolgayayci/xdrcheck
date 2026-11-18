"""per tx in a decoded frame dir: envelope op type / host fn name, result, op change kinds, event counts.
usage: python3 -I txlist.py <decoded dir>"""
import json, glob, sys, os
def envs_of(v):
    out = []
    ts = v['tx_set']
    if 'txs' in ts: return ts['txs']
    arm = next(iter(ts)); t = ts[arm]
    for ph in t['phases']:
        pa = next(iter(ph)); p = ph[pa]
        if pa == 'v0':
            for comp in p:
                out += comp['txset_comp_txs_maybe_discounted_fee']['txs']
        else:
            for st in p['execution_stages']:
                for cl in st:
                    out += cl
    return out
for f in sorted(glob.glob(sys.argv[1] + '/frame[0-9]*.json')):
    j = json.load(open(f)); v = j[next(iter(j))]
    envs = envs_of(v)
    for tp in v.get('tx_processing', []):
        m = tp['tx_apply_processing']; mv = next(iter(m)); mm = m[mv]
        ops = []
        for o in mm.get('operations', []):
            ch = [(next(iter(c)), next(iter(c[next(iter(c))]['data'])) if next(iter(c)) != 'removed' else next(iter(c['removed']))) for c in o['changes']]
            ops.append({'changes': ch, 'events': len(o.get('events', []))})
        sm = mm.get('soroban_meta')
        print(os.path.basename(f), tp['result']['transaction_hash'][:8], json.dumps(tp['result']['result']['result'])[:80],
              'meta', mv, 'fee', [next(iter(c)) for c in tp['fee_processing']], 'ops', ops,
              'txev', len(mm.get('events', [])) , 'diag', len(mm.get('diagnostic_events', [])), 'smeta', None if sm is None else list(sm.keys()))
    for e in envs:
        ea = next(iter(e)); tx = e[ea]['tx']
        for op in tx['operations']:
            b = op['body']; ba = next(iter(b)) if isinstance(b, dict) else b
            fn = ''
            if ba == 'invoke_host_function':
                hf = b[ba]['host_function']; hfa = next(iter(hf))
                fn = hfa + ':' + (hf[hfa].get('function_name', '') if hfa == 'invoke_contract' else '')
            print('   env', ea, 'src', str(tx.get('source_account'))[:12], ba, fn, 'auth', len(b[ba].get('auth', [])) if ba == 'invoke_host_function' else '-')
