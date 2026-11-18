"""Print evidence for shapes a-h from a decoded run. usage: python3 -I shapes.py <run dir>"""
import json, sys, os, glob
R = sys.argv[1]
L = {}
for f in glob.glob(os.path.join(R, 'decoded', '*.json')):
    j = json.load(open(f)); (v, b), = j.items(); L[b['ledger_header']['header']['ledger_seq']] = (v, b)
D = json.load(open(os.path.join(R, 'driver.json')))
def tp(n, i=0): return L[n][1]['tx_processing'][i]
def env(n, i=0):
    b = L[n][1]; out = []
    for ph in b['tx_set']['v1']['phases']:
        if 'v0' in ph:
            for comp in ph['v0']: out += comp['txset_comp_txs_maybe_discounted_fee']['txs']
        else:
            for st in ph['v1']['execution_stages']:
                for cl in st: out += cl
    return out
def changes(t):
    m = t['tx_apply_processing']['v4']; out = []
    for k in ('tx_changes_before', 'tx_changes_after'): out += [(k, c) for c in m[k]]
    for i, op in enumerate(m['operations']): out += [(f'op{i}', c) for c in op['changes']]
    return out
def kinds(t):
    r = []
    for w, c in changes(t):
        (ct, e), = c.items()
        d = e['data'] if 'data' in e else e
        (et, ev), = d.items() if isinstance(d, dict) else [(d, None)]
        r.append(f'{w}:{ct}:{et}')
    return r
def ev(t):
    m = t['tx_apply_processing']['v4']
    return {'tx_events': len(m['events']), 'op_events': [[ (e['body']['v0']['topics'][0]) for e in op['events']] for op in m['operations']],
            'diag': len(m['diagnostic_events'])}
def find_step(name):
    for e in D['log']:
        if e.get('step') == name: return e['ledger']
print('accounts', D['accounts'], 'issuers', D['issuerLabels'], D['issuerOrder'], 'sac', D['sac'], 'pool', D['poolId'])
print('L12 upgrades:', [list(u['upgrade'].keys()) for u in L[12][1]['upgrades_processing']], 'n changes', [len(u['changes']) for u in L[12][1]['upgrades_processing']])
for u in L[12][1]['upgrades_processing']:
    for c in u['changes']:
        (ct, e), = c.items()
        cs = e['data']['config_setting'] if isinstance(e, dict) and 'data' in e and 'config_setting' in e['data'] else None
        if cs and ('contract_compute_v0' in cs or 'contract_execution_lanes' in cs or 'contract_ledger_cost_ext_v0' in cs): print('  ', ct, json.dumps(cs)[:200])
# b
e = env(14)[0]['tx']['tx']; print('b env src', e['source_account'], 'op dest', e['operations'][0]['body']['payment']['destination'])
print('b events', json.dumps(tp(14)['tx_apply_processing']['v4']['operations'][0]['events'])[:900])
# c
for k, c in [x for x in changes(tp(15)) if 'account' in json.dumps(x[1])][-1:]:
    print('c signers', json.dumps(c['updated']['data']['account']['signers'])[:700])
print('c2 sigs', env(16)[0]['tx']['signatures'], tp(16)['result']['result']['result'])
print('c3 cond', json.dumps(env(17)[0]['tx']['tx']['cond'])[:400], 'sigs', len(env(17)[0]['tx']['signatures']))
# d
fb = env(18)[0]; print('d fee-bump keys', list(fb.keys()), json.dumps(fb)[:250]); print('d result', json.dumps(tp(18)['result']['result'])[:400])
# e
print('e L23 kinds', kinds(tp(23))); print('e L24 kinds', kinds(tp(24)))
cp = env(23)[0]['tx']['tx']['operations'][0]['body']['change_trust']['line']; print('e pool line', json.dumps(cp))
# f
print('f memo1', env(25)[0]['tx']['tx']['memo'], ' memo2', env(26)[0]['tx']['tx']['memo'], tp(26)['result']['result']['result'])
print('f memo2 classic events', json.dumps(tp(26)['tx_apply_processing']['v4']['operations'][0]['events'])[:600])
# g/h
for n, nm in [(27, 'g deploy'), (28, 'g trust'), (29, 'g transfer muxed'), (30, 'h unmatched auth')]:
    t = tp(n); print(nm, 'L', n, 'meta', list(t['tx_apply_processing'].keys()), 'result', json.dumps(t['result']['result']['result'])[:120])
    print('   changes', kinds(t)); print('   events', ev(t))
    sm = t['tx_apply_processing']['v4']['soroban_meta']; print('   soroban_meta', json.dumps(sm)[:300])
for w, c in changes(tp(28)):
    if 'created' in c: print('trust created', json.dumps(c)[:600])
print('transfer op events', json.dumps(tp(29)['tx_apply_processing']['v4']['operations'][0]['events'])[:1200])
print('h auth entries in env', len(env(30)[0]['tx']['tx']['operations'][0]['body']['invoke_host_function']['auth']))
print('h diag topics', [json.dumps(d['event']['body']['v0']['topics'])[:80] for d in tp(30)['tx_apply_processing']['v4']['diagnostic_events']][:12])
print('LCM ext L28', json.dumps(L[28][1]['ext']), 'tx meta ext', json.dumps(tp(28)['tx_apply_processing']['v4']['ext'])[:200])
