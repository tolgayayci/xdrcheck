"""For each ledger, say which normalisation step is needed to make runs equal: none / zero-timing / sort / both.
usage: python3 -I cause.py <net dir>"""
import json, sys, os, glob, importlib.util
sys.argv_save = list(sys.argv)
base = sys.argv[1]
runs = sorted(glob.glob(os.path.join(base, 'run-*')))
CHG = {'state', 'created', 'updated', 'removed', 'restored'}
def zero(v):
    if isinstance(v, dict):
        t = v.get('topics')
        if isinstance(t, list) and len(t) == 2 and t[0] == {'symbol': 'core_metrics'} and t[1] == {'symbol': 'invoke_time_nsecs'}:
            v = dict(v); v['data'] = {'u64': '0'}
        return {k: zero(x) for k, x in v.items()}
    if isinstance(v, list): return [zero(x) for x in v]
    return v
canon = lambda v: json.dumps(v, sort_keys=True)
def srt(v, where, path=''):
    if isinstance(v, dict): return {k: srt(x, where, path + '/' + k) for k, x in v.items()}
    if isinstance(v, list):
        v = [srt(x, where, path + '[]') for x in v]
        if v and all(isinstance(x, dict) and len(x) == 1 and next(iter(x)) in CHG for x in v):
            s = sorted(v, key=canon)
            return s
        return v
    return v
def diffpaths(a, b, p=''):
    if type(a) != type(b): return [p]
    if isinstance(a, dict):
        return sum((diffpaths(a[k], b.get(k), p + '/' + k) for k in a), [])
    if isinstance(a, list):
        if len(a) != len(b): return [p]
        return sum((diffpaths(x, y, p + f'[{i}]') for i, (x, y) in enumerate(zip(a, b))), [])
    return [] if a == b else [p]
files = sorted(os.listdir(os.path.join(runs[0], 'decoded')))
for f in files:
    J = [json.load(open(os.path.join(r, 'decoded', f))) for r in runs]
    if all(j == J[0] for j in J): continue
    z = [zero(j) for j in J]; s = [srt(j, None) for j in J]; zs = [srt(zero(j), None) for j in J]
    need = 'zero-timing' if all(x == z[0] for x in z) else 'sort' if all(x == s[0] for x in s) else 'both' if all(x == zs[0] for x in zs) else 'UNRESOLVED'
    paths = set()
    for j in J[1:]:
        for p in diffpaths(zero(J[0]), zero(j)): paths.add(p.split('/changes')[0] if '/changes' in p else p)
    print(f, need, sorted({'/'.join(x for x in p.split('/') if not x.startswith('[')) for p in paths})[:4] if need != 'zero-timing' else '')
