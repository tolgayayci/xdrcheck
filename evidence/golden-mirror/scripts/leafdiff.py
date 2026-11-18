"""value-level (leaf) diff of the focus tx between two decoded LCM JSON frames (one tx each).
usage: python3 -I leafdiff.py <a frame.json> <b frame.json>   — prints path: a -> b for every differing leaf (diag events excluded)"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from skeleton import envelopes
def load(f):
    j = json.load(open(f)); v = j[next(iter(j))]; tp = v['tx_processing'][0]
    m = tp['tx_apply_processing']; mm = m[next(iter(m))]; mm.pop('diagnostic_events', None)
    return {'envelope': envelopes(v)[0], 'tp': tp}
def walk(a, b, p, out):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in a.keys() | b.keys(): walk(a.get(k), b.get(k), p + '.' + k, out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)): walk(x, y, f'{p}[{i}]', out)
    elif a != b: out.append((p, a, b))
out = []; walk(load(sys.argv[1]), load(sys.argv[2]), '', out)
for p, a, b in sorted(out): print(f'{p}: {json.dumps(a)[:70]} -> {json.dumps(b)[:70]}')
print(len(out), 'differing leaves')
