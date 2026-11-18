import json,sys
for fn in sys.argv[1:]:
    print("==", fn)
    for l in open(fn):
        d=json.loads(l)
        print(f"{d['vector']:10} {d['outcome']:7} {str(d.get('detail') or '')[:120]} {str(d.get('got'))[:70] if d['outcome'] in ('ok',) and d.get('got') and len(str(d.get('got')))<70 else ''}")
