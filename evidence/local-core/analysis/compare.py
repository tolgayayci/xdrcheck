"""Compare analysis.json across runs of one network, and between networks (run-1 each).
usage: python3 -I compare.py <out dir>"""
import json, sys, os, glob, difflib
OUT = sys.argv[1]
FIELDS = ['raw_sha256', 'norm_sha256', 'header_hash', 'tx_set_hash', 'bucket_list_hash', 'raw_len']
res = {}
for net in ('testnet', 'mainnet'):
    runs = sorted(glob.glob(os.path.join(OUT, net, 'run-*')))
    A = [json.load(open(os.path.join(r, 'analysis.json')))['ledgers'] for r in runs]
    rows = []
    for i in range(len(A[0])):
        row = {'ledger': A[0][i]['ledger']}
        for f in FIELDS:
            row[f] = len({a[i][f] for a in A})
        row['tx_hashes'] = len({tuple(t['hash'] for t in a[i]['txs']) for a in A})
        row['results'] = len({tuple((t['result'], t['fee_charged']) for t in a[i]['txs']) for a in A})
        rows.append(row)
    res[net] = {'runs': [os.path.basename(r) for r in runs], 'rows': rows}
    print(f'== {net}: distinct values per ledger across {len(runs)} runs (1 = stable)')
    print('ledger ' + ' '.join(f[:11].ljust(11) for f in FIELDS + ['tx_hashes', 'results']))
    for r in rows:
        print(str(r['ledger']).ljust(7) + ' '.join(str(r[f]).ljust(11) for f in FIELDS + ['tx_hashes', 'results']))
# twin comparison
T = json.load(open(os.path.join(OUT, 'testnet', 'run-1', 'analysis.json')))['ledgers']
M = json.load(open(os.path.join(OUT, 'mainnet', 'run-1', 'analysis.json')))['ledgers']
print('== twins (testnet run-1 vs mainnet run-1)')
for t, m in zip(T, M):
    same = [f for f in ['raw_len', 'header_hash', 'tx_set_hash', 'bucket_list_hash', 'norm_sha256'] if t[f] == m[f]]
    rs = [x['result'] for x in t['txs']] == [x['result'] for x in m['txs']]
    fees = [x['fee_charged'] for x in t['txs']] == [x['fee_charged'] for x in m['txs']]
    print(t['ledger'], 'equal:', same, 'results_equal:', rs, 'fees_equal:', fees, 'lens', t['raw_len'], m['raw_len'])
json.dump(res, open(os.path.join(OUT, 'compare.json'), 'w'), indent=1)
