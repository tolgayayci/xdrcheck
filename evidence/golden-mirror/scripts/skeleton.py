"""Throwaway: structural skeleton of ONE transaction's processing record in a LedgerCloseMeta (AG-4 probe).

usage:
  python3 -I skeleton.py <stellar-xdr> <schema.json> <frame.json> [--tx N] [--multiset] [--out file]
      prints {"sections": {...}, "hash": sha256} for transaction N (apply order) of the decoded LCM JSON
  python3 -I skeleton.py diff <a.skel.json> <b.skel.json>
      prints every differing path (not just the first) with both sub-skeletons

Algorithm (exact):
 1. Focus = tx_processing[N] (TransactionResultMetaV1 for LCM v2) plus its envelope from tx_set. The envelope is
    paired by recomputing nothing: the LCM must hold exactly one envelope and one tx_processing entry, or the
    envelope is chosen by result.transaction_hash == sha256 of TransactionSignaturePayload (not needed here;
    refused with an error instead).
 2. Core's normalisation, as stellar-core v30.0.0 src/util/MetaUtils.cpp normalizeMeta / zeroNonDeterministic-
    Diagnostics does it for LCM v2: sort fee_processing, tx_apply_processing.v4.tx_changes_before,
    tx_changes_after and every operations[i].changes by (LedgerKey, rank STATE<CREATED<UPDATED<REMOVED<RESTORED,
    sha256(XDR of the change)); NOT post_tx_apply_fee_processing (core does not sort it); set data to u64 0 on
    diagnostic events whose topics are exactly [sym core_metrics, sym invoke_time_nsecs]. LedgerKey order is
    approximated by the XDR bytes of the key (equal to xdrpp's field-wise operator< for every key containing
    only fixed-size fields and same-length strings/vectors; documented deviation otherwise).
 3. Typed walk driven by the stellar-xdr 30.0.0 JSON schema (`stellar-xdr types schema --type LedgerCloseMeta`):
      struct          -> {field: skel, ...} in declaration (decoder) order; every field name kept
      union (oneOf)   -> {"|": arm_name, "v": skel}; void arm -> {"|": arm_name}
      enum            -> the enum value name (kept)
      bool            -> kept
      optional        -> null, or {"?": skel}
      array           -> {"n": length, "items": [skel, ...]}   (fixed-length opaque arrays are hex leaves)
      leaf            -> "#<TypeName>" where TypeName is the nearest named schema definition, or the JSON type
      string-rendered unions (strkeys) keep their arm: ScAddress/MuxedAccount/SignerKey/PublicKey/AccountId/
        NodeId/ContractId/ClaimableBalanceId/PoolId -> "#<Type>:<strkey version letter>" (G,M,C,P,T,X,B,L)
      ScSymbol values are KEPT (function names, event topic names, map keys are identifiers, not data)
      all other leaves (integers, hashes, keys, signatures, strings, bytes, asset codes) are masked.
    --multiset additionally sorts every LedgerEntryChanges array by the canonical JSON of its element skeletons,
    i.e. compares the changes as a multiset of shapes (immune to key-byte order flips between passphrases).
 4. Canonical JSON (separators , : ; no sort of struct keys, which are already in declaration order), SHA-256 per
    section and over all sections.
"""
import hashlib, json, subprocess, sys

STRKEY_UNIONS = {'ScAddress', 'MuxedAccount', 'SignerKey', 'PublicKey', 'AccountId', 'NodeId', 'ContractId',
                 'ClaimableBalanceId', 'PoolId'}
RANK = {'state': 0, 'created': 1, 'updated': 2, 'removed': 3, 'restored': 4}


def canon(x):
    return json.dumps(x, separators=(',', ':'), ensure_ascii=False)


class Walker:
    def __init__(self, schema):
        self.d = schema['definitions']

    def resolve(self, node, name):
        while '$ref' in node:
            name = node['$ref'].split('/')[-1]
            node = self.d[name]
        return node, name

    def walk(self, node, val, name=None):
        node, name = self.resolve(node, name)
        if 'anyOf' in node:  # optional: [{$ref..}, {type: null}]
            if val is None:
                return None
            inner = [b for b in node['anyOf'] if b.get('type') != 'null'][0]
            return {'?': self.walk(inner, val, name)}
        if 'oneOf' in node:  # union
            if isinstance(val, str):
                for b in node['oneOf']:
                    if b.get('type') == 'string' and 'enum' in b and val in b['enum']:
                        return {'|': val}
                raise ValueError(f'{name}: void arm {val!r} not in schema')
            assert isinstance(val, dict) and len(val) == 1, (name, val)
            arm = next(iter(val))
            for b in node['oneOf']:
                if b.get('type') == 'object' and arm in b.get('properties', {}):
                    return {'|': arm, 'v': self.walk(b['properties'][arm], val[arm], (name or 'union') + '.' + arm)}
            raise ValueError(f'{name}: arm {arm} not in schema')
        t = node.get('type')
        if t == 'string' and 'enum' in node:
            return val  # enum name kept
        if t == 'object':
            props = node.get('properties', {})
            assert isinstance(val, dict), (name, val)
            out = {}
            for k, v in val.items():
                if k not in props:
                    raise ValueError(f'{name}: field {k} not in schema')
                out[k] = self.walk(props[k], v, None)
            return out
        if t == 'array':
            return {'n': len(val), 'items': [self.walk(node['items'], v, None) for v in val]}
        if t == 'boolean':
            return val
        if name in ('ScSymbol',):
            return val
        if name in STRKEY_UNIONS and isinstance(val, str) and val:
            return f'#{name}:{val[0]}'
        return '#' + (name or str(t))


def symbol_keep(w):
    # ScSymbol is a typedef to StringM<32>; resolve() would lose the ScSymbol name, so special-case it.
    orig = w.resolve

    def resolve(node, name):
        while '$ref' in node:
            nm = node['$ref'].split('/')[-1]
            if nm == 'ScSymbol':
                return {'type': 'string', '__symbol': True}, 'ScSymbol'
            name = nm
            node = w.d[nm]
        return node, name
    w.resolve = resolve
    return w


def ledger_key_of(change):
    arm = next(iter(change)); body = change[arm]
    if arm == 'removed':
        return body
    data = body['data']; t = next(iter(data)); e = data[t]
    if t == 'account':
        return {'account': {'account_id': e['account_id']}}
    if t == 'trustline':
        return {'trustline': {'account_id': e['account_id'], 'asset': e['asset']}}
    if t == 'offer':
        return {'offer': {'seller_id': e['seller_id'], 'offer_id': e['offer_id']}}
    if t == 'data':
        return {'data': {'account_id': e['account_id'], 'data_name': e['data_name']}}
    if t == 'claimable_balance':
        return {'claimable_balance': {'balance_id': e['balance_id']}}
    if t == 'liquidity_pool':
        return {'liquidity_pool': {'liquidity_pool_id': e['liquidity_pool_id']}}
    if t == 'contract_data':
        return {'contract_data': {'contract': e['contract'], 'key': e['key'], 'durability': e['durability']}}
    if t == 'contract_code':
        return {'contract_code': {'hash': e['hash']}}
    if t == 'config_setting':
        return {'config_setting': {'config_setting_id': next(iter(e)) if isinstance(e, dict) else e}}
    if t == 'ttl':
        return {'ttl': {'key_hash': e['key_hash']}}
    raise ValueError(t)


def enc(X, typ, val):
    return subprocess.run([X, 'encode', '--type', typ, '--input', 'json', '--output', 'single'],
                          input=canon(val).encode(), capture_output=True, check=True).stdout


def core_sort(X, changes):
    def key(c):
        return (enc(X, 'LedgerKey', ledger_key_of(c)), RANK[next(iter(c))],
                hashlib.sha256(enc(X, 'LedgerEntryChange', c)).digest())
    return sorted(changes, key=key)


def zero_timing(diag):
    for de in diag:
        b = de['event']['body']['v0']
        if de['event']['type'] == 'diagnostic' and [t.get('symbol') if isinstance(t, dict) else None for t in b['topics']] == ['core_metrics', 'invoke_time_nsecs']:
            b['data'] = {'u64': '0'}


def envelopes(v):
    ts = v['tx_set']
    if 'txs' in ts:
        return ts['txs']
    t = ts[next(iter(ts))]; out = []
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


def multiset(sk):
    """sort every LedgerEntryChanges-shaped array ({n, items} of {'|': state/created/...}) by element skeleton"""
    if isinstance(sk, dict):
        if set(sk) == {'n', 'items'}:
            items = [multiset(i) for i in sk['items']]
            if items and all(isinstance(i, dict) and i.get('|') in RANK for i in items):
                items = sorted(items, key=canon)
            return {'n': sk['n'], 'items': items}
        return {k: multiset(v) for k, v in sk.items()}
    if isinstance(sk, list):
        return [multiset(i) for i in sk]
    return sk


def skeleton(X, schema, frame, txi, ms):
    j = json.load(open(frame)); arm = next(iter(j)); v = j[arm]
    tps = v['tx_processing']; envs = envelopes(v)
    if len(envs) != 1 or len(tps) != 1:
        raise SystemExit(f'{frame}: {len(envs)} envelopes / {len(tps)} results; pairing by hash not implemented')
    tp = json.loads(canon(tps[txi])); env = envs[0]
    m = tp['tx_apply_processing']; mv = next(iter(m)); mm = m[mv]
    tp['fee_processing'] = core_sort(X, tp['fee_processing'])
    mm['tx_changes_before'] = core_sort(X, mm['tx_changes_before'])
    mm['tx_changes_after'] = core_sort(X, mm['tx_changes_after'])
    for op in mm['operations']:
        op['changes'] = core_sort(X, op['changes'])
    if mv == 'v4':
        zero_timing(mm.get('diagnostic_events', []))
    w = symbol_keep(Walker(schema))
    D = w.d
    tmeta = D['TransactionMeta']
    # walk sub-trees with their own types, so each section has its own hash
    sec = {}
    sec['envelope'] = w.walk({'$ref': '#/definitions/TransactionEnvelope'}, env)
    sec['result'] = w.walk({'$ref': '#/definitions/TransactionResultPair'}, tp['result'])
    sec['fee_processing'] = w.walk({'$ref': '#/definitions/LedgerEntryChanges'}, tp['fee_processing'])
    full_meta = w.walk({'$ref': '#/definitions/TransactionMeta'}, m)
    inner = full_meta['v']
    sec['meta.arm'] = {'|': full_meta['|'], 'fields': list(inner.keys())}
    for k, val in inner.items():
        sec['meta.' + k] = val
    if 'post_tx_apply_fee_processing' in tp:
        sec['post_tx_apply_fee_processing'] = w.walk({'$ref': '#/definitions/LedgerEntryChanges'}, tp['post_tx_apply_fee_processing'])
    if 'ext' in tp:
        sec['tx_result_meta.ext'] = w.walk({'$ref': '#/definitions/ExtensionPoint'}, tp['ext'])
    if ms:
        sec = {k: multiset(s) for k, s in sec.items()}
    hashes = {k: hashlib.sha256(canon(s).encode()).hexdigest() for k, s in sec.items()}
    return {'frame': frame, 'tx': txi, 'tx_hash': tp['result']['transaction_hash'], 'multiset': ms,
            'section_hashes': hashes, 'hash': hashlib.sha256(canon(sec).encode()).hexdigest(), 'sections': sec}


def diff(a, b, path, out):
    if type(a) != type(b):
        out.append((path, a, b)); return
    if isinstance(a, dict):
        if set(a) == {'n', 'items'} and set(b) == {'n', 'items'}:
            if a['n'] != b['n']:
                out.append((path + '.len', a['n'], b['n']))
            for i in range(min(len(a['items']), len(b['items']))):
                diff(a['items'][i], b['items'][i], f'{path}[{i}]', out)
            for i in range(min(len(a['items']), len(b['items'])), max(len(a['items']), len(b['items']))):
                out.append((f'{path}[{i}]', a['items'][i] if i < len(a['items']) else '<absent>', b['items'][i] if i < len(b['items']) else '<absent>'))
            return
        if '|' in a and '|' in b and a['|'] != b['|']:
            out.append((path + '|', a, b)); return
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a or k not in b:
                out.append((f'{path}.{k}', a.get(k, '<absent>'), b.get(k, '<absent>')))
            else:
                diff(a[k], b[k], f'{path}.{k}' if k not in ('|', 'v') else (path if k == 'v' else path), out)
        return
    if a != b:
        out.append((path, a, b))


def short(x, n=300):
    s = canon(x)
    return s if len(s) <= n else s[:n] + '…'


if __name__ == '__main__':
    if sys.argv[1] == 'diff':
        A = json.load(open(sys.argv[2])); B = json.load(open(sys.argv[3]))
        out = []
        for k in list(A['sections']) + [k for k in B['sections'] if k not in A['sections']]:
            if k not in A['sections'] or k not in B['sections']:
                out.append((k, A['sections'].get(k, '<absent>'), B['sections'].get(k, '<absent>'))); continue
            diff(A['sections'][k], B['sections'][k], k, out)
        same = [k for k in A['section_hashes'] if A['section_hashes'].get(k) == B['section_hashes'].get(k)]
        print('A', A['frame'], 'tx', A['tx_hash'][:16], A['hash']); print('B', B['frame'], 'tx', B['tx_hash'][:16], B['hash'])
        print('identical sections:', ', '.join(same))
        print('differences:', len(out))
        for p, a, b in out:
            print(f'- {p}\n    A: {short(a)}\n    B: {short(b)}')
        sys.exit(0 if not out else 1)
    X, schema, frame = sys.argv[1:4]
    txi = int(sys.argv[sys.argv.index('--tx') + 1]) if '--tx' in sys.argv else 0
    ms = '--multiset' in sys.argv
    r = skeleton(X, json.load(open(schema)), frame, txi, ms)
    s = json.dumps(r, indent=1, ensure_ascii=False)
    if '--out' in sys.argv:
        open(sys.argv[sys.argv.index('--out') + 1], 'w').write(s)
    print(r['hash'], r['tx_hash'], json.dumps(r['section_hashes'])[:0])
