"""dump the rows that matter for #731 from one run DB, addresses rendered as strkeys (decoded here, not by
wallet-backend). usage: python3 -I observe.py <db> [minLedger]   (psql via docker exec xcc-g5-pg)"""
import base64, binascii, csv, io, subprocess, sys
DB = sys.argv[1]; LO = int(sys.argv[2]) if len(sys.argv) > 2 else 13
def crc16(b):
    c = 0
    for x in b:
        c ^= x << 8
        for _ in range(8): c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c
def sk(h):
    if not h: return h
    b = binascii.unhexlify(h[2:] if h.startswith('\\x') else h)
    if len(b) == 33 and b[0] in (0x30, 0x10):   # AddressBytea: version byte + 32-byte key
        p = b; return base64.b32encode(p + crc16(p).to_bytes(2, 'little')).decode().rstrip('=') 
    return '0x' + b.hex() + f'({len(b)}B)'
def Q(sql):
    out = subprocess.run(['docker', 'exec', '-i', 'xcc-g5-pg', 'psql', '-U', 'postgres', '-h', '127.0.0.1', '-qAt', '-d', DB, '-c',
                          f'COPY ({sql}) TO STDOUT WITH CSV HEADER'], capture_output=True, text=True)
    if out.returncode: print('  QUERY ERROR', out.stderr.strip()); return []
    return list(csv.DictReader(io.StringIO(out.stdout)))
def show(title, rows, addr=()):
    print(f'-- {title} ({len(rows)})')
    for r in rows:
        print('  ' + ' | '.join(f'{k}={sk(v) if k in addr else v}' for k, v in r.items() if v not in ('', None)))
print('-- ingest_store'); [print('  ', r['key'], r['value']) for r in Q('SELECT key,value FROM ingest_store ORDER BY key')]
show('row counts per ledger (tx, ops, state_changes)', Q(f"""SELECT l, (SELECT count(*) FROM transactions WHERE ledger_number=l) tx,
  (SELECT count(*) FROM operations WHERE ledger_number=l) ops, (SELECT count(*) FROM state_changes WHERE ledger_number=l) sc
  FROM generate_series({LO},24) l"""))
show(f'transactions ledger>={LO}', Q(f"SELECT ledger_number, to_id, encode(hash,'hex') hash, result_code, fee_charged FROM transactions WHERE ledger_number>={LO} ORDER BY to_id"))
show(f'operations ledger>={LO}', Q(f"SELECT ledger_number, id, operation_type, result_code, successful FROM operations WHERE ledger_number>={LO} ORDER BY id"))
show(f'state_changes ledger>={LO}', Q(f"""SELECT ledger_number, to_id, operation_id, state_change_id, state_change_category cat, state_change_reason reason,
  encode(account_id,'hex') account, encode(token_id,'hex') token, amount, trustline_limit_old, trustline_limit_new, flags,
  encode(signer_account_id,'hex') signer, encode(destination_account_id,'hex') dest, encode(creator_account_id,'hex') creator,
  encode(spender_account_id,'hex') spender, liquidity_pool_id, threshold, key_value, to_muxed_id
  FROM state_changes WHERE ledger_number>={LO} ORDER BY to_id, operation_id, state_change_id"""), addr=('account', 'token', 'signer', 'dest', 'creator', 'spender'))
show(f'transactions_accounts ledger>={LO}', Q(f"""SELECT t.ledger_number, encode(t.hash,'hex') hash, encode(ta.account_id,'hex') account FROM transactions_accounts ta
  JOIN transactions t ON t.to_id=ta.tx_to_id WHERE t.ledger_number>={LO} ORDER BY t.to_id, 3"""), addr=('account',))
show(f'operations_accounts ledger>={LO}', Q(f"""SELECT o.ledger_number, o.id, encode(oa.account_id,'hex') account FROM operations_accounts oa
  JOIN operations o ON o.id=oa.operation_id WHERE o.ledger_number>={LO} ORDER BY o.id, 3"""), addr=('account',))
show('trustline_balances (current state)', Q("""SELECT encode(tb.account_id,'hex') account, ta.code, ta.issuer, tb.balance, tb.trust_limit, tb.flags,
  tb.buying_liabilities, tb.selling_liabilities, tb.last_modified_ledger FROM trustline_balances tb JOIN trustline_assets ta ON ta.id=tb.asset_id ORDER BY 2,1"""), addr=('account',))
show('trustline_assets', Q("SELECT code, issuer FROM trustline_assets ORDER BY 1,2"))
show('contract_tokens', Q("SELECT contract_id, type, code, issuer, name, symbol, decimals FROM contract_tokens ORDER BY 1"))
show('sac_balances', Q("SELECT encode(account_id,'hex') account, contract_id, balance, is_authorized, is_clawback_enabled, last_modified_ledger FROM sac_balances ORDER BY 1"), addr=('account',))
show(f'native_balances modified ledger>={LO}', Q(f"SELECT encode(account_id,'hex') account, balance, num_subentries, last_modified_ledger FROM native_balances WHERE last_modified_ledger>={LO} ORDER BY 1"), addr=('account',))
