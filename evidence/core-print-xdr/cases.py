"""Throwaway: malformed-input transcripts for stellar-core v30.0.0 `print-xdr` (offline decoder column).

usage: python3 -I cases.py <stellar-core> [--depth]
  writes in/<case>.bin, out/<case>.txt (command, input hex, stdout, stderr, exit code) and out/summary.tsv;
  --depth also runs the nested-SCV_VEC depth bisection and writes out/depth.txt
The binary needs LD_LIBRARY_PATH to its libc++ (see README).
"""
import os, struct, subprocess, sys

CORE = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(f'{HERE}/in', exist_ok=True); os.makedirs(f'{HERE}/out', exist_ok=True)
u32 = lambda n: struct.pack('>I', n)
i64 = lambda n: struct.pack('>q', n)
pad = lambda b, fill=b'\0': b + fill * ((4 - len(b) % 4) % 4)

def xstr(b, padbytes=None):
    return u32(len(b)) + (b + padbytes if padbytes is not None else pad(b))

SCV = dict(BOOL=0, VOID=1, ERROR=2, U32=3, BYTES=13, STRING=14, SYMBOL=15, VEC=16, MAP=17, ADDRESS=18)

def vec_nest(d):
    """d nested SCV_VEC (each Some, length 1) around SCV_VOID; d=0 is a bare SCV_VOID"""
    return (u32(SCV['VEC']) + u32(1) + u32(1)) * d + u32(SCV['VOID'])

def ledger_entry_account(nsigners):
    """LedgerEntry{ACCOUNT} with nsigners ed25519 signers (declared max: signers<MAX_SIGNERS = 20>)"""
    acct = (u32(0) + b'\x11' * 32 + i64(100) + i64(1) + u32(nsigners) + u32(0) + u32(0) + xstr(b'') +
            b'\x01\x00\x00\x00' + u32(nsigners) +
            b''.join(u32(0) + bytes([i + 1]) * 32 + u32(1) for i in range(nsigners)) + u32(0))
    return u32(7) + u32(0) + acct + u32(0)

def ledger_entry_contract_data(durability):
    cde = u32(0) + u32(1) + b'\x22' * 32 + u32(SCV['VOID']) + u32(durability) + u32(SCV['VOID'])
    return u32(7) + u32(6) + cde + u32(0)

def map_nest(d):
    """d nested SCV_MAP (each Some, one entry key SCV_VOID) around SCV_VOID"""
    return (u32(SCV['MAP']) + u32(1) + u32(1) + u32(SCV['VOID'])) * d + u32(SCV['VOID'])

CASES = [  # (name, filetype, bytes, what it tests)
    ('bool-1', 'scval', u32(0) + u32(1), 'control: SCV_BOOL true'),
    ('bool-2', 'scval', u32(0) + u32(2), 'SCV_BOOL with bool encoded as 2'),
    ('bool-ffffffff', 'scval', u32(0) + u32(0xFFFFFFFF), 'SCV_BOOL with bool encoded as 0xFFFFFFFF'),
    ('optional-flag-2', 'scval', u32(SCV['VEC']) + u32(2) + u32(0), 'SCV_VEC whose optional (SCVec*) flag is 2, then empty vec'),
    ('optional-flag-0', 'scval', u32(SCV['VEC']) + u32(0), 'control: SCV_VEC with absent vec (flag 0)'),
    ('string-pad-nonzero', 'scval', u32(SCV['STRING']) + xstr(b'a', b'\x01\x02\x03'), 'SCV_STRING "a" with padding 01 02 03'),
    ('bytes-pad-nonzero', 'scval', u32(SCV['BYTES']) + xstr(b'\xaa', b'\x00\x00\x01'), 'SCV_BYTES aa with padding 00 00 01'),
    ('symbol-pad-nonzero', 'scval', u32(SCV['SYMBOL']) + xstr(b'ab', b'\xff\xff'), 'SCV_SYMBOL "ab" with padding ff ff'),
    ('trailing-4', 'scval', u32(SCV['VOID']) + u32(0), 'SCV_VOID followed by 4 extra zero bytes'),
    ('trailing-1', 'scval', u32(SCV['VOID']) + b'\x00', 'SCV_VOID followed by 1 extra byte'),
    ('truncated', 'scval', u32(SCV['U32']) + b'\x00\x00', 'SCV_U32 with only 2 of 4 value bytes'),
    ('enum-undeclared-scerrorcode', 'scval', u32(SCV['ERROR']) + u32(9) + u32(10), 'SCV_ERROR{SCE_AUTH, code 10}: ScErrorCode has 0..9'),
    ('enum-undeclared-scerrortype', 'scval', u32(SCV['ERROR']) + u32(10) + u32(0), 'SCV_ERROR with SCErrorType 10 (declared 0..9)'),
    ('scv-executable-tag-22', 'scval', u32(22) + xstr(b''), 'SCVal discriminant 22 = SCV_EXECUTABLE_TAG (declared in XDR 4f524bba), empty SCString'),
    ('union-undeclared-scvaltype', 'scval', u32(23) + u32(0), 'SCVal discriminant 23 (declared 0..22), 4 bytes after'),
    ('union-undeclared-scvaltype-bare', 'scval', u32(23), 'SCVal discriminant 23, nothing after'),
    ('enum-undeclared-durability', 'ledgerentry', ledger_entry_contract_data(2), 'ContractDataEntry.durability = 2 (enum ContractDataDurability declares 0..1; a struct field, not a discriminant)'),
    ('enum-durability-1', 'ledgerentry', ledger_entry_contract_data(1), 'control: ContractDataEntry.durability = 1 (PERSISTENT)'),
    ('union-undeclared-scaddresstype', 'scval', u32(SCV['ADDRESS']) + u32(9) + b'\0' * 32, 'SCV_ADDRESS with SCAddressType 9 (declared 0..5)'),
    ('symbol-33', 'scval', u32(SCV['SYMBOL']) + xstr(b'a' * 33), 'SCV_SYMBOL of 33 bytes (declared SCSymbol<32>)'),
    ('symbol-32', 'scval', u32(SCV['SYMBOL']) + xstr(b'a' * 32), 'control: SCV_SYMBOL of 32 bytes'),
    ('symbol-bad-charset', 'scval', u32(SCV['SYMBOL']) + xstr(b'a b!'), 'SCV_SYMBOL "a b!" (outside the [a-zA-Z0-9_] host charset)'),
    ('signers-21', 'ledgerentry', ledger_entry_account(21), 'AccountEntry.signers of 21 (declared signers<MAX_SIGNERS=20>)'),
    ('signers-20', 'ledgerentry', ledger_entry_account(20), 'control: AccountEntry.signers of 20'),
    ('string-non-utf8', 'scval', u32(SCV['STRING']) + xstr(b'\xff\xfe\x00A'), 'SCV_STRING bytes ff fe 00 41 (invalid UTF-8, NUL)'),
    ('string-cesu-surrogate', 'scval', u32(SCV['STRING']) + xstr(b'\xed\xa0\x80'), 'SCV_STRING bytes ed a0 80 (encoded lone surrogate)'),
    ('symbol-non-utf8', 'scval', u32(SCV['SYMBOL']) + xstr(b'\xff'), 'SCV_SYMBOL byte ff'),
    ('vec-depth-1', 'scval', vec_nest(1), 'control: one SCV_VEC around SCV_VOID'),
    ('auto-bool-2', 'auto', u32(0) + u32(2), 'auto filetype on the bool-2 bytes: which type wins?'),
]


def run(name, ftype, data, note, quiet=False):
    p = f'{HERE}/in/{name}.bin'
    open(p, 'wb').write(data)
    cmd = [CORE, 'print-xdr', '--filetype', ftype, p] if ftype != 'auto' else [CORE, 'print-xdr', p]
    r = subprocess.run(cmd, capture_output=True)
    out, err = r.stdout.decode('utf-8', 'backslashreplace'), r.stderr.decode('utf-8', 'backslashreplace')
    if not quiet:
        with open(f'{HERE}/out/{name}.txt', 'w') as f:
            f.write(f'# {note}\n$ {" ".join(os.path.relpath(c, HERE) if c.startswith("/") else c for c in cmd)}\n')
            f.write(f'input hex ({len(data)} B): {data.hex()}\n--- stdout ---\n{out}--- stderr ---\n{err}--- exit code: {r.returncode}\n')
    return r.returncode, out, err


def verdict(out, err):
    if 'Could not decode' in err or 'Could not decode' in out:
        return 'REJECTED'
    return 'ACCEPTED' if out.strip().startswith('{') or '{' in out else 'NO-OUTPUT'


if __name__ == '__main__':
    rows = []
    for name, ft, data, note in CASES:
        rc, out, err = run(name, ft, data, note)
        errline = [l for l in err.splitlines() if 'Could not decode' in l]
        body = ' '.join(l.strip() for l in out.splitlines() if 'Warning: running non-release' not in l)
        rows.append((name, ft, verdict(out, err), str(rc), (errline[0] if errline else body)[:200], note))
    with open(f'{HERE}/out/summary.tsv', 'w') as f:
        f.write('case\tfiletype\tverdict\texit\tstdout-or-error\tnote\n')
        for r in rows:
            f.write('\t'.join(r) + '\n')
    for r in rows:
        print(' | '.join(r[:5]))
    def bisect(gen, label):
        lo, hi = 1, 1
        while verdict(*run('d', 'scval', gen(hi), '', quiet=True)[1:]) == 'ACCEPTED':
            lo, hi = hi, hi * 2
            if hi > 1 << 20:
                break
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if verdict(*run('d', 'scval', gen(mid), '', quiet=True)[1:]) == 'ACCEPTED':
                lo = mid
            else:
                hi = mid
        os.remove(f'{HERE}/in/d.bin')
        for d in (lo, hi):
            run(f'{label}-depth-{d}', 'scval', gen(d), f'{d} nested {label.upper()} around SCV_VOID (bisection boundary)')
        return lo, hi
    if '--depth' in sys.argv:
        with open(f'{HERE}/out/depth.txt', 'w') as f:
            for gen, label in ((vec_nest, 'vec'), (map_nest, 'map')):
                lo, hi = bisect(gen, label)
                f.write(f'nested SCV_{label.upper()}: largest accepted {lo}, first rejected {hi}\n')
                print(label, 'depth: largest accepted', lo, 'first rejected', hi)
