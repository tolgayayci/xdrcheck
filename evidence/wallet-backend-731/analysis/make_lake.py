"""write a chain's per-ledger LCMs as a SEP-54 (Galexie) layout, same schema as the public testnet lake.
usage: python3 -I make_lake.py <run dir> <out dir> <passphrase>
key = %08X--%d-%d/ (partition, 64000 files) + %08X--%d.xdr.zst  (go-stellar-sdk v0.7.3 support/datastore/schema.go L34-63)
object = zstd(XDR LedgerCloseMetaBatch{startSequence=S, endSequence=S, ledgerCloseMetas=[lcm]})"""
import glob, json, os, struct, subprocess, sys
RUN, OUT, PP = sys.argv[1:4]
LPF, FPP = 1, 64000
os.makedirs(OUT, exist_ok=True)
cfg = {"networkPassphrase": PP, "version": "1.0", "compression": "zstd", "ledgersPerBatch": LPF, "batchesPerPartition": FPP}
open(OUT + '/.config.json', 'w').write(json.dumps(cfg, separators=(',', ':')))
M = 0xFFFFFFFF
for p in sorted(glob.glob(RUN + '/ledgers/*.xdr'), key=lambda x: int(os.path.basename(x)[:-4])):
    seq = int(os.path.basename(p)[:-4]); lcm = open(p, 'rb').read()
    ps = (seq // (LPF * FPP)) * (LPF * FPP); pe = ps + LPF * FPP - 1
    key = '%08X--%d-%d/%08X--%d.xdr.zst' % (M - ps, ps, pe, M - seq, seq)
    os.makedirs(os.path.dirname(OUT + '/' + key), exist_ok=True)
    batch = struct.pack('>III', seq, seq, 1) + lcm
    z = subprocess.run(['zstd', '-q', '-19', '-c'], input=batch, capture_output=True, check=True).stdout
    open(OUT + '/' + key, 'wb').write(z)
    print(seq, key, len(z))
