"""Split an RFC 5531 record-marked stream into records (stellar-xdr's framed mode ignores record marks)."""
import struct, sys

def frames(path):
    data = open(path, 'rb').read()
    i, out = 0, []
    while i < len(data):
        (hdr,) = struct.unpack('>I', data[i:i + 4]); i += 4
        last, n = hdr >> 31, hdr & 0x7FFFFFFF
        rec = b''
        rec += data[i:i + n]; i += n
        while not last:  # multi-fragment record
            (hdr,) = struct.unpack('>I', data[i:i + 4]); i += 4
            last, n = hdr >> 31, hdr & 0x7FFFFFFF
            rec += data[i:i + n]; i += n
        out.append(rec)
    return out

if __name__ == '__main__':
    for k, r in enumerate(frames(sys.argv[1])):
        print(k, len(r))
