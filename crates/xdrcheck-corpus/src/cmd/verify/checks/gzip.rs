//! gzip (RFC 1952) decoding with a small DEFLATE (RFC 1951) inflater, for the vendored
//! history-archive buckets (`bucket-<hash>.xdr.gz`). The workspace pins no DEFLATE library, and
//! the check needs only correctness, not speed: codes are decoded one bit at a time from canonical
//! code counts. Every member's CRC-32 and size trailer is checked, and the caller compares the
//! output's sha256 with the bucket hash.

/// Decompress every member of a gzip file. Fails on a malformed stream, a trailer that does not
/// match, or more than `max` output bytes.
pub fn gunzip(data: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        pos = member(data, pos, &mut out, max)?;
    }
    if out.is_empty() && data.is_empty() {
        return Err("empty gzip file".into());
    }
    Ok(out)
}

/// One gzip member starting at `start`; returns the offset after it.
fn member(data: &[u8], start: usize, out: &mut Vec<u8>, max: usize) -> Result<usize, String> {
    let d = &data[start..];
    let at = |what: &str| format!("gzip member at byte {start}: {what}");
    if d.len() < 18 {
        return Err(at("truncated"));
    }
    if d[..2] != [0x1f, 0x8b] {
        return Err(at("bad magic (not gzip)"));
    }
    if d[2] != 8 {
        return Err(at("compression method is not deflate"));
    }
    let flags = d[3];
    if flags & 0xe0 != 0 {
        return Err(at("reserved flag bits are set"));
    }
    let mut p = 10;
    if flags & 0x04 != 0 {
        // FEXTRA
        let xlen = u16::from_le_bytes([d[p], d[p + 1]]) as usize;
        p += 2 + xlen;
    }
    for flag in [0x08, 0x10] {
        // FNAME, FCOMMENT: zero-terminated
        if flags & flag != 0 {
            let end = d
                .get(p..)
                .and_then(|r| r.iter().position(|b| *b == 0))
                .ok_or_else(|| at("unterminated header string"))?;
            p += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        p += 2; // FHCRC
    }
    if p > d.len() {
        return Err(at("truncated header"));
    }
    let begin = out.len();
    let mut bits = Bits {
        data: d,
        pos: p,
        buf: 0,
        n: 0,
    };
    inflate(&mut bits, out, max).map_err(|e| at(&e))?;
    // The bits left over after the last block (fewer than 8) are padding of the last byte read.
    let q = bits.pos;
    let trailer = d.get(q..q + 8).ok_or_else(|| at("truncated trailer"))?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let got = crc32(&out[begin..]);
    if got != crc {
        return Err(at(&format!(
            "CRC-32 of the output is {got:08x}, trailer says {crc:08x}"
        )));
    }
    if (out.len() - begin) as u32 != size {
        return Err(at(&format!(
            "output is {} bytes, trailer says {size} (mod 2^32)",
            out.len() - begin
        )));
    }
    Ok(start + q + 8)
}

/// Bit reader, least significant bit first (RFC 1951 §3.1.1).
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    n: u32,
}

impl Bits<'_> {
    fn take(&mut self, n: u32) -> Result<u32, String> {
        while self.n < n {
            let b = *self.data.get(self.pos).ok_or("truncated deflate stream")?;
            self.pos += 1;
            self.buf |= u64::from(b) << self.n;
            self.n += 8;
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.n -= n;
        Ok(v)
    }

    /// Skip to the next byte boundary (fewer than 8 bits are ever buffered between reads).
    fn align(&mut self) {
        self.buf = 0;
        self.n = 0;
    }
}

/// A canonical Huffman code: the number of codes of each length and the symbols in code order.
struct Huffman {
    count: [u16; 16],
    symbol: Vec<u16>,
}

fn huffman(lengths: &[u8]) -> Result<Huffman, String> {
    let mut count = [0u16; 16];
    for &l in lengths {
        count[l as usize] += 1;
    }
    let mut left: i32 = 1;
    for c in &count[1..] {
        left = (left << 1) - i32::from(*c);
        if left < 0 {
            return Err("over-subscribed Huffman code".into());
        }
    }
    let mut offs = [0u16; 16];
    for len in 1..15 {
        offs[len + 1] = offs[len] + count[len];
    }
    let mut symbol = vec![0u16; lengths.len()];
    for (s, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbol[offs[l as usize] as usize] = s as u16;
            offs[l as usize] += 1;
        }
    }
    count[0] = 0;
    Ok(Huffman { count, symbol })
}

fn decode(bits: &mut Bits<'_>, h: &Huffman) -> Result<u16, String> {
    let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
    for len in 1..16 {
        code |= bits.take(1)? as i32;
        let count = i32::from(h.count[len]);
        if code - count < first {
            return Ok(h.symbol[(index + code - first) as usize]);
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    Err("invalid Huffman code".into())
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order of the code-length code lengths in a dynamic block header.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn inflate(bits: &mut Bits<'_>, out: &mut Vec<u8>, max: usize) -> Result<(), String> {
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => stored(bits, out)?,
            1 => {
                let mut l = [0u8; 288];
                l[..144].fill(8);
                l[144..256].fill(9);
                l[256..280].fill(7);
                l[280..].fill(8);
                codes(bits, out, &huffman(&l)?, &huffman(&[5u8; 30])?, max)?
            }
            2 => {
                let (lit, dist) = dynamic(bits)?;
                codes(bits, out, &lit, &dist, max)?
            }
            _ => return Err("invalid block type 3".into()),
        }
        if out.len() > max {
            return Err(format!("output exceeds {max} bytes"));
        }
        if last {
            return Ok(());
        }
    }
}

fn stored(bits: &mut Bits<'_>, out: &mut Vec<u8>) -> Result<(), String> {
    bits.align();
    let d = bits.data;
    let p = bits.pos;
    let hdr = d.get(p..p + 4).ok_or("truncated stored block")?;
    let len = u16::from_le_bytes([hdr[0], hdr[1]]);
    let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
    if len != !nlen {
        return Err("stored block length does not match its complement".into());
    }
    let body = d
        .get(p + 4..p + 4 + len as usize)
        .ok_or("truncated stored block")?;
    out.extend_from_slice(body);
    bits.pos = p + 4 + len as usize;
    Ok(())
}

fn dynamic(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), String> {
    let nlen = bits.take(5)? as usize + 257;
    let ndist = bits.take(5)? as usize + 1;
    let ncode = bits.take(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err("bad dynamic block counts".into());
    }
    let mut lengths = [0u8; 316];
    for &i in &CL_ORDER[..ncode] {
        lengths[i] = bits.take(3)? as u8;
    }
    let cl = huffman(&lengths[..19])?;
    let mut i = 0;
    while i < nlen + ndist {
        let sym = decode(bits, &cl)?;
        if sym < 16 {
            lengths[i] = sym as u8;
            i += 1;
            continue;
        }
        let (value, repeat) = match sym {
            16 if i > 0 => (lengths[i - 1], 3 + bits.take(2)? as usize),
            16 => return Err("repeat with no previous length".into()),
            17 => (0, 3 + bits.take(3)? as usize),
            _ => (0, 11 + bits.take(7)? as usize),
        };
        if i + repeat > nlen + ndist {
            return Err("code lengths overrun".into());
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err("no end-of-block code".into());
    }
    Ok((
        huffman(&lengths[..nlen])?,
        huffman(&lengths[nlen..nlen + ndist])?,
    ))
}

fn codes(
    bits: &mut Bits<'_>,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
    max: usize,
) -> Result<(), String> {
    loop {
        let sym = decode(bits, lit)? as usize;
        if sym < 256 {
            out.push(sym as u8);
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let s = sym - 257;
        if s >= LEN_BASE.len() {
            return Err(format!("invalid length symbol {sym}"));
        }
        let len = LEN_BASE[s] as usize + bits.take(u32::from(LEN_EXTRA[s]))? as usize;
        let d = decode(bits, dist)? as usize;
        if d >= DIST_BASE.len() {
            return Err(format!("invalid distance symbol {d}"));
        }
        let back = DIST_BASE[d] as usize + bits.take(u32::from(DIST_EXTRA[d]))? as usize;
        if back > out.len() {
            return Err("distance reaches before the start of the output".into());
        }
        if out.len() + len > max {
            return Err(format!("output exceeds {max} bytes"));
        }
        let from = out.len() - back;
        for k in 0..len {
            out.push(out[from + k]);
        }
    }
}

/// CRC-32 (ISO-HDLC, reflected polynomial 0xEDB88320), as the gzip trailer uses.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (n, t) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut c = !0u32;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // Written by Python's `gzip.compress(data, compresslevel, mtime=0)` (zlib): a stored block
    // (level 0), a fixed-Huffman block and a dynamic-Huffman block.
    const STORED: &str = "1f8b08000000000004ff010c00f3ff73746f72656420626c6f636b94a3243d0c000000";
    const FIXED: &str = "1f8b08000000000002ffcb48cdc9c957c8402701e3513d8d17000000";
    const DYNAMIC: &str = "1f8b08000000000002ffd58a310100300cc2b442a1c5bf82616339721090d80609e0c8294965a98b775b67f78a54e1f3ff0327b80283f0000000";

    /// The input of `DYNAMIC`: 120 runs of one of `a`…`h`, each 1–3 long.
    fn dynamic_input() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..120usize {
            let c = b"abcdefgh"[(i * i * 7 + i / 3) % 8];
            v.extend(std::iter::repeat_n(c, 1 + i % 3));
        }
        v
    }

    #[test]
    fn inflates_each_block_type() {
        assert_eq!(gunzip(&unhex(STORED), 1 << 20).unwrap(), b"stored block");
        assert_eq!(
            gunzip(&unhex(FIXED), 1 << 20).unwrap(),
            b"hello hello hello hello"
        );
        let mut z = unhex(DYNAMIC);
        assert_eq!((z[10] >> 1) & 3, 2, "the vector's first block is dynamic");
        assert_eq!(gunzip(&z, 1 << 20).unwrap(), dynamic_input());
        // Two members concatenated decode to both outputs.
        let mut two = unhex(STORED);
        two.extend(unhex(FIXED));
        assert_eq!(
            gunzip(&two, 1 << 20).unwrap(),
            b"stored blockhello hello hello hello"
        );
        // A flipped CRC, a truncated stream and an output bound are errors.
        let n = z.len();
        z[n - 8] ^= 1;
        assert!(gunzip(&z, 1 << 20).unwrap_err().contains("CRC-32"));
        assert!(gunzip(&unhex(FIXED)[..20], 1 << 20).is_err());
        assert!(gunzip(&unhex(DYNAMIC), 100)
            .unwrap_err()
            .contains("exceeds"));
        assert!(gunzip(b"not gzip at all, no", 1 << 20).is_err());
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
