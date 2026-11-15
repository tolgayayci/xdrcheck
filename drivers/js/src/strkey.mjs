// SEP-0023 strkey encoding, written here rather than taken from the SDK under test, so that the L2 value
// projection renders the bytes the SDK decoded and not the output of the SDK's own encoder (whose defects are
// L4 matters). Encode only: the projection never parses strkeys.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Version bytes (SEP-0023 v1.4.0): the first base32 character is the letter. */
export const VERSION = {
  G: 6 << 3, // ed25519 public key
  S: 18 << 3, // ed25519 secret seed
  M: 12 << 3, // muxed ed25519 account
  T: 19 << 3, // pre-authorized transaction hash
  X: 23 << 3, // sha256 hash (hash-x)
  P: 15 << 3, // ed25519 signed payload
  C: 2 << 3, // contract
  L: 11 << 3, // liquidity pool
  B: 1 << 3, // claimable balance
  W: 22 << 3, // muxed contract
};

function crc16xmodem(bytes) {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

function base32(bytes) {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** encode(letter, payload) → strkey text, unpadded. */
export function encode(letter, payload) {
  const data = new Uint8Array(1 + payload.length + 2);
  data[0] = VERSION[letter];
  data.set(payload, 1);
  const crc = crc16xmodem(data.subarray(0, 1 + payload.length));
  data[1 + payload.length] = crc & 0xff; // little-endian checksum
  data[2 + payload.length] = crc >> 8;
  return base32(data);
}

/** Big-endian bytes of an unsigned 64-bit bigint. */
export function u64be(v) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt.asUintN(64, v), false);
  return out;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
