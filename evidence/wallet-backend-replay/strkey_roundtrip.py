#!/usr/bin/env python3
"""Throwaway: render stored wallet-backend address bytes (version byte + payload) as a
SEP-23 strkey and check it decodes back. Usage: strkey_roundtrip.py <hex> [expected_strkey]
Exit 0 = round-trips (and equals expected if given); 1 = mismatch/undecodable."""
import base64, sys

def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc

def encode(raw: bytes) -> str:
    return base64.b32encode(raw + crc16_xmodem(raw).to_bytes(2, "little")).decode().rstrip("=")

# version byte -> (letter, allowed payload lengths), SEP-23
KINDS = {6 << 3: ("G", {32}), 2 << 3: ("C", {32}), 12 << 3: ("M", {40}), 15 << 3: ("P", set(range(40, 101))),
         19 << 3: ("T", {32}), 23 << 3: ("X", {32}), 18 << 3: ("S", {32})}

def decode_strict(s: str) -> bytes:
    pad = "=" * (-len(s) % 8)
    raw = base64.b32decode(s + pad)
    body, crc = raw[:-2], raw[-2:]
    if crc16_xmodem(body).to_bytes(2, "little") != crc:
        raise ValueError("bad checksum")
    kind = KINDS.get(body[0])
    if kind is None:
        raise ValueError(f"unknown version byte {body[0]:#x}")
    letter, lens = kind
    payload = body[1:]
    if len(payload) not in lens:
        raise ValueError(f"invalid payload length {len(payload)} for {letter}")
    if letter == "P":  # ed25519(32) | len(4, BE) | payload padded to 4
        n = int.from_bytes(payload[32:36], "big")
        if not 1 <= n <= 64 or len(payload) != 36 + ((n + 3) // 4) * 4:
            raise ValueError(f"inconsistent signed-payload length field {n} vs {len(payload)}")
        if any(payload[36 + n:]):
            raise ValueError("non-zero padding")
    if encode(body) != s:
        raise ValueError("non-canonical")
    return body

def main():
    raw = bytes.fromhex(sys.argv[1])
    s = encode(raw)
    print(f"bytes={len(raw)} version={raw[0]:#04x} strkey={s}")
    try:
        decode_strict(s)
        print("decode: OK")
    except ValueError as e:
        print(f"decode: FAIL ({e})")
        sys.exit(1)
    if len(sys.argv) > 2:
        ok = s == sys.argv[2]
        print("equals expected:", ok)
        sys.exit(0 if ok else 1)

main()
