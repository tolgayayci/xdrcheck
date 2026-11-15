"""SEP-0023 strkey encoding, written here rather than taken from the SDK under test, so that the L2 value
projection renders the bytes the SDK decoded and not the output of the SDK's own encoder (whose defects are L4
matters). Encode only: the projection never parses strkeys.
"""
import base64

# Version bytes (SEP-0023 v1.4.0): the first base32 character is the letter.
VERSION = {
    "G": 6 << 3,  # ed25519 public key
    "S": 18 << 3,  # ed25519 secret seed
    "M": 12 << 3,  # muxed ed25519 account
    "T": 19 << 3,  # pre-authorized transaction hash
    "X": 23 << 3,  # sha256 hash (hash-x)
    "P": 15 << 3,  # ed25519 signed payload
    "C": 2 << 3,  # contract
    "L": 11 << 3,  # liquidity pool
    "B": 1 << 3,  # claimable balance
    "W": 22 << 3,  # muxed contract
}


def crc16xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode(letter: str, payload: bytes) -> str:
    """The strkey text for a payload under the version byte a letter names, unpadded."""
    data = bytes([VERSION[letter]]) + bytes(payload)
    crc = crc16xmodem(data)
    return base64.b32encode(data + crc.to_bytes(2, "little")).decode("ascii").rstrip("=")
