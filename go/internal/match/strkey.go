package match

// The harness's own strict strkey codec (SEP-0023 v1.4.0), used to decode what an indexer stored. It is written
// here rather than taken from an SDK so that no expected value or decoding rule comes from a reader under test.
// Rules: RFC 4648 base32 without padding; the strkey must re-encode to exactly itself (which rejects lengths
// congruent to 1, 3 or 6 mod 8 and non-zero unused bits); a CRC16-XModem checksum, little-endian; a known
// version byte with algorithm bits 0; the payload length fixed by the type; for P the length prefix must match
// and the padding must be zero; for B the type byte must be 0.

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Strkey version bytes.
const (
	VersionAccount          byte = 6 << 3  // G
	VersionMuxedAccount     byte = 12 << 3 // M
	VersionSeed             byte = 18 << 3 // S (never accepted: a secret is not an address)
	VersionPreAuthTx        byte = 19 << 3 // T
	VersionHashX            byte = 23 << 3 // X
	VersionSignedPayload    byte = 15 << 3 // P
	VersionContract         byte = 2 << 3  // C
	VersionLiquidityPool    byte = 11 << 3 // L
	VersionClaimableBalance byte = 1 << 3  // B
	VersionMuxedContract    byte = 22 << 3 // W
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Address is a decoded strkey: a version byte and its payload.
type Address struct {
	Version byte
	Payload []byte
}

// Kind names the address type in the vocabulary of observation.schema.json addresses[].type.
func (a Address) Kind() string {
	switch a.Version {
	case VersionAccount:
		return "account"
	case VersionMuxedAccount:
		return "muxed_account"
	case VersionContract:
		return "contract"
	case VersionMuxedContract:
		return "muxed_contract"
	case VersionClaimableBalance:
		return "claimable_balance"
	case VersionLiquidityPool:
		return "liquidity_pool"
	case VersionSignedPayload:
		return "signed_payload"
	case VersionPreAuthTx:
		return "pre_auth_tx"
	case VersionHashX:
		return "hash_x"
	}
	return "unknown"
}

// String is the canonical strkey.
func (a Address) String() string {
	bin := append([]byte{a.Version}, a.Payload...)
	crc := crc16(bin)
	bin = append(bin, byte(crc), byte(crc>>8))
	return b32.EncodeToString(bin)
}

// Equal compares version and payload.
func (a Address) Equal(b Address) bool {
	return a.Version == b.Version && bytes.Equal(a.Payload, b.Payload)
}

// IsBase reports whether the address is a base identity (G, C, B, L): what participants are matched on.
func (a Address) IsBase() bool {
	switch a.Version {
	case VersionAccount, VersionContract, VersionClaimableBalance, VersionLiquidityPool:
		return true
	}
	return false
}

// IsMuxed reports whether the address is a muxed form (M, W).
func (a Address) IsMuxed() bool {
	return a.Version == VersionMuxedAccount || a.Version == VersionMuxedContract
}

// Base returns the base identity: itself for G, C, B, L; the embedded account or contract for M and W.
func (a Address) Base() (Address, bool) {
	switch {
	case a.IsBase():
		return a, true
	case a.Version == VersionMuxedAccount:
		return Address{Version: VersionAccount, Payload: a.Payload[:32]}, true
	case a.Version == VersionMuxedContract:
		return Address{Version: VersionContract, Payload: a.Payload[:32]}, true
	}
	return Address{}, false
}

// MuxedID returns the ID of an M or W address as a decimal string.
func (a Address) MuxedID() (string, bool) {
	if !a.IsMuxed() {
		return "", false
	}
	return fmt.Sprint(binary.BigEndian.Uint64(a.Payload[32:40])), true
}

// Key returns the 32-byte key material the address is built on (the account key, contract ID, hash or pool ID;
// for P and M the embedded ed25519 key; for B the hash after the type byte).
func (a Address) Key() []byte {
	if a.Version == VersionClaimableBalance {
		return a.Payload[1:33]
	}
	return a.Payload[:32]
}

// DecodeStrkey decodes and checks a strkey.
func DecodeStrkey(s string) (Address, error) {
	if s == "" {
		return Address{}, errors.New("empty strkey")
	}
	bin, err := b32.DecodeString(s)
	if err != nil {
		return Address{}, fmt.Errorf("not base32: %v", err)
	}
	if b32.EncodeToString(bin) != s {
		return Address{}, errors.New("not canonical (length or unused bits)")
	}
	if len(bin) < 3 {
		return Address{}, errors.New("too short")
	}
	body, sum := bin[:len(bin)-2], bin[len(bin)-2:]
	if crc := crc16(body); byte(crc) != sum[0] || byte(crc>>8) != sum[1] {
		return Address{}, errors.New("bad checksum")
	}
	return FromVersionPayload(body)
}

// FromVersionPayload checks a version byte followed by a raw payload (no checksum) — the form an indexer that
// stores `version_byte_payload_hex` keeps.
func FromVersionPayload(b []byte) (Address, error) {
	if len(b) < 1 {
		return Address{}, errors.New("no version byte")
	}
	v, p := b[0], b[1:]
	want := -1
	switch v {
	case VersionAccount, VersionPreAuthTx, VersionHashX, VersionContract, VersionLiquidityPool:
		want = 32
	case VersionMuxedAccount, VersionMuxedContract:
		want = 40
	case VersionClaimableBalance:
		want = 33
	case VersionSignedPayload:
		if len(p) < 36 {
			return Address{}, fmt.Errorf("invalid payload length %d for %s", len(p), prefix(v))
		}
		n := binary.BigEndian.Uint32(p[32:36])
		if n < 1 || n > 64 {
			return Address{}, fmt.Errorf("signed payload length %d outside 1..64", n)
		}
		padded := (int(n) + 3) / 4 * 4
		if len(p) != 36+padded {
			return Address{}, fmt.Errorf("invalid payload length %d for %s with a %d-byte inner payload", len(p), prefix(v), n)
		}
		for _, z := range p[36+int(n):] {
			if z != 0 {
				return Address{}, errors.New("non-zero padding in signed payload")
			}
		}
		return Address{Version: v, Payload: bytes.Clone(p)}, nil
	default:
		return Address{}, fmt.Errorf("unknown version byte 0x%02x", v)
	}
	if len(p) != want {
		return Address{}, fmt.Errorf("invalid payload length %d for %s", len(p), prefix(v))
	}
	if v == VersionClaimableBalance && p[0] != 0 {
		return Address{}, fmt.Errorf("claimable balance type byte %d", p[0])
	}
	return Address{Version: v, Payload: bytes.Clone(p)}, nil
}

func prefix(v byte) string {
	if c := b32.EncodeToString([]byte{v, 0}); c != "" {
		return c[:1]
	}
	return "?"
}

// MustDecode decodes a strkey or panics; for tests and constants.
func MustDecode(s string) Address {
	a, err := DecodeStrkey(s)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", s, err))
	}
	return a
}

// crc16 is CRC16-XModem (polynomial 0x1021, initial 0).
func crc16(b []byte) uint16 {
	var crc uint16
	for _, x := range b {
		crc ^= uint16(x) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---- XDR forms ----

// decodeXDRAddress reads the XDR encodings an address column may hold: MuxedAccount, ScAddress, PublicKey
// (AccountID), and — in a signer context — SignerKey. It returns every reading that consumes the bytes exactly;
// the discriminant and length make most of them unique.
func decodeXDRAddress(b []byte, signer bool) []Address {
	if len(b) < 4 {
		return nil
	}
	d := binary.BigEndian.Uint32(b[:4])
	rest := b[4:]
	var out []Address
	add := func(v byte, p []byte) {
		if a, err := FromVersionPayload(append([]byte{v}, p...)); err == nil {
			out = append(out, a)
		}
	}
	if signer {
		switch d {
		case 0:
			if len(rest) == 32 {
				add(VersionAccount, rest)
			}
		case 1:
			if len(rest) == 32 {
				add(VersionPreAuthTx, rest)
			}
		case 2:
			if len(rest) == 32 {
				add(VersionHashX, rest)
			}
		case 3:
			add(VersionSignedPayload, rest) // key ‖ len ‖ payload ‖ padding, exactly the strkey payload
		}
		return out
	}
	switch {
	case d == 0 && len(rest) == 32: // MuxedAccount KEY_TYPE_ED25519, or PublicKey
		add(VersionAccount, rest)
	case d == 0x100 && len(rest) == 40: // MuxedAccount KEY_TYPE_MUXED_ED25519 { uint64 id; uint256 key }
		add(VersionMuxedAccount, append(bytes.Clone(rest[8:40]), rest[:8]...))
	case d == 0 && len(rest) == 36 && binary.BigEndian.Uint32(rest[:4]) == 0: // ScAddress account
		add(VersionAccount, rest[4:])
	case d == 1 && len(rest) == 32: // ScAddress contract
		add(VersionContract, rest)
	case d == 2 && len(rest) == 40: // ScAddress muxed account { uint64 id; uint256 ed25519 }
		add(VersionMuxedAccount, append(bytes.Clone(rest[8:40]), rest[:8]...))
	case d == 3 && len(rest) == 36 && binary.BigEndian.Uint32(rest[:4]) == 0: // ScAddress claimable balance V0
		add(VersionClaimableBalance, append([]byte{0}, rest[4:]...))
	case d == 4 && len(rest) == 32: // ScAddress liquidity pool
		add(VersionLiquidityPool, rest)
	case d == 5 && len(rest) == 40: // ScAddress muxed contract { uint64 id; ContractID }
		add(VersionMuxedContract, append(bytes.Clone(rest[8:40]), rest[:8]...))
	}
	return out
}

// storedValue is what the harness makes of one as_stored value.
type storedValue struct {
	readings []Address // every valid reading; usually one
	raw      []byte    // the stored bytes (for the key-material search); nil if not even that could be read
	rawKey   bool      // raw_key_hex: a bare key with no type
	err      string    // why no reading exists
	shown    string    // the value as reported, for evidence
}

// context of a stored value: which XDR types a column can hold.
const (
	ctxAccount = iota
	ctxSigner
	ctxAny
)

func decodeStored(encoding, value string, ctx int) storedValue {
	sv := storedValue{shown: encoding + ":" + value}
	switch encoding {
	case "strkey_text":
		a, err := DecodeStrkey(value)
		if err != nil {
			sv.err = err.Error()
			if bin, e := b32.DecodeString(value); e == nil {
				sv.raw = bin
			}
			return sv
		}
		sv.readings, sv.raw = []Address{a}, append([]byte{a.Version}, a.Payload...)
	case "version_byte_payload_hex":
		b, err := hex.DecodeString(value)
		if err != nil {
			sv.err = "not hex"
			return sv
		}
		sv.raw = b
		a, err := FromVersionPayload(b)
		if err != nil {
			sv.err = err.Error()
			return sv
		}
		sv.readings = []Address{a}
	case "xdr_hex":
		b, err := hex.DecodeString(value)
		if err != nil {
			sv.err = "not hex"
			return sv
		}
		sv.raw = b
		switch ctx {
		case ctxAccount:
			sv.readings = decodeXDRAddress(b, false)
		case ctxSigner:
			sv.readings = decodeXDRAddress(b, true)
		default:
			sv.readings = append(decodeXDRAddress(b, false), decodeXDRAddress(b, true)...)
		}
		if len(sv.readings) == 0 {
			sv.err = "no address XDR reading consumes these bytes"
		}
	case "raw_key_hex":
		b, err := hex.DecodeString(value)
		if err != nil {
			sv.err = "not hex"
			return sv
		}
		sv.raw = b
		if len(b) != 32 {
			sv.err = fmt.Sprintf("raw key of %d bytes, want 32", len(b))
			return sv
		}
		sv.rawKey = true
	default:
		sv.err = "unknown encoding " + encoding
	}
	return sv
}

// carriesKey reports whether the stored bytes contain the 32-byte key.
func (sv storedValue) carriesKey(key []byte) bool {
	return len(sv.raw) > 0 && bytes.Contains(sv.raw, key)
}
