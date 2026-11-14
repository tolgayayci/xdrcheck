package match

// Assets (docs/manifest.md §6.3): `native`, `CODE:ISSUER`, `liquidity_pool:<hex id>`, or a contract address. A
// classic asset and its Stellar Asset Contract under the pass's passphrase are the same asset; the contract ID
// is computed here from the asset and the network ID (sha256 of the XDR HashIDPreimage ENVELOPE_TYPE_CONTRACT_ID
// with a CONTRACT_ID_PREIMAGE_FROM_ASSET preimage), never taken from the reader. Any other contract address is a
// different asset, whatever its events claim (rule M-7).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var assetCodeRe = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)

type asset struct {
	native   bool
	code     string
	issuer   Address
	contract *Address // C…
	pool     []byte   // liquidity pool ID
}

func parseAsset(s string) (asset, error) {
	switch {
	case s == "native":
		return asset{native: true}, nil
	case strings.HasPrefix(s, "liquidity_pool:"):
		id, err := hex.DecodeString(strings.TrimPrefix(s, "liquidity_pool:"))
		if err != nil || len(id) != 32 {
			return asset{}, fmt.Errorf("asset %q: bad pool ID", s)
		}
		return asset{pool: id}, nil
	case strings.Contains(s, ":"):
		code, issuer, _ := strings.Cut(s, ":")
		if !assetCodeRe.MatchString(code) {
			return asset{}, fmt.Errorf("asset %q: bad code", s)
		}
		a, err := DecodeStrkey(issuer)
		if err != nil || a.Version != VersionAccount {
			return asset{}, fmt.Errorf("asset %q: issuer is not a G address", s)
		}
		return asset{code: code, issuer: a}, nil
	default:
		a, err := DecodeStrkey(s)
		if err != nil {
			return asset{}, fmt.Errorf("asset %q: %v", s, err)
		}
		switch a.Version {
		case VersionContract:
			return asset{contract: &a}, nil
		case VersionLiquidityPool:
			return asset{pool: a.Payload}, nil
		}
		return asset{}, fmt.Errorf("asset %q is a %s address", s, a.Kind())
	}
}

func (a asset) classic() bool { return a.native || a.code != "" }

// assetXDR encodes a classic asset as XDR Asset.
func (a asset) assetXDR() []byte {
	var b []byte
	u32 := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	if a.native {
		u32(0)
		return b
	}
	n := 4
	if len(a.code) > 4 {
		n = 12
		u32(2)
	} else {
		u32(1)
	}
	code := make([]byte, n)
	copy(code, a.code)
	b = append(b, code...)
	u32(0) // PUBLIC_KEY_TYPE_ED25519
	return append(b, a.issuer.Payload...)
}

// SACAddress returns the Stellar Asset Contract address of a classic asset (`native` or `CODE:ISSUER`) under a
// network passphrase.
func SACAddress(assetText, passphrase string) (Address, error) {
	a, err := parseAsset(assetText)
	if err != nil {
		return Address{}, err
	}
	if !a.classic() {
		return Address{}, fmt.Errorf("asset %q is not a classic asset", assetText)
	}
	return a.sac(passphrase), nil
}

func (a asset) sac(passphrase string) Address {
	network := sha256.Sum256([]byte(passphrase))
	pre := binary.BigEndian.AppendUint32(nil, 8) // ENVELOPE_TYPE_CONTRACT_ID
	pre = append(pre, network[:]...)
	pre = binary.BigEndian.AppendUint32(pre, 1) // CONTRACT_ID_PREIMAGE_FROM_ASSET
	pre = append(pre, a.assetXDR()...)
	id := sha256.Sum256(pre)
	return Address{Version: VersionContract, Payload: id[:]}
}

// sameAsset reports whether an observed asset is the expected one, accepting a classic asset in either form.
func sameAsset(expected, observed, passphrase string) (bool, error) {
	e, err := parseAsset(expected)
	if err != nil {
		return false, err // the manifest's asset is bad
	}
	o, err := parseAsset(observed)
	if err != nil {
		return false, nil // an observed asset the harness cannot read is not the expected one
	}
	switch {
	case e.native || o.native:
		if e.native && o.native {
			return true, nil
		}
	case e.code != "" && o.code != "":
		return e.code == o.code && e.issuer.Equal(o.issuer), nil
	case e.pool != nil || o.pool != nil:
		return e.pool != nil && o.pool != nil && string(e.pool) == string(o.pool), nil
	case e.contract != nil && o.contract != nil:
		return e.contract.Equal(*o.contract), nil
	}
	// One classic, one contract.
	switch {
	case e.classic() && o.contract != nil:
		return e.sac(passphrase).Equal(*o.contract), nil
	case o.classic() && e.contract != nil:
		return o.sac(passphrase).Equal(*e.contract), nil
	}
	return false, nil
}
