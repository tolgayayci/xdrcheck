// Package keys holds two account-key column types, as a reader's storage
// package would: one whose Value() normalises the strkey it stores, and one
// that stores the string as given.
package keys

import (
	"database/sql/driver"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
)

// NormalisedKey reduces M… to G… and W… to C…, and refuses any payload that
// is not a 32-byte key (claimable balances, signed payloads).
type NormalisedKey string

func (a NormalisedKey) Value() (driver.Value, error) {
	vb, raw, err := strkey.DecodeAny(string(a))
	if err != nil {
		return nil, err
	}
	if vb == strkey.VersionByteMuxedAccount || vb == strkey.VersionByteMuxedContract {
		if vb == strkey.VersionByteMuxedAccount {
			vb = strkey.VersionByteAccountID
		} else {
			vb = strkey.VersionByteContract
		}
		raw = raw[:32]
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%s: not a 32-byte key", a)
	}
	return append([]byte{byte(vb)}, raw...), nil
}

// RawKey stores the strkey as given: an M… address becomes a key of its own.
type RawKey string

func (a RawKey) Value() (driver.Value, error) {
	_, raw, err := strkey.DecodeAny(string(a))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// TruncatedKey decodes and names the muxed kind but never checks the
// payload length, so a B… key is stored as 33 bytes: it does not count.
type TruncatedKey string

func (a TruncatedKey) Value() (driver.Value, error) {
	vb, raw, err := strkey.DecodeAny(string(a))
	if err != nil {
		return nil, err
	}
	if vb == strkey.VersionByteMuxedAccount {
		raw = raw[:32]
	}
	return raw, nil
}

// Builder sets account columns, as a state-change builder does.
type Builder struct {
	Account NormalisedKey
	Raw     RawKey
}

// WithAccount only converts its argument to NormalisedKey.
func (b Builder) WithAccount(id string) Builder {
	b.Account = NormalisedKey(id)
	return b
}

// WithRaw stores its argument as given.
func (b Builder) WithRaw(id string) Builder {
	b.Raw = RawKey(id)
	return b
}
