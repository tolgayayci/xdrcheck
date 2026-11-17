// Package types stands in for github.com/stellar/wallet-backend/internal/indexer/types
// in the regression fixtures. StorableAddressString is copied from
// internal/indexer/types/types.go at wallet-backend commit
// 666a64d426263fa6bd2a0ee61ee8dfb1f4729019 (Apache License 2.0); the rest of
// that package is not needed.
package types

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// StorableAddressString returns the strkey of an address a balance or
// allowance row can key on, reducing a muxed account to its base account,
// and storable = false for the kinds it cannot key on.
func StorableAddressString(addr xdr.ScAddress) (string, bool, error) {
	switch addr.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract:
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		muxed := addr.MustMuxedAccount()
		addrStr, err := strkey.Encode(strkey.VersionByteAccountID, muxed.Ed25519[:])
		if err != nil {
			return "", false, fmt.Errorf("encoding muxed account base address: %w", err)
		}
		return addrStr, true, nil
	default:
		return "", false, nil
	}
	addrStr, err := addr.String()
	if err != nil {
		return "", false, fmt.Errorf("encoding address strkey: %w", err)
	}
	return addrStr, true, nil
}
