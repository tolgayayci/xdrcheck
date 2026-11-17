package xdr403

import (
	"strconv"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func destinationChecked(id xdr.Hash) (transferRow, error) {
	to, err := strkey.Encode(strkey.VersionByteContract, id[:])
	if err != nil {
		return transferRow{}, err
	}
	return transferRow{To: to}, nil
}

// Tested before it is stored: an empty value is skipped.
func amountTested(s string, row *transferRow) {
	f, _ := strconv.ParseFloat(s, 64)
	if f == 0 {
		return
	}
	row.Amount = f
}

// Discarded but never stored (only logged or compared).
func isNative(v xdr.ScVal) bool {
	s, _ := v.GetStr()
	return s == "native"
}
