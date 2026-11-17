package xdr403

import (
	"math/big"
	"strconv"

	"github.com/stellar/go-stellar-sdk/strkey"
)

type transferRow struct {
	To     string
	Amount float64
	Asset  string
}

// (a) A strkey that failed to encode (a payload of the wrong length) is
// stored as "".
func destination(payload []byte) transferRow {
	to, _ := strkey.Encode(strkey.VersionByteContract, payload) // want `XDR403 \(warning\): the error of strkey.Encode\(\) is discarded and to is then stored \(a composite literal\)`
	return transferRow{To: to}
}

// (b) An amount that did not parse is stored as 0.
func amount(s string, row *transferRow) {
	f, _ := strconv.ParseFloat(s, 64) // want `XDR403 \(warning\): the error of strconv.ParseFloat\(\) is discarded and f is then stored \(field Amount\)`
	row.Amount = f
}

// (c) A big integer that did not parse: zero is stored.
func bigAmount(s string, rows []transferRow) []transferRow {
	b, _ := new(big.Int).SetString(s, 10) // want `XDR403 \(warning\): the ok result of big.Int.SetString\(\) is discarded and b is then stored \(a composite literal\)`
	return append(rows, transferRow{Asset: b.String()})
}
