// Package xdr203 holds the XDR203 fixtures: decoded integers used as
// allocation sizes or loop bounds.
package xdr203

import (
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func bytesFor(v xdr.ScVal) []byte {
	if v.U32 == nil {
		return nil
	}
	return make([]byte, *v.U32) // want `XDR203 \(warning\): decoded integer \*v.U32 used as an allocation size`
}

func padding(v xdr.ScVal) string {
	n, _ := v.GetU32()
	return strings.Repeat("x", int(n)) // want `XDR203 \(warning\): decoded integer int\(n\) used as a repeat count`
}

func perLedger(h xdr.LedgerHeader) int {
	total := 0
	for i := xdr.Uint32(0); i < h.LedgerSeq; i++ { // want `XDR203 \(warning\): .* used as a loop bound`
		total++
	}
	return total
}

func capacity(v xdr.ScVal) []string {
	n := v.MustU64()
	return make([]string, 0, n) // want `XDR203 \(warning\): decoded integer n used as an allocation size`
}
