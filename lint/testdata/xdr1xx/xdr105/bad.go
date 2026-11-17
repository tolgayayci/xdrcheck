// Package xdr105 holds the fixtures of the opt-in XDR105: Must<Arm>() on a
// multi-arm union with no dominating check of its discriminant. The
// fixture's .xdrlint.yml enables the rule.
package xdr105

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// The check is on the change's type, not on the entry data's discriminant.
func contractDataKey(change ingest.Change) xdr.ScVal {
	if change.Type != xdr.LedgerEntryTypeContractData || change.Post == nil {
		return xdr.ScVal{}
	}
	return change.Post.Data.MustContractData().Key // want `XDR105 \(warning\): xdr.LedgerEntryData.MustContractData\(\) on a union with \d+ arms, with no dominating check of its Type field on the same value`
}

func memoText(m xdr.Memo) string {
	return m.MustText() // want `XDR105 \(warning\): xdr.Memo.MustText\(\)`
}

// A check of one value does not cover another.
func amounts(a, b xdr.ScVal) (xdr.Int128Parts, xdr.Int128Parts) {
	if a.Type != xdr.ScValTypeScvI128 {
		return xdr.Int128Parts{}, xdr.Int128Parts{}
	}
	return a.MustI128(), b.MustI128() // want `XDR105 \(warning\): xdr.ScVal.MustI128\(\)`
}
