package xdr105

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func memoTextChecked(m xdr.Memo) string {
	if m.Type != xdr.MemoTypeMemoText {
		return ""
	}
	return m.MustText()
}

func amountSwitch(v xdr.ScVal) xdr.Int128Parts {
	switch v.Type {
	case xdr.ScValTypeScvI128:
		return v.MustI128()
	}
	return xdr.Int128Parts{}
}

func contractDataChecked(change ingest.Change) (xdr.ContractDataEntry, bool) {
	if change.Post == nil || change.Post.Data.Type != xdr.LedgerEntryTypeContractData {
		return xdr.ContractDataEntry{}, false
	}
	return change.Post.Data.MustContractData(), true
}

// A union with one arm cannot hold another.
func claimant(c xdr.Claimant) xdr.ClaimantV0 {
	return c.MustV0()
}
