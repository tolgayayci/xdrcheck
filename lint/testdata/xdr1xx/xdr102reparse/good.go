package xdr102reparse

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/ingest/sac"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// holderOfChecked has the same shape as holderOf; its only callers store its
// result on the passing branch of a re-parse of the same entry.
func holderOfChecked(entry xdr.ContractDataEntry) (string, bool) {
	vec, ok := entry.Key.GetVec()
	if !ok || vec == nil || len(*vec) != 2 {
		return "", false
	}
	addr, ok := (*vec)[1].GetAddress()
	if !ok {
		return "", false
	}
	s, err := addr.String()
	return s, err == nil
}

// The SDK's balance parser returns ok only when the key's holder is a
// contract (GetContractId), so the address stored here is a C… address.
func sameEntry(change ingest.Change, out *[]balance) {
	data := change.Post.Data.MustContractData()
	holder, ok := holderOfChecked(data)
	if !ok {
		return
	}
	if _, _, ok := sac.ContractBalanceFromContractData(*change.Post, "passphrase"); ok {
		*out = append(*out, balance{Holder: AddressColumn(holder)})
	}
}

// The same check written as an early return.
func sameEntryEarlyReturn(change ingest.Change, out *[]balance) {
	if _, _, ok := sac.ContractBalanceFromContractData(*change.Post, "passphrase"); !ok {
		return
	}
	holder, ok := holderOfChecked(change.Post.Data.MustContractData())
	if !ok {
		return
	}
	*out = append(*out, balance{Holder: AddressColumn(holder)})
}
