package xdr102reparse

import (
	"errors"
	"log"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/ingest/sac"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// AddressColumn stands for an account-key column type (sinksaccountkey).
type AddressColumn string

type balance struct {
	Holder AddressColumn
}

// holderOf renders the address of a contract-data balance key
// ([Balance, Address]) without checking its kind.
func holderOf(entry xdr.ContractDataEntry) (string, error) {
	vec, ok := entry.Key.GetVec()
	if !ok || vec == nil || len(*vec) != 2 {
		return "", errors.New("not a balance key")
	}
	addr, ok := (*vec)[1].GetAddress()
	if !ok {
		return "", errors.New("not an address")
	}
	return addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type xdr102reparse.AddressColumn`
}

// (a) The re-parse checks another entry than the one the address came from.
func otherEntry(change, other ingest.Change, out *[]balance) error {
	data := change.Post.Data.MustContractData()
	holder, err := holderOf(data)
	if err != nil {
		return err
	}
	if _, _, ok := sac.ContractBalanceFromContractData(*other.Post, "passphrase"); ok {
		*out = append(*out, balance{Holder: AddressColumn(holder)})
	}
	return nil
}

// (b) The re-parse of the same entry logs and falls through: both branches
// reach the sink.
func fallsThrough(change ingest.Change, out *[]balance) error {
	data := change.Post.Data.MustContractData()
	holder, err := holderOf(data)
	if err != nil {
		return err
	}
	if _, _, ok := sac.ContractBalanceFromContractData(*change.Post, "passphrase"); !ok {
		log.Print("not a SAC balance")
	}
	*out = append(*out, balance{Holder: AddressColumn(holder)})
	return nil
}

type checkpoint struct {
	entry *xdr.LedgerEntry
}

func (p *checkpoint) holderOf(other xdr.ContractDataEntry) (string, error) {
	vec, ok := other.Key.GetVec()
	if !ok || vec == nil || len(*vec) != 2 {
		return "", errors.New("not a balance key")
	}
	addr, ok := (*vec)[1].GetAddress()
	if !ok {
		return "", errors.New("not an address")
	}
	return addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type xdr102reparse.AddressColumn`
}

// (c) The guard re-parses the receiver's entry; the address comes from
// another entry passed to a method of the same receiver.
func (p *checkpoint) receiverEntry(other xdr.ContractDataEntry, out *[]balance) error {
	holder, err := p.holderOf(other)
	if err != nil {
		return err
	}
	if _, _, ok := sac.ContractBalanceFromContractData(*p.entry, "passphrase"); ok {
		*out = append(*out, balance{Holder: AddressColumn(holder)})
	}
	return nil
}
