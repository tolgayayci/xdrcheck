package xdr101

import (
	"strconv"

	"github.com/stellar/go-stellar-sdk/processors/token_transfer"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type transfer struct {
	To        string
	ToMuxedID *uint64
	MemoID    string
}

// (a) The memo-derived routing ID stored only as an ID, never as an address.
func setToMuxedID(t *transfer, info *token_transfer.MuxedInfo) {
	if info == nil {
		return
	}
	switch c := info.Content.(type) {
	case *token_transfer.MuxedInfo_Id:
		id := c.Id
		t.ToMuxedID = &id
	case *token_transfer.MuxedInfo_Text, *token_transfer.MuxedInfo_Hash:
		// A memo, not a routing ID: not stored as one.
	}
}

// (b) A type switch admitting only *MuxedInfo_Id; the other arms return early.
func destinationFromIDArm(to string, info *token_transfer.MuxedInfo) (string, error) {
	var id uint64
	switch c := info.Content.(type) {
	case *token_transfer.MuxedInfo_Id:
		id = c.Id
	case *token_transfer.MuxedInfo_Text, *token_transfer.MuxedInfo_Hash:
		return to, nil
	default:
		return to, nil
	}
	var m strkey.MuxedAccount
	if err := m.SetAccountID(to); err != nil {
		return "", err
	}
	m.SetID(id)
	return m.Address()
}

// (c) The same with a type assertion.
func destinationFromAssertion(to string, info *token_transfer.MuxedInfo) (string, error) {
	c, ok := info.GetContent().(*token_transfer.MuxedInfo_Id)
	if !ok {
		return to, nil
	}
	var m strkey.MuxedAccount
	if err := m.SetAccountID(to); err != nil {
		return "", err
	}
	m.SetID(c.Id)
	return m.Address()
}

// (d) A V0 source account wrapped as an ed25519 account, not muxed.
func v0Source(v0 xdr.TransactionV0) (xdr.MuxedAccount, error) {
	return xdr.NewMuxedAccount(xdr.CryptoKeyTypeKeyTypeEd25519, v0.SourceAccountEd25519)
}

// (e) The multiplexing ID of a muxed destination, not of the memo.
func destinationFromMuxedAccount(op xdr.PaymentOp) (xdr.MuxedAccount, error) {
	med := op.Destination.MustMed25519()
	return xdr.MuxedAccountFromAccountId(op.Destination.ToAccountId().Address(), uint64(med.Id))
}

// (f) A memo ID kept as a decimal string column.
func memoIDColumn(t *transfer, memo xdr.Memo) {
	if id, ok := memo.GetId(); ok {
		t.MemoID = strconv.FormatUint(uint64(id), 10)
	}
}
