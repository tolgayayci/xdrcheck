// Package xdr101 holds the XDR101 fixtures: values derived from the
// transaction memo reaching the construction of a muxed address. It imports
// the real go-stellar-sdk v0.9.0.
package xdr101

import (
	"encoding/binary"
	"strconv"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/processors/token_transfer"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) MuxedInfo.GetId(), which reports 0 for text and hash memos, set as the
// ID of an M… address.
func destinationFromGetID(to string, info *token_transfer.MuxedInfo) (string, error) {
	var m strkey.MuxedAccount
	if err := m.SetAccountID(to); err != nil {
		return "", err
	}
	m.SetID(info.GetId()) // want `XDR101 \(error\): memo-derived value from token_transfer.MuxedInfo.GetId\(\) \(line \d+\) reaches strkey.MuxedAccount.SetID\(\)`
	return m.Address()
}

// (b) A type switch whose text and hash arm sets id = 0 and falls through
// to SetID.
func destinationFromSwitch(to string, info *token_transfer.MuxedInfo) (string, error) {
	var id uint64
	switch c := info.Content.(type) {
	case *token_transfer.MuxedInfo_Id:
		id = c.Id
	case *token_transfer.MuxedInfo_Text, *token_transfer.MuxedInfo_Hash:
		id = 0
	default:
		return "", nil
	}
	var m strkey.MuxedContract
	if err := m.SetContractID(to); err != nil {
		return "", err
	}
	m.SetID(id) // want `XDR101 \(error\): memo-derived value from the token_transfer.MuxedInfo_(Text|Hash) arm of a type switch`
	return m.Address()
}

// (c) tx.Envelope.Memo().MustId() as the Id of a MuxedAccountMed25519 literal.
func destinationFromEnvelope(tx ingest.LedgerTransaction, key xdr.Uint256) string {
	med := xdr.MuxedAccountMed25519{
		Id:      tx.Envelope.Memo().MustId(), // want `XDR101 \(error\): memo-derived value from xdr.TransactionEnvelope.Memo\(\) .* reaches field xdr.MuxedAccountMed25519.Id, which builds a muxed address`
		Ed25519: key,
	}
	acc := xdr.MuxedAccount{Type: xdr.CryptoKeyTypeKeyTypeMuxedEd25519, Med25519: &med}
	return acc.Address()
}

// (d) A memo ID into xdr.MuxedAccountFromAccountId.
func destinationFromAccountID(memo xdr.Memo, g string) (xdr.MuxedAccount, error) {
	return xdr.MuxedAccountFromAccountId(g, uint64(memo.MustId())) // want `XDR101 \(error\): memo-derived value from xdr.Memo.MustId\(\) .* reaches xdr.MuxedAccountFromAccountId\(\)`
}

// (e) The same through the read-only View API.
func destinationFromView(tx xdr.TransactionView, to string) (string, error) {
	var m strkey.MuxedAccount
	if err := m.SetAccountID(to); err != nil {
		return "", err
	}
	m.SetID(tx.MustMemo().MustId().MustValue()) // want `XDR101 \(error\): memo-derived value from xdr.TransactionView.MustMemo\(\)`
	return m.Address()
}

// (f) A memo ID packed behind the key and encoded with a muxed version byte.
func encodeMuxed(key [32]byte, memo xdr.Memo) (string, error) {
	payload := binary.BigEndian.AppendUint64(key[:], uint64(memo.MustId()))
	return strkey.Encode(strkey.VersionByteMuxedAccount, payload) // want `XDR101 \(error\): .* reaches strkey.Encode\(\) with a muxed version byte`
}

// (g) The ingest helper's memo string parsed back into an ID.
func destinationFromMemoString(tx *ingest.LedgerTransaction, m *strkey.MuxedContract) error {
	id, err := strconv.ParseUint(tx.Memo(), 10, 64)
	if err != nil {
		return err
	}
	m.SetID(id) // want `XDR101 \(error\): memo-derived value from ingest.LedgerTransaction.Memo\(\)`
	return nil
}

// (h) The ID assigned after the literal, then xdr.NewMuxedAccount: one
// report, at the assignment.
func newMuxed(memo xdr.Memo, key xdr.Uint256) (xdr.MuxedAccount, error) {
	med := xdr.MuxedAccountMed25519{Ed25519: key}
	med.Id = memo.MustId() // want `XDR101 \(error\): memo-derived value from xdr.Memo.MustId\(\)`
	return xdr.NewMuxedAccount(xdr.CryptoKeyTypeKeyTypeMuxedEd25519, med)
}

// (i) Through a closure that captured the ID.
func destinationInClosure(info *token_transfer.MuxedInfo, to string) func() (string, error) {
	id := info.GetId()
	return func() (string, error) {
		var m strkey.MuxedAccount
		if err := m.SetAccountID(to); err != nil {
			return "", err
		}
		m.SetID(id) // want `XDR101 \(error\): memo-derived value from token_transfer.MuxedInfo.GetId\(\)`
		return m.Address()
	}
}

// (j) Through a same-package helper.
func memoID(env xdr.TransactionEnvelope) uint64 { return uint64(env.Memo().MustId()) }

func destinationViaHelper(env xdr.TransactionEnvelope, m *strkey.MuxedAccount) {
	m.SetID(memoID(env)) // want `XDR101 \(error\): memo-derived value from xdr.TransactionEnvelope.Memo\(\)`
}

// (g) SetID taken as a method value.
func destinationViaMethodValue(info *token_transfer.MuxedInfo, m *strkey.MuxedAccount) {
	setID := m.SetID
	setID(info.GetId()) // want `XDR101 \(error\): memo-derived value from token_transfer.MuxedInfo.GetId\(\)`
}

// (h) The memo read through an interface of this package whose only
// implementation in the package is the envelope.
type memoReader interface{ Memo() xdr.Memo }

func destinationViaInterface(env xdr.TransactionEnvelope, m *strkey.MuxedAccount) {
	var r memoReader = env
	m.SetID(uint64(r.Memo().MustId())) // want `XDR101 \(error\): memo-derived value from xdr.TransactionEnvelope.Memo\(\)`
}
