// Package xdr102 holds the XDR102 fixtures: address strings that can be
// muxed, a signed payload or a non-account kind used as a participant or
// account key. The fixture's .xdrlint.yml configures AddressBytea as an
// account-key type and Normalise as an address normaliser, the way a
// project profile does.
package xdr102

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// set is a participant set.
type set map[string]bool

func (s set) Add(v string) { s[v] = true }

// AddressBytea stands for a project's binary address column type
// (configured in sinksaccountkey).
type AddressBytea string

// (a) The operation source rendered with Address(): M… when muxed.
func operationParticipants(op xdr.Operation, participants set) {
	participants.Add(op.SourceAccount.Address()) // want `XDR102 \(error\): xdr.MuxedAccount.Address\(\) renders the M… form of a muxed account; it reaches a participant set \(Add\) at line \d+`
}

// (b) ScAddress.String() with no kind check.
func eventParticipants(addr xdr.ScAddress, participants set) error {
	s, err := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	if err != nil {
		return err
	}
	participants.Add(s)
	return nil
}

// (c) A signer key into a configured account-key type.
func signerColumn(key xdr.SignerKey) AddressBytea {
	return AddressBytea(key.Address()) // want `XDR102 \(error\): xdr.SignerKey.Address\(\) renders P…, T… or X… .* reaches account-key type xdr102.AddressBytea`
}

// (d) The ingest helper that skips ToAccountId(), into a participant slice.
func feeParticipants(tx *ingest.LedgerTransaction) []string {
	var participants []string
	fee, _ := tx.FeeAccountAddress() // want `XDR102 \(error\): ingest.LedgerTransaction.FeeAccountAddress\(\) returns the M… form`
	participants = append(participants, fee)
	return participants
}

// (e) Only the muxed-account arm handled: muxed contracts, claimable
// balances and pools still render as W…, B… and L….
func holderKey(addr xdr.ScAddress, participants set) error {
	if addr.Type == xdr.ScAddressTypeScAddressTypeMuxedAccount {
		participants.Add(addr.MustMuxedAccount().Ed25519.String())
		return nil
	}
	s, err := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\)`
	if err != nil {
		return err
	}
	participants.Add(s)
	return nil
}

// (f) AccountMuxed() as a participant map key.
func sourceParticipants(tx *ingest.LedgerTransaction) map[string]bool {
	participants := map[string]bool{}
	if acc, ok := tx.AccountMuxed(); ok { // want `XDR102 \(error\): ingest.LedgerTransaction.AccountMuxed\(\) returns the M… form .* reaches a participant map key`
		participants[acc] = true
	}
	return participants
}

// (g) The keys of SignerSummary(), which include P… signed payloads.
func signerParticipants(entry xdr.AccountEntry) []string {
	var participants []string
	for signer := range entry.SignerSummary() { // want `XDR102 \(error\): xdr.AccountEntry.SignerSummary\(\) is keyed by signer addresses`
		participants = append(participants, signer)
	}
	return participants
}

// (h) The raw XDR of a muxed source account from the View API as a key.
func viewParticipants(tx xdr.TransactionView, participants set) {
	participants.Add(string(tx.MustSourceAccount().MustRaw())) // want `XDR102 \(error\): xdr.MuxedAccountView.MustRaw\(\) is the raw XDR of a possibly muxed account`
}

// (i) A function annotated as an account-key sink.
//
//xdrlint:sink accountkey
func storeHolder(addr string) { _ = addr }

func paymentHolder(op xdr.Operation) {
	pay := op.Body.MustPaymentOp()
	storeHolder(pay.Destination.Address()) // want `XDR102 \(error\): xdr.MuxedAccount.Address\(\) .* reaches account-key sink xdr102.storeHolder`
}

// (j) Through a same-package helper, reported once at the helper however
// many sinks it reaches.
func addrString(addr xdr.ScAddress) string {
	s, _ := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\)`
	return s
}

func transferParticipants(from, to xdr.ScAddress, participants set) {
	participants.Add(addrString(from))
	participants.Add(addrString(to))
}

// (k) An authorization-tree address: XDR301 says it must not be a
// participant at all; stored anyway, its kind is not checked either.
func authParticipants(entry xdr.SorobanAuthorizationEntry, participants set) error {
	s, err := entry.Credentials.MustAddress().Address.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	if err != nil {
		return err
	}
	participants.Add(s)
	return nil
}

// (l) String taken as a method value.
func methodValueParticipants(addr xdr.ScAddress, participants set) {
	render := addr.String
	s, _ := render() // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	participants.Add(s)
}

// (m) String as a method expression.
func methodExprParticipants(addr xdr.ScAddress, participants set) {
	s, _ := xdr.ScAddress.String(addr) // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	participants.Add(s)
}

// (n) An interface of this package that the address is converted to.
type renderer interface{ String() (string, error) }

func interfaceParticipants(addr xdr.ScAddress, participants set) {
	var r renderer = addr
	s, _ := r.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	participants.Add(s)
}

// (o) The participant set behind an interface of this package, its Add
// taken as a method value.
type adder interface{ Add(string) }

func interfaceSink(op xdr.Operation, participants set) {
	var participantSet adder = participants
	add := participantSet.Add
	add(op.SourceAccount.Address()) // want `XDR102 \(error\): xdr.MuxedAccount.Address\(\) renders the M… form of a muxed account; it reaches a participant set \(Add\)`
}

// (p) An interface of this package implemented by a type of this package:
// the call reaches the method, and its result carries what it rendered.
type holderView interface{ Holder() string }

type sacBalance struct{ holder xdr.ScAddress }

func (b sacBalance) Holder() string {
	s, _ := b.holder.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) renders M…, W…, B… and L… strkeys`
	return s
}

func balanceParticipants(holder xdr.ScAddress, participants set) {
	var v holderView = sacBalance{holder: holder}
	participants.Add(v.Holder())
}
