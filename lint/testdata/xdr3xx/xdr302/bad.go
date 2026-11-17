// Package xdr302 holds the XDR302 fixtures: operation accounts from the
// envelope used as participants without a success check.
package xdr302

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type indexer struct {
	participants map[string]bool
}

// (a) A payment destination recorded with no success check.
func (ix *indexer) paymentParticipants(tx ingest.LedgerTransaction, op xdr.Operation) {
	_ = tx.FeeChanges
	if p, ok := op.Body.GetPaymentOp(); ok {
		acc := p.Destination.ToAccountId() // want `XDR302 \(error\): p.Destination \(operation accounts from the envelope\) reaches participant sink ix.participants`
		ix.participants[acc.Address()] = true
	}
}

// destinations returns the accounts an operation names. A library-style
// helper: it is reported where it is called without a success check.
func destinations(op xdr.Operation) []xdr.AccountId {
	var out []xdr.AccountId
	if op.SourceAccount != nil {
		out = append(out, op.SourceAccount.ToAccountId())
	}
	switch op.Body.Type {
	case xdr.OperationTypePayment:
		out = append(out, op.Body.MustPaymentOp().Destination.ToAccountId())
	case xdr.OperationTypeCreateAccount:
		out = append(out, op.Body.MustCreateAccountOp().Destination)
	case xdr.OperationTypeAccountMerge:
		out = append(out, op.Body.MustDestination().ToAccountId())
	}
	return out
}

// (b) An unguarded call of the helper.
func (ix *indexer) txParticipants(tx ingest.LedgerTransaction) {
	_ = tx.FeeChanges
	ix.participants[tx.Envelope.SourceAccount().ToAccountId().Address()] = true
	for _, op := range tx.Envelope.Operations() {
		for _, a := range destinations(op) { // want `XDR302 \(error\): destinations\(\)`
			ix.participants[a.Address()] = true
		}
	}
}

// (c) The success check exists but comes after the envelope accounts were
// taken (the shape fixed upstream by moving the check up).
func opParticipants(tx ingest.LedgerTransaction, op xdr.Operation) []string {
	_ = tx.FeeChanges
	participants := []string{}
	for _, a := range destinations(op) { // want `XDR302 \(error\): destinations\(\)`
		participants = append(participants, a.Address())
	}
	if !tx.Successful() {
		return participants
	}
	return participants
}

// A library helper that nobody calls is silent for XDR302: the report
// belongs to an unguarded call site. It reads no meta, so XDR303 reports it.
func operationParticipants(op xdr.Operation) []xdr.AccountId { // want `XDR303 \(warning\): participant builder operationParticipants never reads ledger meta`
	var participants []xdr.AccountId
	if p, ok := op.Body.GetPaymentOp(); ok {
		participants = append(participants, p.Destination.ToAccountId())
	}
	return participants
}

// (d) A claimant destination inside the wrong branch.
func (ix *indexer) claimants(tx ingest.LedgerTransaction, op xdr.CreateClaimableBalanceOp) {
	_ = tx.FeeChanges
	if tx.Successful() {
		return
	} else {
		for _, c := range op.Claimants {
			ix.participants[c.MustV0().Destination.Address()] = true // want `XDR302 \(error\): c.MustV0\(\).Destination`
		}
	}
}

// (e) Comparing the check with false inverts it; only the check itself, or
// its negation with !, counts.
func (ix *indexer) comparedWithFalse(tx ingest.LedgerTransaction, op xdr.PaymentOp) {
	_ = tx.FeeChanges
	if tx.Successful() == false {
		ix.participants[op.Destination.ToAccountId().Address()] = true // want `XDR302 \(error\): op.Destination`
	}
}
