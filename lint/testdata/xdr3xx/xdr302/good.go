package xdr302

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) The same as bad (c) with the check first: a failed transaction is
// attributed to its source and fee-bump source only.
func opParticipantsGated(tx ingest.LedgerTransaction, op xdr.Operation) []string {
	_ = tx.FeeChanges
	if !tx.Successful() {
		sourceOnly := []string{tx.Envelope.SourceAccount().ToAccountId().Address()}
		if tx.Envelope.IsFeeBump() {
			sourceOnly = append(sourceOnly, tx.Envelope.FeeBumpAccount().ToAccountId().Address())
		}
		return sourceOnly
	}
	participants := []string{}
	for _, a := range destinations(op) {
		participants = append(participants, a.Address())
	}
	return participants
}

// (b) A destination inside the success branch.
func (ix *indexer) paymentParticipantsGated(tx ingest.LedgerTransaction, op xdr.Operation) {
	_ = tx.FeeChanges
	if tx.Result.Successful() && op.Body.Type == xdr.OperationTypePayment {
		ix.participants[op.Body.MustPaymentOp().Destination.ToAccountId().Address()] = true
	}
}

// addOperationAccounts writes into a set its caller passes in; the caller
// is responsible for the success check.
func addOperationAccounts(op xdr.Operation, participants map[string]bool) {
	for _, a := range destinations(op) {
		participants[a.Address()] = true
	}
}

// (c) The helper called under a success check held in a variable.
func (ix *indexer) txParticipantsGated(tx ingest.LedgerTransaction) {
	_ = tx.FeeChanges
	ok := tx.Successful()
	if !ok {
		return
	}
	for _, op := range tx.Envelope.Operations() {
		addOperationAccounts(op, ix.participants)
	}
}

// (d) Closures run inside the guarded block are guarded.
func (ix *indexer) eachGated(tx ingest.LedgerTransaction, ops []xdr.Operation) {
	_ = tx.FeeChanges
	if !tx.Successful() {
		return
	}
	each(ops, func(op xdr.Operation) {
		for _, a := range destinations(op) {
			ix.participants[a.Address()] = true
		}
	})
}

func each(ops []xdr.Operation, f func(xdr.Operation)) {
	for _, op := range ops {
		f(op)
	}
}
