// Package xdr303 holds the XDR303 fixtures: participant builders that never
// read ledger meta.
package xdr303

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) A builder that reads only the envelope's operations.
func EnvelopeParticipants(tx ingest.LedgerTransaction) []string { // want `XDR303 \(warning\): participant builder EnvelopeParticipants never reads ledger meta` EnvelopeParticipants:`returns=\[env\] readsMeta=false`
	var participants []string
	participants = append(participants, tx.Envelope.SourceAccount().ToAccountId().Address())
	for _, op := range tx.Envelope.Operations() {
		if op.SourceAccount != nil {
			participants = append(participants, op.SourceAccount.ToAccountId().Address())
		}
	}
	return participants
}

// (b) sourceAccounts writes the set; its only caller reads no meta either,
// so the writer is reported (the caller writes no sink itself).
func sourceAccounts(env xdr.TransactionEnvelope, participants map[string]bool) { // want `XDR303 \(warning\): participant builder sourceAccounts`
	participants[env.SourceAccount().ToAccountId().Address()] = true
}

func BuildParticipants(tx ingest.LedgerTransaction) map[string]bool {
	participants := map[string]bool{}
	sourceAccounts(tx.Envelope, participants)
	return participants
}
