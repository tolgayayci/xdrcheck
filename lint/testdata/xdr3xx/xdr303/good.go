package xdr303

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) A builder that also reads fee changes.
func FeeAwareParticipants(tx ingest.LedgerTransaction) []string { // want FeeAwareParticipants:`returns=\[meta\] readsMeta=true`
	var participants []string
	participants = append(participants, tx.Envelope.SourceAccount().ToAccountId().Address())
	for _, c := range tx.FeeChanges {
		if c.Type == xdr.LedgerEntryChangeTypeLedgerEntryUpdated && c.Updated.Data.Type == xdr.LedgerEntryTypeAccount {
			participants = append(participants, c.Updated.Data.Account.AccountId.Address())
		}
	}
	return participants
}

// accountsOf writes participants from changes it is given: a meta type
// parameter is a meta read.
func accountsOf(changes []ingest.Change, participants map[string]bool) {
	for _, c := range changes {
		if c.Post != nil && c.Post.Data.Type == xdr.LedgerEntryTypeAccount {
			participants[c.Post.Data.MustAccount().AccountId.Address()] = true
		}
	}
}

// opSources reads no meta itself, but its only caller does.
func opSources(env xdr.TransactionEnvelope, participants map[string]bool) {
	participants[env.SourceAccount().ToAccountId().Address()] = true
}

// (b) A builder that reads operation changes through a helper and calls a
// meta-free helper too.
func OperationParticipants(tx ingest.LedgerTransaction, i uint32) (map[string]bool, error) { // want OperationParticipants:`returns=\[\] readsMeta=true`
	participants := map[string]bool{}
	changes, err := tx.GetOperationChanges(i)
	if err != nil {
		return nil, err
	}
	accountsOf(changes, participants)
	opSources(tx.Envelope, participants)
	return participants, nil
}
