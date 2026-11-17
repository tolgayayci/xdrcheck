package xdr405

import (
	"github.com/stellar/go-stellar-sdk/ingest"
)

// The caller gates on success.
func balanceChangesGated(tx ingest.LedgerTransaction) ([]balanceChange, error) {
	events, err := tx.GetDiagnosticEvents()
	if err != nil {
		return nil, err
	}
	var out []balanceChange
	for _, ev := range events {
		out = append(out, balanceChange{Event: ev.Event})
	}
	return out, nil
}

func exportSuccessful(txs []ingest.LedgerTransaction) [][]balanceChange {
	var out [][]balanceChange
	for _, tx := range txs {
		if !tx.Successful() {
			continue
		}
		rows, _ := balanceChangesGated(tx)
		out = append(out, rows)
	}
	return out
}

// One operation's own changes.
func operationEffectsOwn(tx ingest.LedgerTransaction, opIndex uint32) ([]effect, error) {
	changes, err := tx.GetOperationChanges(opIndex)
	if err != nil {
		return nil, err
	}
	var out []effect
	for _, c := range changes {
		out = append(out, effect{Op: opIndex, Entry: c.Type})
	}
	return out, nil
}

// Transaction-level changes in a transaction-level function.
func transactionChanges(tx ingest.LedgerTransaction) (int, error) {
	changes, err := tx.GetChanges()
	return len(changes), err
}
