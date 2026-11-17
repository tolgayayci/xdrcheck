package xdr405

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type balanceChange struct {
	Event xdr.ContractEvent
}

// (a) Rows from diagnostic events with no success gate here or in the
// caller: a failed transaction's rolled-back calls become balance changes.
func balanceChanges(tx ingest.LedgerTransaction) ([]balanceChange, error) {
	events, err := tx.GetDiagnosticEvents() // want `XDR405 \(error\): LedgerTransaction.GetDiagnosticEvents\(\) feeds rows with no check that the transaction succeeded`
	if err != nil {
		return nil, err
	}
	var out []balanceChange
	for _, ev := range events {
		if !ev.InSuccessfulContractCall {
			continue
		}
		out = append(out, balanceChange{Event: ev.Event})
	}
	return out, nil
}

func exportAll(txs []ingest.LedgerTransaction) [][]balanceChange {
	var out [][]balanceChange
	for _, tx := range txs {
		rows, _ := balanceChanges(tx)
		out = append(out, rows)
	}
	return out
}

type effect struct {
	Op    uint32
	Entry xdr.LedgerEntryType
}

// (b) The whole transaction's changes attributed to one operation.
func operationEffects(tx ingest.LedgerTransaction, opIndex uint32) ([]effect, error) {
	changes, err := tx.GetChanges() // want `XDR405 \(warning\): LedgerTransaction.GetChanges\(\) is read in operationEffects, which works on one operation`
	if err != nil {
		return nil, err
	}
	var out []effect
	for _, c := range changes {
		out = append(out, effect{Op: opIndex, Entry: c.Type})
	}
	return out, nil
}
