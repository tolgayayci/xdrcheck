package xdr401

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Every version the SDK declares handled; the default is the reviewed-version
// policy (stop with a typed error above what was reviewed).
func txChangesAfterAll(meta xdr.TransactionMeta) (xdr.LedgerEntryChanges, error) {
	switch meta.V {
	case 0:
		return nil, nil
	case 1:
		return nil, nil
	case 2:
		return meta.MustV2().TxChangesAfter, nil
	case 3:
		return meta.MustV3().TxChangesAfter, nil
	case 4:
		return meta.MustV4().TxChangesAfter, nil
	default:
		return nil, fmt.Errorf("meta version %d is above the reviewed versions", meta.V)
	}
}

// An arm read under its own check; other versions skipped, not fatal.
func sorobanMetaChecked(tx ingest.LedgerTransaction) *xdr.SorobanTransactionMetaV2 {
	if tx.UnsafeMeta.V != 4 {
		return nil
	}
	return tx.UnsafeMeta.V4.SorobanMeta
}

// The ok-accessor.
func eventsChecked(tx ingest.LedgerTransaction) []xdr.TransactionEvent {
	if v4, ok := tx.UnsafeMeta.GetV4(); ok {
		return v4.Events
	}
	return nil
}

// Building meta (a test helper) is not reading it.
func buildMeta(ops []xdr.OperationMetaV2) xdr.TransactionMeta {
	var m xdr.TransactionMeta
	m.V = 4
	m.V4 = &xdr.TransactionMetaV4{Operations: ops}
	return m
}
