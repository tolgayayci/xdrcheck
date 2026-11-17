package xdr401

import (
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) One arm read without a version check.
func operationCount(tx ingest.LedgerTransaction) int {
	return len(tx.UnsafeMeta.MustV3().Operations) // want `XDR401 \(error\): tx.UnsafeMeta.MustV3\(\) reads the v3 arm of xdr.TransactionMeta with no check of tx.UnsafeMeta.V; on a ledger with another version \(v0–v2, v4\) it panics`
}

// (b) A field of one arm, read as if every ledger had it.
func sorobanMeta(tx ingest.LedgerTransaction) *xdr.SorobanTransactionMetaV2 {
	return tx.UnsafeMeta.V4.SorobanMeta // want `XDR401 \(error\): tx.UnsafeMeta.V4 reads the v4 arm .* it panics \(nil dereference\)`
}

// (c) A version check that halts on every other version (the export dies on
// older meta).
func unifiedEvents(tx ingest.LedgerTransaction) ([]xdr.TransactionEvent, error) {
	version := tx.UnsafeMeta.V
	if version != 4 { // want `XDR401 \(error\): the check of tx.UnsafeMeta.V accepts only v4 and halts the job otherwise .* v0–v3`
		return nil, fmt.Errorf("expected meta version 4, got %d", version)
	}
	return tx.UnsafeMeta.MustV4().Events, nil
}

// (d) A switch whose default halts on the versions it does not list.
func txChangesAfter(meta xdr.TransactionMeta) (xdr.LedgerEntryChanges, error) {
	switch meta.V { // want `XDR401 \(error\): switch on meta.V handles v3, v4 and its default halts the job .* v0–v2`
	case 3:
		return meta.MustV3().TxChangesAfter, nil
	case 4:
		return meta.MustV4().TxChangesAfter, nil
	default:
		return nil, errors.New("unsupported meta version")
	}
}

// (e) LedgerCloseMeta: a panic on anything but v1.
func txCount(lcm xdr.LedgerCloseMeta) int {
	if lcm.V != 1 { // want `XDR401 \(error\): the check of lcm.V accepts only v1 .* v0, v2`
		panic("unsupported ledger close meta")
	}
	return len(lcm.MustV1().TxProcessing)
}
