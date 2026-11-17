// Package toid stands in for github.com/stellar/stellar-etl/v2/internal/toid
// in the regression fixtures.
package toid

// ID is a total-order ID (SEP-35 layout: ledger, transaction, operation).
type ID struct {
	LedgerSequence   int32
	TransactionOrder int32
	OperationOrder   int32
}

// New returns the ID of an operation.
func New(ledger, tx, op int32) *ID { return &ID{ledger, tx, op} }

// ToInt64 packs the ID.
func (id *ID) ToInt64() int64 {
	return int64(id.LedgerSequence)<<32 | int64(id.TransactionOrder)<<12 | int64(id.OperationOrder)
}
