package xdr406

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// A default that reports the unknown value without halting.
func memoRowChecked(m xdr.Memo) (row, error) {
	switch m.Type {
	case xdr.MemoTypeMemoNone, xdr.MemoTypeMemoText, xdr.MemoTypeMemoId, xdr.MemoTypeMemoHash, xdr.MemoTypeMemoReturn:
		return row{Kind: m.Type.String()}, nil
	default:
		return row{}, fmt.Errorf("unknown memo type %d", m.Type)
	}
}

// A switch that writes no rows (a predicate).
func isClassic(t xdr.OperationType) bool {
	switch t {
	case xdr.OperationTypeInvokeHostFunction, xdr.OperationTypeExtendFootprintTtl, xdr.OperationTypeRestoreFootprint:
		return false
	}
	return true
}
