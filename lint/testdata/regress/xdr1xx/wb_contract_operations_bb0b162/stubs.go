// Package processors is the fixed counterpart of the XDR102 regression
// fixture wb_contract_operations_f8e5786: wallet-backend at PR #753, where
// the operation source is reduced with ToAccountId() before Address(), so
// the four reports at lines 156, 259, 303 and 347 are gone. XDR102 still
// reports lines 66, 113 and 350, where an ScAddress from the authorization
// tree or the invocation arguments is rendered with String() and no kind
// check on its way into the participant set; PR #739 removed that harvest
// (the copies at e967ce8 are silent).
//
// contract_operations.go is internal/indexer/processors/contract_operations.go
// of github.com/stellar/wallet-backend at commit
// bb0b162b072583c7dabffbdee664d1c117e5ba56 (Apache License 2.0). It is
// unchanged except that import paths outside go-stellar-sdk point at the
// stand-ins under ../stub; every line keeps its number. This file declares
// what the copied file uses from the rest of that package, taken from the
// pre-fix commit f8e5786d22c04adad16318f2e126728beec5aac9.
package processors

import (
	"time"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TransactionOperationWrapper and its two methods are copied from
// internal/indexer/processors/transaction_operation_wrapper.go at the
// pre-fix commit.
type TransactionOperationWrapper struct {
	Index          uint32
	Transaction    ingest.LedgerTransaction
	Operation      xdr.Operation
	LedgerSequence uint32
	Network        string
	LedgerClosed   time.Time
}

// SourceAccount returns the operation source, or the transaction source.
func (operation *TransactionOperationWrapper) SourceAccount() *xdr.MuxedAccount {
	sourceAccount := operation.Operation.SourceAccount
	if sourceAccount != nil {
		return sourceAccount
	} else {
		ret := operation.Transaction.Envelope.SourceAccount()
		return &ret
	}
}

// OperationType returns the operation type.
func (operation *TransactionOperationWrapper) OperationType() xdr.OperationType {
	return operation.Operation.Body.Type
}

// deployerAddressString stands in for the wallet-backend helper of that name
// (defined outside the copied file): the strkey of a deployer address, and
// whether it is a kind that can be stored.
func deployerAddressString(addr xdr.ScAddress) (string, bool, error) {
	switch addr.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract:
	default:
		return "", false, nil
	}
	s, err := addr.String()
	return s, err == nil, err
}
