// Package processors is an XDR102 regression fixture: wallet-backend just
// before PR #753 ("reduce a Soroban operation's source to its base
// account"), where the operation source entered the participant set as
// Address() and so in its M… form when muxed (lines 156, 259, 303, 347).
// Lines 66, 113 and 350 report the ScAddress.String() calls on the
// authorization tree and invocation arguments, which remain after #753.
//
// contract_operations.go is internal/indexer/processors/contract_operations.go
// of github.com/stellar/wallet-backend at commit
// f8e5786d22c04adad16318f2e126728beec5aac9 (Apache License 2.0). It is
// unchanged except that import paths outside go-stellar-sdk point at the
// stand-ins under ../stub and expectation (want) comments mark the expected reports;
// every line keeps its number. This file declares what the copied file uses
// from the rest of that package.
package processors

import (
	"time"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TransactionOperationWrapper and its two methods are copied from
// internal/indexer/processors/transaction_operation_wrapper.go at the same
// commit.
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
