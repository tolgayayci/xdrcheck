// Package transform is the compliant counterpart of the XDR101 regression
// fixture etl_token_transfer_2b24ec89. stellar-etl has no fix yet (issue
// #450 is open), so this is that file with the smallest change that removes
// the defect, made for this fixture and not taken from upstream: the text and
// hash memo arm of encodeMuxedDestination returns without building an
// address. The rule must be silent here.
//
// token_transfer.go is internal/transform/token_transfer.go of
// github.com/stellar/stellar-etl at commit
// 2b24ec89ddce7fc0beb7795de982c93e6895eaf3 (Apache License 2.0) with that
// change, import paths outside go-stellar-sdk pointing at the stand-ins under
// ../stub, and line 40 calling ledgerCloseTimeMs (below) because
// LedgerCloseMeta.LedgerCloseTimeMs is newer than go-stellar-sdk v0.8.0.
package transform

import (
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/tolgayayci/xdrcheck/lint/testdata/regress/xdr1xx/stub/null"
)

// TokenTransferOutput is the exported row (fields only).
type TokenTransferOutput struct {
	TransactionHash string
	TransactionID   int64
	OperationID     null.Int
	EventTopic      string
	From            null.String
	To              null.String
	Asset           string
	AssetType       string
	AssetCode       null.String
	AssetIssuer     null.String
	AmountRaw       string
	Amount          float64
	ContractID      string
	LedgerSequence  uint32
	ClosedAt        time.Time
	ClosedAtMs      time.Time
	ToMuxed         null.String
	ToMuxedID       null.String
}

func ledgerCloseTimeMs(lcm xdr.LedgerCloseMeta) (int64, error) {
	return lcm.ClosedAt().UnixMilli(), nil
}

func closedAtMsToTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
