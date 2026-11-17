// Package transform is an XDR101 regression fixture: stellar-etl's
// encodeMuxedDestination, whose text and hash memo arm sets id = 0 and falls
// through to SetID, so a text or hash memo becomes a fabricated M… or W…
// destination (stellar-etl issue #450, open and deliberately deferred).
//
// token_transfer.go is internal/transform/token_transfer.go of
// github.com/stellar/stellar-etl at commit
// 2b24ec89ddce7fc0beb7795de982c93e6895eaf3 (Apache License 2.0). It is
// unchanged except that import paths outside go-stellar-sdk point at the
// stand-ins under ../stub, line 40 calls ledgerCloseTimeMs (below) because
// LedgerCloseMeta.LedgerCloseTimeMs is newer than go-stellar-sdk v0.8.0, and
// expectation (want) comments mark the expected reports; every line keeps its number.
// This file declares what the copied file uses from the rest of that package.
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
