// Package transform is an XDR101 regression fixture: the older stellar-etl
// shape, where ToMuxedInfo.GetId() (0 for a text or hash memo) went straight
// into strkey.MuxedAccount.SetID.
//
// token_transfer.go is internal/transform/token_transfer.go of
// github.com/stellar/stellar-etl at commit
// dea2cd9ea92dad7be78d4df0d8b696064831a946 (Apache License 2.0). It is
// unchanged except that import paths outside go-stellar-sdk point at the
// stand-ins under ../stub and an expectation (want) comment marks the
// expected report; every line keeps its number. This file declares what the copied
// file uses from the rest of that package.
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
