// Package types stands in for wallet-backend's internal/indexer/types at
// commit 666a64d: the names contract_deploy.go uses.
package types

type (
	StateChangeCategory string
	StateChangeReason   string
)

const (
	StateChangeSubBaseContractDeploy int64               = 7
	StateChangeCategoryAccount       StateChangeCategory = "ACCOUNT"
	StateChangeReasonCreate          StateChangeReason   = "CREATE"
)

// StateChange is one recorded state change.
type StateChange struct {
	LedgerNumber   uint32
	LedgerClosed   int64
	TxID           int64
	OperationID    int64
	Category       StateChangeCategory
	Reason         StateChangeReason
	AccountID      string
	CreatorAccount string
}
