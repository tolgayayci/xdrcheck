// Trimmed from wallet-backend internal/indexer/processors/transaction_operation_wrapper.go
// at commit 666a64d426263fa6bd2a0ee61ee8dfb1f4729019 (Apache License 2.0): the type
// and the methods contract_operations.go and participants.go call. Details() and its
// helpers are left out; github.com/pkg/errors is replaced by the standard library.
package processors

import (
	"errors"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/toid"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/lint/testdata/regress/wb666a64d/metrics"
	"github.com/tolgayayci/xdrcheck/lint/testdata/regress/wb666a64d/types"
)

// Claimant represents a claimant for a claimable balance
type Claimant struct {
	Destination string             `json:"destination"`
	Predicate   xdr.ClaimPredicate `json:"predicate"`
}

// ErrLiquidityPoolChangeNotFound is returned when a liquidity pool change is not found
var ErrLiquidityPoolChangeNotFound = errors.New("liquidity pool change not found")

// TransactionOperationWrapper represents the data for a single operation within a transaction
type TransactionOperationWrapper struct {
	Index          uint32
	Transaction    ingest.LedgerTransaction
	Operation      xdr.Operation
	LedgerSequence uint32
	Network        string
	LedgerClosed   time.Time
}

// ID returns the ID for the operation.
func (operation *TransactionOperationWrapper) ID() int64 {
	return toid.New(
		int32(operation.LedgerSequence),
		int32(operation.Transaction.Index),
		int32(operation.Index+1),
	).ToInt64()
}

// Order returns the operation order.
func (operation *TransactionOperationWrapper) Order() uint32 {
	return operation.Index + 1
}

// TransactionID returns the id for the transaction related with this operation.
func (operation *TransactionOperationWrapper) TransactionID() int64 {
	return toid.New(int32(operation.LedgerSequence), int32(operation.Transaction.Index), 0).ToInt64()
}

// SourceAccount returns the operation's source account.
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

func (operation *TransactionOperationWrapper) getSignerSponsorInChange(signerKey string, change ingest.Change) xdr.SponsorshipDescriptor {
	if change.Type != xdr.LedgerEntryTypeAccount || change.Post == nil {
		return nil
	}

	preSigners := map[string]xdr.AccountId{}
	if change.Pre != nil {
		account := change.Pre.Data.MustAccount()
		preSigners = account.SponsorPerSigner()
	}

	account := change.Post.Data.MustAccount()
	postSigners := account.SponsorPerSigner()

	pre, preFound := preSigners[signerKey]
	post, postFound := postSigners[signerKey]

	if !postFound {
		return nil
	}

	if preFound {
		formerSponsor := pre.Address()
		newSponsor := post.Address()
		if formerSponsor == newSponsor {
			return nil
		}
	}

	return &post
}

func (operation *TransactionOperationWrapper) getSponsor() (*xdr.AccountId, error) {
	changes, err := operation.Transaction.GetOperationChanges(operation.Index)
	if err != nil {
		return nil, fmt.Errorf("getting operation changes: %w", err)
	}
	var signerKey string
	if setOps, ok := operation.Operation.Body.GetSetOptionsOp(); ok && setOps.Signer != nil {
		signerKey = setOps.Signer.Key.Address()
	}

	for _, c := range changes {
		// Check Signer changes
		if signerKey != "" {
			if sponsorAccount := operation.getSignerSponsorInChange(signerKey, c); sponsorAccount != nil {
				return sponsorAccount, nil
			}
		}

		// Check Ledger key changes
		if c.Pre != nil || c.Post == nil {
			// We are only looking for entry creations denoting that a sponsor
			// is associated to the ledger entry of the operation.
			continue
		}
		if sponsorAccount := c.Post.SponsoringID(); sponsorAccount != nil {
			return sponsorAccount, nil
		}
	}

	return nil, nil
}

// OperationResult returns the operation's result record
func (operation *TransactionOperationWrapper) OperationResult() *xdr.OperationResultTr {
	results, _ := operation.Transaction.Result.OperationResults()
	tr := results[operation.Index].MustTr()
	return &tr
}

func (operation *TransactionOperationWrapper) findInitatingBeginSponsoringOp() *TransactionOperationWrapper {
	if !operation.Transaction.Result.Successful() {
		// Failed transactions may not have a compliant sandwich structure
		// we can rely on (e.g. invalid nesting or a being operation with the wrong sponsoree ID)
		// and thus we bail out since we could return incorrect information.
		return nil
	}
	sponsoree := operation.SourceAccount().ToAccountId()
	operations := operation.Transaction.Envelope.Operations()
	for i := int(operation.Index) - 1; i >= 0; i-- {
		if beginOp, ok := operations[i].Body.GetBeginSponsoringFutureReservesOp(); ok &&
			beginOp.SponsoredId.Address() == sponsoree.Address() {
			result := *operation
			result.Index = uint32(i)
			result.Operation = operations[i]
			return &result
		}
	}
	return nil
}

func getLedgerKeyParticipants(ledgerKey xdr.LedgerKey) []xdr.AccountId {
	var result []xdr.AccountId
	//exhaustive:ignore
	switch ledgerKey.Type {
	case xdr.LedgerEntryTypeAccount:
		result = append(result, ledgerKey.Account.AccountId)
	case xdr.LedgerEntryTypeClaimableBalance:
		// nothing to do
	case xdr.LedgerEntryTypeData:
		result = append(result, ledgerKey.Data.AccountId)
	case xdr.LedgerEntryTypeOffer:
		result = append(result, ledgerKey.Offer.SellerId)
	case xdr.LedgerEntryTypeTrustline:
		result = append(result, ledgerKey.TrustLine.AccountId)
	}
	return result
}

// Participants returns the accounts taking part in the operation.
func (operation *TransactionOperationWrapper) Participants() ([]xdr.AccountId, error) {
	participants := []xdr.AccountId{}
	participants = append(participants, operation.SourceAccount().ToAccountId())
	op := operation.Operation

	switch operation.OperationType() {
	case xdr.OperationTypeCreateAccount:
		participants = append(participants, op.Body.MustCreateAccountOp().Destination)
	case xdr.OperationTypePayment:
		participants = append(participants, op.Body.MustPaymentOp().Destination.ToAccountId())
	case xdr.OperationTypePathPaymentStrictReceive:
		participants = append(participants, op.Body.MustPathPaymentStrictReceiveOp().Destination.ToAccountId())
	case xdr.OperationTypePathPaymentStrictSend:
		participants = append(participants, op.Body.MustPathPaymentStrictSendOp().Destination.ToAccountId())
	case xdr.OperationTypeManageBuyOffer:
		// the only direct participant is the source_account
	case xdr.OperationTypeManageSellOffer:
		// the only direct participant is the source_account
	case xdr.OperationTypeCreatePassiveSellOffer:
		// the only direct participant is the source_account
	case xdr.OperationTypeSetOptions:
		// the only direct participant is the source_account
	case xdr.OperationTypeChangeTrust:
		// the only direct participant is the source_account
	case xdr.OperationTypeAllowTrust:
		participants = append(participants, op.Body.MustAllowTrustOp().Trustor)
	case xdr.OperationTypeAccountMerge:
		participants = append(participants, op.Body.MustDestination().ToAccountId())
	case xdr.OperationTypeInflation:
		// the only direct participant is the source_account
	case xdr.OperationTypeManageData:
		// the only direct participant is the source_account
	case xdr.OperationTypeBumpSequence:
		// the only direct participant is the source_account
	case xdr.OperationTypeCreateClaimableBalance:
		for _, c := range op.Body.MustCreateClaimableBalanceOp().Claimants {
			participants = append(participants, c.MustV0().Destination)
		}
	case xdr.OperationTypeClaimClaimableBalance:
		// the only direct participant is the source_account
	case xdr.OperationTypeBeginSponsoringFutureReserves:
		participants = append(participants, op.Body.MustBeginSponsoringFutureReservesOp().SponsoredId)
	case xdr.OperationTypeEndSponsoringFutureReserves:
		beginSponsorshipOp := operation.findInitatingBeginSponsoringOp()
		if beginSponsorshipOp != nil {
			participants = append(participants, beginSponsorshipOp.SourceAccount().ToAccountId())
		}
	case xdr.OperationTypeRevokeSponsorship:
		op := operation.Operation.Body.MustRevokeSponsorshipOp()
		switch op.Type {
		case xdr.RevokeSponsorshipTypeRevokeSponsorshipLedgerEntry:
			participants = append(participants, getLedgerKeyParticipants(*op.LedgerKey)...)
		case xdr.RevokeSponsorshipTypeRevokeSponsorshipSigner:
			participants = append(participants, op.Signer.AccountId)
			// We don't add signer as a participant because a signer can be arbitrary account.
			// This can spam successful operations history of any account.
		}
	case xdr.OperationTypeClawback:
		op := operation.Operation.Body.MustClawbackOp()
		participants = append(participants, op.From.ToAccountId())
	case xdr.OperationTypeClawbackClaimableBalance:
		// the only direct participant is the source_account
	case xdr.OperationTypeSetTrustLineFlags:
		op := operation.Operation.Body.MustSetTrustLineFlagsOp()
		participants = append(participants, op.Trustor)
	case xdr.OperationTypeLiquidityPoolDeposit:
		// the only direct participant is the source_account
	case xdr.OperationTypeLiquidityPoolWithdraw:
		// the only direct participant is the source_account
	case xdr.OperationTypeInvokeHostFunction:
		// the only direct participant is the source_account
	case xdr.OperationTypeExtendFootprintTtl:
		// the only direct participant is the source_account
	case xdr.OperationTypeRestoreFootprint:
		// the only direct participant is the source_account
	default:
		return participants, fmt.Errorf("unknown operation type: %s", op.Body.Type)
	}

	sponsor, err := operation.getSponsor()
	if err != nil {
		return nil, err
	}
	if sponsor != nil {
		participants = append(participants, *sponsor)
	}

	return dedupeParticipants(participants), nil
}

// dedupeParticipants remove any duplicate ids from `in`
func dedupeParticipants(in []xdr.AccountId) (out []xdr.AccountId) {
	set := map[string]xdr.AccountId{}
	for _, id := range in {
		set[id.Address()] = id
	}

	for _, id := range set {
		out = append(out, id)
	}
	return
}

// deployerAddressString stands in for the upstream helper of the same name
// (another file at this commit): the deployer's address, and whether it can
// be stored.
func deployerAddressString(address xdr.ScAddress) (string, bool, error) {
	// Upstream delegates to types.StorableAddressString, which checks the
	// kind before rendering; so does this stand-in.
	if address.Type != xdr.ScAddressTypeScAddressTypeAccount && address.Type != xdr.ScAddressTypeScAddressTypeContract {
		return "", false, nil
	}
	s, err := address.String()
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

// StateChangeBuilder stands in for the builder in state_change_builder.go at
// this commit: the methods contract_deploy.go calls. Shapes only.
type StateChangeBuilder struct{ sc types.StateChange }

// NewStateChangeBuilder starts a state change for a transaction.
func NewStateChangeBuilder(ledger uint32, closed, txID int64, _ *metrics.IngestionMetrics) *StateChangeBuilder {
	return &StateChangeBuilder{sc: types.StateChange{LedgerNumber: ledger, LedgerClosed: closed, TxID: txID}}
}

// Clone copies the builder.
func (b *StateChangeBuilder) Clone() *StateChangeBuilder { c := *b; return &c }

func (b *StateChangeBuilder) WithOperationID(id int64) *StateChangeBuilder {
	b.sc.OperationID = id
	return b
}

func (b *StateChangeBuilder) WithCategory(cat types.StateChangeCategory) *StateChangeBuilder {
	b.sc.Category = cat
	return b
}

func (b *StateChangeBuilder) WithReason(r types.StateChangeReason) *StateChangeBuilder {
	b.sc.Reason = r
	return b
}

func (b *StateChangeBuilder) WithAccount(a string) *StateChangeBuilder {
	b.sc.AccountID = a
	return b
}

func (b *StateChangeBuilder) WithCreator(a string) *StateChangeBuilder {
	b.sc.CreatorAccount = a
	return b
}

func (b *StateChangeBuilder) Build() types.StateChange { return b.sc }
