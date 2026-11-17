package processors

// Stand-ins for the helpers contract_deploy.go calls that live in other
// files of wallet-backend at commit e967ce8 (state_change_builder.go and the
// deployer-address helper). Shapes only; behaviour is not modelled.

import (
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/lint/testdata/regress/wbe967ce8/types"
)

// StateChangeBuilder builds a state change.
type StateChangeBuilder struct{ sc types.StateChange }

// NewStateChangeBuilder starts a state change for a transaction.
func NewStateChangeBuilder(ledger uint32, closed, txID int64) *StateChangeBuilder {
	return &StateChangeBuilder{sc: types.StateChange{LedgerNumber: ledger, LedgerClosed: closed, TxID: txID}}
}

func (b *StateChangeBuilder) clone() *StateChangeBuilder { c := *b; return &c }

func (b *StateChangeBuilder) WithOperationID(id int64) *StateChangeBuilder {
	c := b.clone()
	c.sc.OperationID = id
	return c
}

func (b *StateChangeBuilder) WithCategory(cat types.StateChangeCategory) *StateChangeBuilder {
	c := b.clone()
	c.sc.Category = cat
	return c
}

func (b *StateChangeBuilder) WithReason(r types.StateChangeReason) *StateChangeBuilder {
	c := b.clone()
	c.sc.Reason = r
	return c
}

func (b *StateChangeBuilder) WithAccount(a string) *StateChangeBuilder {
	c := b.clone()
	c.sc.AccountID = a
	return c
}

func (b *StateChangeBuilder) WithCreator(a string) *StateChangeBuilder {
	c := b.clone()
	c.sc.CreatorAccount = a
	return c
}

func (b *StateChangeBuilder) Build() types.StateChange { return b.sc }

// deployerAddressString returns the deployer's address and whether it can
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
