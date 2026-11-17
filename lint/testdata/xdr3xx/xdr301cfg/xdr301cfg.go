// Package xdr301cfg is the XDR301 fixture for a configured sink: the test
// lists StateChangeBuilder.WithAccount under sinksparticipant, the way the
// wallet-backend profile does.
package xdr301cfg

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type StateChangeBuilder struct{ account, creator string }

func (b *StateChangeBuilder) WithAccount(a string) *StateChangeBuilder { b.account = a; return b }

func (b *StateChangeBuilder) WithCreator(a string) *StateChangeBuilder { b.creator = a; return b }

func deployStateChange(tx ingest.LedgerTransaction, inv xdr.SorobanAuthorizedInvocation) *StateChangeBuilder {
	_ = tx.FeeChanges
	b := &StateChangeBuilder{}
	pre := inv.Function.MustCreateContractHostFn().ContractIdPreimage
	deployer, _ := pre.MustFromAddress().Address.String() // want `XDR301 \(error\): pre.MustFromAddress\(\).Address .* reaches participant sink b.WithAccount`
	b.WithAccount(deployer)
	b.WithCreator(deployer) // not configured: no second report
	return b
}
