package xdr301

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) Authorizers are the owners of the nonce entries the host created.
func authorizers(tx ingest.LedgerTransaction, opIndex uint32) (addrSet, error) {
	participants := addrSet{}
	changes, err := tx.GetOperationChanges(opIndex)
	if err != nil {
		return nil, err
	}
	for _, c := range changes {
		if c.Type != xdr.LedgerEntryTypeContractData || c.Post == nil {
			continue
		}
		cd := c.Post.Data.MustContractData()
		if cd.Key.Type != xdr.ScValTypeScvLedgerKeyNonce {
			continue
		}
		a, err := cd.Contract.String()
		if err != nil {
			return nil, err
		}
		participants.Add(a)
	}
	return participants, nil
}

// (b) A declared deploy is recorded only when meta shows the contract was
// created (membership test in the if statement).
func declaredDeploys(tx ingest.LedgerTransaction, opIndex uint32, entries []xdr.SorobanAuthorizationEntry, participants addrSet) error {
	created := map[string]bool{}
	changes, err := tx.GetOperationChanges(opIndex)
	if err != nil {
		return err
	}
	for _, c := range changes {
		if c.Post != nil && c.Post.Data.Type == xdr.LedgerEntryTypeContractData {
			id, _ := c.Post.Data.MustContractData().Contract.String()
			created[id] = true
		}
	}
	for _, e := range entries {
		fn := e.RootInvocation.Function
		if fn.Type != xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn {
			continue
		}
		deployer, err := fn.MustCreateContractHostFn().ContractIdPreimage.MustFromAddress().Address.String()
		if err != nil {
			continue
		}
		if _, ok := created[deployer]; ok {
			participants.Add(deployer)
		}
	}
	return nil
}

// (c) The same with an early exit.
func declaredDeploysEarlyExit(tx ingest.LedgerTransaction, entries []xdr.SorobanAuthorizationEntry, participants addrSet) {
	created := map[string]bool{}
	for _, c := range tx.GetFeeChanges() {
		if c.Post != nil && c.Post.Data.Type == xdr.LedgerEntryTypeContractData {
			id, _ := c.Post.Data.MustContractData().Contract.String()
			created[id] = true
		}
	}
	for _, e := range entries {
		a, err := e.Credentials.MustAddress().Address.String()
		if err != nil {
			continue
		}
		if !created[a] {
			continue
		}
		participants.Add(a)
	}
}

// (d) Reading the authorization tree without storing it is fine.
func countEntries(op xdr.InvokeHostFunctionOp) int {
	n := 0
	for _, e := range op.Auth {
		n += 1 + len(e.RootInvocation.SubInvocations)
	}
	return n
}
