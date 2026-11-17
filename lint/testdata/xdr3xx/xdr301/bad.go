// Package xdr301 holds the XDR301 fixtures: participants taken from the
// authorization tree or the invocation arguments.
package xdr301

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type addrSet map[string]bool

func (s addrSet) Add(a string) { s[a] = true }

// (a) A credential address goes straight into the participant set.
func credentialParticipants(tx ingest.LedgerTransaction, entries []xdr.SorobanAuthorizationEntry) addrSet {
	participants := addrSet{}
	_ = tx.GetFeeChanges()
	for _, e := range entries {
		if e.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress {
			continue
		}
		addr, err := e.Credentials.MustAddress().Address.String() // want `XDR301 \(error\): e.Credentials.MustAddress\(\).Address \(authorization tree or invocation arguments\) reaches participant sink participants.Add`
		if err != nil {
			continue
		}
		participants.Add(addr)
	}
	return participants
}

// (b) The invoked contract, named by the invocation arguments.
func invokedContract(tx ingest.LedgerTransaction, op xdr.InvokeHostFunctionOp, participants map[string]bool) {
	_ = tx.UnsafeMeta
	args := op.HostFunction.MustInvokeContract()
	id, _ := args.ContractAddress.String() // want `XDR301 \(error\): args.ContractAddress`
	participants[id] = true
}

// (c) A delegate's address.
func delegateParticipants(tx ingest.LedgerTransaction, c xdr.SorobanAddressCredentialsWithDelegates) []string {
	var participants []string
	_, _ = tx.GetChanges()
	for _, d := range c.Delegates {
		a, _ := d.Address.String() // want `XDR301 \(error\): d.Address`
		participants = append(participants, a)
	}
	return participants
}

// invocationContracts returns the contracts an invocation tree names. It
// writes no participant set itself; its callers do.
func invocationContracts(inv xdr.SorobanAuthorizedInvocation) []string {
	var out []string
	if fn, ok := inv.Function.GetContractFn(); ok {
		if s, err := fn.ContractAddress.String(); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// credentialAddress hides the source behind an accessor.
func credentialAddress(e xdr.SorobanAuthorizationEntry) xdr.ScAddress {
	return e.Credentials.MustAddress().Address
}

// (e) The accessor's result is reported at its call.
func accessorParticipants(tx ingest.LedgerTransaction, entries []xdr.SorobanAuthorizationEntry, participants addrSet) {
	_ = tx.FeeChanges
	for _, e := range entries {
		a, _ := credentialAddress(e).String() // want `XDR301 \(error\): credentialAddress\(\)`
		participants.Add(a)
	}
}

// (d) The root invocation, walked through a helper.
func rootInvocationParticipants(tx ingest.LedgerTransaction, entries []xdr.SorobanAuthorizationEntry, participants addrSet) {
	_ = tx.FeeChanges
	for _, e := range entries {
		for _, c := range invocationContracts(e.RootInvocation) { // want `XDR301 \(error\): e.RootInvocation`
			participants.Add(c)
		}
	}
}

// (f) A test on meta alone corroborates nothing: the address itself must be
// found in, or compared with, what meta holds.
func metaTypeOnly(tx ingest.LedgerTransaction, entries []xdr.SorobanAuthorizationEntry, participants addrSet) {
	for _, c := range tx.GetFeeChanges() {
		if c.ChangeType == xdr.LedgerEntryChangeTypeLedgerEntryCreated {
			for _, e := range entries {
				a, _ := e.Credentials.MustAddress().Address.String() // want `XDR301 \(error\): e.Credentials.MustAddress\(\).Address`
				participants.Add(a)
			}
		}
	}
}
