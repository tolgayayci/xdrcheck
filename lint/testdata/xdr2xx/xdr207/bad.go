// Package xdr207 holds the XDR207 fixtures: constant bounds below what
// stellar-core admits, on paths fed from ledger meta.
package xdr207

import (
	"errors"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

var errTooDeep = errors.New("too deep")

const maxScValDepth = 32

// eventDepths reads events (ledger meta) and walks their data.
func eventDepths(tx ingest.LedgerTransaction) error {
	events, err := tx.GetContractEvents()
	if err != nil {
		return err
	}
	for _, ev := range events {
		if err := walkEventValue(ev.Body.V0.Data, 0); err != nil {
			return err
		}
		if err := walkHundred(ev.Body.V0.Data, 0); err != nil {
			return err
		}
		if err := walkBudget(ev.Body.V0.Data, 32); err != nil {
			return err
		}
	}
	// The same walker also sees the invocation arguments in the envelope.
	for _, op := range tx.Envelope.Operations() {
		if ih, ok := op.Body.GetInvokeHostFunctionOp(); ok {
			if args, ok := ih.HostFunction.GetInvokeContract(); ok {
				for _, a := range args.Args {
					if err := walkHundred(a, 0); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func walkEventValue(v xdr.ScVal, depth int) error {
	if depth > maxScValDepth { // want `XDR207 \(warning\): bound 32 on xdr.ScVal is below the 100 nested levels ledger meta can hold \(the host's value depth limit`
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkEventValue(x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A cap of 100 on a walk that also sees the envelope: the host's limit does
// not hold there, and core's envelope limit is not established.
func walkHundred(v xdr.ScVal, depth int) error {
	if depth > 100 { // want `XDR207 \(info\): bound 100 on xdr.ScVal: envelope limit not established; 499 is the decoder upper bound`
		return errTooDeep
	}
	if m, ok := v.GetMap(); ok && m != nil {
		for _, e := range *m {
			if err := walkHundred(e.Val, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A budget counted down from 32: the start is the bound.
func walkBudget(v xdr.ScVal, remaining int) error {
	if remaining <= 0 { // want `XDR207 \(warning\): bound 32 on xdr.ScVal is below the 100 nested levels`
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkBudget(x, remaining-1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A bound of 100 on an authorization tree fed from operation changes: XDR201
// is satisfied, and XDR207 says no floor is established for this structure.
func deploys(tx ingest.LedgerTransaction, i uint32, inv xdr.SorobanAuthorizedInvocation) error {
	if _, err := tx.GetOperationChanges(i); err != nil {
		return err
	}
	return walkAuth(inv, 0)
}

func walkAuth(inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > 100 { // want `XDR207 \(info\): bound 100 on xdr.SorobanAuthorizedInvocation: stellar-core's limit for this structure is not yet established`
		return errTooDeep
	}
	for _, sub := range inv.SubInvocations {
		if err := walkAuth(sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// A claim predicate walker capped below core's own limit of 4.
func predicateDepth(tx ingest.LedgerTransaction, op xdr.CreateClaimableBalanceOp) error {
	_ = tx.FeeChanges
	for _, c := range op.Claimants {
		if err := walkPredicate(c.MustV0().Predicate, 1); err != nil {
			return err
		}
	}
	return nil
}

func walkPredicate(p xdr.ClaimPredicate, depth int) error {
	if depth > 3 { // want `XDR207 \(warning\): bound 3 on xdr.ClaimPredicate is below the 4 nested levels`
		return errTooDeep
	}
	if p.AndPredicates != nil {
		for _, q := range *p.AndPredicates {
			if err := walkPredicate(q, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A decoder depth below what ledger meta needs.
func decodeLedger(b string) (xdr.LedgerCloseMeta, error) {
	var lcm xdr.LedgerCloseMeta
	err := xdr.SafeUnmarshalBase64WithOptions(b, &lcm, xdr.DecodeOptions{MaxDepth: 500}) // want `XDR207 \(warning\): decoder MaxDepth 500 is below the 1500 go-xdr depth units`
	return lcm, err
}
