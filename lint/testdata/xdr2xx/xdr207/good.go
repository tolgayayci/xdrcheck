package xdr207

import (
	"io"
	"net/http"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const maxValueDepth = 499

type settings struct{ MaxDepth int }

const hostDepth = 100

// At the decoder's upper bound: silent on every meta path, the envelope of a
// failed transaction included.
func contractData(tx ingest.LedgerTransaction) error {
	changes, err := tx.GetChanges()
	if err != nil {
		return err
	}
	for _, c := range changes {
		if c.Post != nil && c.Post.Data.Type == xdr.LedgerEntryTypeContractData {
			if err := walkAtFloor(c.Post.Data.MustContractData().Val, 0); err != nil {
				return err
			}
		}
	}
	for _, op := range tx.Envelope.Operations() {
		if ih, ok := op.Body.GetInvokeHostFunctionOp(); ok {
			if args, ok := ih.HostFunction.GetInvokeContract(); ok {
				for _, a := range args.Args {
					if err := walkAtFloor(a, 0); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// 100 over values the host wrote: event data, contract data and a return
// value never nest deeper than the host's own limit of 100.
func hostValues(tx ingest.LedgerTransaction) error {
	events, err := tx.GetContractEvents()
	if err != nil {
		return err
	}
	for _, ev := range events {
		data := ev.Body.V0.Data
		if err := walkHostValue(data, 0); err != nil {
			return err
		}
		if err := walkHostBudget(data, hostDepth); err != nil {
			return err
		}
	}
	changes, err := tx.GetChanges()
	if err != nil {
		return err
	}
	for _, c := range changes {
		if c.Post != nil && c.Post.Data.Type == xdr.LedgerEntryTypeContractData {
			if err := walkHostValue(c.Post.Data.MustContractData().Val, 0); err != nil {
				return err
			}
		}
	}
	if meta, ok := tx.UnsafeMeta.GetV4(); ok && meta.SorobanMeta != nil && meta.SorobanMeta.ReturnValue != nil {
		return walkHostValue(*meta.SorobanMeta.ReturnValue, 0)
	}
	return nil
}

func walkHostValue(v xdr.ScVal, depth int) error {
	if depth > hostDepth {
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkHostValue(x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// The same bound as a budget counted down to zero.
func walkHostBudget(v xdr.ScVal, remaining int) error {
	if remaining == 0 {
		return errTooDeep
	}
	if m, ok := v.GetMap(); ok && m != nil {
		for _, e := range *m {
			if err := walkHostBudget(e.Val, remaining-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkAtFloor(v xdr.ScVal, depth int) error {
	if depth > maxValueDepth {
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkAtFloor(x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A bound from configuration: the project owns the number.
func walkConfigured(cfg settings, tx ingest.LedgerTransaction, v xdr.ScVal, depth int) error {
	_ = tx.FeeChanges
	if depth > cfg.MaxDepth {
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkConfigured(cfg, tx, x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Untrusted input before submission: a tighter cap is legitimate there.
func simulate(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshal(body, &env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, op := range env.Operations() {
		if ih, ok := op.Body.GetInvokeHostFunctionOp(); ok {
			if args, ok := ih.HostFunction.GetInvokeContract(); ok {
				for _, a := range args.Args {
					_ = walkArgument(a, 0)
				}
			}
		}
	}
}

func walkArgument(v xdr.ScVal, depth int) error {
	if depth > 100 {
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := walkArgument(x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A decoder at the go-xdr default for ledger meta.
func decodeLedgerDefault(b string) (xdr.LedgerCloseMeta, error) {
	var lcm xdr.LedgerCloseMeta
	err := xdr.SafeUnmarshalBase64WithOptions(b, &lcm, xdr.DecodeOptions{MaxDepth: 1500})
	return lcm, err
}
