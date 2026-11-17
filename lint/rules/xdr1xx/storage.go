package xdr1xx

// Addresses read from contract storage (XDR102).
//
// The host refuses to store a claimable-balance or liquidity-pool address,
// and a muxed address, in contract storage (soroban-env-host: such an
// ScAddress fails conversion to a storable Val). An address read from the
// key or value of a contract-data entry is therefore a G… or C… address.
//
// The rendering often happens in a helper shared with other inputs
// (`addrString(v xdr.ScVal)`, called on event topics and on storage values
// alike), so the exemption is decided per call: a call of a same-package
// function whose address-carrying arguments are all read from contract
// storage returns a value without the XDR102 aspects, while the same
// function called on an event topic still carries them.
//
// "Read from contract storage" means: walking back from the argument through
// field reads, dereferences, indexing, map lookups, the elements of ranged
// slices and maps, ok-accessors (GetMap, MustVec, …), conversions, phis and
// same-package helpers' results, every path ends at the Key or Val field of
// an xdr.ContractDataEntry.

import (
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// storageFields are the contract-data fields whose contents the host wrote
// into storage under its storable-value rules.
var storageFields = map[string]bool{
	xp + "ContractDataEntry.Key": true,
	xp + "ContractDataEntry.Val": true,
}

// storageCall reports whether every address-carrying argument of a
// same-package call is read from contract storage.
func (e *engine) storageCall(c *ssa.Call) bool {
	if v, ok := e.storageMemo[c]; ok {
		return v
	}
	e.storageMemo[c] = false
	n := 0
	for _, a := range c.Common().Args {
		if !e.carriesAddress(a.Type()) {
			continue
		}
		n++
		if !e.fromStorage(a, 0, map[ssa.Value]bool{}) {
			return false
		}
	}
	e.storageMemo[c] = n > 0
	return n > 0
}

// carriesAddress reports whether a value of type t can hold an ScAddress:
// xdr.ScVal, xdr.ScAddress, or a pointer, slice or map entry of them.
func (e *engine) carriesAddress(t types.Type) bool {
	for i := 0; i < 4; i++ {
		switch u := t.(type) {
		case *types.Pointer:
			t = u.Elem()
			continue
		case *types.Slice:
			t = u.Elem()
			continue
		}
		break
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || catalogue.Canonical(n.Obj().Pkg().Path(), e.aliases) != catalogue.XDR {
		return false
	}
	switch n.Obj().Name() {
	case "ScVal", "ScAddress", "ScMapEntry", "ScVec", "ScMap":
		return true
	}
	return false
}

func (e *engine) fromStorage(v ssa.Value, depth int, seen map[ssa.Value]bool) bool {
	return e.fromStorageIn(v, depth, seen, nil)
}

// fromStorageIn walks with ctx, the same-package calls whose results the walk
// entered: a parameter of the innermost one is its argument at that call.
func (e *engine) fromStorageIn(v ssa.Value, depth int, seen map[ssa.Value]bool, ctx []ssa.CallInstruction) bool {
	if depth > 40 {
		return false
	}
	if seen[v] && len(ctx) == 0 {
		return true // a cycle adds no new origin
	}
	if len(ctx) > 6 {
		return false
	}
	seen[v] = true
	field := func(t types.Type, i int) bool { return storageFields[e.fieldName(t, i)] }
	switch x := v.(type) {
	case *ssa.Field:
		return field(x.X.Type(), x.Field) || e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.FieldAddr:
		return field(x.X.Type(), x.Field) || e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.UnOp:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Index:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.IndexAddr:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Lookup:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Extract:
		return e.fromStorageIn(x.Tuple, depth+1, seen, ctx)
	case *ssa.ChangeType:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Convert:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Slice:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Next:
		return e.fromStorageIn(x.Iter, depth+1, seen, ctx)
	case *ssa.Range:
		return e.fromStorageIn(x.X, depth+1, seen, ctx)
	case *ssa.Phi:
		for _, ed := range x.Edges {
			if !e.fromStorageIn(ed, depth+1, seen, ctx) {
				return false
			}
		}
		return len(x.Edges) > 0
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeSlice:
		// A local container: what was stored into it. One that is only
		// read (a zero value, `return xdr.ScVal{}, false`) holds no address.
		stored, other := false, false
		for _, r := range *v.Referrers() {
			var val ssa.Value
			switch r := r.(type) {
			case *ssa.UnOp, *ssa.DebugRef:
			default:
				other = true
			case *ssa.Store:
				if r.Addr == v {
					// The whole variable: what it was set to.
					if !e.fromStorageIn(r.Val, depth+1, seen, ctx) {
						return false
					}
					stored = true
				}
			case *ssa.MapUpdate:
				if r.Map == v {
					val = r.Value
				}
			case *ssa.IndexAddr:
				for _, rr := range *r.Referrers() {
					if st, ok := rr.(*ssa.Store); ok && st.Addr == r {
						if !e.fromStorageIn(st.Val, depth+1, seen, ctx) {
							return false
						}
						stored = true
					}
				}
			}
			if val != nil {
				if !e.carriesAddress(val.Type()) {
					continue
				}
				if !e.fromStorageIn(val, depth+1, seen, ctx) {
					return false
				}
				stored = true
			}
		}
		return stored || !other
	case *ssa.Call:
		common := x.Common()
		if fn := e.inPkgCallee(common); fn != nil {
			// A same-package helper: every value it returns.
			ok := false
			for _, r := range returns(fn) {
				for _, res := range r.Results {
					if !e.carriesAddress(res.Type()) {
						continue
					}
					if !e.fromStorageIn(res, depth+1, seen, append(ctx[:len(ctx):len(ctx)], x)) {
						if _, isConst := res.(*ssa.Const); isConst {
							continue // a zero value on an error path
						}
						return false
					}
					ok = true
				}
			}
			return ok
		}
		// An accessor of the SDK's xdr types (GetMap, MustVec, …): its
		// receiver.
		if recv, _ := splitArgs(common); recv != nil && e.carriesAddress(recv.Type()) {
			return e.fromStorageIn(recv, depth+1, seen, ctx)
		}
		_, name := e.callee(common)
		// Decoding a contract-data entry: LedgerEntryData.MustContractData /
		// GetContractData and ContractDataEntry accessors are covered by the
		// field walk; anything else is not storage.
		_ = name
	case *ssa.Parameter:
		// Every same-package call of the function passes a storage value.
		fn := x.Parent()
		i := paramIndex(fn, x)
		if n := len(ctx); n > 0 && ctx[n-1].Common().StaticCallee() == fn {
			args := ctx[n-1].Common().Args
			return i >= 0 && i < len(args) && e.fromStorageIn(args[i], depth+1, seen, ctx[:n-1])
		}
		sites := e.callSites(fn)
		if i < 0 || len(sites) == 0 {
			return false
		}
		for _, c := range sites {
			args := c.Common().Args
			if i >= len(args) || !e.fromStorageIn(args[i], depth+1, seen, ctx) {
				return false
			}
		}
		return true
	case *ssa.Const:
		return false
	}
	return false
}

// callSites returns the static same-package calls of fn, or nil when fn is
// also used as a value (its callers are then not all known).
func (e *engine) callSites(fn *ssa.Function) []ssa.CallInstruction {
	if e.sites == nil {
		e.sites = map[*ssa.Function][]ssa.CallInstruction{}
		e.escapes = map[*ssa.Function]bool{}
		for _, f := range e.funcs {
			for _, b := range f.Blocks {
				for _, in := range b.Instrs {
					if c, ok := in.(ssa.CallInstruction); ok {
						if callee := c.Common().StaticCallee(); callee != nil && e.inPkg[callee] {
							e.sites[callee] = append(e.sites[callee], c)
						}
					}
					for _, op := range in.Operands(nil) {
						if g, ok := (*op).(*ssa.Function); ok && e.inPkg[g] {
							if c, ok := in.(ssa.CallInstruction); !ok || c.Common().Value != g {
								e.escapes[g] = true
							}
						}
					}
				}
			}
		}
	}
	if e.escapes[fn] {
		return nil
	}
	return e.sites[fn]
}
