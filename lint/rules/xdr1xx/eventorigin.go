package xdr1xx

// Where claimable-balance and liquidity-pool addresses come from (XDR102).
//
// The host refuses to convert an ScAddress of the claimable-balance (B…) or
// liquidity-pool (L…) kind to a contract value, so a contract can never
// store, return or emit one. Values the host produced (contract storage,
// simulation results, the events of a Wasm contract) therefore hold no such
// address. Two places still can: the events the host itself emits for the
// Stellar Asset Contract (classic operations), and the transaction envelope,
// which the host never converted: invocation arguments, the authorization
// tree and the deploy preimage are submitter bytes (a transaction carrying
// one fails, but its envelope is still in the ledger). The
// non-account-kind aspect of ScAddress.String() therefore applies only to an
// address that may have been read from those: the Topics or Data of a
// contract event, or a catalogued authorization-tree or invocation field.
//
// "May have been read from" is a backward walk like the storage walk
// (storage.go) that succeeds when any path reaches one of them; a parameter
// takes its arguments at the call being walked from, or at every
// same-package call site, and a parameter of an exported function with no
// same-package caller may be anything. As with the storage exemption, a
// helper shared by several inputs keeps the aspect for the call sites that
// may pass such a value (callDrop).
//
// The aspect is also dropped for a same-package call made only on the branch
// where the event's name (a string compared with a literal) is one the Stellar
// Asset Contract never emits: `switch name { case "supply": decode(topics) }`
// reads a protocol's own event, which a contract emitted, so it cannot carry
// a B… or L… address. The SAC's event names are transfer, mint, burn,
// clawback, approve, set_admin, set_authorized and fee.
//
// Limit: values decoded from bytes (an RPC getEvents response, base64
// topics) are not recognised; an address read that way loses the
// non-account-kind aspect (a false negative).

import (
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

var eventFields = map[string]bool{
	xp + "ContractEventV0.Topics": true,
	xp + "ContractEventV0.Data":   true,
}

// mayBeEvent reports whether v may have been read from contract event topics
// or data.
func (e *engine) mayBeEvent(v ssa.Value) bool {
	return e.mayBeEventIn(v, 0, map[ssa.Value]bool{}, nil)
}

func (e *engine) mayBeEventIn(v ssa.Value, depth int, seen map[ssa.Value]bool, ctx []ssa.CallInstruction) bool {
	if depth > 40 || len(ctx) > 6 {
		return true // too deep to tell: keep the aspect
	}
	if seen[v] && len(ctx) == 0 {
		return false
	}
	seen[v] = true
	field := func(x ssa.Value, i int) bool {
		n := e.fieldName(x.Type(), i)
		return eventFields[n] || catalogue.Has(n, catalogue.AuthSource)
	}
	walk := func(x ssa.Value) bool { return e.mayBeEventIn(x, depth+1, seen, ctx) }
	switch x := v.(type) {
	case *ssa.Field:
		return field(x.X, x.Field) || walk(x.X)
	case *ssa.FieldAddr:
		return field(x.X, x.Field) || walk(x.X)
	case *ssa.UnOp:
		if x.Op == token.ARROW { // a value received from a channel: unknown
			return true
		}
		return walk(x.X)
	case *ssa.Index:
		return walk(x.X)
	case *ssa.IndexAddr:
		return walk(x.X)
	case *ssa.Lookup:
		return walk(x.X)
	case *ssa.Extract:
		return walk(x.Tuple)
	case *ssa.ChangeType:
		return walk(x.X)
	case *ssa.Convert:
		return walk(x.X)
	case *ssa.Slice:
		return walk(x.X)
	case *ssa.Next:
		return walk(x.Iter)
	case *ssa.Range:
		return walk(x.X)
	case *ssa.TypeAssert:
		return walk(x.X)
	case *ssa.MakeInterface:
		return walk(x.X)
	case *ssa.Phi:
		for _, ed := range x.Edges {
			if walk(ed) {
				return true
			}
		}
		return false
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeSlice:
		for _, r := range *v.Referrers() {
			switch r := r.(type) {
			case *ssa.Store:
				if r.Addr == v && walk(r.Val) {
					return true
				}
			case *ssa.MapUpdate:
				if r.Map == v && walk(r.Value) {
					return true
				}
			case *ssa.IndexAddr, *ssa.FieldAddr:
				for _, rr := range *r.(ssa.Value).Referrers() {
					if st, ok := rr.(*ssa.Store); ok && st.Addr == r.(ssa.Value) && walk(st.Val) {
						return true
					}
				}
			case *ssa.Call:
				// Filled by a callee through its address (a decoder): unknown.
				return true
			}
		}
		return false
	case *ssa.Call:
		common := x.Common()
		if fn := e.inPkgCallee(common); fn != nil {
			for _, r := range returns(fn) {
				for _, res := range r.Results {
					if e.carriesAddress(res.Type()) && e.mayBeEventIn(res, depth+1, seen, append(ctx[:len(ctx):len(ctx)], x)) {
						return true
					}
				}
			}
			return false
		}
		if _, name := e.callee(common); catalogue.Has(name, catalogue.AuthSource) {
			return true
		}
		if recv, _ := splitArgs(common); recv != nil && e.carriesAddress(recv.Type()) {
			return walk(recv)
		}
		for _, a := range common.Args {
			if e.isEventType(a) {
				return true
			}
		}
		return false
	case *ssa.Parameter:
		fn := x.Parent()
		i := paramIndex(fn, x)
		if n := len(ctx); n > 0 && ctx[n-1].Common().StaticCallee() == fn {
			args := ctx[n-1].Common().Args
			return i < 0 || i >= len(args) || e.mayBeEventIn(args[i], depth+1, seen, ctx[:n-1])
		}
		sites := e.callSites(fn)
		if i < 0 || len(sites) == 0 {
			// Called from elsewhere: it may be anything.
			return fn.Object() == nil || fn.Object().Exported() || e.escapes[fn]
		}
		for _, c := range sites {
			args := c.Common().Args
			if i >= len(args) || walk(args[i]) {
				return true
			}
		}
		return false
	case *ssa.FreeVar, *ssa.Global:
		return true
	case *ssa.Const:
		return false
	}
	return false
}

// isEventType reports whether v is an xdr contract event or its body.
func (e *engine) isEventType(v ssa.Value) bool {
	st, _ := e.contractEventIDField(v.Type())
	return st != nil
}

// eventFreeCall reports whether no address-carrying argument of a
// same-package call may have been read from contract event topics or data.
func (e *engine) eventFreeCall(c *ssa.Call) bool {
	if v, ok := e.eventMemo[c]; ok {
		return v
	}
	n := 0
	free := true
	for _, a := range c.Common().Args {
		if !e.carriesAddress(a.Type()) && !e.isEventType(a) {
			continue
		}
		n++
		if e.isEventType(a) || e.mayBeEvent(a) {
			free = false
			break
		}
	}
	e.eventMemo[c] = free && n > 0
	return e.eventMemo[c]
}

// sacEventNames are the event names (first topic) the Stellar Asset Contract
// emits, the only events that can carry claimable-balance or pool addresses.
var sacEventNames = map[string]bool{
	"transfer": true, "mint": true, "burn": true, "clawback": true, "approve": true,
	"set_admin": true, "set_authorized": true, "fee": true,
}

// nonSACEventCall reports whether a call is made only where an event name
// read from the topics equals a literal the Stellar Asset Contract never
// emits.
func (e *engine) nonSACEventCall(c *ssa.Call) bool {
	if c.Block() == nil {
		return false
	}
	for _, b := range c.Parent().Blocks {
		if len(b.Instrs) == 0 || len(b.Succs) != 2 {
			continue
		}
		iff, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		cmp, ok := iff.Cond.(*ssa.BinOp)
		if !ok || (cmp.Op != token.EQL && cmp.Op != token.NEQ) {
			continue
		}
		for _, x := range []ssa.Value{cmp.X, cmp.Y} {
			k, ok := otherConst(cmp, x)
			if !ok || k.Kind() != constant.String || sacEventNames[constant.StringVal(k)] || !isString(x.Type()) {
				continue
			}
			to := b.Succs[0]
			if cmp.Op == token.NEQ {
				to = b.Succs[1]
			}
			if edgeDominates(edge{b, to}, c.Block()) && e.mayBeEvent(x) {
				return true
			}
		}
	}
	return false
}

// contractEventIDField returns the struct of xdr.ContractEvent and the index
// of its ContractId field when t is that type (or a pointer to it).
func (e *engine) contractEventIDField(t types.Type) (*types.Struct, int) {
	n, ok := types.Unalias(deref(t)).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || catalogue.Canonical(n.Obj().Pkg().Path(), e.aliases) != catalogue.XDR || n.Obj().Name() != "ContractEvent" {
		return nil, -1
	}
	st, ok := n.Underlying().(*types.Struct)
	if !ok {
		return nil, -1
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == "ContractId" {
			return st, i
		}
	}
	return nil, -1
}
