package xdr1xx

// Re-parse guards (XDR102).
//
// A reader often renders an address in one helper and checks the entry it
// came from again in another: wallet-backend's checkpoint reads the holder of
// a contract-data balance key with ScAddress.String(), and stores it only
// inside `if _, _, ok := sac.ContractBalanceFromContractData(entry, …); ok`.
// That SDK function returns ok only when the same key's address is a contract
// (it calls GetContractId on it), so the stored address cannot be muxed or a
// non-account kind.
//
// A call catalogued as an address-kind guard (catalogue.AddressKindGuard)
// therefore kind-checks an address used at a sink when
//
//   - the edge on which its ok result is true dominates the sink (a check
//     whose failing branch falls through guards nothing), and
//   - the guard's argument and the sink's value are read from the same
//     entry: walking back from each through field reads, dereferences,
//     indexing, method receivers, call arguments and results, both reach the
//     same variable, and the field path of one is a prefix of the other's
//     (`*change.Post` and `change.Post.Data.MustContractData().Key`).
//
// A guard on another entry, or one whose failing branch does not leave,
// leaves the report in place.

import (
	"fmt"
	"slices"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// kindGuardResult is the index of the ok result of each catalogued guard.
var kindGuardResult = map[string]int{
	catalogue.Ingest + "/sac.ContractBalanceFromContractData": 2,
}

// root is where a value was read from: a variable and the field path below it.
type root struct {
	base ssa.Value
	path []int
}

func (r root) related(o root) bool {
	if r.base != o.base {
		return false
	}
	// The same field below the same variable: an empty path (a receiver or
	// a whole parameter) would make every read of it "the same entry".
	n := min(len(r.path), len(o.path))
	return n > 0 && slices.Equal(r.path[:n], o.path[:n])
}

// roots walks back from v to the variables it was read from.
func (e *engine) roots(v ssa.Value) []root {
	var out []root
	type visit struct {
		v    ssa.Value
		path string
	}
	seen := map[visit]bool{}
	var walk func(v ssa.Value, path []int, depth int)
	walk = func(v ssa.Value, path []int, depth int) {
		k := visit{v, fmt.Sprint(path)}
		if v == nil || depth > 24 || seen[k] {
			return
		}
		seen[k] = true
		switch x := v.(type) {
		case *ssa.UnOp:
			walk(x.X, path, depth+1)
		case *ssa.Field:
			walk(x.X, append([]int{x.Field}, path...), depth+1)
		case *ssa.FieldAddr:
			walk(x.X, append([]int{x.Field}, path...), depth+1)
		case *ssa.Index:
			walk(x.X, path, depth+1)
		case *ssa.IndexAddr:
			walk(x.X, path, depth+1)
		case *ssa.Extract:
			walk(x.Tuple, path, depth+1)
		case *ssa.ChangeType:
			walk(x.X, path, depth+1)
		case *ssa.Convert:
			walk(x.X, path, depth+1)
		case *ssa.MakeInterface:
			walk(x.X, path, depth+1)
		case *ssa.TypeAssert:
			walk(x.X, path, depth+1)
		case *ssa.Slice:
			walk(x.X, path, depth+1)
		case *ssa.Phi:
			for _, ed := range x.Edges {
				walk(ed, path, depth+1)
			}
		case *ssa.Call:
			// A value computed from its arguments (a same-package helper, an
			// SDK accessor): it was read from what they were read from.
			for _, a := range x.Common().Args {
				walk(a, path, depth+1)
			}
			if fn := e.inPkgCallee(x.Common()); fn != nil && !e.rootsIn[fn] {
				e.rootsIn[fn] = true
				defer delete(e.rootsIn, fn)
				// and from what the helper's results were read from, with the
				// helper's parameters mapped back to the arguments.
				for _, r := range returns(fn) {
					for _, res := range r.Results {
						for _, rr := range e.roots(res) {
							if p, ok := rr.base.(*ssa.Parameter); ok {
								if i := paramIndex(fn, p); i >= 0 && i < len(x.Common().Args) {
									walk(x.Common().Args[i], append(slices.Clone(rr.path), path...), depth+1)
								}
							}
						}
					}
				}
			}
		case *ssa.Alloc:
			// A local variable: also where it was stored from.
			out = append(out, root{x, path})
			for _, r := range *x.Referrers() {
				if st, ok := r.(*ssa.Store); ok && st.Addr == x {
					walk(st.Val, path, depth+1)
				}
			}
		default:
			out = append(out, root{v, path})
		}
	}
	walk(v, nil, 0)
	return out
}

// reparseGuarded reports whether the address value v, used at instruction
// at, is on the passing branch of a catalogued address-kind guard on the
// entry v was read from.
func (e *engine) reparseGuarded(at ssa.Instruction, v ssa.Value) bool {
	if at.Block() == nil {
		return false
	}
	fn := at.Parent()
	var vroots []root
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			c, ok := in.(*ssa.Call)
			if !ok {
				continue
			}
			_, name := e.callee(c.Common())
			idx, ok := kindGuardResult[name]
			if !ok || len(c.Common().Args) == 0 {
				continue
			}
			okv := verdictValue(c, idx)
			if okv == nil {
				continue
			}
			o := passEdges(okv, vTrue)
			dominated := false
			for _, ed := range o.edges {
				if edgeDominates(ed, at.Block()) {
					dominated = true
				}
			}
			if !dominated {
				continue
			}
			if vroots == nil {
				vroots = e.roots(v)
			}
			for _, gr := range e.roots(c.Common().Args[0]) {
				for _, vr := range vroots {
					if gr.related(vr) {
						return true
					}
				}
			}
		}
	}
	return false
}
