package xdr3xx

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// kind is one kind of taint; a taint is a set of kinds.
type kind uint16

const (
	kAuth     kind = 1 << iota // authorization tree or invocation arguments (XDR301)
	kEnv                       // operation source or body account from the envelope (XDR302)
	kEvent                     // contract event topics or data (XDR304)
	kMeta                      // ledger meta (XDR301 guard, XDR303)
	kVerifier                  // a contract ID derived from an asset (XDR304 guard)
	kCID                       // an event's emitting contract ID (XDR304 guard)
	kSuccess                   // the result of a success check (XDR302 guard)
	nKinds    = 7
)

// exported kinds are the ones a function summary carries.
const summaryKinds = kAuth | kEnv | kEvent | kMeta | kVerifier | kCID

// origin is where a kind of taint entered: a source expression, or the call
// of a summarised helper.
type origin struct {
	pos  token.Pos
	desc string
}

// taint is a set of kinds with the origin of each.
type taint struct {
	k kind
	o [nKinds]origin
}

func (t taint) has(k kind) bool { return t.k&k != 0 }

func bit(k kind) int {
	for i := 0; i < nKinds; i++ {
		if k == 1<<i {
			return i
		}
	}
	panic(fmt.Sprint("not a single kind: ", k))
}

func (t taint) origin(k kind) origin { return t.o[bit(k)] }

// set adds kind k with origin o, replacing an inherited origin: the source
// nearest to the use is the one reported.
func (t *taint) set(k kind, o origin) {
	t.k |= k
	t.o[bit(k)] = o
}

// merge adds the kinds of u that t lacks, keeping t's origins.
func (t *taint) merge(u taint) bool {
	changed := false
	for i := 0; i < nKinds; i++ {
		k := kind(1 << i)
		if u.k&k != 0 && t.k&k == 0 {
			t.k |= k
			t.o[i] = u.o[i]
			changed = true
		}
	}
	return changed
}

// sourceKinds returns the taint kinds a catalogued name introduces.
func sourceKinds(name string) kind {
	var k kind
	if catalogue.Has(name, catalogue.AuthSource) {
		k |= kAuth
	}
	if catalogue.Has(name, catalogue.EnvelopeParticipant) {
		k |= kEnv
	}
	if catalogue.Has(name, catalogue.EventSource) && strings.HasPrefix(name, catalogue.XDR+".ContractEventV0.") {
		k |= kEvent // topics and data; the event value itself (and its ContractId) is not a source
	}
	if catalogue.Has(name, catalogue.MetaSource) {
		k |= kMeta
	}
	if catalogue.Has(name, catalogue.EventVerifier) {
		k |= kVerifier
	}
	if catalogue.Has(name, catalogue.EventContractID) {
		k |= kCID
	}
	if catalogue.Has(name, catalogue.SuccessGate) {
		k |= kSuccess
	}
	return k
}

// exprTaint computes the taint of e in function f.
func (s *state) exprTaint(f *fn, e ast.Expr) taint {
	var t taint
	switch e := e.(type) {
	case *ast.Ident:
		if obj := s.info.ObjectOf(e); obj != nil {
			t = f.vars[obj]
		}
	case *ast.ParenExpr:
		t = s.exprTaint(f, e.X)
	case *ast.StarExpr:
		t = s.exprTaint(f, e.X)
	case *ast.UnaryExpr:
		t = s.exprTaint(f, e.X)
	case *ast.IndexExpr:
		t = s.exprTaint(f, e.X)
	case *ast.IndexListExpr:
		t = s.exprTaint(f, e.X)
	case *ast.SliceExpr:
		t = s.exprTaint(f, e.X)
	case *ast.TypeAssertExpr:
		t = s.exprTaint(f, e.X)
	case *ast.KeyValueExpr:
		t = s.exprTaint(f, e.Value)
	case *ast.CompositeLit:
		for _, el := range e.Elts {
			t.merge(s.exprTaint(f, el))
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			// a comparison carries no value
		default:
			t = s.exprTaint(f, e.X)
			t.merge(s.exprTaint(f, e.Y))
			if e.Op == token.EQL {
				t.k &^= kSuccess // tx.Successful() == false is not a success check
			}
		}
	case *ast.SelectorExpr:
		if sel, ok := s.info.Selections[e]; ok {
			t = s.exprTaint(f, e.X)
			if sel.Kind() == types.FieldVal {
				if k := sourceKinds(catalogue.SelectionName(sel, s.aliases)) &^ kSuccess; k != 0 { // only a call checks success
					s.addSource(&t, k, e)
				}
			}
		} else if obj := s.info.Uses[e.Sel]; obj != nil { // qualified identifier
			t = f.vars[obj]
		}
	case *ast.CallExpr:
		t = s.callTaint(f, e)
	}
	return t
}

func (s *state) addSource(t *taint, k kind, at ast.Expr) {
	pos := at.Pos()
	if sel, ok := at.(*ast.SelectorExpr); ok {
		pos = sel.Sel.Pos()
	}
	o := origin{pos: pos, desc: types.ExprString(at)}
	for i := 0; i < nKinds; i++ {
		if k&(1<<i) != 0 {
			t.set(1<<i, o)
		}
	}
}

// callTaint is the taint of a call's result: its arguments and receiver,
// the kinds the callee is catalogued with, and the callee's summary.
func (s *state) callTaint(f *fn, call *ast.CallExpr) taint {
	var t taint
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if b, ok := s.info.Uses[id].(*types.Builtin); ok && (b.Name() == "len" || b.Name() == "cap") {
			return t
		}
	}
	if tv, ok := s.info.Types[call.Fun]; ok && tv.IsType() { // conversion
		for _, a := range call.Args {
			t.merge(s.exprTaint(f, a))
		}
		return t
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if _, isSel := s.info.Selections[sel]; isSel {
			t.merge(s.exprTaint(f, sel.X))
		}
	}
	for _, a := range call.Args {
		t.merge(s.exprTaint(f, a))
	}
	callee := s.callee(call)
	if callee == nil {
		return t
	}
	if k := sourceKinds(catalogue.Name(callee, s.aliases)); k != 0 {
		s.addSource(&t, k, call.Fun)
	}
	if sum := s.summary(callee); sum != nil && sum.Returns != 0 {
		k := kind(sum.Returns) & summaryKinds
		o := origin{pos: callPos(call), desc: types.ExprString(call.Fun) + "()"}
		for i := 0; i < nKinds; i++ {
			if k&(1<<i) != 0 && !t.has(1<<i) { // an argument that already carries the kind names the source better
				t.set(1<<i, o)
			}
		}
	}
	if isErrorType(s.info.TypeOf(call)) {
		return taint{}
	}
	return t
}

func callPos(call *ast.CallExpr) token.Pos {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		return sel.Sel.Pos()
	}
	return call.Pos()
}

func isErrorType(t types.Type) bool {
	return t != nil && types.Identical(t, types.Universe.Lookup("error").Type())
}

func isBool(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

// root returns the variable an assignment target or sink destination
// belongs to: x for x, x.f, x[i], *x.
func (s *state) root(e ast.Expr) types.Object {
	switch e := e.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return nil
		}
		return s.info.ObjectOf(e)
	case *ast.ParenExpr:
		return s.root(e.X)
	case *ast.StarExpr:
		return s.root(e.X)
	case *ast.IndexExpr:
		return s.root(e.X)
	case *ast.SelectorExpr:
		if sel, ok := s.info.Selections[e]; ok && sel.Kind() == types.FieldVal {
			return s.root(e.X)
		}
		return s.info.Uses[e.Sel]
	}
	return nil
}

func (s *state) flowInto(f *fn, lhs ast.Expr, t taint) bool {
	if t.k == 0 {
		return false
	}
	obj := s.root(lhs)
	if obj == nil || isErrorType(obj.Type()) {
		return false
	}
	cur := f.vars[obj]
	if !cur.merge(t) {
		return false
	}
	f.vars[obj] = cur
	return true
}

// propagate computes the taint of every variable of f to a fixed point.
func (s *state) propagate(f *fn) {
	f.vars = map[types.Object]taint{}
	for iter := 0; iter < 25; iter++ {
		changed := false
		ast.Inspect(f.decl.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				// m[k] = v: the map holds the key's taint as well as the value's.
				for _, l := range n.Lhs {
					if ix, ok := l.(*ast.IndexExpr); ok {
						changed = s.flowInto(f, ix.X, s.exprTaint(f, ix.Index)) || changed
					}
				}
				if len(n.Lhs) == len(n.Rhs) {
					for i := range n.Lhs {
						changed = s.flowInto(f, n.Lhs[i], s.exprTaint(f, n.Rhs[i])) || changed
					}
				} else if len(n.Rhs) == 1 {
					t := s.exprTaint(f, n.Rhs[0])
					if ix, ok := ast.Unparen(n.Rhs[0]).(*ast.IndexExpr); ok && len(n.Lhs) == 2 {
						// v, ok := m[k]: ok says whether k is in m
						changed = s.flowInto(f, n.Lhs[1], s.exprTaint(f, ix.Index)) || changed
					}
					for _, l := range n.Lhs {
						changed = s.flowInto(f, l, t) || changed
					}
				}
			case *ast.ValueSpec:
				for i, name := range n.Names {
					switch {
					case len(n.Values) == len(n.Names):
						changed = s.flowInto(f, name, s.exprTaint(f, n.Values[i])) || changed
					case len(n.Values) == 1:
						changed = s.flowInto(f, name, s.exprTaint(f, n.Values[0])) || changed
					}
				}
			case *ast.RangeStmt:
				t := s.exprTaint(f, n.X)
				if n.Key != nil {
					changed = s.flowInto(f, n.Key, t) || changed
				}
				if n.Value != nil {
					changed = s.flowInto(f, n.Value, t) || changed
				}
			case *ast.CallExpr:
				// A method call with tainted arguments taints its receiver:
				// created.Add(id), m.Store(k, v).
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					if selection, ok := s.info.Selections[sel]; ok && selection.Kind() == types.MethodVal {
						var t taint
						for _, a := range n.Args {
							t.merge(s.exprTaint(f, a))
						}
						changed = s.flowInto(f, sel.X, t) || changed
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
	// Return values, not counting returns of function literals.
	f.ret = taint{}
	f.returned = map[types.Object]bool{}
	if f.decl.Type.Results != nil {
		for _, field := range f.decl.Type.Results.List {
			for _, name := range field.Names {
				if obj := s.info.Defs[name]; obj != nil {
					f.returned[obj] = true
					f.ret.merge(f.vars[obj])
				}
			}
		}
	}
	ast.Inspect(f.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			for _, r := range n.Results {
				f.ret.merge(s.exprTaint(f, r))
				ast.Inspect(r, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok {
						if obj := s.info.Uses[id]; obj != nil {
							if _, isVar := obj.(*types.Var); isVar {
								f.returned[obj] = true
							}
						}
					}
					return true
				})
			}
		}
		return true
	})
}
