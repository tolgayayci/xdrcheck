package xdr2xx

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// decodedInt reports whether e is a decoded integer: an integer field of a
// struct of the xdr package, or the integer result of an xdr method or
// function (ScVal.GetU32, MustU64, …).
func (s *state) decodedInt(e ast.Expr) bool {
	switch e := ast.Unparen(e).(type) {
	case *ast.SelectorExpr:
		sel, ok := s.info.Selections[e]
		if !ok || sel.Kind() != types.FieldVal {
			return false
		}
		owner := sel.Recv()
		for {
			p, ok := owner.(*types.Pointer)
			if !ok {
				break
			}
			owner = p.Elem()
		}
		n, ok := types.Unalias(owner).(*types.Named)
		return ok && s.inXDR(n.Obj().Pkg()) && isInteger(derefType(sel.Obj().Type()))
	case *ast.CallExpr:
		c := s.callee(e)
		if c == nil || !s.inXDR(c.Pkg()) || countsDecoded(c.Name()) {
			return false
		}
		res := c.Type().(*types.Signature).Results()
		return res.Len() > 0 && isInteger(derefType(res.At(0).Type()))
	}
	return false
}

// countsDecoded reports whether an xdr method name counts elements the
// decoder already materialised (LedgerCloseMeta.CountTransactions, …): like
// len(decodedSlice), such a count is bounded by the input and is not a
// decoded integer.
func countsDecoded(name string) bool {
	return strings.HasPrefix(name, "Count") || strings.HasSuffix(name, "Count") || name == "Len"
}

func (s *state) inXDR(p *types.Package) bool {
	return p != nil && catalogue.Canonical(p.Path(), s.aliases) == catalogue.XDR
}

func derefType(t types.Type) types.Type {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			return t
		}
		t = p.Elem()
	}
}

// allocations implements XDR203.
func (s *state) allocations() {
	for _, n := range s.nodes {
		if n.lit != nil {
			continue // literals are walked with their declaration
		}
		fl := s.newFlow(n.body, s.decodedInt, nil)
		isSubject := func(e ast.Expr) bool { return fl.mentions(e) }
		sink := func(at ast.Node, size ast.Expr, what string) {
			if !fl.derived(size) || s.isLenCall(size) { // min(n, max) and other calls end the derivation
				return
			}
			if s.findGuard(at, boundPredicate(isSubject), true) != nil {
				return
			}
			s.report(XDR203.ID, at.Pos(), "",
				"decoded integer %s used as %s with no upper bound: the submitter chooses it; compare it with a limit first (go-xdr already bounds decoded slice lengths, so use len() of decoded data where you can)",
				types.ExprString(size), what)
		}
		ast.Inspect(n.body, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.CallExpr:
				if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok && id.Name == "make" {
					if _, builtin := s.info.Uses[id].(*types.Builtin); builtin {
						for _, a := range x.Args[1:] {
							sink(x, a, "an allocation size")
						}
					}
				}
				if c := s.callee(x); c != nil && c.Pkg() != nil && c.Name() == "Repeat" &&
					slices.Contains([]string{"strings", "bytes"}, c.Pkg().Path()) && len(x.Args) == 2 {
					sink(x, x.Args[1], "a repeat count")
				}
			case *ast.ForStmt:
				if x.Cond != nil {
					if b, ok := ast.Unparen(x.Cond).(*ast.BinaryExpr); ok {
						if _, _, isRel := relational(b, isSubject); isRel {
							for _, side := range []ast.Expr{b.X, b.Y} {
								if fl.derived(side) {
									sink(x, side, "a loop bound")
								}
							}
						}
					}
				}
			}
			return true
		})
	}
}

func (s *state) isLenCall(e ast.Expr) bool {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := c.Fun.(*ast.Ident)
	return ok && (id.Name == "len" || id.Name == "cap")
}

// serialisedRecursive reports whether e serialises a value of a recursive
// type: v.MarshalBinary(), xdr.MarshalBase64(v), xdr.MarshalHex(v),
// fmt.Sprint…(v).
func (s *state) serialisedRecursive(e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	c := s.callee(call)
	if c == nil {
		return false
	}
	switch {
	case c.Type().(*types.Signature).Recv() != nil && slices.Contains([]string{"MarshalBinary", "MarshalBase64", "MarshalHex", "MarshalJSON", "String"}, c.Name()):
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			return s.recursiveType(s.info.TypeOf(sel.X)) != ""
		}
	case s.inXDR(c.Pkg()) && slices.Contains([]string{"MarshalBase64", "MarshalHex"}, c.Name()),
		c.Pkg() != nil && c.Pkg().Path() == "fmt" && slices.Contains([]string{"Sprint", "Sprintf", "Sprintln"}, c.Name()):
		for _, a := range call.Args {
			if s.recursiveType(s.info.TypeOf(a)) != "" {
				return true
			}
		}
	}
	return false
}

// serialised implements XDR204: a serialisation of a recursive value passed
// to database/sql with no length check.
func (s *state) serialised() {
	for _, n := range s.nodes {
		if n.lit != nil {
			continue
		}
		fl := s.newFlow(n.body, s.serialisedRecursive, nil)
		lengthChecked := func(e ast.Expr) bool {
			found := false
			ast.Inspect(e, func(x ast.Node) bool {
				if c, ok := x.(*ast.CallExpr); ok && s.isLenCall(c) && len(c.Args) == 1 && fl.mentions(c.Args[0]) {
					found = true
				}
				return !found
			})
			return found
		}
		ast.Inspect(n.body, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			c := s.callee(call)
			if c == nil || !catalogue.Has(s.qname(c), catalogue.TextSink) {
				return true
			}
			for _, a := range call.Args {
				if fl.mentions(a) && s.findGuard(call, boundPredicate(lengthChecked), true) == nil {
					s.report(XDR204.ID, a.Pos(), "",
						"serialised recursive xdr value %s is stored with no length check; its size grows with nesting the submitter chose", types.ExprString(a))
				}
			}
			return true
		})
	}
}
