package xdr2xx

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// worklists implements XDR202 and the XDR206 check of its bounds.
func (s *state) worklists() {
	for _, n := range s.nodes {
		s.walkBody(n, func(x ast.Node) {
			loop, ok := x.(*ast.ForStmt)
			if !ok {
				return
			}
			ast.Inspect(loop.Body, func(y ast.Node) bool {
				if _, ok := y.(*ast.FuncLit); ok {
					return false
				}
				as, ok := y.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				s.worklistAppend(n, loop, as)
				return true
			})
		})
	}
}

func (s *state) worklistAppend(n *node, loop *ast.ForStmt, as *ast.AssignStmt) {
	call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "append" || len(call.Args) < 2 {
		return
	}
	w, ok := ast.Unparen(as.Lhs[0]).(*ast.Ident)
	if !ok {
		return
	}
	wobj := s.info.ObjectOf(w)
	structure := s.recursiveType(s.info.TypeOf(w))
	if wobj == nil || structure == "" || !s.readsChildren(call.Args[1:]) || !s.pops(loop, wobj) {
		return
	}
	// a counter incremented inside the loop, or len(worklist)
	ctr := map[types.Object]bool{}
	ast.Inspect(loop.Body, func(y ast.Node) bool {
		switch y := y.(type) {
		case *ast.IncDecStmt:
			if obj := s.counterObj(y.X); obj != nil {
				ctr[obj] = true
			}
		case *ast.AssignStmt:
			if y.Tok == token.ADD_ASSIGN {
				for _, l := range y.Lhs {
					if obj := s.counterObj(l); obj != nil {
						ctr[obj] = true
					}
				}
			}
		}
		return true
	})
	isSubject := func(e ast.Expr) bool {
		if s.mentionsAny(e, ctr) {
			return true
		}
		found := false
		ast.Inspect(e, func(y ast.Node) bool {
			if c, ok := y.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "len" && len(c.Args) == 1 {
					if a, ok := ast.Unparen(c.Args[0]).(*ast.Ident); ok && s.info.Uses[a] == wobj {
						found = true
					}
				}
			}
			return !found
		})
		return found
	}
	pred := boundPredicate(isSubject)
	g := s.findGuard(as, pred, false)
	if g == nil { // a check anywhere in the loop that leaves it bounds the next round
		ast.Inspect(loop.Body, func(y ast.Node) bool {
			if _, ok := y.(*ast.FuncLit); ok || g != nil {
				return false
			}
			if is, ok := y.(*ast.IfStmt); ok && terminates(is.Body) {
				if a := falseAtom(is.Cond, pred); a != nil {
					g = &guard{ifStmt: is, atom: a, form: earlyExit}
				}
			}
			return true
		})
	}
	if g == nil {
		s.report(XDR202.ID, as.Pos(), "",
			"worklist %s of xdr.%s grows with every child and nothing bounds it: compare its length or a node counter with a limit inside the loop, at or above what stellar-core admits for ledger meta (guide, Caps)",
			w.Name, structure)
		return
	}
	if g.ifStmt != nil {
		s.checkPolicy(n, g, structure)
	}
}

// readsChildren reports whether the appended values come from a field (or
// accessor) that leads to the children of a recursive type.
func (s *state) readsChildren(args []ast.Expr) bool {
	found := false
	for _, a := range args {
		ast.Inspect(a, func(y ast.Node) bool {
			switch y := y.(type) {
			case *ast.SelectorExpr:
				if sel, ok := s.info.Selections[y]; ok && sel.Kind() == types.FieldVal &&
					catalogue.Has(catalogue.SelectionName(sel, s.aliases), catalogue.RecursiveEdge) {
					found = true
				}
			case *ast.CallExpr:
				if c := s.callee(y); c != nil && catalogue.Has(s.qname(c), catalogue.RecursiveEdge) {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// pops reports whether the loop takes items from the worklist: it appears
// in the loop condition, or is indexed or sliced in the body.
func (s *state) pops(loop *ast.ForStmt, w types.Object) bool {
	uses := func(e ast.Node) bool {
		found := false
		ast.Inspect(e, func(y ast.Node) bool {
			if id, ok := y.(*ast.Ident); ok && s.info.Uses[id] == w {
				found = true
			}
			return !found
		})
		return found
	}
	if loop.Cond != nil && uses(loop.Cond) {
		return true
	}
	found := false
	ast.Inspect(loop.Body, func(y ast.Node) bool {
		switch y := y.(type) {
		case *ast.IndexExpr:
			if uses(y.X) {
				found = true
			}
		case *ast.SliceExpr:
			if uses(y.X) {
				found = true
			}
		}
		return !found
	})
	return found
}
