package xdr3xx

// Guards. A sink is guarded by a predicate P when, walking out from the
// sink to its function declaration,
//
//   - it sits in the then-branch of `if c` where c being true implies P, or
//     in the else-branch where c being false implies P; or
//   - an earlier statement of an enclosing block is `if c { …; return }`
//     (or continue, break, goto, panic, os.Exit, log.Fatal…) where c being
//     false implies P.
//
// "c true implies P" follows !, && and parentheses; "c false implies P"
// follows !, || and parentheses. Function literals are walked through, so a
// closure passed to an iterator inside a guarded block is guarded.

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/ast/astutil"
)

// predicate recognises the atoms of one kind of guard.
type predicate struct {
	pos func(e ast.Expr) bool // e true ⇒ P
	neg func(e ast.Expr) bool // e false ⇒ P
}

func (s *state) guarded(f *fn, node ast.Node, p predicate) bool {
	file := s.fileOf(node.Pos())
	if file == nil {
		return false
	}
	path, _ := astutil.PathEnclosingInterval(file, node.Pos(), node.End())
	for i := 1; i < len(path); i++ {
		child, parent := path[i-1], path[i]
		switch parent := parent.(type) {
		case *ast.FuncDecl:
			return false
		case *ast.IfStmt:
			if child == parent.Body && trueImplies(parent.Cond, p) {
				return true
			}
			if child == parent.Else && falseImplies(parent.Cond, p) {
				return true
			}
		case *ast.BlockStmt:
			if earlyExit(parent.List, child, p) {
				return true
			}
		case *ast.CaseClause:
			if earlyExit(parent.Body, child, p) {
				return true
			}
		case *ast.CommClause:
			if earlyExit(parent.Body, child, p) {
				return true
			}
		}
	}
	return false
}

func earlyExit(stmts []ast.Stmt, child ast.Node, p predicate) bool {
	for _, st := range stmts {
		if st == child {
			return false
		}
		if is, ok := st.(*ast.IfStmt); ok && is.Else == nil && terminates(is.Body) && falseImplies(is.Cond, p) {
			return true
		}
	}
	return false
}

func trueImplies(e ast.Expr, p predicate) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return trueImplies(e.X, p)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return falseImplies(e.X, p)
		}
	case *ast.BinaryExpr:
		if e.Op == token.LAND {
			return trueImplies(e.X, p) || trueImplies(e.Y, p)
		}
	}
	return p.pos != nil && p.pos(e)
}

func falseImplies(e ast.Expr, p predicate) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return falseImplies(e.X, p)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return trueImplies(e.X, p)
		}
	case *ast.BinaryExpr:
		if e.Op == token.LOR {
			return falseImplies(e.X, p) || falseImplies(e.Y, p)
		}
	}
	return p.neg != nil && p.neg(e)
}

// terminates reports whether a block always leaves the enclosing flow.
func terminates(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.ExprStmt:
		if call, ok := last.X.(*ast.CallExpr); ok {
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				return fun.Name == "panic"
			case *ast.SelectorExpr:
				if id, ok := fun.X.(*ast.Ident); ok {
					return id.Name == "os" && fun.Sel.Name == "Exit" ||
						id.Name == "log" && (fun.Sel.Name == "Fatal" || fun.Sel.Name == "Fatalf" || fun.Sel.Name == "Fatalln")
				}
			}
		}
	}
	return false
}

func (s *state) fileOf(pos token.Pos) *ast.File {
	for _, f := range s.pass.Files {
		if f.FileStart <= pos && pos <= f.FileEnd {
			return f
		}
	}
	return nil
}

// successGuard: the transaction succeeded (XDR302).
func (s *state) successGuard(f *fn) predicate {
	return predicate{pos: func(e ast.Expr) bool {
		return isBool(s.info.TypeOf(e)) && s.exprTaint(f, e).has(kSuccess) && !isComparison(e)
	}}
}

// metaGuard: the authorization-tree value was found in, or equals something
// from, a set built from meta (XDR301). Both sides must be present: a test
// on meta alone (change.Type == …) corroborates nothing.
func (s *state) metaGuard(f *fn) predicate {
	pair := func(x, y ast.Expr) bool {
		tx, ty := s.exprTaint(f, x), s.exprTaint(f, y)
		return tx.has(kMeta) && ty.has(kAuth) || ty.has(kMeta) && tx.has(kAuth)
	}
	side := func(b *ast.BinaryExpr) bool { return pair(b.X, b.Y) }
	return predicate{
		pos: func(e ast.Expr) bool {
			switch e := e.(type) {
			case *ast.BinaryExpr:
				return e.Op == token.EQL && side(e)
			case *ast.IndexExpr: // created[id] on a map[…]bool
				return isBool(s.info.TypeOf(e)) && pair(e.X, e.Index)
			}
			t := s.exprTaint(f, e) // ok of `_, ok := created[id]`, created.Contains(id)
			return isBool(s.info.TypeOf(e)) && t.has(kMeta) && t.has(kAuth)
		},
		neg: func(e ast.Expr) bool {
			b, ok := e.(*ast.BinaryExpr)
			return ok && b.Op == token.NEQ && side(b)
		},
	}
}

// eventGuard: the event's contract ID equals a contract ID derived from the
// asset, or a configured verifier accepted the event (XDR304).
func (s *state) eventGuard(f *fn) predicate {
	both := func(x, y ast.Expr) bool {
		tx, ty := s.exprTaint(f, x), s.exprTaint(f, y)
		return tx.has(kCID) && ty.has(kVerifier) || ty.has(kCID) && tx.has(kVerifier)
	}
	return predicate{
		pos: func(e ast.Expr) bool {
			if b, ok := e.(*ast.BinaryExpr); ok {
				return b.Op == token.EQL && both(b.X, b.Y)
			}
			if call, ok := e.(*ast.CallExpr); ok {
				if callee := s.callee(call); callee != nil && s.cfgEventSanitizer[nameOf(s, callee)] {
					return true
				}
			}
			t := s.exprTaint(f, e)
			return isBool(s.info.TypeOf(e)) && t.has(kCID) && t.has(kVerifier)
		},
		neg: func(e ast.Expr) bool {
			b, ok := e.(*ast.BinaryExpr)
			return ok && b.Op == token.NEQ && both(b.X, b.Y)
		},
	}
}

func isComparison(e ast.Expr) bool {
	b, ok := e.(*ast.BinaryExpr)
	return ok && (b.Op == token.EQL || b.Op == token.NEQ)
}
