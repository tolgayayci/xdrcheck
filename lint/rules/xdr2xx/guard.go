package xdr2xx

// Guards: a node is guarded by a predicate when, walking out from the node
// to its function,
//
//   - it sits in the then-branch of `if c` where c being true implies the
//     predicate (form inBranch), or in the else-branch where c being false
//     implies it; or
//   - an earlier statement of an enclosing block is `if c { …; exit }`
//     (return, break, continue, goto, panic, os.Exit, log.Fatal…) where c
//     being false implies it (form earlyExit): the exit is the branch taken
//     at the bound.
//
// "c true implies P" follows !, && and parentheses; "c false implies P"
// follows !, || and parentheses. The walk stops at the innermost function
// (declaration or literal) unless crossLiterals is set.

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

type guardForm int

const (
	inBranch guardForm = iota
	inElse
	earlyExit
)

// guard is a found guard: the if statement, the atom of its condition that
// matched, and how the guarded node relates to it.
type guard struct {
	ifStmt *ast.IfStmt
	atom   ast.Expr
	form   guardForm
}

func (s *state) findGuard(node ast.Node, p predicate, crossLiterals bool) *guard {
	file := s.fileOf(node.Pos())
	if file == nil {
		return nil
	}
	path, _ := astutil.PathEnclosingInterval(file, node.Pos(), node.End())
	for i := 1; i < len(path); i++ {
		child, parent := path[i-1], path[i]
		switch parent := parent.(type) {
		case *ast.FuncDecl:
			return nil
		case *ast.FuncLit:
			if !crossLiterals {
				return nil
			}
		case *ast.IfStmt:
			if child == parent.Body {
				if a := trueAtom(parent.Cond, p); a != nil {
					return &guard{ifStmt: parent, atom: a, form: inBranch}
				}
			}
			if child == parent.Else {
				if a := falseAtom(parent.Cond, p); a != nil {
					return &guard{ifStmt: parent, atom: a, form: inElse}
				}
			}
		case *ast.BlockStmt:
			if g := earlyExitGuard(parent.List, child, p); g != nil {
				return g
			}
		case *ast.CaseClause:
			if g := earlyExitGuard(parent.Body, child, p); g != nil {
				return g
			}
		case *ast.CommClause:
			if g := earlyExitGuard(parent.Body, child, p); g != nil {
				return g
			}
		case *ast.ForStmt:
			// for cond; …: the body runs only while cond holds
			if child == parent.Body && parent.Cond != nil {
				if a := trueAtom(parent.Cond, p); a != nil {
					return &guard{atom: a, form: inBranch}
				}
			}
		}
	}
	return nil
}

func earlyExitGuard(stmts []ast.Stmt, child ast.Node, p predicate) *guard {
	for _, st := range stmts {
		if st == child {
			return nil
		}
		if is, ok := st.(*ast.IfStmt); ok && is.Else == nil && terminates(is.Body) {
			if a := falseAtom(is.Cond, p); a != nil {
				return &guard{ifStmt: is, atom: a, form: earlyExit}
			}
		}
	}
	return nil
}

func trueAtom(e ast.Expr, p predicate) ast.Expr {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return trueAtom(e.X, p)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return falseAtom(e.X, p)
		}
	case *ast.BinaryExpr:
		if e.Op == token.LAND {
			if a := trueAtom(e.X, p); a != nil {
				return a
			}
			return trueAtom(e.Y, p)
		}
	}
	if p.pos != nil && p.pos(e) {
		return e
	}
	return nil
}

func falseAtom(e ast.Expr, p predicate) ast.Expr {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return falseAtom(e.X, p)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return trueAtom(e.X, p)
		}
	case *ast.BinaryExpr:
		if e.Op == token.LOR {
			if a := falseAtom(e.X, p); a != nil {
				return a
			}
			return falseAtom(e.Y, p)
		}
	}
	if p.neg != nil && p.neg(e) {
		return e
	}
	return nil
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
		return isProcessEnd(last.X, nil)
	}
	return false
}

// isProcessEnd reports whether e is a call to panic, os.Exit, log.Fatal…,
// or one of the configured halting functions (by qualified or plain name).
func isProcessEnd(e ast.Expr, s *state) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if fun.Name == "panic" {
			return true
		}
	case *ast.SelectorExpr:
		if id, ok := fun.X.(*ast.Ident); ok {
			if id.Name == "os" && fun.Sel.Name == "Exit" ||
				id.Name == "log" && (fun.Sel.Name == "Fatal" || fun.Sel.Name == "Fatalf" || fun.Sel.Name == "Fatalln" ||
					fun.Sel.Name == "Panic" || fun.Sel.Name == "Panicf" || fun.Sel.Name == "Panicln") {
				return true
			}
		}
	}
	if s != nil {
		if callee := s.callee(call); callee != nil && (s.haltingFuncs[s.qname(callee)] || s.haltingFuncs[callee.Name()]) {
			return true
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

// relational splits an ordering comparison (<, <=, >, >=) of a subject
// against something else: it returns the other side, and tooBig, true when
// the comparison holds past the bound (subject > X, subject >= X, X < subject,
// X <= subject). Equality is not a bound: `x == nil` bounds nothing.
func relational(e ast.Expr, isSubject func(ast.Expr) bool) (other ast.Expr, tooBig, ok bool) {
	b, isBin := ast.Unparen(e).(*ast.BinaryExpr)
	if !isBin {
		return nil, false, false
	}
	switch b.Op {
	case token.GTR, token.GEQ, token.LSS, token.LEQ:
	default:
		return nil, false, false
	}
	left := isSubject(b.X)
	right := isSubject(b.Y)
	if left == right {
		return nil, false, false
	}
	other = b.Y
	if right {
		other = b.X
	}
	switch b.Op {
	case token.GTR, token.GEQ:
		return other, left, true
	default: // LSS, LEQ
		return other, right, true
	}
}

// boundPredicate: a comparison of a subject against a bound, true when the
// subject is still within the bound (pos) or false when it is past it (neg).
func boundPredicate(isSubject func(ast.Expr) bool) predicate {
	return predicate{
		pos: func(e ast.Expr) bool {
			_, tooBig, ok := relational(e, isSubject)
			return ok && !tooBig
		},
		neg: func(e ast.Expr) bool {
			_, tooBig, ok := relational(e, isSubject)
			return ok && tooBig
		},
	}
}

// countdownPredicate: a comparison of a decrementing budget against a
// bound, usually 0. The budget is past its bound when it is small
// (b <= 0, b < 1, 0 >= b, b == 0) and within it when it is large (b > 0,
// b != 0).
func countdownPredicate(isSubject func(ast.Expr) bool) predicate {
	equality := func(e ast.Expr) (token.Token, bool) {
		b, ok := ast.Unparen(e).(*ast.BinaryExpr)
		if !ok || (b.Op != token.EQL && b.Op != token.NEQ) || isSubject(b.X) == isSubject(b.Y) {
			return 0, false
		}
		return b.Op, true
	}
	return predicate{
		pos: func(e ast.Expr) bool {
			if op, ok := equality(e); ok {
				return op == token.NEQ
			}
			_, tooBig, ok := relational(e, isSubject)
			return ok && tooBig
		},
		neg: func(e ast.Expr) bool {
			if op, ok := equality(e); ok {
				return op == token.EQL
			}
			_, tooBig, ok := relational(e, isSubject)
			return ok && !tooBig
		},
	}
}
