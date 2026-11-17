package xdr2xx

// A small local flow: which variables of a function hold a value derived
// from a source. Flow-insensitive (a variable assigned a derived value once
// is derived everywhere in the function, closures included); a call passes
// derivation on only when `through` says so.

import (
	"go/ast"
	"go/token"
	"go/types"
)

type flow struct {
	s       *state
	source  func(e ast.Expr) bool    // e itself is a source
	through func(*ast.CallExpr) bool // a call's result is derived from its arguments
	objs    map[types.Object]bool
}

func (s *state) newFlow(body ast.Node, source func(ast.Expr) bool, through func(*ast.CallExpr) bool) *flow {
	f := &flow{s: s, source: source, through: through, objs: map[types.Object]bool{}}
	for iter := 0; iter < 20; iter++ {
		changed := false
		mark := func(lhs ast.Expr) {
			if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && id.Name != "_" {
				if obj := s.info.ObjectOf(id); obj != nil && !f.objs[obj] {
					f.objs[obj] = true
					changed = true
				}
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i := range n.Lhs {
						if f.derived(n.Rhs[i]) {
							mark(n.Lhs[i])
						}
					}
				} else if len(n.Rhs) == 1 && f.derived(n.Rhs[0]) {
					for _, l := range n.Lhs {
						mark(l)
					}
				}
			case *ast.ValueSpec:
				for i, name := range n.Names {
					if i < len(n.Values) && f.derived(n.Values[i]) || len(n.Values) == 1 && f.derived(n.Values[0]) {
						mark(name)
					}
				}
			case *ast.RangeStmt:
				if f.derived(n.X) {
					if n.Key != nil {
						mark(n.Key)
					}
					if n.Value != nil {
						mark(n.Value)
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
	return f
}

// derived reports whether e holds a value derived from a source.
func (f *flow) derived(e ast.Expr) bool {
	if e == nil {
		return false
	}
	if f.source(e) {
		return true
	}
	switch e := e.(type) {
	case *ast.Ident:
		return f.objs[f.s.info.ObjectOf(e)]
	case *ast.ParenExpr:
		return f.derived(e.X)
	case *ast.StarExpr:
		return f.derived(e.X)
	case *ast.UnaryExpr:
		return f.derived(e.X)
	case *ast.SelectorExpr:
		return f.derived(e.X)
	case *ast.IndexExpr:
		return f.derived(e.X)
	case *ast.SliceExpr:
		return f.derived(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return false
		}
		return f.derived(e.X) || f.derived(e.Y)
	case *ast.CallExpr:
		if tv, ok := f.s.info.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 { // conversion
			return f.derived(e.Args[0])
		}
		if f.through != nil && f.through(e) {
			for _, a := range e.Args {
				if f.derived(a) {
					return true
				}
			}
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				return f.derived(sel.X)
			}
		}
	}
	return false
}

// mentions reports whether e contains a derived sub-expression.
func (f *flow) mentions(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && f.derived(x) {
			found = true
		}
		return !found
	})
	return found
}
