package xdr4xx

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// The guard model of the syntax-based rules: a condition guards a node when
//
//   - the node sits in the then- or else-branch of an `if` whose condition
//     (or init statement) satisfies the predicate, or in a case of a
//     `switch` whose tag or case expressions satisfy it, or
//   - an earlier statement of an enclosing block is an `if` whose condition
//     satisfies it and whose body always leaves (return, continue, break,
//     goto, panic, a Fatal call, os.Exit).
//
// The predicate sees each expression of the condition; idents bound earlier
// in the function to an expression it accepts count as that expression
// (`v := meta.V; if v != 4 { … }`).

// cond is a predicate on one expression.
type cond func(ast.Expr) bool

// guarded reports whether the innermost node of stack is guarded by a
// condition containing an expression p accepts.
func guarded(info *types.Info, stack []ast.Node, p cond) bool {
	mentions := func(n ast.Node) bool {
		if n == nil {
			return false
		}
		found := false
		ast.Inspect(n, func(x ast.Node) bool {
			if found {
				return false
			}
			if e, ok := x.(ast.Expr); ok && p(e) {
				found = true
			}
			return !found
		})
		return found
	}
	for i := len(stack) - 2; i >= 0; i-- {
		child := stack[i+1]
		switch s := stack[i].(type) {
		case *ast.IfStmt:
			if child == s.Body || child == s.Else {
				if mentions(s.Cond) || mentions(s.Init) {
					return true
				}
			}
		case *ast.CaseClause:
			for _, st := range s.Body {
				if st == child {
					break
				}
				if is, ok := st.(*ast.IfStmt); ok && (mentions(is.Cond) || mentions(is.Init)) && leaves(info, is.Body) {
					return true
				}
			}
			if i > 1 {
				if sw, ok := stack[i-2].(*ast.SwitchStmt); ok {
					if mentions(sw.Tag) || mentions(sw.Init) {
						return true
					}
					for _, e := range s.List {
						if mentions(e) {
							return true
						}
					}
				}
				if sw, ok := stack[i-2].(*ast.TypeSwitchStmt); ok && mentions(sw.Assign) {
					return true
				}
			}
		case *ast.ForStmt:
			if child == s.Body && mentions(s.Cond) {
				return true
			}
		case *ast.BinaryExpr:
			// `ok && x.MustSym()`: the right operand of && or || is
			// evaluated only after the left.
			if (s.Op == token.LAND || s.Op == token.LOR) && child == s.Y && mentions(s.X) {
				return true
			}
		case *ast.BlockStmt:
			for _, st := range s.List {
				if st == child {
					break
				}
				if is, ok := st.(*ast.IfStmt); ok && (mentions(is.Cond) || mentions(is.Init)) && leaves(info, is.Body) {
					return true
				}
				if sw, ok := st.(*ast.SwitchStmt); ok && (mentions(sw.Tag) || mentions(sw.Init)) {
					// A switch whose every arm leaves except the ones that
					// fall out to the node is still a check: count it.
					return true
				}
			}
		}
		if _, ok := stack[i].(*ast.FuncLit); ok {
			continue
		}
		if _, ok := stack[i].(*ast.FuncDecl); ok {
			break
		}
	}
	return false
}

// leaves reports whether a block always leaves the enclosing flow.
func leaves(info *types.Info, b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	return terminal(info, b.List[len(b.List)-1])
}

func terminal(info *types.Info, s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.ExprStmt:
		return isExitCall(info, s.X)
	case *ast.BlockStmt:
		return leaves(info, s)
	case *ast.IfStmt:
		if s.Else == nil {
			return false
		}
		e, ok := s.Else.(ast.Stmt)
		return ok && leaves(info, s.Body) && terminal(info, e)
	}
	return false
}

// isExitCall reports whether e is panic(…), os.Exit(…), log.Fatal… or a
// method named Fatal, Fatalf, Panic or Panicf.
func isExitCall(info *types.Info, e ast.Expr) bool {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		if b, ok := info.Uses[f].(*types.Builtin); ok && b.Name() == "panic" {
			return true
		}
	case *ast.SelectorExpr:
		switch f.Sel.Name {
		case "Exit":
			if obj, ok := info.Uses[f.Sel].(*types.Func); ok && obj.Pkg() != nil && obj.Pkg().Path() == "os" {
				return true
			}
		case "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
			return true
		}
	}
	return false
}

// halts reports whether a block halts the job: it panics or exits, or
// returns a non-nil error from a function whose last result is an error.
func halts(info *types.Info, b *ast.BlockStmt, sig *types.Signature) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch s := b.List[len(b.List)-1].(type) {
	case *ast.ExprStmt:
		return isExitCall(info, s.X)
	case *ast.ReturnStmt:
		if sig == nil || sig.Results().Len() == 0 || len(s.Results) != sig.Results().Len() {
			return false
		}
		last := sig.Results().At(sig.Results().Len() - 1).Type()
		if !types.Identical(last, types.Universe.Lookup("error").Type()) {
			return false
		}
		r := ast.Unparen(s.Results[len(s.Results)-1])
		if id, ok := r.(*ast.Ident); ok && id.Name == "nil" {
			return false
		}
		return true
	}
	return false
}

// enclosingSig returns the signature of the innermost function of stack.
func enclosingSig(info *types.Info, stack []ast.Node) *types.Signature {
	for i := len(stack) - 1; i >= 0; i-- {
		switch f := stack[i].(type) {
		case *ast.FuncLit:
			if t, ok := info.Types[f].Type.(*types.Signature); ok {
				return t
			}
			return nil
		case *ast.FuncDecl:
			if obj, ok := info.Defs[f.Name].(*types.Func); ok {
				return obj.Type().(*types.Signature)
			}
			return nil
		}
	}
	return nil
}

// enclosingFunc returns the innermost FuncDecl of stack.
func enclosingFunc(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if f, ok := stack[i].(*ast.FuncDecl); ok {
			return f
		}
	}
	return nil
}

// xdrNamed returns the named type of the SDK's xdr package that t is (or
// points to), or nil.
func xdrNamed(t types.Type, aliases []string) *types.Named {
	if t == nil {
		return nil
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		if _, isNamed := t.(*types.Named); !isNamed {
			t = p.Elem()
		}
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || catalogue.Canonical(n.Obj().Pkg().Path(), aliases) != catalogue.XDR {
		return nil
	}
	return n
}

// inSDK reports whether an object is declared in the go-stellar-sdk module.
func inSDK(obj types.Object, aliases []string) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	p := catalogue.Canonical(obj.Pkg().Path(), aliases)
	return p == catalogue.SDKModule || strings.HasPrefix(p, catalogue.SDKModule+"/")
}

// sameExpr reports whether two expressions are written the same.
func sameExpr(a, b ast.Expr) bool {
	return types.ExprString(ast.Unparen(a)) == types.ExprString(ast.Unparen(b))
}

// aliasesOf returns the objects of the function body's variables assigned
// (with := or =, or in a var declaration) an expression p accepts.
func aliasesOf(info *types.Info, body ast.Node, p cond) map[types.Object]bool {
	out := map[types.Object]bool{}
	if body == nil {
		return out
	}
	accept := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(x ast.Node) bool {
			if ex, ok := x.(ast.Expr); ok && p(ex) {
				found = true
			}
			return !found
		})
		return found
	}
	var stack []ast.Node
	underCheck := func() bool {
		// An assignment inside an if whose condition p accepts
		// (`for … { if len(t) == n { matched = true } }`).
		for i := len(stack) - 2; i >= 0; i-- {
			if is, ok := stack[i].(*ast.IfStmt); ok && accept(is.Cond) {
				return true
			}
		}
		return false
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 && (accept(s.Rhs[0]) || underCheck()) {
				for _, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
						if obj := objOf(info, id); obj != nil {
							out[obj] = true
						}
					}
				}
			} else if len(s.Lhs) == len(s.Rhs) {
				for i, r := range s.Rhs {
					if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" && accept(r) {
						if obj := objOf(info, id); obj != nil {
							out[obj] = true
						}
					}
				}
			}
		case *ast.ValueSpec:
			for i, v := range s.Values {
				if i < len(s.Names) && accept(v) {
					if obj := info.Defs[s.Names[i]]; obj != nil {
						out[obj] = true
					}
				}
			}
		}
		return true
	})
	return out
}

func objOf(info *types.Info, id *ast.Ident) types.Object {
	if o := info.Defs[id]; o != nil {
		return o
	}
	return info.Uses[id]
}

// withAliases extends p to idents bound to an expression p accepts.
func withAliases(info *types.Info, p cond, al map[types.Object]bool) cond {
	return func(e ast.Expr) bool {
		if p(e) {
			return true
		}
		if id, ok := e.(*ast.Ident); ok && al[info.Uses[id]] {
			return true
		}
		return false
	}
}

// funcBodies calls f with every declared function of the files and the
// inspector's stack machinery.
func eachFunc(insp *inspector.Inspector, f func(fd *ast.FuncDecl)) {
	insp.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(n ast.Node) {
		fd := n.(*ast.FuncDecl)
		if fd.Body != nil {
			f(fd)
		}
	})
}

// report is a shorthand for the framework report.
func report(p *framework.Pass, rule string, pos token.Pos, assume string, sev framework.Severity, msg string) {
	if skipFile(p.Fset, pos) {
		return
	}
	p.Report(framework.Report{Rule: rule, Pos: pos, Message: msg, Assumption: assume, Severity: sev})
}

// skipFile reports whether a file is test support code that ships in the
// package (a test helper or builder, an integration-test harness, a load
// generator): reads there build inputs, they do not index ledgers.
func skipFile(fset *token.FileSet, pos token.Pos) bool {
	name := fset.Position(pos).Filename
	if strings.Contains(name, "/lint/testdata/") {
		return false
	}
	base := strings.ToLower(filepath.Base(name))
	for _, p := range []string{"test_util", "testutil", "_test_", "mock_", "_mock"} {
		if strings.Contains(base, p) {
			return true
		}
	}
	for _, d := range []string{"/integrationtests/", "/loadtest/", "/testutil", "/mocks/"} {
		if strings.Contains(name, d) {
			return true
		}
	}
	return false
}
