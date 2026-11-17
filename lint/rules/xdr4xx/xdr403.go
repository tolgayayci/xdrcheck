package xdr4xx

// XDR403: an error or ok result discarded on a value that is then stored.
//
// `v, _ := f(…)` throws away the only signal that v is not a real value. When
// f parses or renders ledger data (a strkey, a number, an address, an arm of
// a union) and v is then written into a row, a failure stores a zero value
// that cannot be told apart from a real one: an empty address, amount 0, a
// zero muxed ID.
//
// The rule reports an assignment whose last left-hand operand is the blank
// identifier and whose right-hand side is one call
//
//   - returning (…, error), of a function of the SDK module (xdr, strkey,
//     amount, ingest, processors, …), strconv, encoding/hex,
//     encoding/base64, encoding/json, math/big or time, or
//   - big.Int.SetString (its ok result),
//
// except calls the input cannot make fail: strkey.Encode of a 32-byte array,
// and a parse of a string field of an SDK struct (the SDK formatted it).
// A discarded ok of an xdr Get<Arm>() accessor is not reported: reading every
// arm and keeping the zero value of the others is a common, deliberate
// layout (one wide row per union); XDR105 covers the arm reads that panic.
//
// when a variable it assigns is later used, in the same function, as part of
// a composite literal, the right side of an assignment to a field, map entry
// or slice element, an argument of append, or an argument of a database call
// or a builder (With…, Set…). A variable compared or tested in a condition
// between the two (`if v == "" { … }`) counts as checked.

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer403 = framework.Register(framework.Spec{
	Name:     "discardederr",
	Doc:      "discardederr reports errors and ok results discarded on values that are then stored (XDR403)",
	Rules:    []framework.Rule{XDR403},
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run403,
})

var errPkgs = map[string]bool{
	"strconv": true, "encoding/hex": true, "encoding/base64": true, "encoding/json": true, "math/big": true, "time": true,
}

func run403(p *framework.Pass) (any, error) {
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	info := p.TypesInfo
	aliases := p.Config().XDRPackageAliases
	eachFunc(insp, func(fd *ast.FuncDecl) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || len(as.Lhs) < 2 {
				return true
			}
			last, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
			if !ok || last.Name != "_" {
				return true
			}
			call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := calleeFunc(info, call)
			if !ok {
				return true
			}
			sig := fn.Type().(*types.Signature)
			res := sig.Results()
			if res.Len() != len(as.Lhs) {
				return true
			}
			lastT := res.At(res.Len() - 1).Type()
			isErr := types.Identical(lastT, types.Universe.Lookup("error").Type())
			isOK := basicKind(lastT) == types.Bool
			switch {
			case isErr && (inSDK(fn, aliases) || fn.Pkg() != nil && errPkgs[fn.Pkg().Path()]):
			case isOK && fn.Name() == "SetString" && fn.Pkg() != nil && fn.Pkg().Path() == "math/big":
			default:
				return true
			}
			if cannotFail(info, fd.Body, fn, call, aliases) {
				return true
			}
			for _, l := range as.Lhs[:len(as.Lhs)-1] {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				obj := objOf(info, id)
				if obj == nil {
					continue
				}
				if where := storedUse(info, fd.Body, obj, as.End()); where != "" {
					what := "error"
					if isOK {
						what = "ok result"
					}
					report(p, XDR403.ID, as.Pos(), AssumeDiscardedError, "", fmt.Sprintf(
						"the %s of %s is discarded and %s is then stored (%s); when the call fails, a zero value is stored as if it were real",
						what, funcName(fn), id.Name, where))
					break
				}
			}
			return true
		})
	})
	return nil, nil
}

func calleeFunc(info *types.Info, c *ast.CallExpr) (*types.Func, bool) {
	var id *ast.Ident
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return nil, false
	}
	fn, ok := info.Uses[id].(*types.Func)
	return fn, ok
}

func funcName(fn *types.Func) string {
	sig := fn.Type().(*types.Signature)
	if sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := types.Unalias(t).(*types.Named); ok {
			return n.Obj().Pkg().Name() + "." + n.Obj().Name() + "." + fn.Name() + "()"
		}
	}
	if fn.Pkg() != nil {
		return fn.Pkg().Name() + "." + fn.Name() + "()"
	}
	return fn.Name() + "()"
}

// storedUse returns where obj is stored after pos, or "" when it is not, or
// when a condition tests it first.
func storedUse(info *types.Info, body *ast.BlockStmt, obj types.Object, after token.Pos) string {
	where := ""
	checkedAt := token.NoPos
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || info.Uses[id] != obj || id.Pos() < after {
			return true
		}
		if inCondition(stack) {
			if checkedAt == token.NoPos || id.Pos() < checkedAt {
				checkedAt = id.Pos()
			}
			return true
		}
		if w := storeContext(info, stack); w != "" && where == "" && (checkedAt == token.NoPos || id.Pos() < checkedAt) {
			where = w
		}
		return true
	})
	return where
}

// inCondition reports whether the innermost node is part of an if, switch or
// for condition.
func inCondition(stack []ast.Node) bool {
	for i := len(stack) - 2; i >= 0; i-- {
		child := stack[i+1]
		switch s := stack[i].(type) {
		case *ast.IfStmt:
			return child == s.Cond
		case *ast.SwitchStmt:
			return child == s.Tag
		case *ast.ForStmt:
			return child == s.Cond
		case *ast.BlockStmt, *ast.FuncLit:
			return false
		}
	}
	return false
}

// storeContext names the store the innermost node is part of, or "".
func storeContext(info *types.Info, stack []ast.Node) string {
	return storeContextVia(info, stack, nil)
}

// storeContextVia is storeContext where an argument of a call that via
// accepts (a same-package row builder) also counts as stored.
func storeContextVia(info *types.Info, stack []ast.Node, via func(*types.Func) bool) string {
	for i := len(stack) - 2; i >= 0; i-- {
		child := stack[i+1]
		switch s := stack[i].(type) {
		case *ast.CompositeLit:
			return "a composite literal"
		case *ast.KeyValueExpr:
			continue
		case *ast.AssignStmt:
			for j, r := range s.Rhs {
				if r != child || j >= len(s.Lhs) && len(s.Lhs) != 1 {
					continue
				}
				l := s.Lhs[0]
				if len(s.Lhs) == len(s.Rhs) {
					l = s.Lhs[j]
				}
				switch l := ast.Unparen(l).(type) {
				case *ast.SelectorExpr:
					return "field " + l.Sel.Name
				case *ast.IndexExpr:
					return "an element of " + types.ExprString(l.X)
				}
			}
			return ""
		case *ast.CallExpr:
			switch f := ast.Unparen(s.Fun).(type) {
			case *ast.Ident:
				if f.Name == "append" && child != s.Args[0] {
					return "append"
				}
			case *ast.SelectorExpr:
				n := f.Sel.Name
				if strings.HasPrefix(n, "With") || strings.HasPrefix(n, "Set") || strings.HasPrefix(n, "Exec") || strings.HasPrefix(n, "Insert") {
					return "the argument of " + n + "()"
				}
			}
			if fn, ok := calleeFunc(info, s); ok && via != nil && via(fn) {
				continue
			}
			// Through a conversion or a formatting call.
			if tv, ok := info.Types[s.Fun]; ok && tv.IsType() {
				continue
			}
			if fn, ok := calleeFunc(info, s); ok && fn.Pkg() != nil && (fn.Pkg().Path() == "fmt" || fn.Pkg().Path() == "strconv") {
				continue
			}
			if sel, ok := ast.Unparen(s.Fun).(*ast.SelectorExpr); ok && (sel.Sel.Name == "String" || sel.Sel.Name == "Address") {
				continue
			}
			return ""
		case *ast.UnaryExpr, *ast.ParenExpr, *ast.StarExpr, *ast.SelectorExpr, *ast.BinaryExpr:
			continue
		case *ast.ReturnStmt, *ast.ExprStmt, *ast.BlockStmt, *ast.IfStmt, *ast.RangeStmt, *ast.ForStmt:
			return ""
		}
	}
	return ""
}

// cannotFail reports calls whose error the input cannot trigger:
// strkey.Encode of a fixed 32-byte array (a contract or account ID), and a
// parse of a string the SDK itself formatted (a field of an SDK struct, such
// as a token-transfer amount).
func cannotFail(info *types.Info, body *ast.BlockStmt, fn *types.Func, call *ast.CallExpr, aliases []string) bool {
	// every reports whether e, or every value assigned to the variable e
	// names in the function, satisfies ok.
	every := func(e ast.Expr, ok func(ast.Expr) bool) bool {
		e = ast.Unparen(e)
		if ok(e) {
			return true
		}
		id, isID := e.(*ast.Ident)
		if !isID || info.Uses[id] == nil {
			return false
		}
		obj, n, all := info.Uses[id], 0, true
		ast.Inspect(body, func(x ast.Node) bool {
			as, isAs := x.(*ast.AssignStmt)
			if !isAs {
				return true
			}
			for i, l := range as.Lhs {
				lid, isL := l.(*ast.Ident)
				if !isL || objOf(info, lid) != obj {
					continue
				}
				n++
				switch {
				case len(as.Lhs) == len(as.Rhs):
					all = all && ok(ast.Unparen(as.Rhs[i]))
				case len(as.Rhs) == 1 && i == 0:
					all = all && ok(ast.Unparen(as.Rhs[0]))
				default:
					all = false
				}
			}
			return true
		})
		return n > 0 && all
	}
	fixed32 := func(e ast.Expr) bool {
		t := types.Type(nil)
		switch x := e.(type) {
		case *ast.SliceExpr:
			if tv, ok := info.Types[x.X]; ok {
				t = tv.Type
			}
		case *ast.CallExpr: // h.MarshalBinary() of a fixed-size hash
			if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "MarshalBinary" {
				if tv, ok := info.Types[sel.X]; ok {
					t = tv.Type
				}
			}
		}
		if t == nil {
			return false
		}
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = p.Elem()
		}
		a, ok := t.Underlying().(*types.Array)
		return ok && a.Len() == 32
	}
	sdkField := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		obj, ok := info.Uses[sel.Sel].(*types.Var)
		return ok && obj.IsField() && inSDK(obj, aliases)
	}
	if fn.Name() == "Encode" && inSDK(fn, aliases) && len(call.Args) == 2 && every(call.Args[1], fixed32) {
		return true
	}
	if fn.Pkg() != nil && fn.Pkg().Path() == "strconv" && len(call.Args) > 0 && every(call.Args[0], sdkField) {
		return true
	}
	return false
}
