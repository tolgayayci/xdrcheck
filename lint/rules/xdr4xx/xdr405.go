package xdr4xx

// XDR405: rows from meta that a failed transaction or another phase wrote.
//
// Two shapes of one mistake: reading meta that does not mean what the row
// says.
//
//  1. Diagnostic events of a failed Soroban transaction still record the
//     events of calls that ran before the failure (InSuccessfulContractCall
//     may be true for them), but the transaction rolled them back. A row
//     built from LedgerTransaction.GetDiagnosticEvents() (or a
//     DiagnosticEvents field of the SDK's meta and event types) with no
//     success check (LedgerTransaction.Successful(), Result.Successful(), a
//     variable holding one) in the function or in every same-package caller
//     is a phantom movement (assumption success-gate:diagnostic-events).
//  2. LedgerTransaction.GetChanges() and the TxChangesBefore/TxChangesAfter
//     fields hold the fee, sequence-number and transaction-level changes as
//     well as every operation's. Read in a function that works on one
//     operation (it has an operation index parameter, or works on an
//     operation wrapper), they attribute those changes to that operation
//     (assumption phase:tx-changes-as-op; a warning).
//
// "Builds a row" means the value, or a value ranged from it, is used in a
// composite literal, appended, or assigned to a field or map entry in the
// same function, or passed to a same-package function that does.

import (
	"fmt"
	"go/ast"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer405 = framework.Register(framework.Spec{
	Name:     "metagate",
	Doc:      "metagate reports rows built from diagnostic events without a success gate and transaction-level changes read in operation scope (XDR405)",
	Rules:    []framework.Rule{XDR405},
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run405,
})

var opIndexName = regexp.MustCompile(`(?i)^(op|operation)(index|idx|i)$|^opindex$|^index$`)

func run405(p *framework.Pass) (any, error) {
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	info := p.TypesInfo
	aliases := p.Config().XDRPackageAliases

	isLedgerTx := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		if !ok {
			return false
		}
		t := tv.Type
		if pt, ok := t.Underlying().(*types.Pointer); ok {
			t = pt.Elem()
		}
		n, ok := types.Unalias(t).(*types.Named)
		return ok && n.Obj().Pkg() != nil && catalogue.Canonical(n.Obj().Pkg().Path(), aliases) == catalogue.Ingest && n.Obj().Name() == "LedgerTransaction"
	}
	successCheck := func(e ast.Expr) bool {
		switch s := e.(type) {
		case *ast.SelectorExpr:
			return s.Sel.Name == "Successful" || s.Sel.Name == "TransactionResultCodeTxSuccess" || s.Sel.Name == "TransactionResultCodeTxFeeBumpInnerSuccess"
		case *ast.Ident:
			return strings.Contains(strings.ToLower(s.Name), "success")
		}
		return false
	}

	// Per function: its declaration, and every same-package call of it with
	// its stack, for the callers' success checks.
	decls := map[*types.Func]*ast.FuncDecl{}
	eachFunc(insp, func(fd *ast.FuncDecl) {
		if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
			decls[fn] = fd
		}
	})
	type site struct{ stack []ast.Node }
	callers := map[*types.Func][]site{}
	insp.WithStack([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if push {
			if fn, ok := calleeFunc(info, n.(*ast.CallExpr)); ok && decls[fn] != nil {
				callers[fn] = append(callers[fn], site{append([]ast.Node(nil), stack...)})
			}
		}
		return true
	})
	var gatedAbove func(fn *types.Func, depth int, seen map[*types.Func]bool) bool
	gatedAbove = func(fn *types.Func, depth int, seen map[*types.Func]bool) bool {
		if depth > 4 || seen[fn] {
			return false
		}
		seen[fn] = true
		sites := callers[fn]
		if len(sites) == 0 {
			return false
		}
		for _, s := range sites {
			fd := enclosingFunc(s.stack)
			al := aliasesOf(info, fd.Body, successCheck)
			if guarded(info, s.stack, withAliases(info, successCheck, al)) {
				continue
			}
			caller, _ := info.Defs[fd.Name].(*types.Func)
			if caller == nil || !gatedAbove(caller, depth+1, seen) {
				return false
			}
		}
		return true
	}

	samePkg := func(f *types.Func) bool { return decls[f] != nil }
	// recordsSuccess: the function, or a same-package function it calls,
	// reads the transaction's success into its rows: the rows say whether
	// the transaction failed (an export of the events as they are).
	var recordsSuccess func(fd *ast.FuncDecl) bool
	memo := map[*ast.FuncDecl]bool{}
	recordsSuccess = func(fd *ast.FuncDecl) bool {
		if v, ok := memo[fd]; ok {
			return v
		}
		memo[fd] = false
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			if sel, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Successful" {
				found = true
			}
			if fn, ok := calleeFunc(info, c); ok && decls[fn] != nil && decls[fn] != fd {
				if r, ok := memo[decls[fn]]; ok {
					found = found || r
				} else {
					found = found || recordsSuccess(decls[fn])
				}
			}
			return !found
		})
		memo[fd] = found
		return found
	}
	insp.WithStack([]ast.Node{(*ast.CallExpr)(nil), (*ast.SelectorExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		fd := enclosingFunc(stack)
		if fd == nil {
			return true
		}
		fn, _ := info.Defs[fd.Name].(*types.Func)
		var what string
		var diag, phase bool
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr)
			if !ok || !isLedgerTx(sel.X) {
				return true
			}
			switch sel.Sel.Name {
			case "GetDiagnosticEvents":
				diag, what = true, "LedgerTransaction.GetDiagnosticEvents()"
			case "GetChanges":
				phase, what = true, "LedgerTransaction.GetChanges()"
			}
		case *ast.SelectorExpr:
			tv, ok := info.Types[x.X]
			if !ok {
				return true
			}
			nt := xdrNamed(tv.Type, aliases)
			if nt == nil {
				// ingest.LedgerTransaction / TransactionEvents fields
				t := tv.Type
				if pt, ok := t.Underlying().(*types.Pointer); ok {
					t = pt.Elem()
				}
				if named, ok := types.Unalias(t).(*types.Named); ok && inSDK(named.Obj(), aliases) && x.Sel.Name == "DiagnosticEvents" {
					diag, what = true, named.Obj().Name()+".DiagnosticEvents"
				}
				break
			}
			switch x.Sel.Name {
			case "DiagnosticEvents":
				diag, what = true, "xdr."+nt.Obj().Name()+".DiagnosticEvents"
			case "TxChangesBefore", "TxChangesAfter":
				phase, what = true, "xdr."+nt.Obj().Name()+"."+x.Sel.Name
			}
			if isAssigned(stack) {
				return true
			}
		}
		switch {
		case diag:
			if copiesField(stack) || !buildsRow(info, fd, stack, samePkg) || recordsSuccess(fd) {
				return true
			}
			al := aliasesOf(info, fd.Body, successCheck)
			if guarded(info, stack, withAliases(info, successCheck, al)) || fn != nil && gatedAbove(fn, 0, map[*types.Func]bool{}) {
				return true
			}
			report(p, XDR405.ID, n.Pos(), AssumeDiagnosticSuccess, "", fmt.Sprintf(
				"%s feeds rows with no check that the transaction succeeded, here or in any caller; a failed transaction's diagnostic events record calls that were rolled back, so the rows describe movements that did not happen",
				what))
		case phase:
			if !operationScope(info, fd) || !buildsRow(info, fd, stack, samePkg) {
				return true
			}
			report(p, XDR405.ID, n.Pos(), AssumeTxChangesInOp, framework.SeverityWarning, fmt.Sprintf(
				"%s is read in %s, which works on one operation; it also holds the fee, sequence-number and transaction-level changes, which are then attributed to this operation (use GetOperationChanges)",
				what, fd.Name.Name))
		}
		return true
	})
	return nil, nil
}

// operationScope reports whether a function works on one operation: an
// integer parameter named like an operation index, or a receiver or
// parameter whose type name contains "Operation".
func operationScope(info *types.Info, fd *ast.FuncDecl) bool {
	var fields []*ast.Field
	if fd.Recv != nil {
		fields = append(fields, fd.Recv.List...)
	}
	fields = append(fields, fd.Type.Params.List...)
	for _, f := range fields {
		tv, ok := info.Types[f.Type]
		if !ok {
			continue
		}
		t := tv.Type
		if pt, ok := t.Underlying().(*types.Pointer); ok {
			t = pt.Elem()
		}
		if n, ok := types.Unalias(t).(*types.Named); ok && strings.Contains(n.Obj().Name(), "Operation") {
			return true
		}
		if k := basicKind(t); k >= types.Int && k <= types.Uintptr {
			for _, nm := range f.Names {
				if opIndexName.MatchString(nm.Name) {
					return true
				}
			}
		}
	}
	return false
}

// buildsRow reports whether the value read at the innermost node of stack is
// assigned to a variable that, or whose ranged elements, reach a store in the
// function; or is used directly in one.
func buildsRow(info *types.Info, fd *ast.FuncDecl, stack []ast.Node, via func(*types.Func) bool) bool {
	if storeContextVia(info, stack, via) != "" {
		return true
	}
	// The variables it is assigned to, and the range variables over them.
	vars := map[types.Object]bool{}
	for i := len(stack) - 2; i >= 0; i-- {
		if as, ok := stack[i].(*ast.AssignStmt); ok {
			for _, l := range as.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
					if obj := objOf(info, id); obj != nil {
						vars[obj] = true
					}
				}
			}
			break
		}
		if r, ok := stack[i].(*ast.RangeStmt); ok {
			for _, e := range []ast.Expr{r.Key, r.Value} {
				if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
					if obj := objOf(info, id); obj != nil {
						vars[obj] = true
					}
				}
			}
			break
		}
		if _, ok := stack[i].(ast.Stmt); ok {
			break
		}
	}
	if len(vars) == 0 {
		return false
	}
	// Close over ranges and assignments from these variables.
	for round := 0; round < 4; round++ {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.RangeStmt:
				if mentionsAny(info, s.X, vars) {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
							if obj := objOf(info, id); obj != nil {
								vars[obj] = true
							}
						}
					}
				}
			case *ast.AssignStmt:
				for _, r := range s.Rhs {
					if mentionsAny(info, r, vars) {
						for _, l := range s.Lhs {
							if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
								if obj := objOf(info, id); obj != nil {
									vars[obj] = true
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	found := false
	var st []ast.Node
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == nil {
			st = st[:len(st)-1]
			return true
		}
		st = append(st, n)
		if id, ok := n.(*ast.Ident); ok && vars[info.Uses[id]] {
			if w := storeContextVia(info, st, via); w != "" && w != "field DiagnosticEvents" {
				found = true
			}
		}
		return true
	})
	return found
}

func mentionsAny(info *types.Info, e ast.Node, vars map[types.Object]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && vars[info.Uses[id]] {
			found = true
		}
		return !found
	})
	return found
}

// copiesField reports whether the read is copied into a field of the same
// name (an accessor that passes the events on: the caller decides).
func copiesField(stack []ast.Node) bool {
	n := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		switch s := stack[i].(type) {
		case *ast.AssignStmt:
			for j, r := range s.Rhs {
				if r == n && j < len(s.Lhs) {
					if sel, ok := s.Lhs[j].(*ast.SelectorExpr); ok && sel.Sel.Name == "DiagnosticEvents" {
						return true
					}
				}
			}
			return false
		case *ast.KeyValueExpr:
			if id, ok := s.Key.(*ast.Ident); ok && id.Name == "DiagnosticEvents" && s.Value == n {
				return true
			}
			return false
		case *ast.ParenExpr:
			n = s
			continue
		}
		return false
	}
	return false
}
