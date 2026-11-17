package xdr4xx

// XDR406 (opt-in): a closed switch over an xdr enum that writes rows.
//
// A switch over an enum of the SDK's xdr package (OperationType,
// LedgerEntryType, ScValType, …) whose cases write rows and that has no
// default drops a value it does not handle without a trace; one whose default
// panics or exits stops the job on it. The usual source of such a value is a
// protocol upgrade: a new operation, entry or value type arrives on upgrade
// day, before the reader is updated. The rule reports such a switch and
// lists the values the SDK declares that it does not handle (when it handles
// all of them, a value a later protocol adds still falls through).
//
// A case body writes rows when it appends, assigns to a field or map entry,
// builds a composite literal or calls a builder or database method. A
// default that returns an error, logs or counts is a decision and is not
// reported.

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer406 = framework.Register(framework.Spec{
	Name:     "enumswitch",
	Doc:      "enumswitch reports closed switches over xdr enums that write rows with no default or a panicking default (XDR406, opt-in)",
	Rules:    []framework.Rule{XDR406},
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run406,
})

func run406(p *framework.Pass) (any, error) {
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	info := p.TypesInfo
	aliases := p.Config().XDRPackageAliases
	insp.Preorder([]ast.Node{(*ast.SwitchStmt)(nil)}, func(n ast.Node) {
		s := n.(*ast.SwitchStmt)
		if s.Tag == nil {
			return
		}
		tv, ok := info.Types[s.Tag]
		if !ok {
			return
		}
		nt := xdrNamed(tv.Type, aliases)
		if nt == nil {
			return
		}
		if b, ok := nt.Underlying().(*types.Basic); !ok || b.Info()&types.IsInteger == 0 {
			return
		}
		declared := enumValues(nt)
		if len(declared) < 2 {
			return
		}
		handled := map[string]bool{}
		var def *ast.CaseClause
		writes := false
		for _, c := range s.Body.List {
			cc := c.(*ast.CaseClause)
			if cc.List == nil {
				def = cc
				continue
			}
			for _, e := range cc.List {
				if v, ok := info.Types[e]; ok && v.Value != nil {
					handled[v.Value.ExactString()] = true
				}
			}
			if writesRows(cc.Body) {
				writes = true
			}
		}
		if !writes {
			return
		}
		panics := def != nil && len(def.Body) > 0 && isExitStmt(info, def.Body[len(def.Body)-1])
		if def != nil && !panics {
			return
		}
		var missing []string
		for _, d := range declared {
			if !handled[d.val] {
				missing = append(missing, d.name)
			}
		}
		how := "has no default, so a value it does not handle is dropped silently"
		if panics {
			how = "panics or exits in its default, so a value it does not handle stops the job"
		}
		which := "it handles every value the SDK declares; a value a later protocol adds"
		if len(missing) > 0 {
			shown := missing
			more := ""
			if len(shown) > 4 {
				more = fmt.Sprintf(" and %d more", len(shown)-4)
				shown = shown[:4]
			}
			which = "it does not handle " + strings.Join(shown, ", ") + more + ", nor a value a later protocol adds; such a value"
		}
		report(p, XDR406.ID, s.Pos(), AssumeEnumClosed, "", fmt.Sprintf(
			"switch over xdr.%s writes rows and %s: %s is lost",
			nt.Obj().Name(), how, which))
	})
	return nil, nil
}

func isExitStmt(info *types.Info, s ast.Stmt) bool {
	es, ok := s.(*ast.ExprStmt)
	return ok && isExitCall(info, es.X)
}

type enumValue struct{ name, val string }

// enumValues returns the constants of the enum's package of its type, by
// value.
func enumValues(nt *types.Named) []enumValue {
	scope := nt.Obj().Pkg().Scope()
	var out []enumValue
	seen := map[string]bool{}
	for _, name := range scope.Names() {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok || !types.Identical(c.Type(), nt) || c.Val().Kind() != constant.Int {
			continue
		}
		v := c.Val().ExactString()
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, enumValue{name: strings.TrimPrefix(name, nt.Obj().Name()), val: v})
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := constant.Int64Val(constant.MakeFromLiteral(out[i].val, 5, 0))
		b, _ := constant.Int64Val(constant.MakeFromLiteral(out[j].val, 5, 0))
		return a < b
	})
	return out
}

// writesRows reports whether statements append, assign to a field or map
// entry, build a composite literal or call a builder or database method.
func writesRows(stmts []ast.Stmt) bool {
	found := false
	for _, s := range stmts {
		ast.Inspect(s, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				found = true
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					switch ast.Unparen(l).(type) {
					case *ast.SelectorExpr, *ast.IndexExpr:
						found = true
					}
				}
			case *ast.CallExpr:
				switch f := ast.Unparen(x.Fun).(type) {
				case *ast.Ident:
					if f.Name == "append" {
						found = true
					}
				case *ast.SelectorExpr:
					n := f.Sel.Name
					if strings.HasPrefix(n, "With") || strings.HasPrefix(n, "Add") || strings.HasPrefix(n, "Exec") || strings.HasPrefix(n, "Insert") {
						found = true
					}
				}
			}
			return !found
		})
	}
	return found
}
