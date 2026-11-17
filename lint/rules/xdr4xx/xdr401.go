package xdr4xx

// XDR401: one meta version assumed.
//
// TransactionMeta and LedgerCloseMeta are unions over a version number V.
// Which version a reader receives depends on where the ledgers come from, not
// only on the protocol: the public data lake re-encodes all history as
// TransactionMeta v4, captive core and older datastores emit v1–v3 for older
// ledgers, and a later protocol adds versions. The rule reports:
//
//  1. an arm read without a version check of the same value: X.MustV3(),
//     X.V4.… (a nil dereference on another version) or X.V0 (silently empty
//     on another version), where no enclosing or earlier `if`/`switch`
//     mentions X.V, X.GetVn() or a variable bound to them;
//  2. a version check that halts on the versions it does not accept: `if
//     X.V != 4 { return err }`, `if X.V < 3 { panic(…) }`, or `switch X.V`
//     whose default returns an error or panics, when the accepted versions do
//     not cover every version the SDK declares. A default that halts after
//     every declared version is handled is the reviewed-version policy and is
//     not reported.
//
// Assignments to an arm (building meta in a test helper) are not reads.

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer401 = framework.Register(framework.Spec{
	Name:     "metaversion",
	Doc:      "metaversion reports reads of one TransactionMeta or LedgerCloseMeta version without a version check, and version checks that halt on the others (XDR401)",
	Rules:    []framework.Rule{XDR401},
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run401,
})

// producible lists, per union, the versions the rule takes as emitted by a
// current stellar-core when it replays or closes ledgers (an assumption of
// the rule, not checked against stellar-core): TransactionMeta v2 to v4,
// LedgerCloseMeta v0 to v2. Rejecting only TransactionMeta v0 or v1 is not
// reported.
var producible = map[string][]int{"TransactionMeta": {2, 3, 4}, "LedgerCloseMeta": {0, 1, 2}}

// metaTypes are the versioned unions XDR401 knows.
var metaTypes = map[string]string{"TransactionMeta": "TransactionMeta", "LedgerCloseMeta": "LedgerCloseMeta"}

// versions returns the arms (V numbers) a versioned union declares: its
// Get<Vn> methods.
func versions(n *types.Named) []int {
	var out []int
	ms := types.NewMethodSet(types.NewPointer(n))
	for i := 0; i < ms.Len(); i++ {
		name := ms.At(i).Obj().Name()
		if rest, ok := strings.CutPrefix(name, "GetV"); ok {
			if k, err := strconv.Atoi(rest); err == nil {
				out = append(out, k)
			}
		}
	}
	// TransactionMeta's v0 arm is Operations (GetOperations), not V0.
	if ms.Lookup(n.Obj().Pkg(), "GetOperations") != nil && !slices.Contains(out, 0) {
		out = append(out, 0)
	}
	slices.Sort(out)
	return out
}

func run401(p *framework.Pass) (any, error) {
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	info := p.TypesInfo
	aliases := p.Config().XDRPackageAliases
	metaOf := func(e ast.Expr) *types.Named {
		tv, ok := info.Types[e]
		if !ok {
			return nil
		}
		n := xdrNamed(tv.Type, aliases)
		if n == nil || metaTypes[n.Obj().Name()] == "" {
			return nil
		}
		return n
	}
	// isVersionOf: e reads the version of x (x.V, x.GetVn(), x.MustVn() as
	// a value inside a check).
	isVersionOf := func(x ast.Expr) cond {
		return func(e ast.Expr) bool {
			switch s := e.(type) {
			case *ast.SelectorExpr:
				return s.Sel.Name == "V" && sameExpr(s.X, x)
			case *ast.CallExpr:
				if sel, ok := ast.Unparen(s.Fun).(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "GetV") {
					return sameExpr(sel.X, x)
				}
			}
			return false
		}
	}
	done := map[token.Pos]bool{}
	insp.WithStack([]ast.Node{(*ast.SelectorExpr)(nil), (*ast.IfStmt)(nil), (*ast.SwitchStmt)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		fd := enclosingFunc(stack)
		if fd == nil {
			return true
		}
		switch n := n.(type) {
		case *ast.SelectorExpr:
			arm, ok := strings.CutPrefix(n.Sel.Name, "V")
			if !ok {
				arm, ok = strings.CutPrefix(n.Sel.Name, "MustV")
				if !ok {
					return true
				}
			}
			k, err := strconv.Atoi(arm)
			if err != nil {
				return true
			}
			mt := metaOf(n.X)
			if mt == nil || done[n.Pos()] {
				return true
			}
			// Not a read: the left side of an assignment, or &x.Vn.
			if isAssigned(stack) {
				return true
			}
			al := aliasesOf(info, fd.Body, isVersionOf(n.X))
			if guarded(info, stack, withAliases(info, isVersionOf(n.X), al)) {
				return true
			}
			done[n.Pos()] = true
			key := versionKey(mt, []int{k})
			what := types.ExprString(n)
			effect := "panics (nil dereference)"
			if strings.HasPrefix(n.Sel.Name, "MustV") {
				what += "()"
				effect = "panics"
			} else if mt.Obj().Name() == "TransactionMeta" && k == 0 {
				effect = "is silently empty"
			}
			report(p, XDR401.ID, n.Sel.Pos(), key, "", fmt.Sprintf(
				"%s reads the v%d arm of xdr.%s with no check of %s.V; on a ledger with another version (%s) it %s",
				what, k, mt.Obj().Name(), types.ExprString(n.X), others(versions(mt), []int{k}), effect))
		case *ast.IfStmt:
			check401If(p, info, n, stack, metaOf, aliasesOf, isVersionOf, fd)
		case *ast.SwitchStmt:
			check401Switch(p, info, n, stack, metaOf, isVersionOf, fd)
		}
		return true
	})
	return nil, nil
}

func isAssigned(stack []ast.Node) bool {
	n := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		switch s := stack[i].(type) {
		case *ast.AssignStmt:
			for _, l := range s.Lhs {
				if l == n {
					return true
				}
			}
			return false
		case *ast.SelectorExpr, *ast.IndexExpr, *ast.ParenExpr, *ast.StarExpr:
			n = s
			continue
		case *ast.UnaryExpr:
			return s.Op == token.AND
		}
		return false
	}
	return false
}

// versionExpr finds, in e, the meta whose version it reads: x.V, or an ident
// bound to x.V.
func versionExpr(info *types.Info, e ast.Expr, fd *ast.FuncDecl, metaOf func(ast.Expr) *types.Named) (ast.Expr, *types.Named) {
	e = ast.Unparen(e)
	if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == "V" {
		if mt := metaOf(sel.X); mt != nil {
			return sel.X, mt
		}
	}
	if id, ok := e.(*ast.Ident); ok {
		obj := info.Uses[id]
		var x ast.Expr
		var mt *types.Named
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, l := range as.Lhs {
				if lid, ok := l.(*ast.Ident); ok && objOf(info, lid) == obj {
					if sel, ok := ast.Unparen(as.Rhs[i]).(*ast.SelectorExpr); ok && sel.Sel.Name == "V" {
						if m := metaOf(sel.X); m != nil {
							x, mt = sel.X, m
						}
					}
				}
			}
			return true
		})
		return x, mt
	}
	return nil, nil
}

func constInt(info *types.Info, e ast.Expr) (int, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0, false
	}
	v, ok := constant.Int64Val(tv.Value)
	return int(v), ok
}

func check401If(p *framework.Pass, info *types.Info, s *ast.IfStmt, stack []ast.Node, metaOf func(ast.Expr) *types.Named,
	_ func(*types.Info, ast.Node, cond) map[types.Object]bool, _ func(ast.Expr) cond, fd *ast.FuncDecl) {
	be, ok := ast.Unparen(s.Cond).(*ast.BinaryExpr)
	if !ok {
		return
	}
	// The last arm of an else-if chain: the earlier arms accepted other
	// versions (GetV1, GetV2, …), which this check alone does not show.
	if len(stack) > 1 {
		if parent, ok := stack[len(stack)-2].(*ast.IfStmt); ok && parent.Else == s {
			return
		}
	}
	x, mt := versionExpr(info, be.X, fd, metaOf)
	k, isConst := constInt(info, be.Y)
	op := be.Op
	if x == nil {
		x, mt = versionExpr(info, be.Y, fd, metaOf)
		k, isConst = constInt(info, be.X)
		op = flip(op)
	}
	if x == nil || !isConst {
		return
	}
	all := versions(mt)
	sig := enclosingSig(info, stack)
	// The versions for which the condition holds.
	holds := func(v int) bool {
		switch op {
		case token.EQL:
			return v == k
		case token.NEQ:
			return v != k
		case token.LSS:
			return v < k
		case token.LEQ:
			return v <= k
		case token.GTR:
			return v > k
		case token.GEQ:
			return v >= k
		}
		return false
	}
	var accepted []int
	switch {
	case halts(info, s.Body, sig):
		for _, v := range all {
			if !holds(v) {
				accepted = append(accepted, v)
			}
		}
	case s.Else != nil && haltsStmt(info, s.Else, sig):
		for _, v := range all {
			if holds(v) {
				accepted = append(accepted, v)
			}
		}
	default:
		return
	}
	rejected := others(all, accepted)
	if rejected == "" || others(producible[mt.Obj().Name()], accepted) == "" {
		return
	}
	report(p, XDR401.ID, s.Pos(), versionKey(mt, accepted), "", fmt.Sprintf(
		"the check of %s.V accepts only %s and halts the job otherwise (an error or a panic); xdr.%s %s from captive core, older history or a later protocol stops the export",
		types.ExprString(x), list(accepted), mt.Obj().Name(), rejected))
}

func haltsStmt(info *types.Info, s ast.Stmt, sig *types.Signature) bool {
	if b, ok := s.(*ast.BlockStmt); ok {
		return halts(info, b, sig)
	}
	return false
}

func flip(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.GTR:
		return token.LSS
	case token.LEQ:
		return token.GEQ
	case token.GEQ:
		return token.LEQ
	}
	return op
}

func check401Switch(p *framework.Pass, info *types.Info, s *ast.SwitchStmt, stack []ast.Node, metaOf func(ast.Expr) *types.Named,
	_ func(ast.Expr) cond, fd *ast.FuncDecl) {
	if s.Tag == nil {
		return
	}
	x, mt := versionExpr(info, s.Tag, fd, metaOf)
	if x == nil {
		return
	}
	sig := enclosingSig(info, stack)
	var accepted []int
	var def *ast.CaseClause
	for _, c := range s.Body.List {
		cc := c.(*ast.CaseClause)
		if cc.List == nil {
			def = cc
			continue
		}
		for _, e := range cc.List {
			if k, ok := constInt(info, e); ok {
				accepted = append(accepted, k)
			}
		}
	}
	if def == nil || !halts(info, &ast.BlockStmt{List: def.Body}, sig) {
		return
	}
	rejected := others(versions(mt), accepted)
	if rejected == "" || others(producible[mt.Obj().Name()], accepted) == "" {
		return
	}
	slices.Sort(accepted)
	report(p, XDR401.ID, s.Pos(), versionKey(mt, accepted), "", fmt.Sprintf(
		"switch on %s.V handles %s and its default halts the job (an error or a panic); xdr.%s %s from captive core, older history or a later protocol stops the export",
		types.ExprString(x), list(accepted), mt.Obj().Name(), rejected))
}

// versionKey returns the assumption key for accepting only these versions.
func versionKey(mt *types.Named, accepted []int) string {
	if len(accepted) == 1 {
		k := accepted[0]
		switch mt.Obj().Name() {
		case "TransactionMeta":
			if k >= 0 && k < len(AssumeMetaV) {
				return AssumeMetaV[k]
			}
		case "LedgerCloseMeta":
			if k >= 0 && k < len(AssumeLCMV) {
				return AssumeLCMV[k]
			}
		}
	}
	if mt.Obj().Name() == "LedgerCloseMeta" {
		return AssumeLCMSubset
	}
	return AssumeMetaSubset
}

// others names the declared versions not in accepted: "v0–v3", "v1, v3" or
// "" when none.
func others(all, accepted []int) string {
	var rest []int
	for _, v := range all {
		if !slices.Contains(accepted, v) {
			rest = append(rest, v)
		}
	}
	if len(rest) == 0 {
		return ""
	}
	return list(rest)
}

func list(vs []int) string {
	if len(vs) == 0 {
		return "no version"
	}
	var parts []string
	for i := 0; i < len(vs); {
		j := i
		for j+1 < len(vs) && vs[j+1] == vs[j]+1 {
			j++
		}
		switch {
		case j-i >= 2:
			parts = append(parts, fmt.Sprintf("v%d–v%d", vs[i], vs[j]))
		default:
			for k := i; k <= j; k++ {
				parts = append(parts, "v"+strconv.Itoa(vs[k]))
			}
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}
