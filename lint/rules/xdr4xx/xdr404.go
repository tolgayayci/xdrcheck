package xdr4xx

// XDR404: contract event topics or data trusted by position or kind.
//
// Any contract can emit any number of topics of any type. A reader that
// indexes topics[i] without a length check, or calls Must<Arm>() on a topic
// or on the data without checking its type, panics on the first event that
// does not have the shape it expected, and wallet-backend-style readers halt
// on a panic. The check is either a shape check (len(topics), v.Type,
// Get<Arm>() with its ok) or a check of the emitting contract (a comparison
// of the event's ContractId), which fixes the shape to that contract's.
//
// Event values are the Topics and Data fields of xdr.ContractEventV0 and what
// is read from them (indexing, ranging, accessors, variables bound to them),
// and the parameters named like topics or data of a function whose type is
// xdr.ScVal, []xdr.ScVal or xdr.ScVec. The rule reports
//
//   - topics[k] with a constant k, with no enclosing or earlier check that
//     mentions len(topics) (assumption event-shape:topic-count), and
//   - v.Must<Arm>() on an event value, with no enclosing or earlier check of
//     v.Type or v.Get<Arm>() (assumption event-shape:value-kind),
//
// unless a check of the event's ContractId against something other than nil
// guards the read.

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer404 = framework.Register(framework.Spec{
	Name:     "eventshape",
	Doc:      "eventshape reports contract event topics and data read by position or kind without a shape or emitter check (XDR404)",
	Rules:    []framework.Rule{XDR404},
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run404,
})

var eventParamName = regexp.MustCompile(`(?i)^(topics?|data|eventdata|evdata|value)$`)

func run404(p *framework.Pass) (any, error) {
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	info := p.TypesInfo
	aliases := p.Config().XDRPackageAliases
	isScValish := func(t types.Type) bool {
		if s, ok := t.Underlying().(*types.Slice); ok {
			t = s.Elem()
		}
		n := xdrNamed(t, aliases)
		return n != nil && (n.Obj().Name() == "ScVal" || n.Obj().Name() == "ScVec" || n.Obj().Name() == "ScMap" || n.Obj().Name() == "ScMapEntry")
	}
	eachFunc(insp, func(fd *ast.FuncDecl) {
		evObjs := map[types.Object]bool{}
		// Parameters named like event topics or data.
		if fd.Type.Params != nil {
			for _, f := range fd.Type.Params.List {
				for _, nm := range f.Names {
					if obj := info.Defs[nm]; obj != nil && eventParamName.MatchString(nm.Name) && isScValish(obj.Type()) {
						evObjs[obj] = true
					}
				}
			}
		}
		var isEvent func(e ast.Expr) bool
		isEvent = func(e ast.Expr) bool {
			switch x := ast.Unparen(e).(type) {
			case *ast.Ident:
				return evObjs[info.Uses[x]]
			case *ast.SelectorExpr:
				if x.Sel.Name == "Topics" || x.Sel.Name == "Data" {
					if tv, ok := info.Types[x.X]; ok {
						if n := xdrNamed(tv.Type, aliases); n != nil && n.Obj().Name() == "ContractEventV0" {
							return true
						}
					}
				}
				if x.Sel.Name == "Key" || x.Sel.Name == "Val" {
					return isEvent(x.X)
				}
			case *ast.IndexExpr:
				return isEvent(x.X)
			case *ast.StarExpr:
				return isEvent(x.X)
			case *ast.CallExpr:
				if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && (strings.HasPrefix(sel.Sel.Name, "Get") || strings.HasPrefix(sel.Sel.Name, "Must")) {
					return isEvent(sel.X)
				}
			}
			return false
		}
		// Variables bound to event values, to a fixed point.
		for round := 0; round < 4; round++ {
			grew := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.AssignStmt:
					if len(s.Rhs) == 1 && isEvent(s.Rhs[0]) {
						for _, l := range s.Lhs {
							if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
								if obj := objOf(info, id); obj != nil && !evObjs[obj] && isScValish(obj.Type()) {
									evObjs[obj] = true
									grew = true
								}
							}
						}
					} else if len(s.Lhs) == len(s.Rhs) {
						for i, r := range s.Rhs {
							if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" && isEvent(r) {
								if obj := objOf(info, id); obj != nil && !evObjs[obj] {
									evObjs[obj] = true
									grew = true
								}
							}
						}
					}
				case *ast.RangeStmt:
					if isEvent(s.X) {
						for _, v := range []ast.Expr{s.Value} {
							if id, ok := v.(*ast.Ident); ok && id.Name != "_" {
								if obj := objOf(info, id); obj != nil && !evObjs[obj] {
									evObjs[obj] = true
									grew = true
								}
							}
						}
					}
				}
				return true
			})
			if !grew {
				break
			}
		}
		emitterChecked := func(e ast.Expr) bool {
			be, ok := e.(*ast.BinaryExpr)
			if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
				return false
			}
			for _, side := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
				if mentionsContractID(side[0]) {
					if id, ok := ast.Unparen(side[1]).(*ast.Ident); ok && id.Name == "nil" {
						return false
					}
					return true
				}
			}
			return false
		}
		var stack []ast.Node
		ast.Inspect(fd, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			switch x := n.(type) {
			case *ast.IndexExpr:
				if !isEvent(x.X) || isAssigned(stack) {
					return true
				}
				tv, ok := info.Types[x.X]
				if !ok {
					return true
				}
				if _, isSlice := tv.Type.Underlying().(*types.Slice); !isSlice {
					return true
				}
				k, ok := constInt(info, x.Index)
				if !ok {
					return true
				}
				lenOf := func(e ast.Expr) bool {
					c, ok := e.(*ast.CallExpr)
					if !ok || len(c.Args) != 1 {
						return false
					}
					if id, ok := ast.Unparen(c.Fun).(*ast.Ident); !ok || id.Name != "len" {
						return false
					}
					return sameExpr(c.Args[0], x.X) || refersToSameRoot(info, c.Args[0], x.X)
				}
				al := aliasesOf(info, fd.Body, lenOf)
				if guarded(info, stack, withAliases(info, lenOf, al)) || guarded(info, stack, emitterChecked) {
					return true
				}
				report(p, XDR404.ID, x.Lbrack, AssumeTopicCount, "", fmt.Sprintf(
					"%s reads position %d of a contract event's %s with no check of len(%s); an event with fewer values (any contract can emit one) panics with index out of range",
					types.ExprString(x), k, whatOf(x.X), types.ExprString(x.X)))
			case *ast.CallExpr:
				sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr)
				if !ok || !strings.HasPrefix(sel.Sel.Name, "Must") || !isEvent(sel.X) {
					return true
				}
				tv, ok := info.Types[sel.X]
				if !ok {
					return true
				}
				n := xdrNamed(tv.Type, aliases)
				if n == nil || n.Obj().Name() != "ScVal" {
					return true
				}
				recv := sel.X
				arm := strings.TrimPrefix(sel.Sel.Name, "Must")
				typeCheck := func(e ast.Expr) bool {
					switch s := e.(type) {
					case *ast.SelectorExpr:
						return s.Sel.Name == "Type" && sameExpr(s.X, recv)
					case *ast.CallExpr:
						if f, ok := ast.Unparen(s.Fun).(*ast.SelectorExpr); ok && (strings.HasPrefix(f.Sel.Name, "Get") || f.Sel.Name == "IsBool") {
							return sameExpr(f.X, recv)
						}
					}
					return false
				}
				al := aliasesOf(info, fd.Body, typeCheck)
				if guarded(info, stack, withAliases(info, typeCheck, al)) || guarded(info, stack, emitterChecked) {
					return true
				}
				report(p, XDR404.ID, sel.Sel.Pos(), AssumeTopicKind, "", fmt.Sprintf(
					"%s.%s() assumes a value of a contract event is a %s, with no check of its Type and no check of the emitting contract; a contract can emit any type there and %s panics",
					types.ExprString(recv), sel.Sel.Name, arm, sel.Sel.Name))
			}
			return true
		})
	})
	return nil, nil
}

func mentionsContractID(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && (s.Sel.Name == "ContractId" || s.Sel.Name == "ContractID") {
			found = true
		}
		if id, ok := n.(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "contractid") {
			found = true
		}
		return !found
	})
	return found
}

// refersToSameRoot reports whether a and b end in the same identifier
// (`len(topics)` and `event.Body.V0.Topics[1]` bound to topics).
func refersToSameRoot(info *types.Info, a, b ast.Expr) bool {
	ia, ok1 := ast.Unparen(a).(*ast.Ident)
	ib, ok2 := ast.Unparen(b).(*ast.Ident)
	return ok1 && ok2 && info.Uses[ia] != nil && info.Uses[ia] == info.Uses[ib]
}

func whatOf(e ast.Expr) string {
	s := strings.ToLower(types.ExprString(e))
	if strings.Contains(s, "topic") {
		return "topics"
	}
	return "values"
}
