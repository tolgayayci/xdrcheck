package xdr3xx

// Sinks.
//
// A participant sink is
//
//   - a call of Add, Append or Union on a destination whose name matches
//     the participant pattern (configuration participantnameregex, default
//     (?i)participant);
//   - an assignment of append(dst, …) or of a New…Set(…) constructor to such
//     a destination, or an index assignment dst[key] = … into such a map with
//     string keys (the key is the value written);
//   - the same into a destination of another name that the function returns,
//     when the function's own name matches the pattern;
//   - a call of a function annotated //xdrlint:sink participant, or of one
//     listed under sinksparticipant.
//
// The destination's name is the variable, field or map it names. Struct
// fields set in a composite literal are not sinks.
//
// The XDR304 sinks add asset construction: the catalogued asset
// constructors, an xdr.Asset composite literal, splitting a string on ":"
// (strings.Split, SplitN, SplitAfter, SplitAfterN, Cut), and the configured
// sinksmovement calls.

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// sinkKind says which rules a sink serves.
type sinkKind int

const (
	participantSink sinkKind = iota
	assetSink                // XDR304 only
)

// target says where a participant sink writes, which decides whether a
// function is a helper whose callers carry the obligation (XDR302).
type target int

const (
	targetOther  target = iota // state the function keeps or hands elsewhere
	targetReturn               // a value the function returns
	targetParam                // a set or slice the caller passed in
)

type sink struct {
	node   ast.Node   // the call or assignment, for guards
	values []ast.Expr // what is written
	desc   string     // for messages: "participants.Add", "participants"
	kind   sinkKind
	target target
	// a call of a helper that writes envelope participants into its
	// parameter: the call itself is the event (XDR302)
	envHelperCall *ast.CallExpr
	// the sink's call also names the event's contract ID, as an argument
	// (a movement sink) or earlier in its builder chain (XDR304 (ii))
	keyedByContract bool
}

var setMethods = []string{"Add", "Append", "Union"}

var newSetRe = regexp.MustCompile(`^New\w*Set`)

// destName is the name a destination expression goes by.
func destName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return destName(e.X)
	case *ast.StarExpr:
		return destName(e.X)
	case *ast.ParenExpr:
		return destName(e.X)
	}
	return ""
}

func (s *state) classify(f *fn, obj types.Object) target {
	switch {
	case obj == nil:
		return targetOther
	case f.returned[obj]:
		return targetReturn
	case f.params[obj]:
		return targetParam
	}
	return targetOther
}

// participantDest reports whether writing into dst is a participant sink.
func (s *state) participantDest(f *fn, dst ast.Expr) bool {
	if s.re.MatchString(destName(dst)) {
		return true
	}
	return s.re.MatchString(f.decl.Name.Name) && f.returned[s.root(dst)]
}

// collectSinks finds every sink in f.
func (s *state) collectSinks(f *fn) {
	f.sinks = nil
	add := func(sk sink) { f.sinks = append(f.sinks, sk) }
	ast.Inspect(f.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			s.callSinks(f, n, add)
		case *ast.AssignStmt:
			if n.Tok != token.ASSIGN && n.Tok != token.DEFINE {
				return true
			}
			for i, lhs := range n.Lhs {
				var rhs ast.Expr
				switch {
				case len(n.Rhs) == len(n.Lhs):
					rhs = n.Rhs[i]
				case len(n.Rhs) == 1 && i == 0:
					rhs = n.Rhs[0]
				default:
					continue
				}
				s.assignSink(f, n, lhs, rhs, add)
			}
		case *ast.ReturnStmt:
			if !s.re.MatchString(f.decl.Name.Name) {
				return true
			}
			for _, r := range n.Results {
				if call, ok := ast.Unparen(r).(*ast.CallExpr); ok && s.isNewSet(call) {
					add(sink{node: n, values: call.Args, desc: f.decl.Name.Name + " result", target: targetReturn})
				}
			}
		case *ast.CompositeLit:
			if tn := namedType(s.info.TypeOf(n)); tn != nil && s.isAssetType(tn) {
				var vals []ast.Expr
				for _, el := range n.Elts {
					vals = append(vals, el)
				}
				add(sink{node: n, values: vals, desc: "an xdr.Asset literal", kind: assetSink})
			}
		}
		return true
	})
}

func (s *state) isNewSet(call *ast.CallExpr) bool {
	callee := s.callee(call)
	return callee != nil && newSetRe.MatchString(callee.Name())
}

func (s *state) assignSink(f *fn, stmt *ast.AssignStmt, lhs, rhs ast.Expr, add func(sink)) {
	if ix, ok := lhs.(*ast.IndexExpr); ok {
		if m, ok := s.info.TypeOf(ix.X).Underlying().(*types.Map); ok && isString(m.Key()) && s.participantDest(f, ix.X) {
			add(sink{node: stmt, values: []ast.Expr{ix.Index}, desc: types.ExprString(ix.X), target: s.classify(f, s.root(ix.X))})
		}
		return
	}
	call, ok := ast.Unparen(rhs).(*ast.CallExpr)
	if !ok || !s.participantDest(f, lhs) {
		return
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "append" {
		if _, builtin := s.info.Uses[id].(*types.Builtin); builtin && len(call.Args) > 1 {
			add(sink{node: stmt, values: call.Args[1:], desc: types.ExprString(lhs), target: s.classify(f, s.root(lhs))})
		}
		return
	}
	if s.isNewSet(call) && len(call.Args) > 0 {
		add(sink{node: stmt, values: call.Args, desc: types.ExprString(lhs), target: s.classify(f, s.root(lhs))})
	}
}

func (s *state) callSinks(f *fn, call *ast.CallExpr, add func(sink)) {
	callee := s.callee(call)
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && slices.Contains(setMethods, sel.Sel.Name) {
		if selection, ok := s.info.Selections[sel]; ok && selection.Kind() == types.MethodVal && s.participantDest(f, sel.X) {
			add(sink{node: call, values: call.Args, desc: types.ExprString(sel), target: s.classify(f, s.root(sel.X))})
		}
	}
	if callee == nil {
		return
	}
	name := catalogue.Name(callee, s.aliases)
	if s.annotated[callee] || s.cfgParticipant[name] {
		add(sink{node: call, values: call.Args, desc: types.ExprString(call.Fun), keyedByContract: s.builderKeyed(f, call)})
	}
	if sum := s.summary(callee); sum != nil && sum.EnvParamSink {
		// The callee writes envelope participants into a set it was given.
		tg := targetOther
		for _, a := range call.Args {
			if t := s.classify(f, s.root(a)); t != targetOther {
				tg = t
			}
		}
		add(sink{node: call, desc: types.ExprString(call.Fun), target: tg, envHelperCall: call})
	}
	// XDR304 asset sinks.
	switch {
	case catalogue.Has(name, catalogue.AssetConstructor):
		add(sink{node: call, values: call.Args, desc: types.ExprString(call.Fun), kind: assetSink})
	case s.cfgMovement[name]:
		add(sink{node: call, values: call.Args, desc: types.ExprString(call.Fun), kind: assetSink,
			keyedByContract: s.mentionsContractID(call.Args) || s.builderKeyed(f, call)})
	case callee.Pkg() != nil && callee.Pkg().Path() == "strings" &&
		slices.Contains([]string{"Split", "SplitN", "SplitAfter", "SplitAfterN", "Cut"}, callee.Name()) &&
		len(call.Args) >= 2 && s.isColon(call.Args[1]):
		add(sink{node: call, values: call.Args[:1], desc: "strings." + callee.Name() + ` on ":" (an asset string)`, kind: assetSink})
	}
}

func (s *state) isColon(e ast.Expr) bool {
	tv, ok := s.info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == ":"
}

// mentionsContractID reports whether some expression reads an event's
// emitting contract ID.
func (s *state) mentionsContractID(es []ast.Expr) bool {
	found := false
	for _, e := range es {
		ast.Inspect(e, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if selection, ok := s.info.Selections[sel]; ok &&
					catalogue.Has(catalogue.SelectionName(selection, s.aliases), catalogue.EventContractID) {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// builderKeyed reports whether call is a method call on a builder that was
// given an event's emitting contract ID: the receiver (the chain of calls
// before this one, and the variable it starts from) carries that ID. A
// record built on it is kept for the contract that emitted the event.
func (s *state) builderKeyed(f *fn, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if selection, ok := s.info.Selections[sel]; !ok || selection.Kind() != types.MethodVal {
		return false
	}
	return s.exprTaint(f, sel.X).has(kCID)
}

func (s *state) callee(call *ast.CallExpr) *types.Func {
	fn, _ := typeutil.Callee(s.info, call).(*types.Func)
	if fn != nil {
		fn = fn.Origin()
	}
	return fn
}

func namedType(t types.Type) *types.TypeName {
	if t == nil {
		return nil
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		return n.Obj()
	}
	return nil
}

func (s *state) isAssetType(tn *types.TypeName) bool {
	if tn.Pkg() == nil {
		return false
	}
	p := catalogue.Canonical(tn.Pkg().Path(), s.aliases)
	return p == catalogue.XDR && (tn.Name() == "Asset" || tn.Name() == "AlphaNum4" || tn.Name() == "AlphaNum12")
}

func isString(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}
