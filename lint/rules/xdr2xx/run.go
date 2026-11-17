package xdr2xx

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

type state struct {
	pass    *framework.Pass
	info    *types.Info
	cfg     *framework.Config
	aliases []string

	nodes []*node
	byObj map[*types.Func]*node
	byLit map[*ast.FuncLit]*node
	fed   map[*node]bool

	recSet       map[string]bool
	cfgFloors    map[string]int
	haltingFuncs map[string]bool
	budget       map[string]bool
	flags        map[string]bool

	reported206 map[token.Pos]bool
	reported207 map[token.Pos]bool
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func run(p *framework.Pass) (any, error) {
	cfg := p.Config()
	s := &state{
		pass:         p,
		info:         p.TypesInfo,
		cfg:          cfg,
		aliases:      cfg.XDRPackageAliases,
		cfgFloors:    cfg.Floors,
		haltingFuncs: set(cfg.HaltingFuncs),
		budget:       set(cfg.BudgetMethods),
		flags:        set(cfg.OverflowFlags),
		reported206:  map[token.Pos]bool{},
		reported207:  map[token.Pos]bool{},
	}
	s.recSet = s.recursiveSet()
	s.collectNodes()
	s.fed = s.metaFed()
	if s.recSet != nil {
		s.recursion()
		s.worklists()
		s.serialised()
	}
	s.decoders()
	s.allocations()
	return nil, nil
}

func (s *state) report(rule string, pos token.Pos, sev framework.Severity, format string, args ...any) {
	s.pass.Report(framework.Report{Rule: rule, Pos: pos, Severity: sev, Message: fmt.Sprintf(format, args...)})
}

// recursiveArg returns the recursive type a call passes (argument or
// receiver), or "".
func (s *state) recursiveArg(call *ast.CallExpr) string {
	for _, a := range call.Args {
		if t := s.recursiveType(s.info.TypeOf(a)); t != "" {
			return t
		}
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection, ok := s.info.Selections[sel]; ok && selection.Kind() == types.MethodVal {
			return s.recursiveType(s.info.TypeOf(sel.X))
		}
	}
	return ""
}

type recEdge struct {
	from *node
	edge
	structure string
}

// recursion implements XDR201 and the XDR206/XDR207 checks of its bounds.
func (s *state) recursion() {
	for _, comp := range s.components() {
		in := map[*node]bool{}
		for _, n := range comp {
			in[n] = true
		}
		var edges []recEdge
		for _, n := range comp {
			for _, e := range n.calls {
				if !in[e.to] {
					continue
				}
				if t := s.recursiveArg(e.call); t != "" {
					edges = append(edges, recEdge{n, e, t})
				}
			}
		}
		if len(edges) == 0 {
			continue
		}
		sort.Slice(edges, func(i, j int) bool { return edges[i].call.Pos() < edges[j].call.Pos() })
		var unbounded []recEdge
		for _, re := range edges {
			b := s.depthGuard(re.from, re.call)
			if b == nil {
				unbounded = append(unbounded, re)
				continue
			}
			s.checkPolicy(re.from, b.guard, re.structure)
			s.checkFloor(re.from, b, re.structure, comp)
		}
		if len(unbounded) == 0 {
			continue
		}
		first := unbounded[0]
		sev, extra := framework.Severity(""), ""
		if s.mergesPerLevel(comp) {
			sev, extra = framework.SeverityError, "; per-level merge is O(n·depth)"
		}
		s.report(XDR201.ID, first.call.Pos(), sev,
			"unbounded recursion over xdr.%s in %s: add a depth bound at or above what stellar-core admits (guide, Caps), and declare what happens when it is reached; a low fixed cap on ledger meta drops valid ledgers%s",
			first.structure, first.from.name, extra)
	}
}

// direction says how a depth counter moves on the way down the recursion.
type direction int

const (
	countsUp   direction = iota // a depth: d+1 per level, bounded from above
	countsDown                  // a budget: b-1 per level, bounded from below (usually 0)
)

// counter is a depth counter of a recursive function. param is its index
// among the function's parameters, or -1 for a field or captured variable.
type counter struct {
	dir   direction
	param int
}

// counters returns the depth counters of n for the recursive call. A counter
// is tied to the recursion: an integer parameter the call passes as p±c
// (p+c counts up, p-c counts down), or an integer field, captured variable
// or package variable — declared outside n's body, so a loop index or other
// local never counts — that n increments (counts up) or only decrements
// (counts down).
func (s *state) counters(n *node, call *ast.CallExpr) map[types.Object]counter {
	out := map[types.Object]counter{}
	i := 0
	for _, field := range n.params() {
		names := field.Names
		if len(names) == 0 {
			i++
			continue
		}
		for _, name := range names {
			obj := s.info.Defs[name]
			if obj != nil && isInteger(obj.Type()) {
				for _, a := range call.Args {
					if dir, ok := s.stepOf(a, obj); ok {
						out[obj] = counter{dir: dir, param: i}
					}
				}
			}
			i++
		}
	}
	up, down := map[types.Object]bool{}, map[types.Object]bool{}
	note := func(e ast.Expr, inc bool) {
		obj := s.counterObj(e)
		if obj == nil || n.body.Pos() <= obj.Pos() && obj.Pos() < n.body.End() {
			return
		}
		if inc {
			up[obj] = true
		} else {
			down[obj] = true
		}
	}
	s.walkBody(n, func(x ast.Node) {
		switch x := x.(type) {
		case *ast.IncDecStmt:
			note(x.X, x.Tok == token.INC)
		case *ast.AssignStmt:
			if x.Tok == token.ADD_ASSIGN || x.Tok == token.SUB_ASSIGN {
				for _, l := range x.Lhs {
					note(l, x.Tok == token.ADD_ASSIGN)
				}
			}
		}
	})
	for obj := range up {
		out[obj] = counter{dir: countsUp, param: -1}
	}
	for obj := range down {
		if !up[obj] {
			out[obj] = counter{dir: countsDown, param: -1}
		}
	}
	return out
}

// stepOf reports whether e is obj+c or c+obj (counting up) or obj-c
// (counting down).
func (s *state) stepOf(e ast.Expr, obj types.Object) (direction, bool) {
	b, ok := ast.Unparen(e).(*ast.BinaryExpr)
	if !ok || (b.Op != token.ADD && b.Op != token.SUB) {
		return 0, false
	}
	is := func(side ast.Expr) bool {
		id, ok := ast.Unparen(side).(*ast.Ident)
		return ok && s.info.Uses[id] == obj
	}
	switch {
	case b.Op == token.ADD && (is(b.X) || is(b.Y)):
		return countsUp, true
	case b.Op == token.SUB && is(b.X):
		return countsDown, true
	}
	return 0, false
}

func (s *state) counterObj(e ast.Expr) types.Object {
	var obj types.Object
	switch e := ast.Unparen(e).(type) {
	case *ast.Ident:
		obj = s.info.ObjectOf(e)
	case *ast.SelectorExpr:
		if sel, ok := s.info.Selections[e]; ok && sel.Kind() == types.FieldVal {
			obj = sel.Obj()
		}
	}
	if obj == nil || !isInteger(obj.Type()) {
		return nil
	}
	return obj
}

func (s *state) mentionsAny(e ast.Expr, objs map[types.Object]bool) bool {
	found := false
	ast.Inspect(e, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.Ident:
			if objs[s.info.Uses[x]] {
				found = true
			}
		case *ast.SelectorExpr:
			if sel, ok := s.info.Selections[x]; ok && objs[sel.Obj()] {
				found = true
			}
		}
		return !found
	})
	return found
}

// bound is a guard XDR201 accepted, with the counter it compares (nil for a
// budget method).
type bound struct {
	*guard
	ctr *counter
}

// depthGuard finds the bound guarding a recursive call: a comparison of a
// depth counter in the right direction, or a checked call of a configured
// budget method.
func (s *state) depthGuard(n *node, call *ast.CallExpr) *bound {
	ctrs := s.counters(n, call)
	for _, dir := range []direction{countsUp, countsDown} {
		objs := map[types.Object]bool{}
		for obj, c := range ctrs {
			if c.dir == dir {
				objs[obj] = true
			}
		}
		if len(objs) == 0 {
			continue
		}
		isSubject := func(e ast.Expr) bool { return s.mentionsAny(e, objs) }
		p := boundPredicate(isSubject)
		if dir == countsDown {
			p = countdownPredicate(isSubject)
		}
		if g := s.findGuard(call, p, false); g != nil {
			b := &bound{guard: g}
			for obj, c := range ctrs {
				if c.dir == dir && s.mentionsAny(g.atom, map[types.Object]bool{obj: true}) {
					c := c
					b.ctr = &c
					break
				}
			}
			return b
		}
	}
	if len(s.budget) == 0 {
		return nil
	}
	fl := s.newFlow(n.body, func(e ast.Expr) bool {
		c, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		callee := s.callee(c)
		return callee != nil && (s.budget[s.qname(callee)] || s.budget[callee.Name()])
	}, nil)
	isBudget := func(e ast.Expr) bool { return fl.mentions(e) }
	g := s.findGuard(call, predicate{
		pos: func(e ast.Expr) bool {
			if b, ok := ast.Unparen(e).(*ast.BinaryExpr); ok {
				return b.Op == token.EQL && (isBudget(b.X) || isBudget(b.Y))
			}
			return isBudget(e) && isBool(s.info.TypeOf(e))
		},
		neg: func(e ast.Expr) bool {
			b, ok := ast.Unparen(e).(*ast.BinaryExpr)
			return ok && b.Op == token.NEQ && (isBudget(b.X) || isBudget(b.Y))
		},
	}, false)
	if g == nil {
		return nil
	}
	return &bound{guard: g}
}

func (s *state) mergesPerLevel(comp []*node) bool {
	merge := false
	for _, n := range comp {
		s.walkBody(n, func(x ast.Node) {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Union" {
				merge = true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "append" && call.Ellipsis.IsValid() {
				merge = true
			}
			if c := s.callee(call); c != nil && c.Pkg() != nil && c.Pkg().Path() == "maps" && c.Name() == "Copy" {
				merge = true
			}
		})
	}
	return merge
}

// overflowBranch returns the statements run past the bound, and whether
// there are any (an in-bound test without else falls through).
func overflowBranch(g *guard) (ast.Stmt, bool) {
	switch g.form {
	case earlyExit, inElse:
		return g.ifStmt.Body, true
	default:
		if g.ifStmt.Else != nil {
			return g.ifStmt.Else, true
		}
		return nil, false
	}
}

// checkPolicy is XDR206 for one accepted bound.
func (s *state) checkPolicy(n *node, g *guard, structure string) {
	if g.ifStmt == nil || s.reported206[g.ifStmt.Pos()] {
		return
	}
	branch, has := overflowBranch(g)
	what := "the bound on xdr." + structure
	if has && s.ends(branch) {
		s.reported206[g.ifStmt.Pos()] = true
		s.report(XDR206.ID, g.ifStmt.Pos(), "", "%s ends the process; a crash is neither a typed stop nor a flagged skip: return a typed error (overflowpolicy halt-ledger) or flag the record and continue (skip-and-flag)%s",
			what, s.policyHint())
		return
	}
	switch s.cfg.OverflowPolicy {
	case framework.PolicyHaltLedger:
		if !has || !s.returnsError(n, branch) {
			s.reported206[g.ifStmt.Pos()] = true
			s.report(XDR206.ID, g.ifStmt.Pos(), "", "%s gives up without an error, so the walk silently truncates; the declared policy halt-ledger needs a typed error here", what)
		}
	case framework.PolicySkipAndFlag:
		if !has || !s.flagsRecord(branch) {
			s.reported206[g.ifStmt.Pos()] = true
			s.report(XDR206.ID, g.ifStmt.Pos(), "", "%s skips without marking the record incomplete; the declared policy skip-and-flag needs one of the overflowflags markers here", what)
		}
	}
}

func (s *state) policyHint() string {
	if s.cfg.OverflowPolicy == "" {
		return "; declare which in the configuration (overflowpolicy)"
	}
	return ""
}

// ends reports whether the branch can end the process.
func (s *state) ends(branch ast.Node) bool {
	found := false
	ast.Inspect(branch, func(x ast.Node) bool {
		if _, ok := x.(*ast.FuncLit); ok {
			return false
		}
		if e, ok := x.(ast.Expr); ok && isProcessEnd(e, s) {
			found = true
		}
		return !found
	})
	return found
}

// returnsError reports whether the branch leaves with a non-nil error.
func (s *state) returnsError(n *node, branch ast.Stmt) bool {
	blk, ok := branch.(*ast.BlockStmt)
	if !ok || len(blk.List) == 0 {
		return false
	}
	ret, ok := blk.List[len(blk.List)-1].(*ast.ReturnStmt)
	if !ok {
		return false // break, continue, goto, or falling through
	}
	results := n.ftype.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	last := results.List[len(results.List)-1]
	if !isErrorType(s.info.TypeOf(last.Type)) {
		return false
	}
	if len(ret.Results) == 0 {
		return true // named results; assume the error was set
	}
	id, isID := ast.Unparen(ret.Results[len(ret.Results)-1]).(*ast.Ident)
	return !(isID && id.Name == "nil")
}

// flagsRecord reports whether the branch sets a configured overflow marker.
func (s *state) flagsRecord(branch ast.Node) bool {
	found := false
	ast.Inspect(branch, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && s.flagNamed(sel.Sel.Name) {
					found = true
				}
			}
		case *ast.CallExpr:
			if c := s.callee(x); c != nil && (s.flags[s.qname(c)] || s.flagNamed(c.Name())) {
				found = true
			}
		}
		return !found
	})
	return found
}

func (s *state) flagNamed(name string) bool {
	for f := range s.flags {
		if f == name || len(f) > len(name) && f[len(f)-len(name)-1:] == "."+name {
			return true
		}
	}
	return false
}

// checkFloor is XDR207 for one accepted bound.
func (s *state) checkFloor(n *node, b *bound, structure string, comp []*node) {
	atom, ok := ast.Unparen(b.atom).(*ast.BinaryExpr)
	if !ok || !s.fed[n] || s.reported207[atom.Pos()] {
		return
	}
	limit, ok := s.boundLimit(n, b, atom)
	if !ok {
		return // a bound from configuration or a variable: the project owns the number
	}
	s.reported207[atom.Pos()] = true
	fl, known := s.floorFor(structure)
	switch {
	case !known:
		s.report(XDR207.ID, atom.Pos(), framework.SeverityInfo,
			"bound %d on xdr.%s: stellar-core's limit for this structure is not yet established; a fixed cap here may reject valid ledgers (guide, Caps)", limit, structure)
	case limit < int64(fl.levels):
		s.report(XDR207.ID, atom.Pos(), "",
			"bound %d on xdr.%s is below the %d %s ledger meta can hold (%s); a reader of ledger meta with this cap rejects or truncates valid ledgers",
			limit, structure, fl.levels, fl.unit, fl.source)
	case fl.upper > 0 && limit < int64(fl.upper) && !s.hostWrittenOnly(comp):
		s.report(XDR207.ID, atom.Pos(), framework.SeverityInfo,
			"bound %d on xdr.%s: %s; a fixed cap here may reject valid ledgers unless the walk only sees values the host wrote (events, contract data, return values) (guide, Caps)",
			limit, structure, fl.band)
	}
}

// boundLimit returns the deepest level a bound lets through when it is a
// compile-time constant. A depth counter compared with a constant gives it
// directly. A budget parameter counting down is compared with 0; its limit
// is the budget the walk starts with, when every call into the recursion
// from outside passes the same kind of constant (the largest is taken).
func (s *state) boundLimit(n *node, b *bound, atom *ast.BinaryExpr) (int64, bool) {
	if b.ctr == nil || b.ctr.dir == countsUp {
		return s.allowed(atom)
	}
	if b.ctr.param < 0 {
		return 0, false // a budget field or captured variable: its start is not visible
	}
	var limit int64
	found := false
	for _, m := range s.nodes {
		for _, e := range m.calls {
			if e.to != n || m == n || b.ctr.param >= len(e.call.Args) {
				continue
			}
			v := s.constInt(e.call.Args[b.ctr.param])
			if v == nil {
				if !s.inComponentOf(m, n) {
					return 0, false
				}
				continue
			}
			k, _ := constant.Int64Val(v)
			if !found || k > limit {
				limit, found = k, true
			}
		}
	}
	return limit, found
}

// inComponentOf reports whether m calls n and n (transitively) calls m.
func (s *state) inComponentOf(m, n *node) bool {
	seen := map[*node]bool{}
	var reach func(x *node) bool
	reach = func(x *node) bool {
		if x == m {
			return true
		}
		if seen[x] {
			return false
		}
		seen[x] = true
		for _, e := range x.calls {
			if reach(e.to) {
				return true
			}
		}
		return false
	}
	return reach(n)
}

// allowed returns the deepest level a constant bound lets through.
func (s *state) allowed(b *ast.BinaryExpr) (int64, bool) {
	var c ast.Expr
	constLeft := s.constInt(b.X) != nil
	if constLeft {
		c = b.X
	} else {
		c = b.Y
	}
	v := s.constInt(c)
	if v == nil {
		return 0, false
	}
	n, _ := constant.Int64Val(v)
	op := b.Op
	if constLeft { // N < d is d > N
		switch op {
		case token.LSS:
			op = token.GTR
		case token.LEQ:
			op = token.GEQ
		case token.GTR:
			op = token.LSS
		case token.GEQ:
			op = token.LEQ
		}
	}
	switch op {
	case token.GTR, token.LEQ: // d > N past it, d <= N within
		return n, true
	default: // d >= N, d < N, d == N
		return n - 1, true
	}
}

func (s *state) constInt(e ast.Expr) constant.Value {
	tv, ok := s.info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return nil
	}
	return tv.Value
}

func isInteger(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}

func isBool(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

func isErrorType(t types.Type) bool {
	return t != nil && types.Identical(t, types.Universe.Lookup("error").Type())
}

// nodeAt returns the innermost function containing pos.
func (s *state) nodeAt(pos token.Pos) *node {
	var best *node
	for _, n := range s.nodes {
		if n.body.Pos() <= pos && pos < n.body.End() && (best == nil || n.body.Pos() >= best.body.Pos()) {
			best = n
		}
	}
	return best
}
