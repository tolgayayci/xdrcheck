package xdr1xx

import (
	"go/constant"
	"go/token"
	"go/types"
	"strings"
	"unicode/utf8"

	"golang.org/x/tools/go/ssa"
)

// Text guards (XDR103). A check is a call that tests a value for valid
// UTF-8 (utf8.ValidString, utf8.Valid) or for NUL bytes (strings.IndexByte
// with 0, strings.Contains with "\x00", …), or a same-package helper that
// validates a parameter that way and says so in its result (a bool that is
// true, or an error that is nil, only when the checks passed).
//
// A check guards a use of the tested value only on the branch where it
// passed: the use must be dominated by the edge out of the deciding `if`
// that is taken when the check passed. So
//
//	if !utf8.ValidString(s) { return err }; db.Exec(q, s)     // guarded: the failing branch leaves
//	if utf8.ValidString(s) { db.Exec(q, s) }                   // guarded: the sink is on the passing branch
//	if !utf8.ValidString(s) { log.Print("bad") }; db.Exec(q, s) // not guarded: both branches reach the sink
//
// A value merged in a phi is guarded on the edge it arrives by, so
// `if !valid { s = "" }` followed by a use of s is guarded too.

type argCheck struct {
	arg  ssa.Value
	m    aspectMask
	val  ssa.Value // the value that carries the verdict
	kind verdict
}

// verdict says how a check's value reports success.
type verdict int

const (
	vTrue     verdict = iota // a bool, true when the check passed
	vFalse                   // a bool, true when it failed (Contains "\x00")
	vNegative                // an index, negative when it passed (IndexByte(s, 0))
	vNil                     // an error, nil when it passed
)

// edge is a control-flow edge out of a deciding `if`.
type edge struct{ from, to *ssa.BasicBlock }

// textChecks returns what a call tests.
func (e *engine) textChecks(c *ssa.Call) []argCheck {
	common := c.Common()
	_, name := e.callee(common)
	_, args := splitArgs(common)
	var out []argCheck
	add := func(arg ssa.Value, m aspectMask, k verdict) {
		out = append(out, argCheck{arg: arg, m: m, val: c, kind: k})
	}
	switch name {
	case "unicode/utf8.ValidString", "unicode/utf8.Valid":
		if len(args) == 1 {
			add(args[0], mUTF8, vTrue)
		}
	case "strings.IndexByte", "bytes.IndexByte", "strings.IndexRune", "bytes.IndexRune":
		if len(args) == 2 && isZero(args[1]) {
			add(args[0], mNUL, vNegative)
		}
	case "strings.ContainsRune", "bytes.ContainsRune":
		if len(args) == 2 && isZero(args[1]) {
			add(args[0], mNUL, vFalse)
		}
	case "strings.Contains", "bytes.Contains":
		if len(args) == 2 && isNULString(args[1]) {
			add(args[0], mNUL, vFalse)
		}
	case "strings.ContainsAny":
		if len(args) == 2 && containsNUL(args[1]) {
			add(args[0], mNUL, vFalse)
		}
	case "strconv.ParseUint", "strconv.ParseInt", "strconv.Atoi":
		// Text that parsed as an integer is a sign, a base prefix, digits
		// and underscores: ASCII without NUL.
		if len(args) >= 1 {
			if errv := verdictValue(c, 1); errv != nil {
				out = append(out, argCheck{arg: args[0], m: mText, val: errv, kind: vNil})
			}
		}
	}
	if fn := e.inPkgCallee(common); fn != nil {
		if h := e.helpers[fn]; h != nil {
			val := verdictValue(c, h.result)
			for i, m := range h.params {
				if i < len(common.Args) && val != nil {
					out = append(out, argCheck{arg: common.Args[i], m: m, val: val, kind: h.kind})
				}
			}
		}
	}
	return out
}

// verdictValue returns result i of a call: the call itself when it has one
// result, else the Extract of that index, if any.
func verdictValue(c *ssa.Call, i int) ssa.Value {
	if c.Type() == nil {
		return nil
	}
	if _, ok := c.Type().(*types.Tuple); !ok {
		return c
	}
	for _, r := range *c.Referrers() {
		if ex, ok := r.(*ssa.Extract); ok && ex.Index == i {
			return ex
		}
	}
	return nil
}

// helper is a same-package validator: which parameters it checks for which
// aspects, and which result reports it.
type helper struct {
	params map[int]aspectMask
	result int
	kind   verdict // vTrue or vNil
}

// outcome is what the analysis of one check found: the edges taken when it
// passed, and the values that equal "passed" when true (or when false).
type outcome struct {
	edges  []edge
	passIf map[ssa.Value]bool // value → the boolean value that means "passed"
}

// passEdges follows a check's verdict to the branches it decides.
func passEdges(val ssa.Value, kind verdict) *outcome {
	o := &outcome{passIf: map[ssa.Value]bool{}}
	var phis []*ssa.Phi
	var walkBool func(x ssa.Value, pass bool, depth int)
	walkBool = func(x ssa.Value, pass bool, depth int) {
		if depth > 8 || x.Referrers() == nil {
			return
		}
		if _, seen := o.passIf[x]; seen {
			return
		}
		o.passIf[x] = pass
		for _, r := range *x.Referrers() {
			switch r := r.(type) {
			case *ssa.If:
				b := r.Block()
				if len(b.Succs) == 2 && b.Succs[0] != b.Succs[1] {
					to := b.Succs[1]
					if pass {
						to = b.Succs[0]
					}
					o.edges = append(o.edges, edge{b, to})
				}
			case *ssa.UnOp:
				if r.Op == token.NOT {
					walkBool(r, !pass, depth+1)
				}
			case *ssa.BinOp:
				if c, ok := otherConst(r, x); ok && c.Kind() == constant.Bool && (r.Op == token.EQL || r.Op == token.NEQ) {
					same := constant.BoolVal(c) == pass // x == c holds exactly when passed
					walkBool(r, same == (r.Op == token.EQL), depth+1)
				}
			}
		}
	}
	switch kind {
	case vTrue:
		walkBool(val, true, 0)
	case vFalse:
		walkBool(val, false, 0)
	case vNegative, vNil:
		for _, r := range *val.Referrers() {
			cmp, ok := r.(*ssa.BinOp)
			if !ok {
				continue
			}
			if pass, ok := comparePass(cmp, val, kind); ok {
				walkBool(cmp, pass, 0)
			}
		}
	}
	// A phi of booleans (`ok := a && b`) means "passed" for a value v when
	// every edge into it either is the constant !v, carries a value known to
	// mean "passed" when v, or comes from a block only reached when passed.
	// The check's own value need not be an edge of the phi (in a && b, a
	// only decides which block the edge comes from), so every boolean phi of
	// the function is a candidate.
	if in, ok := val.(ssa.Instruction); ok && in.Parent() != nil {
		for _, b := range in.Parent().Blocks {
			for _, x := range b.Instrs {
				if p, ok := x.(*ssa.Phi); ok && isBool(p.Type()) {
					phis = append(phis, p)
				}
			}
		}
	}
	for round := 0; round < 4 && len(phis) > 0; round++ {
		var rest []*ssa.Phi
		for _, p := range phis {
			if _, seen := o.passIf[p]; seen {
				continue
			}
			decided := false
			for _, v := range []bool{true, false} {
				if o.phiMeans(p, v) {
					walkBool(p, v, 0)
					decided = true
					break
				}
			}
			if !decided {
				rest = append(rest, p)
			}
		}
		phis = rest
	}
	return o
}

func (o *outcome) phiMeans(p *ssa.Phi, v bool) bool {
	preds := p.Block().Preds
	for i, ed := range p.Edges {
		if c, ok := ed.(*ssa.Const); ok && c.Value != nil && c.Value.Kind() == constant.Bool {
			if constant.BoolVal(c.Value) != v {
				continue
			}
			return false
		}
		if pass, ok := o.passIf[ed]; ok && pass == v {
			continue
		}
		if i < len(preds) && o.reachedOnlyPassing(preds[i]) {
			continue
		}
		return false
	}
	return true
}

func (o *outcome) reachedOnlyPassing(b *ssa.BasicBlock) bool {
	for _, e := range o.edges {
		if edgeDominates(e, b) {
			return true
		}
	}
	return false
}

// comparePass interprets a comparison of an index (vNegative) or an error
// (vNil) with a constant: it returns the boolean result that means "passed".
func comparePass(cmp *ssa.BinOp, x ssa.Value, kind verdict) (bool, bool) {
	c, ok := otherConst(cmp, x)
	if !ok {
		return false, false
	}
	op := cmp.Op
	if cmp.Y == x { // k op x is x op' k
		switch op {
		case token.LSS:
			op = token.GTR
		case token.GTR:
			op = token.LSS
		case token.LEQ:
			op = token.GEQ
		case token.GEQ:
			op = token.LEQ
		}
	}
	if kind == vNil {
		if c.Kind() != constant.Unknown { // only nil compares an error
			return false, false
		}
		switch op {
		case token.EQL:
			return true, true
		case token.NEQ:
			return false, true
		}
		return false, false
	}
	if c.Kind() != constant.Int {
		return false, false
	}
	k, exact := constant.Int64Val(c)
	if !exact {
		return false, false
	}
	switch {
	case op == token.LSS && k == 0, op == token.LEQ && k == -1, op == token.EQL && k == -1:
		return true, true // true ⇒ negative
	case op == token.GEQ && k == 0, op == token.GTR && k == -1, op == token.NEQ && k == -1:
		return false, true // false ⇒ negative
	}
	return false, false
}

// otherConst returns the constant operand of a comparison whose other
// operand is x. A nil constant has kind Unknown.
func otherConst(b *ssa.BinOp, x ssa.Value) (constant.Value, bool) {
	var other ssa.Value
	switch x {
	case b.X:
		other = b.Y
	case b.Y:
		other = b.X
	default:
		return nil, false
	}
	c, ok := other.(*ssa.Const)
	if !ok {
		return nil, false
	}
	if c.Value == nil {
		return constant.MakeUnknown(), true
	}
	return c.Value, true
}

// edgeDominates reports whether every path to block b takes edge e: e's
// target dominates b and is entered from nowhere else (other than by a back
// edge from inside it).
func edgeDominates(e edge, b *ssa.BasicBlock) bool {
	if e.from == nil { // a guard that holds wherever its target dominates
		return e.to.Parent() == b.Parent() && e.to.Dominates(b)
	}
	if e.from.Parent() != b.Parent() || !e.to.Dominates(b) {
		return false
	}
	for _, p := range e.to.Preds {
		if p != e.from && !e.to.Dominates(p) {
			return false
		}
	}
	return true
}

func paramIndex(fn *ssa.Function, v ssa.Value) int {
	for i, p := range fn.Params {
		if p == v {
			return i
		}
	}
	return -1
}

// summariseValidators finds same-package helpers that validate a parameter,
// so that calling them counts as a check (for example a validateTokenString
// that checks length, utf8.ValidString and IndexByte(s, 0) and returns an
// error). A helper qualifies when its last result is a bool or an error and
// every return that can report success is reached only where the check
// passed (or returns the check's own verdict).
func (e *engine) summariseValidators() {
	for round := 0; round < 5; round++ {
		changed := false
		for _, fn := range e.funcs {
			res := fn.Signature.Results()
			if res.Len() == 0 {
				continue
			}
			k := res.Len() - 1
			var kind verdict
			switch t := res.At(k).Type(); {
			case types.Identical(t, errorType):
				kind = vNil
			case isBool(t):
				kind = vTrue
			default:
				continue
			}
			rets := returns(fn)
			for _, b := range fn.Blocks {
				for _, in := range b.Instrs {
					c, ok := in.(*ssa.Call)
					if !ok {
						continue
					}
					for _, ck := range e.textChecks(c) {
						i := paramIndex(fn, stripConv(ck.arg))
						if i < 0 {
							continue
						}
						o := passEdges(ck.val, ck.kind)
						if !o.coversReturns(rets, k, kind) {
							continue
						}
						h := e.helpers[fn]
						if h == nil {
							h = &helper{params: map[int]aspectMask{}, result: k, kind: kind}
							e.helpers[fn] = h
						}
						if h.params[i]|ck.m != h.params[i] {
							h.params[i] |= ck.m
							changed = true
						}
					}
				}
			}
		}
		if !changed {
			return
		}
	}
}

func returns(fn *ssa.Function) []*ssa.Return {
	var out []*ssa.Return
	for _, b := range fn.Blocks {
		if len(b.Instrs) > 0 {
			if r, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// coversReturns reports whether every return of the helper that can report
// success either comes after the check passed or returns its verdict.
func (o *outcome) coversReturns(rets []*ssa.Return, k int, kind verdict) bool {
	if len(rets) == 0 {
		return false
	}
	for _, r := range rets {
		if k >= len(r.Results) {
			return false
		}
		v := r.Results[k]
		if !maySucceed(v, kind) {
			continue
		}
		if pass, ok := o.passIf[v]; ok && kind == vTrue && pass {
			continue
		}
		if o.reachedOnlyPassing(r.Block()) {
			continue
		}
		return false
	}
	return true
}

// maySucceed reports whether a returned verdict can mean success: true for
// a bool, nil for an error. Constructed errors (errors.New, fmt.Errorf, a
// package-level error variable, a concrete value in an interface) cannot.
func maySucceed(v ssa.Value, kind verdict) bool {
	switch x := v.(type) {
	case *ssa.Const:
		if kind == vNil {
			return x.Value == nil
		}
		return x.Value == nil || x.Value.Kind() != constant.Bool || constant.BoolVal(x.Value)
	case *ssa.MakeInterface:
		return kind != vNil
	case *ssa.UnOp:
		if _, ok := x.X.(*ssa.Global); ok && kind == vNil && x.Op == token.MUL {
			return false
		}
	case *ssa.Call:
		if kind == vNil {
			if fn, ok := x.Common().Value.(*ssa.Function); ok && fn.Pkg != nil {
				switch fn.Pkg.Pkg.Path() + "." + fn.Name() {
				case "errors.New", "fmt.Errorf":
					return false
				}
			}
		}
	case *ssa.Phi:
		for _, ed := range x.Edges {
			if maySucceed(ed, kind) {
				return true
			}
		}
		return false
	}
	return true
}

func isBool(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

// loadKey returns the object a field read or load reads, so that a guard on
// one read of p.Name also covers a later read of p.Name.
func (e *engine) loadKey(v ssa.Value) (memKey, bool) {
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op == token.MUL {
			return e.objKey(x), true
		}
	case *ssa.Field:
		return e.objKey(x), true
	}
	return memKey{}, false
}

func (e *engine) collectGuards() {
	e.guardsByKey = map[memKey][]guard{}
	for _, fn := range e.funcs {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				c, ok := in.(*ssa.Call)
				if !ok {
					continue
				}
				for _, ck := range e.textChecks(c) {
					o := passEdges(ck.val, ck.kind)
					if len(o.edges) == 0 {
						continue
					}
					e.addGuard(ck.arg, guard{edges: o.edges, aspects: ck.m})
				}
			}
		}
		e.constantGuards(fn)
	}
}

func (e *engine) addGuard(arg ssa.Value, g guard) {
	for v := arg; v != nil; v = unwrap(v) {
		e.guards[v] = append(e.guards[v], g)
		if k, ok := e.loadKey(v); ok {
			e.guardsByKey[k] = append(e.guardsByKey[k], g)
		}
	}
}

// constantGuards finds blocks entered only where a string equals one of a
// set of clean literals: every edge into the block is the passing edge of an
// `x == "lit"` (or `x != "lit"`) test, as in `switch x { case "a", "b": … }`.
// Inside such a block, and below it, x is one of those literals, so it holds
// no invalid UTF-8 and no NUL. The guard is an edge with no source: it holds
// wherever its target dominates.
func (e *engine) constantGuards(fn *ssa.Function) {
	type target struct {
		x  ssa.Value
		to *ssa.BasicBlock
	}
	passFrom := map[target]map[*ssa.BasicBlock]bool{}
	for _, b := range fn.Blocks {
		if len(b.Instrs) == 0 || len(b.Succs) != 2 {
			continue
		}
		cond, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		cmp, ok := cond.Cond.(*ssa.BinOp)
		if !ok || (cmp.Op != token.EQL && cmp.Op != token.NEQ) {
			continue
		}
		for _, x := range []ssa.Value{cmp.X, cmp.Y} {
			c, ok := otherConst(cmp, x)
			if !ok || !cleanLiteral(c) || !isString(x.Type()) {
				continue
			}
			to := b.Succs[0]
			if cmp.Op == token.NEQ {
				to = b.Succs[1]
			}
			t := target{x, to}
			if passFrom[t] == nil {
				passFrom[t] = map[*ssa.BasicBlock]bool{}
			}
			passFrom[t][b] = true
		}
	}
	for t, from := range passFrom {
		all := len(t.to.Preds) > 0
		for _, p := range t.to.Preds {
			if !from[p] && !t.to.Dominates(p) {
				all = false
			}
		}
		if all {
			e.addGuard(t.x, guard{edges: []edge{{nil, t.to}}, aspects: mText})
		}
	}
}

// cleanLiteral reports whether c is a string constant that is valid UTF-8
// and holds no NUL.
func cleanLiteral(c constant.Value) bool {
	if c.Kind() != constant.String {
		return false
	}
	s := constant.StringVal(c)
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// unwrap returns the operand of a conversion, or nil.
func unwrap(v ssa.Value) ssa.Value {
	switch x := v.(type) {
	case *ssa.ChangeType:
		return x.X
	case *ssa.Convert:
		return x.X
	case *ssa.MakeInterface:
		return x.X
	}
	return nil
}

func (e *engine) hasGuards(v ssa.Value) bool {
	if len(e.guards[v]) > 0 {
		return true
	}
	if k, ok := e.loadKey(v); ok {
		return len(e.guardsByKey[k]) > 0
	}
	return false
}

// guardedAt returns the aspects validated for v by checks that passed on
// every path to instruction at.
func (e *engine) guardedAt(at ssa.Instruction, v ssa.Value) aspectMask {
	if at.Block() == nil {
		return 0
	}
	return e.guardedWhere(v, func(ed edge) bool { return edgeDominates(ed, at.Block()) })
}

// guardedOnEdge returns the aspects validated for v on the control-flow edge
// from pred to succ (a phi's incoming edge).
func (e *engine) guardedOnEdge(pred, succ *ssa.BasicBlock, v ssa.Value) aspectMask {
	return e.guardedWhere(v, func(ed edge) bool {
		return ed.from == pred && ed.to == succ || edgeDominates(ed, pred)
	})
}

func (e *engine) guardedWhere(v ssa.Value, holds func(edge) bool) aspectMask {
	var m aspectMask
	check := func(gs []guard) {
		for _, g := range gs {
			for _, ed := range g.edges {
				if holds(ed) {
					m |= g.aspects
					break
				}
			}
		}
	}
	check(e.guards[v])
	if k, ok := e.loadKey(v); ok {
		check(e.guardsByKey[k])
	}
	return m
}
