package xdr1xx

import (
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// memKey names an abstract memory location: an allocation (or global,
// parameter, call result) and a field path below it ("/3/[]/0").
type memKey struct {
	root ssa.Value
	path string
}

// armRegion is the part of a function reached through a type-switch arm that
// chose *MuxedInfo_Text or *MuxedInfo_Hash: a value leaving it through a phi
// was chosen on a memo that is not a routing ID.
type armRegion struct {
	entry *ssa.BasicBlock
	label set
}

// guard is a check that validates a value for some text aspects on the
// edges taken when it passed.
type guard struct {
	edges   []edge
	aspects aspectMask
}

type engine struct {
	p       *framework.Pass
	cfg     *framework.Config
	aliases []string
	funcs   []*ssa.Function
	inPkg   map[*ssa.Function]bool
	ast     *astIndex
	partRe  *regexp.Regexp

	origins []origin
	src     map[ssa.Value]set // labels a value introduces
	val     map[ssa.Value]set
	mem     map[ssa.Value]map[string]set
	ret     map[*ssa.Function][]set
	pin     map[*ssa.Function]set           // labels that entered a function through its parameters
	rmem    map[*ssa.Function]map[int]shape // what returned struct pointers point to
	pshape  map[*ssa.Parameter]shape        // struct parameters, field by field
	rshape  map[*ssa.Function]map[int]shape // struct results, field by field
	dropAt  map[*ssa.Call]aspectMask        // aspects a sanitiser call removes
	fvBind  map[*ssa.FreeVar]ssa.Value
	arms    map[*ssa.Function][]armRegion
	guards  map[ssa.Value][]guard
	// guardsByKey holds guards on loads and field reads by the object read.
	guardsByKey map[memKey][]guard
	helpers     map[*ssa.Function]*helper // same-package validators

	sinkObjs map[types.Object]string // //xdrlint:sink kind on a function, field or type
	cfgSink  map[string][]string     // configured sink name → kinds
	sanAddr  map[string]bool
	sanText  map[string]bool
	unions   map[*types.Named]*unionInfo
	boxed    []boxedType // concrete types converted to an interface type

	pending  []report
	lastMemo []int // memo origins the last checked call reported
	reported map[string]bool
	addrDone map[int]bool // XDR102 origins already reported

	norm        *normInfo                               // account-key types whose Value() normalises, and their setters (addrnorm.go)
	rootsIn     map[*ssa.Function]bool                  // helpers roots() is walking (reparse.go)
	sites       map[*ssa.Function][]ssa.CallInstruction // static same-package call sites (storage.go)
	escapes     map[*ssa.Function]bool                  // functions also used as values
	eventMemo   map[*ssa.Call]bool                      // eventFreeCall results (eventorigin.go)
	emitterMemo map[*ssa.Call]bool                      // emitterSelected results (emitter.go)
	storageMemo map[*ssa.Call]bool                      // storageCall results (storage.go)
}

func newEngine(p *framework.Pass, res *buildssa.SSA, idx *astIndex) *engine {
	cfg := p.Config()
	e := &engine{
		p: p, cfg: cfg, aliases: cfg.XDRPackageAliases, funcs: res.SrcFuncs, ast: idx,
		partRe:      cfg.ParticipantName(),
		inPkg:       map[*ssa.Function]bool{},
		src:         map[ssa.Value]set{},
		val:         map[ssa.Value]set{},
		mem:         map[ssa.Value]map[string]set{},
		ret:         map[*ssa.Function][]set{},
		pin:         map[*ssa.Function]set{},
		rmem:        map[*ssa.Function]map[int]shape{},
		pshape:      map[*ssa.Parameter]shape{},
		rshape:      map[*ssa.Function]map[int]shape{},
		dropAt:      map[*ssa.Call]aspectMask{},
		fvBind:      map[*ssa.FreeVar]ssa.Value{},
		arms:        map[*ssa.Function][]armRegion{},
		guards:      map[ssa.Value][]guard{},
		helpers:     map[*ssa.Function]*helper{},
		sinkObjs:    map[types.Object]string{},
		cfgSink:     map[string][]string{},
		sanAddr:     map[string]bool{},
		sanText:     map[string]bool{},
		unions:      map[*types.Named]*unionInfo{},
		reported:    map[string]bool{},
		addrDone:    map[int]bool{},
		rootsIn:     map[*ssa.Function]bool{},
		storageMemo: map[*ssa.Call]bool{},
		eventMemo:   map[*ssa.Call]bool{},
	}
	e.norm, _ = p.ResultOf[Normalisers].(*normInfo)
	if e.norm == nil {
		e.norm = &normInfo{}
	}
	for _, fn := range e.funcs {
		e.inPkg[fn] = true
	}
	for kind, names := range map[string][]string{
		sinkParticipant: cfg.SinksParticipant, sinkAccountKey: cfg.SinksAccountKey, sinkText: cfg.SinksText,
	} {
		for _, n := range names {
			e.cfgSink[n] = append(e.cfgSink[n], kind)
		}
	}
	for _, n := range cfg.SanitizersAddress {
		e.sanAddr[n] = true
	}
	for _, n := range cfg.SanitizersText {
		e.sanText[n] = true
	}
	return e
}

// Sink kinds, as written in //xdrlint:sink directives.
const (
	sinkParticipant = "participant"
	sinkAccountKey  = "accountkey"
	sinkText        = "text"
)

func (e *engine) newOrigin(o origin) set {
	e.origins = append(e.origins, o)
	id := len(e.origins) - 1
	var s set
	for a := aspect(0); a < nAspects; a++ {
		if o.aspects.has(a) {
			s.add(label(id, a))
		}
	}
	return s
}

// ---- preparation ----

// bindFreeVars maps each captured variable of a closure to the value its
// MakeClosure binds, so that both name the same memory.
func (e *engine) bindFreeVars() {
	for _, fn := range e.funcs {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				if mc, ok := in.(*ssa.MakeClosure); ok {
					if f, ok := mc.Fn.(*ssa.Function); ok {
						for i, fv := range f.FreeVars {
							if i < len(mc.Bindings) {
								e.fvBind[fv] = mc.Bindings[i]
							}
						}
					}
				}
			}
		}
	}
}

// prepare finds sources, type-switch arms, validators, guards and annotated
// sinks.
func (e *engine) prepare() {
	e.collectDirectives()
	e.collectBoxed()
	for _, fn := range e.funcs {
		for _, prm := range fn.Params {
			e.sourceAt(prm)
			e.addVal(prm, e.src[prm]) // parameters have no transfer of their own
		}
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				if v, ok := in.(ssa.Value); ok {
					e.sourceAt(v)
				}
			}
		}
		e.findArms(fn)
	}
	e.summariseValidators()
	e.collectGuards()
}

// ---- solving ----

// solve propagates labels over the package until nothing changes.
func (e *engine) solve() {
	for round := 0; round < 100; round++ {
		changed := false
		for _, fn := range e.funcs {
			if e.step(fn) {
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

func (e *engine) addVal(v ssa.Value, s set) bool {
	if s.empty() {
		return false
	}
	cur := e.val[v]
	grew := cur.union(s)
	if grew {
		e.val[v] = cur
	}
	return grew
}

func (e *engine) addMem(k memKey, s set) bool {
	if s.empty() || k.root == nil {
		return false
	}
	m := e.mem[k.root]
	if m == nil {
		m = map[string]set{}
		e.mem[k.root] = m
	}
	cur := m[k.path]
	grew := cur.union(s)
	if grew {
		m[k.path] = cur
	}
	return grew
}

func (e *engine) addRet(fn *ssa.Function, i int, s set) bool {
	if s.empty() {
		return false
	}
	r := e.ret[fn]
	for len(r) <= i {
		r = append(r, nil)
	}
	grew := r[i].union(s)
	e.ret[fn] = r
	return grew
}

func (e *engine) step(fn *ssa.Function) bool {
	changed := false
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			switch in := in.(type) {
			case *ssa.MakeClosure:
				if f, ok := in.Fn.(*ssa.Function); ok {
					for i, fv := range f.FreeVars {
						if i < len(in.Bindings) && e.addVal(fv, e.deepUse(in, in.Bindings[i])) {
							changed = true
						}
					}
				}
			case *ssa.Store:
				if isStruct(in.Val.Type()) {
					if e.storeShape(e.key(in.Addr), in.Val) {
						changed = true
					}
				} else if e.addMem(e.key(in.Addr), e.deepUse(in, in.Val)) {
					changed = true
				}
			case *ssa.MapUpdate:
				s := union(e.use(in, in.Key), e.deepUse(in, in.Value))
				if e.addVal(in.Map, s) {
					changed = true
				}
				if ld, ok := in.Map.(*ssa.UnOp); ok && ld.Op == token.MUL && e.addMem(e.key(ld.X), s) {
					changed = true
				}
			case *ssa.Return:
				for i, r := range in.Results {
					if isStructPtr(r.Type()) {
						// A returned struct pointer hands its target to the
						// caller path by path, like a struct pointer argument.
						if e.addRet(fn, i, e.use(in, r)) {
							changed = true
						}
						if e.addRMem(fn, i, e.below(e.key(r))) {
							changed = true
						}
						continue
					}
					if e.addRet(fn, i, e.deepUse(in, r)) {
						changed = true
					}
					if isStruct(r.Type()) && e.addRShape(fn, i, e.shapeOf(r, 0)) {
						changed = true
					}
				}
			case *ssa.Call:
				if isStructPtr(in.Type()) && e.resultPointee(in, in, 0) {
					changed = true
				}
			case *ssa.Extract:
				if c, ok := in.Tuple.(*ssa.Call); ok && isStructPtr(in.Type()) && e.resultPointee(in, c, in.Index) {
					changed = true
				}
			}
			if c, ok := in.(ssa.CallInstruction); ok {
				if e.callParams(in, c.Common()) {
					changed = true
				}
			}
			if v, ok := in.(ssa.Value); ok {
				if e.addVal(v, e.transfer(v)) {
					changed = true
				}
			}
		}
	}
	return changed
}

// inPkgCallee returns the same-package function a call reaches statically.
func (e *engine) inPkgCallee(c *ssa.CallCommon) *ssa.Function {
	var fn *ssa.Function
	switch v := c.Value.(type) {
	case *ssa.Function:
		fn = v
	case *ssa.MakeClosure:
		fn, _ = v.Fn.(*ssa.Function)
	}
	if c.IsInvoke() || fn == nil {
		return nil
	}
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if !e.inPkg[fn] {
		return nil
	}
	return fn
}

func (e *engine) callParams(at ssa.Instruction, c *ssa.CallCommon) bool {
	changed := false
	for _, t := range e.inPkgTargets(c) {
		for i, a := range t.args {
			if i >= len(t.fn.Params) {
				continue
			}
			if isStructPtr(a.Type()) && isStructPtr(t.fn.Params[i].Type()) {
				// A struct pointer (a method receiver, a builder) keeps its
				// target field by field: the parameter gets the caller's
				// memory below the pointer, so reading one field of the
				// target does not see what another field holds.
				if e.addVal(t.fn.Params[i], e.use(at, a)) {
					changed = true
				}
				if e.copyPointee(t.fn.Params[i], e.key(a)) {
					changed = true
				}
				e.addPin(t.fn, e.argUse(at, a))
				continue
			}
			if e.addVal(t.fn.Params[i], e.deepUse(at, a)) {
				changed = true
			}
			if isStruct(a.Type()) && isStruct(t.fn.Params[i].Type()) && e.addPShape(t.fn.Params[i], e.shapeOf(a, 0)) {
				changed = true
			}
			e.addPin(t.fn, e.argUse(at, a))
		}
	}
	return changed
}

// argUse is everything an argument hands a same-package callee: its labels,
// what is stored behind it, and the fields of a struct value.
func (e *engine) argUse(at ssa.Instruction, a ssa.Value) set {
	s := append(set(nil), e.deepUse(at, a)...)
	if isStruct(a.Type()) {
		s.union(e.shapeOf(a, 0).labels())
	}
	return s
}

func (e *engine) addPin(fn *ssa.Function, s set) {
	cur := e.pin[fn]
	if cur.union(s) {
		e.pin[fn] = cur
	}
}

// foreign is what a same-package callee's results may carry only because
// another call site passed it in: the labels that entered the callee through
// its parameters, less what this call's own arguments carry. A helper such
// as an asset formatter called on a contract-supplied value at one site and
// on a ledger entry at another returns the first site's labels to the first
// site only.
func (e *engine) foreign(at ssa.Instruction, t callTarget) set {
	in := e.pin[t.fn]
	if in.empty() {
		return nil
	}
	var here set
	for _, a := range t.args {
		here.union(e.argUse(at, a))
	}
	return in.minus(here)
}

// copyPointee adds what memory holds at and below k to the memory of the
// pointer parameter p, path by path. What is stored above k (a whole value
// stored into an enclosing location) applies to every field of p's target.
func (e *engine) copyPointee(p *ssa.Parameter, k memKey) bool {
	return e.addMemShape(p, e.below(k))
}

// below returns what memory holds at and below k, as a shape relative to k;
// what is stored above k lands at "".
func (e *engine) below(k memKey) shape {
	out := shape{}
	for path, s := range e.mem[k.root] {
		switch {
		case path == k.path || strings.HasPrefix(path, k.path+"/"):
			out.add(path[len(k.path):], append(set(nil), s...))
		case path == "" || strings.HasPrefix(k.path, path+"/"):
			out.add("", append(set(nil), s...))
		}
	}
	return out
}

// addMemShape stores a shape below the location rooted at root.
func (e *engine) addMemShape(root ssa.Value, sh shape) bool {
	grew := false
	for path, s := range sh {
		if e.addMem(memKey{root: root, path: path}, s) {
			grew = true
		}
	}
	return grew
}

func (e *engine) addRMem(fn *ssa.Function, i int, sh shape) bool {
	m := e.rmem[fn]
	if m == nil {
		m = map[int]shape{}
		e.rmem[fn] = m
	}
	cur := m[i]
	if cur == nil {
		cur = shape{}
		m[i] = cur
	}
	return cur.addAll(sh)
}

// resultPointee stores what result i of a same-package call points to below
// v, the value that holds the result, less what other call sites passed in.
func (e *engine) resultPointee(v ssa.Value, c *ssa.Call, i int) bool {
	grew := false
	for _, t := range e.inPkgTargets(c.Common()) {
		if sh := e.rmem[t.fn][i]; len(sh) > 0 && e.addMemShape(v, sh.minus(e.foreign(c, t)).dropAspects(e.callDrop(c))) {
			grew = true
		}
	}
	return grew
}

func isStructPtr(t types.Type) bool {
	p, ok := t.Underlying().(*types.Pointer)
	return ok && isStruct(p.Elem())
}

// key returns the abstract location an address denotes.
func (e *engine) key(addr ssa.Value) memKey {
	switch a := addr.(type) {
	case *ssa.FieldAddr:
		k := e.key(a.X)
		k.path += "/" + strconv.Itoa(a.Field)
		return k
	case *ssa.IndexAddr:
		k := e.key(a.X)
		k.path += "/[]"
		return k
	case *ssa.Slice:
		return e.key(a.X)
	case *ssa.ChangeType:
		return e.key(a.X)
	case *ssa.FreeVar:
		if b, ok := e.fvBind[a]; ok {
			return e.key(b)
		}
	case *ssa.UnOp:
		if a.Op == token.MUL { // a pointer loaded from a location: what it points to
			k := e.key(a.X)
			k.path += "/*"
			return k
		}
	case *ssa.Field: // a pointer field of a struct value
		k := e.objKey(a)
		k.path += "/*"
		return k
	}
	return memKey{root: addr}
}

// objKey names the object a value or pointer denotes, so that two reads of
// the same variable or field compare equal: a load *p and the pointer p
// share a key, and x.f extends the key of x.
func (e *engine) objKey(v ssa.Value) memKey {
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op == token.MUL {
			return e.key(x.X)
		}
	case *ssa.Field:
		k := e.objKey(x.X)
		k.path += "/" + strconv.Itoa(x.Field)
		return k
	}
	if _, ok := v.Type().Underlying().(*types.Pointer); ok {
		return e.key(v)
	}
	return memKey{root: v}
}

func related(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// memLoad returns the labels stored at k or at any location above or below it.
func (e *engine) memLoad(k memKey) set {
	var out set
	for path, s := range e.mem[k.root] {
		if related(path, k.path) {
			out.union(s)
		}
	}
	return out
}

// use returns the labels of v as used by instruction at: a dominating
// checked guard on v removes the text aspects it validated.
func (e *engine) use(at ssa.Instruction, v ssa.Value) set {
	s := e.val[v]
	if !s.any(mText) || !e.hasGuards(v) {
		return s
	}
	return s.drop(e.guardedAt(at, v))
}

// useOnEdge is use for a value arriving at a phi along the edge pred → succ.
func (e *engine) useOnEdge(pred, succ *ssa.BasicBlock, v ssa.Value) set {
	s := e.val[v]
	if !s.any(mText) || !e.hasGuards(v) {
		return s
	}
	return s.drop(e.guardedOnEdge(pred, succ, v))
}

// deepUse is use plus whatever is stored behind v when v is a pointer,
// slice, map or interface.
func (e *engine) deepUse(at ssa.Instruction, v ssa.Value) set {
	s := e.use(at, v)
	switch v.Type().Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Interface:
		if _, ok := v.(*ssa.Const); !ok {
			m := e.memLoad(e.key(v))
			if !m.empty() {
				out := append(set(nil), s...)
				out.union(m)
				return out
			}
		}
	}
	return s
}

func union(sets ...set) set {
	var out set
	for _, s := range sets {
		out.union(s)
	}
	return out
}

// carries reports whether a value of type t can carry a tainted string, ID
// or byte slice. Booleans, errors, functions and channels cannot.
func carries(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsBoolean == 0 && u.Kind() != types.UntypedNil
	case *types.Signature, *types.Chan:
		return false
	case *types.Interface:
		return !types.Identical(t, errorType)
	}
	return true
}

var errorType = types.Universe.Lookup("error").Type()

func isByteSlice(t types.Type) bool {
	s, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := s.Elem().Underlying().(*types.Basic)
	return ok && b.Kind() == types.Byte
}

func isString(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}

// transfer computes the labels of an SSA value from its operands.
func (e *engine) transfer(v ssa.Value) set {
	var s set
	switch v := v.(type) {
	case *ssa.Call:
		s = e.callResult(v)
	case *ssa.Extract:
		s = e.extract(v)
	case *ssa.Phi:
		preds := v.Block().Preds
		for i, ed := range v.Edges {
			if i < len(preds) {
				s.union(e.useOnEdge(preds[i], v.Block(), ed))
			} else {
				s.union(e.use(v, ed))
			}
			if i < len(preds) && armCarrier(v.Type()) {
				for _, r := range e.arms[v.Parent()] {
					if r.entry.Dominates(preds[i]) && !r.entry.Dominates(v.Block()) {
						s.union(r.label)
					}
				}
			}
		}
	case *ssa.UnOp:
		switch v.Op {
		case token.MUL:
			s = union(e.use(v, v.X), e.memLoad(e.key(v.X)))
		case token.ARROW:
		default:
			s = e.use(v, v.X)
		}
	case *ssa.BinOp:
		switch v.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		default:
			s = union(e.use(v, v.X), e.use(v, v.Y))
		}
	case *ssa.Convert:
		s = e.use(v, v.X)
		if isByteSlice(v.Type()) && isString(v.X.Type()) {
			s = s.drop(mText) // stored as bytes
		}
	case *ssa.MakeInterface:
		s = e.deepUse(v, v.X)
		if isByteSlice(v.X.Type()) {
			s = s.drop(mText)
		}
	case *ssa.ChangeType:
		s = e.use(v, v.X)
	case *ssa.ChangeInterface:
		s = e.use(v, v.X)
	case *ssa.SliceToArrayPointer:
		s = e.use(v, v.X)
	case *ssa.Slice:
		s = union(e.use(v, v.X), e.memLoad(e.key(v.X)))
	case *ssa.Field:
		s = e.fieldRead(v, v.X, v.Field)
	case *ssa.FieldAddr:
		s = e.use(v, v.X)
	case *ssa.Index:
		s = e.use(v, v.X)
	case *ssa.IndexAddr:
		s = e.use(v, v.X)
	case *ssa.Lookup:
		s = e.deepUse(v, v.X)
	case *ssa.Range:
		s = e.deepUse(v, v.X)
	case *ssa.Next:
		s = e.use(v, v.Iter)
	case *ssa.TypeAssert:
		s = e.use(v, v.X)
		if e.armRole(v.AssertedType) == catalogue.MemoArmID {
			s = s.drop(mMemo) // the routing-ID arm: the accepted shape
		}
	}
	if !carries(v.Type()) {
		return nil
	}
	if src := e.src[v]; !src.empty() {
		s = union(s, src)
	}
	return s
}

// armCarrier reports whether a phi of type t can carry an ID chosen by a
// type-switch arm: an integer, a string or a byte slice.
func armCarrier(t types.Type) bool {
	if isByteSlice(t) || isString(t) {
		return true
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}

func (e *engine) extract(v *ssa.Extract) set {
	c, ok := v.Tuple.(*ssa.Call)
	if !ok {
		return e.use(v, v.Tuple)
	}
	targets := e.inPkgTargets(c.Common())
	if len(targets) == 0 {
		return e.use(v, v.Tuple)
	}
	var s set
	for _, t := range targets {
		if r := e.ret[t.fn]; v.Index < len(r) {
			s.union(r[v.Index].minus(e.foreign(c, t)))
		}
	}
	s = s.drop(e.callDrop(c))
	s = s.drop(e.dropAt[c])
	return union(s, e.src[c])
}

// callee returns the object and catalogue name of a call's static target
// (the interface method for an interface call, the method behind a bound
// method value or a method expression).
func (e *engine) callee(c *ssa.CallCommon) (types.Object, string) {
	if c.IsInvoke() {
		return c.Method, catalogue.Name(c.Method, e.aliases)
	}
	if w, _ := boundMethod(c); w != nil {
		if obj := w.Object(); obj != nil {
			return obj, catalogue.Name(obj, e.aliases)
		}
		return nil, ""
	}
	if fn, ok := c.Value.(*ssa.Function); ok {
		if o := fn.Origin(); o != nil {
			fn = o
		}
		if obj := fn.Object(); obj != nil {
			return obj, catalogue.Name(obj, e.aliases)
		}
	}
	return nil, ""
}

// splitArgs returns a call's receiver (nil for a function) and its other
// arguments.
func splitArgs(c *ssa.CallCommon) (ssa.Value, []ssa.Value) {
	if c.IsInvoke() {
		return c.Value, c.Args
	}
	if w, recv := boundMethod(c); w != nil {
		return recv, c.Args
	}
	if sig := c.Signature(); sig != nil && sig.Recv() != nil && len(c.Args) > 0 {
		return c.Args[0], c.Args[1:]
	}
	if fn, ok := c.Value.(*ssa.Function); ok && (fn.Signature.Recv() != nil || isThunk(fn)) && len(c.Args) > 0 {
		return c.Args[0], c.Args[1:]
	}
	return nil, c.Args
}

func (e *engine) callResult(c *ssa.Call) set {
	common := c.Common()
	if b, ok := common.Value.(*ssa.Builtin); ok {
		switch b.Name() {
		case "append", "min", "max":
			var s set
			for _, a := range common.Args {
				s.union(e.deepUse(c, a))
			}
			return s
		}
		return nil
	}
	var s set
	if targets := e.inPkgTargets(common); len(targets) > 0 {
		for _, t := range targets {
			f := e.foreign(c, t)
			for _, r := range e.ret[t.fn] {
				s.union(r.minus(f))
			}
		}
		if d := e.callDrop(c); s.any(d) {
			e.dropAt[c] |= d
			s = s.drop(d)
		}
	} else {
		if common.IsInvoke() {
			s.union(e.deepUse(c, common.Value))
		}
		for _, a := range common.Args {
			s.union(e.deepUse(c, a))
		}
	}
	_, name := e.callee(common)
	drop := e.sanitises(name, common)
	if drop != 0 {
		e.dropAt[c] |= drop
		s = s.drop(drop)
	}
	return s
}

// callDrop is what a same-package call removes from what it returns because
// of where its arguments come from: the address aspects for arguments read
// from contract storage (storage.go), the non-account kind for an event
// that is not one the Stellar Asset Contract emits (eventorigin.go).
func (e *engine) callDrop(c *ssa.Call) aspectMask {
	if c == nil || e.inPkgCallee(c.Common()) == nil && len(e.inPkgTargets(c.Common())) == 0 {
		return 0
	}
	var m aspectMask
	if e.storageCall(c) {
		m |= mAddress
	}
	if e.eventFreeCall(c) || e.nonSACEventCall(c) {
		m |= mKind
	}
	return m
}
