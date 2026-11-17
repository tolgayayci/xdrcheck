package xdr3xx

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// funcFact summarises a function for its callers, in this package (during
// the fixed point) and in importing packages (as a fact).
type funcFact struct {
	// Returns holds the taint kinds of the function's results that callers
	// must treat as sources: authorization-tree values the function did not
	// already report, envelope participants of a helper with no success
	// check, unreported event values, meta, asset-derived contract IDs, and
	// an event's emitting contract ID (a helper that renders it).
	Returns uint16
	// ReadsMeta: the function or a callee reads ledger meta.
	ReadsMeta bool
	// EnvParamSink: the function writes envelope participants, unguarded,
	// into a set or slice its caller passed in.
	EnvParamSink bool
}

func (*funcFact) AFact() {}

func (f *funcFact) String() string {
	var ks []string
	for i, name := range []string{"auth", "env", "event", "meta", "verifier", "cid"} {
		if f.Returns&(1<<i) != 0 {
			ks = append(ks, name)
		}
	}
	return fmt.Sprintf("returns=[%s] readsMeta=%v envParamSink=%v", strings.Join(ks, ","), f.ReadsMeta, f.EnvParamSink)
}

func (f funcFact) zero() bool { return f.Returns == 0 && !f.ReadsMeta && !f.EnvParamSink }

// fn is one function declaration under analysis; function literals belong
// to the declaration that contains them.
type fn struct {
	decl     *ast.FuncDecl
	obj      *types.Func
	params   map[types.Object]bool // parameters other than the receiver
	vars     map[types.Object]taint
	ret      taint
	returned map[types.Object]bool
	sinks    []sink
	callees  []*types.Func // same-package static callees

	hasSuccessCheck bool
	readsMetaDirect bool
	envParam        bool

	reports map[string][]report // rule → reports
	sum     funcFact
}

type report struct {
	pos token.Pos
	msg string
}

type state struct {
	pass    *framework.Pass
	info    *types.Info
	aliases []string
	re      *regexp.Regexp

	funcs []*fn
	byObj map[*types.Func]*fn

	annotated         map[*types.Func]bool
	cfgParticipant    map[string]bool
	cfgMovement       map[string]bool
	cfgEventSanitizer map[string]bool
}

func nameOf(s *state, f *types.Func) string { return catalogue.Name(f, s.aliases) }

// summary returns the summary of a callee: the current fixed-point value for
// a function of this package, the fact for an imported one.
func (s *state) summary(callee *types.Func) *funcFact {
	if f, ok := s.byObj[callee]; ok {
		return &f.sum
	}
	if callee.Pkg() == nil || callee.Pkg() == s.pass.Pkg {
		return nil
	}
	var ff funcFact
	if s.pass.ImportObjectFact(callee, &ff) {
		return &ff
	}
	return nil
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
		pass:              p,
		info:              p.TypesInfo,
		aliases:           cfg.XDRPackageAliases,
		re:                cfg.ParticipantName(),
		byObj:             map[*types.Func]*fn{},
		annotated:         map[*types.Func]bool{},
		cfgParticipant:    set(cfg.SinksParticipant),
		cfgMovement:       set(cfg.SinksMovement),
		cfgEventSanitizer: set(cfg.SanitizersEvent),
	}
	s.collectFuncs()

	// Summaries feed taint, and taint decides summaries: iterate to a fixed
	// point (bounded; the summaries only grow in practice).
	for iter := 0; iter < 10; iter++ {
		changed := false
		for _, f := range s.funcs {
			s.analyze(f)
			if sum := s.summarise(f); sum != f.sum {
				f.sum = sum
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	s.readsMeta()
	for _, f := range s.funcs {
		if !f.sum.zero() && f.obj.Exported() { // only exported functions can be called from other packages
			p.ExportObjectFact(f.obj, &f.sum)
		}
	}

	s.reportXDR303()
	for _, f := range s.funcs {
		for _, rule := range []string{XDR301.ID, XDR302.ID, XDR304.ID} {
			for _, r := range f.reports[rule] {
				p.Report(framework.Report{Rule: rule, Pos: r.pos, Message: r.msg})
			}
		}
	}
	return nil, nil
}

func (s *state) collectFuncs() {
	for _, file := range s.pass.Files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			obj, _ := s.info.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			f := &fn{decl: fd, obj: obj, params: map[types.Object]bool{}}
			for _, field := range fd.Type.Params.List {
				for _, name := range field.Names {
					if o := s.info.Defs[name]; o != nil {
						f.params[o] = true
					}
				}
			}
			s.funcs = append(s.funcs, f)
			s.byObj[obj] = f
		}
	}
	for _, d := range s.pass.Directives() {
		if d.Verb != "sink" || d.Arg != "participant" || d.Problem != "" {
			continue
		}
		for _, f := range s.funcs {
			if doc := f.decl.Doc; doc != nil && doc.Pos() <= d.Pos && d.Pos < doc.End() {
				s.annotated[f.obj] = true
			}
		}
	}
}

// analyze computes f's taint, sinks and reports for the current summaries.
func (s *state) analyze(f *fn) {
	s.propagate(f)
	s.collectSinks(f)
	f.reports = map[string][]report{}
	f.hasSuccessCheck = false
	f.readsMetaDirect = false
	f.callees = nil
	ast.Inspect(f.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if callee := s.callee(n); callee != nil {
				name := nameOf(s, callee)
				if catalogue.Has(name, catalogue.SuccessGate) {
					f.hasSuccessCheck = true
				}
				if catalogue.Has(name, catalogue.MetaSource) {
					f.readsMetaDirect = true
				}
				if _, local := s.byObj[callee]; local {
					f.callees = append(f.callees, callee)
				} else if sum := s.summary(callee); sum != nil && sum.ReadsMeta {
					f.readsMetaDirect = true
				}
			}
		case *ast.SelectorExpr:
			if sel, ok := s.info.Selections[n]; ok && sel.Kind() == types.FieldVal &&
				catalogue.Has(catalogue.SelectionName(sel, s.aliases), catalogue.MetaSource) {
				f.readsMetaDirect = true
			}
		}
		if e, ok := n.(ast.Expr); ok && s.isMetaType(s.info.TypeOf(e)) {
			f.readsMetaDirect = true
		}
		return true
	})

	seen := map[string]map[token.Pos]bool{}
	emit := func(rule string, o origin, msg string) {
		if seen[rule] == nil {
			seen[rule] = map[token.Pos]bool{}
		}
		if seen[rule][o.pos] {
			return
		}
		seen[rule][o.pos] = true
		f.reports[rule] = append(f.reports[rule], report{pos: o.pos, msg: msg})
	}
	var envParam bool
	for _, sk := range f.sinks {
		var t taint
		for _, v := range sk.values {
			t.merge(s.exprTaint(f, v))
		}
		if sk.envHelperCall != nil {
			t.set(kEnv, origin{pos: callPos(sk.envHelperCall), desc: types.ExprString(sk.envHelperCall.Fun) + "()"})
		}
		if sk.kind == participantSink && t.has(kAuth) && !s.guarded(f, sk.node, s.metaGuard(f)) {
			o := t.origin(kAuth)
			emit(XDR301.ID, o, fmt.Sprintf("%s (authorization tree or invocation arguments) reaches participant sink %s with no meta corroboration; "+
				"the host never checks entries that no require_auth matched, so take authorizers from the nonce entries in meta", o.desc, sk.desc))
		}
		if sk.kind == participantSink && t.has(kEnv) && !s.guarded(f, sk.node, s.successGuard(f)) {
			switch {
			case !f.hasSuccessCheck && sk.target == targetReturn:
				// a helper: its callers carry the obligation (Returns kEnv)
			case !f.hasSuccessCheck && sk.target == targetParam:
				envParam = true
			default:
				o := t.origin(kEnv)
				emit(XDR302.ID, o, fmt.Sprintf("%s (operation accounts from the envelope) reaches participant sink %s with no success check; "+
					"a failed transaction changes only its fee, so attribute it to the transaction and fee-bump sources only", o.desc, sk.desc))
			}
		}
		if t.has(kEvent) && !sk.keyedByContract && !s.guarded(f, sk.node, s.eventGuard(f)) {
			o := t.origin(kEvent)
			what := "participant sink " + sk.desc
			if sk.kind == assetSink {
				what = "asset construction " + sk.desc
			}
			emit(XDR304.ID, o, fmt.Sprintf("%s (contract event topics or data) reaches %s with no check that the event's ContractId is the expected contract; "+
				"any contract can emit a token-shaped event, so compare it with asset.ContractID(passphrase) first", o.desc, what))
		}
	}
	f.envParam = envParam
}

// summarise derives f's summary from the latest analysis.
func (s *state) summarise(f *fn) funcFact {
	var k kind
	if f.ret.has(kAuth) && len(f.reports[XDR301.ID]) == 0 {
		k |= kAuth
	}
	if f.ret.has(kEnv) && !f.hasSuccessCheck && len(f.reports[XDR302.ID]) == 0 {
		k |= kEnv
	}
	if f.ret.has(kEvent) && len(f.reports[XDR304.ID]) == 0 {
		k |= kEvent
	}
	k |= f.ret.k & (kMeta | kVerifier | kCID)
	return funcFact{Returns: uint16(k), ReadsMeta: f.sum.ReadsMeta, EnvParamSink: f.envParam && len(f.reports[XDR302.ID]) == 0}
}

// readsMeta computes ReadsMeta over the package's static call graph.
func (s *state) readsMeta() {
	for _, f := range s.funcs {
		f.sum.ReadsMeta = f.readsMetaDirect
	}
	for changed := true; changed; {
		changed = false
		for _, f := range s.funcs {
			if f.sum.ReadsMeta {
				continue
			}
			for _, c := range f.callees {
				if s.byObj[c].sum.ReadsMeta {
					f.sum.ReadsMeta = true
					changed = true
					break
				}
			}
		}
	}
}

// reportXDR303 reports participant builders that read no meta and are not
// reached from a same-package function that does.
func (s *state) reportXDR303() {
	covered := map[*fn]bool{}
	for _, f := range s.funcs {
		covered[f] = f.sum.ReadsMeta
	}
	for changed := true; changed; {
		changed = false
		for _, f := range s.funcs {
			if !covered[f] {
				continue
			}
			for _, c := range f.callees {
				if g := s.byObj[c]; !covered[g] {
					covered[g] = true
					changed = true
				}
			}
		}
	}
	var out []*fn
	for _, f := range s.funcs {
		if !covered[f] && slices.ContainsFunc(f.sinks, func(sk sink) bool { return sk.kind == participantSink }) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].decl.Pos() < out[j].decl.Pos() })
	for _, f := range out {
		s.pass.Report(framework.Report{Rule: XDR303.ID, Pos: f.decl.Name.Pos(), Message: fmt.Sprintf(
			"participant builder %s never reads ledger meta (fee changes, operation changes or events), and no function of this package that reads meta calls it; "+
				"participants come from meta, the envelope only labels causes", f.decl.Name.Name)})
	}
}

// isMetaType reports whether t (through pointers and slices) is one of the
// catalogued meta types or a contract event.
func (s *state) isMetaType(t types.Type) bool {
	for t != nil {
		switch u := t.(type) {
		case *types.Pointer:
			t = u.Elem()
			continue
		case *types.Slice:
			t = u.Elem()
			continue
		}
		break
	}
	tn := namedType(t)
	if tn == nil || tn.Pkg() == nil {
		return false
	}
	name := catalogue.Canonical(tn.Pkg().Path(), s.aliases) + "." + tn.Name()
	for _, e := range catalogue.Lookup(name) {
		// Contract events are part of the meta too.
		if e.Kind == catalogue.KindType && (slices.Contains(e.Roles, catalogue.MetaSource) || slices.Contains(e.Roles, catalogue.EventSource)) {
			return true
		}
	}
	return false
}

var _ analysis.Fact = (*funcFact)(nil)
