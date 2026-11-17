package xdr1xx

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// Sinks.
//
//   - XDR101: the ID of a muxed-address constructor (composite literal or
//     assignment of MuxedAccountMed25519.Id, MuxedEd25519Account.Id,
//     MuxedContract.Id; strkey.MuxedAccount.SetID, strkey.MuxedContract.SetID;
//     strkey.Encode with a muxed version byte; xdr.NewMuxedAccount with
//     KEY_TYPE_MUXED_ED25519; xdr.MuxedAccountFromAccountId).
//   - XDR102: a participant sink (Add or Append on a set, a set constructor,
//     append to a slice, or an assignment into a map[string]…, where the
//     receiver, destination, map or enclosing function name matches
//     participantnameregex), an account-key sink (sinksaccountkey), or a
//     function, field or type marked //xdrlint:sink participant|accountkey.
//   - XDR103: database/sql, pgx, sqlx and lib/pq query and exec arguments;
//     string fields tagged db:"…" or as proto3 strings (error; the reader's
//     own message types, not the SDK's) or json:"…" (warning); sinkstext;
//     //xdrlint:sink text.

type report struct {
	rule   string
	pos    token.Pos
	sev    framework.Severity
	msg    string
	assume string // "" = the rule's default assumption key
}

var setConstructors = map[string]bool{
	"NewSet": true, "NewSetWith": true, "NewSetFromSlice": true,
	"NewThreadUnsafeSet": true, "NewThreadUnsafeSetWith": true, "NewThreadUnsafeSetFromSlice": true,
	"NewThreadSafeSet": true, "NewThreadSafeSetWith": true,
}

var dbDrivers = []string{"github.com/jackc/pgx", "github.com/jmoiron/sqlx", "github.com/lib/pq"}

var dbMethods = map[string]bool{
	"Exec": true, "ExecContext": true, "MustExec": true, "MustExecContext": true,
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Queryx": true, "QueryxContext": true, "QueryRowx": true, "QueryRowxContext": true,
	"NamedExec": true, "NamedExecContext": true, "NamedQuery": true, "NamedQueryContext": true,
	"Get": true, "GetContext": true, "Select": true, "SelectContext": true, "CopyFrom": true,
}

func isDBDriverCall(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil || !dbMethods[obj.Name()] {
		return false
	}
	for _, p := range dbDrivers {
		if strings.HasPrefix(obj.Pkg().Path(), p) {
			return true
		}
	}
	return false
}

func (e *engine) line(pos token.Pos) int { return e.p.Fset.Position(pos).Line }

// lineAt names pos for a message reported at report: "line 12" in the same
// file, "events.go:12" in another file of the package.
func (e *engine) lineAt(pos, report token.Pos) string {
	p, r := e.p.Fset.Position(pos), e.p.Fset.Position(report)
	if p.Filename != r.Filename {
		return fmt.Sprintf("%s:%d", filepath.Base(p.Filename), p.Line)
	}
	return fmt.Sprintf("line %d", p.Line)
}

func (e *engine) emit(rule string, pos token.Pos, sev framework.Severity, msg string) {
	if !e.p.Enabled(rule) || !pos.IsValid() {
		return
	}
	key := fmt.Sprintf("%s@%d", rule, pos)
	if e.reported[key] {
		return
	}
	e.reported[key] = true
	e.pending = append(e.pending, report{rule: rule, pos: pos, sev: sev, msg: msg})
}

func (e *engine) flush() {
	slices.SortStableFunc(e.pending, func(a, b report) int {
		if a.pos != b.pos {
			return int(a.pos - b.pos)
		}
		return strings.Compare(a.rule, b.rule)
	})
	for _, r := range e.pending {
		e.p.Report(framework.Report{Rule: r.rule, Pos: r.pos, Severity: r.sev, Message: r.msg, Assumption: r.assume})
	}
}

// memo reports XDR101 at a sink and returns the memo origins it reached.
func (e *engine) memo(s set, sink string, pos token.Pos) []int {
	os := s.origins(mMemo)
	if len(os) == 0 {
		return nil
	}
	o := e.origins[os[0]]
	e.emit(XDR101.ID, pos, "", fmt.Sprintf(
		"memo-derived value from %s (%s) reaches %s, which builds a muxed address; a memo is not a routing ID",
		o.what, e.lineAt(o.pos, pos), sink))
	return os
}

// addr reports XDR102 once per address source that reaches a sink, at the
// source.
func (e *engine) addr(s set, sink string, pos token.Pos) {
	for _, oi := range s.origins(mAddress) {
		if e.addrDone[oi] {
			continue
		}
		o := e.origins[oi]
		why := o.why
		if why == "" {
			why = "can render a muxed or non-account address"
		}
		if e.p.Enabled(XDR102.ID) {
			e.addrDone[oi] = true
		}
		e.emit(XDR102.ID, o.pos, "", fmt.Sprintf(
			"%s %s; it reaches %s at %s without being reduced to the base account (ToAccountId) or kind-checked",
			o.what, why, sink, e.lineAt(pos, o.pos)))
	}
}

// text reports XDR103 at a sink.
func (e *engine) text(s set, sink string, pos token.Pos, sev framework.Severity) {
	os := s.origins(mText)
	if len(os) == 0 {
		return
	}
	var missing aspectMask
	s.each(func(_ int, a aspect) {
		if mText.has(a) {
			missing |= 1 << a
		}
	})
	first, allInfo := os[0], true
	for _, oi := range os {
		if !e.origins[oi].info {
			if allInfo {
				first = oi
			}
			allInfo = false
		}
	}
	check := "UTF-8 and NUL"
	switch missing {
	case mUTF8:
		check = "UTF-8"
	case mNUL:
		check = "NUL"
	}
	o := e.origins[first]
	msg := fmt.Sprintf("%s (%s) carries submitter- or contract-controlled bytes into %s without a %s check",
		o.what, e.lineAt(o.pos, pos), sink, check)
	if allInfo {
		sev = framework.SeverityInfo
		msg += "; the host restricts a symbol's character set, so this is informational"
	}
	e.emit(XDR103.ID, pos, sev, msg)
	if strings.Contains(o.what, "Memo") && len(e.pending) > 0 && e.pending[len(e.pending)-1].pos == pos && e.pending[len(e.pending)-1].rule == XDR103.ID {
		e.pending[len(e.pending)-1].assume = AssumeMemoText
	}
}

// textUse is the labels of v reaching a text sink; a byte slice goes to a
// bytes column and carries no text aspects.
func (e *engine) textUse(at ssa.Instruction, v ssa.Value) set {
	s := e.deepUse(at, v)
	if isByteSlice(v.Type()) {
		s = s.drop(mText)
	}
	return s
}

func (e *engine) checkSinks() {
	type deferred struct {
		fn  *ssa.Function
		s   set
		pos token.Pos
	}
	var newMuxed []deferred
	memoDone := map[*ssa.Function]map[int]bool{}
	markMemo := func(fn *ssa.Function, os []int) {
		if memoDone[fn] == nil {
			memoDone[fn] = map[int]bool{}
		}
		for _, o := range os {
			memoDone[fn][o] = true
		}
	}
	for _, fn := range e.funcs {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				switch in := in.(type) {
				case ssa.CallInstruction:
					if s, pos, ok := e.callSink(in); ok {
						newMuxed = append(newMuxed, deferred{fn, s, pos})
					} else {
						markMemo(fn, e.lastMemo)
					}
				case *ssa.Store:
					markMemo(fn, e.storeSink(in))
				case *ssa.MapUpdate:
					e.mapSink(in)
				case *ssa.ChangeType:
					e.convSink(in, in.X)
				case *ssa.Convert:
					e.convSink(in, in.X)
				}
				e.lastMemo = nil
			}
		}
	}
	// xdr.NewMuxedAccount is usually handed a MuxedAccountMed25519 literal
	// that was already reported; report it only for memo origins that
	// reached no other constructor in the same function.
	for _, d := range newMuxed {
		var rest set
		d.s.each(func(o int, a aspect) {
			if a == aMemo && !memoDone[d.fn][o] {
				rest.add(label(o, a))
			}
		})
		e.memo(rest, "xdr.NewMuxedAccount() with KEY_TYPE_MUXED_ED25519", d.pos)
	}
}

// callSink checks one call. For xdr.NewMuxedAccount it returns the labels
// instead of reporting (ok = true), so that checkSinks can avoid a second
// report of the same literal.
func (e *engine) callSink(ci ssa.CallInstruction) (set, token.Pos, bool) {
	c := ci.Common()
	pos := ci.Pos()
	if b, ok := c.Value.(*ssa.Builtin); ok {
		if b.Name() == "append" && len(c.Args) > 1 && e.namesMatch(e.callNames(pos)) {
			e.addr(e.deepUse(ci, c.Args[1]), "a participant slice (append)", pos)
		}
		return nil, 0, false
	}
	var muxed set
	isMuxed := false
	for _, ce := range e.callees(c) {
		if s, ok := e.callSinkTo(ci, ce.obj, ce.name); ok {
			muxed.union(s)
			isMuxed = true
		}
	}
	return muxed, pos, isMuxed
}

// callSinkTo checks one call against one of its possible targets.
func (e *engine) callSinkTo(ci ssa.CallInstruction, obj types.Object, name string) (set, bool) {
	c := ci.Common()
	pos := ci.Pos()
	recv, args := splitArgs(c)
	argUse := func(vs ...ssa.Value) set {
		var s set
		for _, v := range vs {
			u := e.deepUse(ci, v)
			if u.any(mAddress) && e.reparseGuarded(ci, v) {
				u = u.drop(mAddress)
			}
			s.union(u)
		}
		return s
	}

	// XDR101
	switch {
	case obj.Name() == "SetID" && catalogue.Has(name, catalogue.MuxedConstructor) && len(args) == 1:
		e.lastMemo = e.memo(argUse(args[0]), display(name)+"()", pos)
	case name == xp+"MuxedAccountFromAccountId" && len(args) == 2:
		e.lastMemo = e.memo(argUse(args[1]), display(name)+"()", pos)
	case name == catalogue.Strkey+".Encode" && len(args) == 2 &&
		isConstNamed(args[0], obj.Pkg(), "VersionByteMuxedAccount", "VersionByteMuxedContract"):
		e.lastMemo = e.memo(argUse(args[1]), "strkey.Encode() with a muxed version byte", pos)
	case name == xp+"NewMuxedAccount" && len(args) == 2 &&
		isConstNamed(args[0], obj.Pkg(), "CryptoKeyTypeKeyTypeMuxedEd25519"):
		return argUse(args[1]), true
	}

	// XDR102: participant heuristics. A method value called later is named
	// after the receiver it was taken from as well.
	names := e.callNames(pos)
	if mc, ok := c.Value.(*ssa.MakeClosure); ok && recv != nil {
		if sel := e.ast.selectors[mc.Pos()]; sel != nil {
			names = append(names, exprName(sel.X))
		}
	}
	if recv != nil && (obj.Name() == "Add" || obj.Name() == "Append") && len(args) > 0 && e.namesMatch(names) {
		e.addr(argUse(args...), "a participant set ("+obj.Name()+")", pos)
	}
	if recv == nil && setConstructors[obj.Name()] && len(args) > 0 && e.namesMatch(e.callNames(pos)) {
		e.addr(argUse(args...), "a participant set ("+obj.Name()+")", pos)
	}
	// Configured and annotated sinks. An argument the sink only converts to
	// a normalising key type is stored as its base key (addrnorm.go).
	sinkUse := func() (set, string) {
		fn, _ := obj.(*types.Func)
		var s set
		note := ""
		for i, a := range args {
			u := argUse(a)
			if fn != nil && e.norm.params[fn][i] {
				u = u.drop(mAddr)
				note = normNote
			}
			s.union(u)
		}
		return s, note
	}
	for _, kind := range e.kindsOf(name, obj) {
		switch kind {
		case sinkParticipant:
			s, note := sinkUse()
			e.addr(s, "participant sink "+display(name)+note, pos)
		case sinkAccountKey:
			s, note := sinkUse()
			e.addr(s, "account-key sink "+display(name)+note, pos)
		case sinkText:
			e.text(e.textArgs(ci, args), "text sink "+display(name), pos, "")
		}
	}
	// XDR103: database calls.
	if catalogue.Has(name, catalogue.TextSink) || isDBDriverCall(obj) {
		e.text(e.textArgs(ci, args), display(name)+"()", pos, "")
	}
	return nil, false
}

func (e *engine) textArgs(at ssa.Instruction, args []ssa.Value) set {
	var s set
	for _, a := range args {
		s.union(e.textUse(at, a))
	}
	return s
}

// kindsOf returns the configured and annotated sink kinds of a name.
func (e *engine) kindsOf(name string, obj types.Object) []string {
	kinds := slices.Clone(e.cfgSink[name])
	if k, ok := e.sinkObjs[obj]; ok && obj != nil {
		kinds = append(kinds, k)
	}
	return kinds
}

func isConstNamed(v ssa.Value, pkg *types.Package, names ...string) bool {
	c := constOf(v)
	if c == nil || pkg == nil {
		return false
	}
	for _, n := range names {
		if k, ok := pkg.Scope().Lookup(n).(*types.Const); ok && constant.Compare(c, token.EQL, k.Val()) {
			return true
		}
	}
	return false
}

func (e *engine) storeSink(st *ssa.Store) []int {
	fa, ok := st.Addr.(*ssa.FieldAddr)
	if !ok {
		return nil
	}
	strct := structOf(fa.X.Type())
	if strct == nil || fa.Field >= strct.NumFields() {
		return nil
	}
	f := strct.Field(fa.Field)
	fname := e.fieldName(fa.X.Type(), fa.Field)
	pos := st.Pos()
	if !pos.IsValid() {
		pos = fa.Pos()
	}
	s := e.deepUse(st, st.Val)
	if s.any(mAddress) && e.reparseGuarded(st, st.Val) {
		s = s.drop(mAddress)
	}
	var memoHit []int
	if catalogue.Has(fname, catalogue.MuxedConstructor) {
		memoHit = e.memo(s, "field "+display(fname), pos)
	}
	for _, kind := range e.kindsOf(fname, f) {
		switch kind {
		case sinkParticipant:
			e.addr(s, "participant field "+display(fname), pos)
		case sinkAccountKey:
			e.addr(s, "account-key field "+display(fname), pos)
		case sinkText:
			e.text(e.textUse(st, st.Val), "text field "+display(fname), pos, "")
		}
	}
	if isString(deref(f.Type())) {
		tag := reflect.StructTag(strct.Tag(fa.Field))
		if v, ok := tag.Lookup("db"); ok && v != "-" {
			e.text(e.textUse(st, st.Val), "database field "+display(fname), pos, "")
		} else if v, ok := tag.Lookup("protobuf"); ok && strings.Contains(v, "proto3") && !e.sdkDeclared(f) {
			e.text(e.textUse(st, st.Val), "proto3 string field "+display(fname), pos, "")
		} else if v, ok := tag.Lookup("json"); ok && v != "-" {
			e.text(e.textUse(st, st.Val), "JSON field "+display(fname), pos, framework.SeverityWarning)
		}
	}
	return memoHit
}

// sdkDeclared reports whether a struct field belongs to a type the go-stellar-sdk declares. Its generated
// message types are judged by the catalogue and the configuration (sinkstext), not by their struct tags: the
// proto3 tag rule is for the reader's own message types.
func (e *engine) sdkDeclared(f *types.Var) bool {
	if f.Pkg() == nil {
		return false
	}
	p := catalogue.Canonical(f.Pkg().Path(), e.aliases)
	return p == catalogue.SDKModule || strings.HasPrefix(p, catalogue.SDKModule+"/")
}

func (e *engine) mapSink(mu *ssa.MapUpdate) {
	if !isString(mu.Key.Type()) {
		return
	}
	names := []string{framework.EnclosingFunction(e.p.Fset, e.p.Files, mu.Pos())}
	if st := e.ast.stack(mu.Pos()); len(st) > 0 {
		if ix, ok := st[len(st)-1].(*ast.IndexExpr); ok {
			names = append(names, exprName(ix.X))
		}
	}
	if e.namesMatch(names) {
		e.addr(e.addrUse(mu, mu.Key), "a participant map key", mu.Pos())
	}
}

func (e *engine) convSink(v ssa.Value, x ssa.Value) {
	n, ok := types.Unalias(v.Type()).(*types.Named)
	if !ok {
		return
	}
	name := catalogue.Name(n.Obj(), e.aliases)
	in := v.(ssa.Instruction)
	for _, kind := range e.kindsOf(name, n.Obj()) {
		switch kind {
		case sinkParticipant:
			e.addr(e.addrUse(in, x), "participant type "+display(name), v.Pos())
		case sinkAccountKey:
			if e.norm.types[n.Obj()] {
				// Its Value() stores the base key of a muxed address; a
				// non-account kind is refused with an error (addrnorm.go).
				e.addr(e.addrUse(in, x).drop(mAddr), "account-key type "+display(name)+normNote, v.Pos())
				continue
			}
			e.addr(e.addrUse(in, x), "account-key type "+display(name), v.Pos())
		case sinkText:
			e.text(e.textUse(in, x), "text type "+display(name), v.Pos(), "")
		}
	}
}

func (e *engine) namesMatch(names []string) bool {
	for _, n := range names {
		if n != "" && e.partRe.MatchString(n) {
			return true
		}
	}
	return false
}

// callNames returns the names a participant-sink heuristic looks at for the
// call whose opening parenthesis is at pos: the enclosing declared function,
// the receiver expression, the first argument of append, and the variable,
// field or key the result is assigned to.
func (e *engine) callNames(pos token.Pos) []string {
	names := []string{framework.EnclosingFunction(e.p.Fset, e.p.Files, pos)}
	stack := e.ast.stack(pos)
	if len(stack) == 0 {
		return names
	}
	call, ok := stack[len(stack)-1].(*ast.CallExpr)
	if !ok {
		return names
	}
	fun := ast.Unparen(call.Fun)
	switch f := fun.(type) {
	case *ast.IndexExpr:
		fun = f.X
	case *ast.IndexListExpr:
		fun = f.X
	}
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		names = append(names, exprName(f.X))
	case *ast.Ident:
		if f.Name == "append" && len(call.Args) > 0 {
			names = append(names, exprName(call.Args[0]))
		}
	}
	child := ast.Node(call)
parents:
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.ParenExpr:
			child = p
			continue parents
		case *ast.AssignStmt:
			for j, r := range p.Rhs {
				if r == child {
					if len(p.Lhs) == len(p.Rhs) {
						names = append(names, exprName(p.Lhs[j]))
					} else {
						for _, l := range p.Lhs {
							names = append(names, exprName(l))
						}
					}
				}
			}
		case *ast.ValueSpec:
			for _, n := range p.Names {
				names = append(names, n.Name)
			}
		case *ast.KeyValueExpr:
			names = append(names, exprName(p.Key))
		}
		break parents
	}
	return names
}

// exprName returns the identifier an expression ends in: x, x.f, *x, x[i],
// x.f().
func exprName(x ast.Expr) string {
	switch x := ast.Unparen(x).(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return exprName(x.X)
	case *ast.IndexExpr:
		return exprName(x.X)
	case *ast.CallExpr:
		return exprName(x.Fun)
	case *ast.UnaryExpr:
		return exprName(x.X)
	}
	return ""
}

// addrUse is use with the address aspect removed when a re-parse guard on the
// same entry kind-checks v at instruction at (reparse.go).
func (e *engine) addrUse(at ssa.Instruction, v ssa.Value) set {
	s := e.use(at, v)
	if s.any(mAddress) && e.reparseGuarded(at, v) {
		s = s.drop(mAddress)
	}
	return s
}

// normNote is added to a sink that stores the base key of a muxed address
// itself: what is left to report is a non-account kind, which it refuses.
const normNote = " (which reduces M… and W… itself but refuses B…, L… and P… with a write error)"
