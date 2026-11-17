package xdr1xx

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

var (
	xp   = catalogue.XDR + "."
	ttp  = catalogue.TokenTransfer + "."
	ingp = catalogue.Ingest + "."
)

// memoIDField is the one memo-derived field that is accepted: the routing-ID
// arm of the token-transfer processor's MuxedInfo, read after a type switch
// (or assertion) chose that arm.
var memoIDField = ttp + "MuxedInfo_Id.Id"

// rolesOf returns the roles of a name among catalogue entries of the given kinds.
func rolesOf(name string, kinds ...catalogue.Kind) []catalogue.Role {
	var out []catalogue.Role
	for _, en := range catalogue.Lookup(name) {
		if slices.Contains(kinds, en.Kind) {
			out = append(out, en.Roles...)
		}
	}
	return out
}

// maskOf returns the aspects a source with these roles carries.
func maskOf(roles []catalogue.Role) (m aspectMask, info bool) {
	for _, r := range roles {
		switch r {
		case catalogue.MemoSource:
			m |= mMemo
		case catalogue.TextSource:
			m |= mText
		case catalogue.AddressSource:
			m |= mAddress
		}
	}
	if m&mText == 0 && slices.Contains(roles, catalogue.SymbolInfo) {
		m |= mText
		info = true
	}
	if slices.Contains(roles, catalogue.TextValidated) {
		m &^= mText
	}
	return m, info
}

// display shortens a catalogue name for a message: "xdr.ScAddress.String".
func display(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

var addrWhy = map[string]string{
	xp + "ScAddress.String":                      "renders M…, W…, B… and L… strkeys for the muxed, claimable-balance and pool kinds",
	xp + "MuxedAccount.Address":                  "renders the M… form of a muxed account",
	xp + "MuxedAccount.GetAddress":               "renders the M… form of a muxed account",
	xp + "SignerKey.Address":                     "renders P…, T… or X… for signers that are not ed25519 keys",
	xp + "SignerKey.GetAddress":                  "renders P…, T… or X… for signers that are not ed25519 keys",
	xp + "AccountEntry.SignerSummary":            "is keyed by signer addresses, P… for signed payloads",
	ingp + "LedgerTransaction.AccountMuxed":      "returns the M… form when the source account is muxed",
	ingp + "LedgerTransaction.FeeAccountAddress": "returns the M… form when the fee account is muxed",
	xp + "MuxedAccountView.Raw":                  "is the raw XDR of a possibly muxed account, multiplexing ID included",
	xp + "MuxedAccountView.MustRaw":              "is the raw XDR of a possibly muxed account, multiplexing ID included",
	xp + "ScAddressView.Raw":                     "is the raw XDR of an address of any kind",
	xp + "ScAddressView.MustRaw":                 "is the raw XDR of an address of any kind",
}

// Kinds of each carrier that do not render a base account (G…) or contract (C…).
var (
	scAddressMuxed      = []string{"ScAddressTypeScAddressTypeMuxedAccount", "ScAddressTypeScAddressTypeMuxedContract"}
	scAddressNonAccount = []string{"ScAddressTypeScAddressTypeClaimableBalance", "ScAddressTypeScAddressTypeLiquidityPool"}
	muxedAccountUnsafe  = []string{"CryptoKeyTypeKeyTypeMuxedEd25519"}
	signerKeyUnsafe     = []string{
		"SignerKeyTypeSignerKeyTypePreAuthTx", "SignerKeyTypeSignerKeyTypeHashX",
		"SignerKeyTypeSignerKeyTypeEd25519SignedPayload",
	}
)

// addrSourceKinds is what each other address source can render: the muxed
// form (M…, W…), a non-account kind (B…, L…, P…, T…, X…), or both.
var addrSourceKinds = map[string]aspectMask{
	xp + "AccountEntry.SignerSummary":            mKind,
	ingp + "LedgerTransaction.AccountMuxed":      mAddr,
	ingp + "LedgerTransaction.FeeAccountAddress": mAddr,
	xp + "MuxedAccountView.Raw":                  mAddr,
	xp + "MuxedAccountView.MustRaw":              mAddr,
	xp + "ScAddressView.Raw":                     mAddress,
	xp + "ScAddressView.MustRaw":                 mAddress,
}

func deref(t types.Type) types.Type {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}

func structOf(t types.Type) *types.Struct {
	s, _ := deref(t).Underlying().(*types.Struct)
	return s
}

// fieldName is the catalogue name of field i of the struct type t (or *t).
func (e *engine) fieldName(t types.Type, i int) string {
	st := structOf(t)
	if st == nil || i >= st.NumFields() {
		return ""
	}
	return catalogue.FieldName(deref(t), st.Field(i).Name(), e.aliases)
}

func (e *engine) typeName(t types.Type) string {
	n, ok := types.Unalias(deref(t)).(*types.Named)
	if !ok {
		return ""
	}
	return catalogue.Name(n.Obj(), e.aliases)
}

// isScText reports whether t is xdr.ScString or xdr.ScBytes (or a pointer to
// one): contract-supplied bytes with no content check.
func (e *engine) isScText(t types.Type) bool {
	switch e.typeName(t) {
	case xp + "ScString", xp + "ScBytes":
		return true
	}
	return false
}

func (e *engine) armRole(t types.Type) catalogue.Role {
	name := e.typeName(t)
	switch {
	case catalogue.Has(name, catalogue.MemoArmID):
		return catalogue.MemoArmID
	case catalogue.Has(name, catalogue.MemoArmUnsafe):
		return catalogue.MemoArmUnsafe
	}
	return ""
}

// sourceAt records the labels v introduces, if v is a source.
func (e *engine) sourceAt(v ssa.Value) {
	var o origin
	switch v := v.(type) {
	case *ssa.Call:
		for _, ce := range e.callees(v.Common()) {
			mask, info := maskOf(rolesOf(ce.name, catalogue.KindMethod, catalogue.KindFunc))
			if mask&mAddress != 0 {
				mask &^= mAddress &^ e.addrSourceApplies(v, ce.name)
			}
			if mask != 0 {
				o = origin{pos: v.Pos(), aspects: mask, what: display(ce.name) + "()", why: addrWhy[ce.name], info: info}
				break
			}
		}
	case *ssa.Field:
		o = e.fieldSource(v.X.Type(), v.Field, v.Pos())
	case *ssa.FieldAddr:
		o = e.fieldSource(v.X.Type(), v.Field, v.Pos())
	case *ssa.TypeAssert:
		if e.armRole(v.AssertedType) == catalogue.MemoArmUnsafe {
			o = origin{pos: v.Pos(), aspects: mMemo, what: "the " + display(e.typeName(v.AssertedType)) + " arm of a type switch"}
		}
	case *ssa.Parameter:
		if e.isScText(v.Type()) {
			o = origin{pos: v.Pos(), aspects: mText, what: "parameter " + v.Name() + " of type " + display(e.typeName(v.Type()))}
		}
	}
	if o.aspects == 0 {
		return
	}
	if !o.pos.IsValid() {
		if in, ok := v.(ssa.Instruction); ok && in.Block() != nil {
			o.pos = in.Parent().Pos()
		}
	}
	e.src[v] = union(e.src[v], e.newOrigin(o))
}

func (e *engine) fieldSource(t types.Type, i int, pos token.Pos) origin {
	name := e.fieldName(t, i)
	if name == "" || name == memoIDField {
		return origin{}
	}
	mask, info := maskOf(rolesOf(name, catalogue.KindField))
	if st := structOf(t); st != nil && e.isScText(st.Field(i).Type()) && mask&mText == 0 && !info {
		mask |= mText
	}
	return origin{pos: pos, aspects: mask, what: display(name), info: info}
}

// addrSourceApplies reports whether an address-rendering call is an XDR102
// source here: not when a dominating kind check rules out every kind that
// does not render a base address, and not for an ScAddress written by the
// host into a contract-data entry (never a muxed kind). An address from the
// authorization tree or invocation arguments is a source like any other:
// XDR301 says it must not be a participant at all, and XDR102 says that, if
// it is stored, it is stored without its kind being checked.
func (e *engine) addrSourceApplies(c *ssa.Call, name string) aspectMask {
	recv, _ := splitArgs(c.Common())
	var m aspectMask
	switch name {
	case xp + "ScAddress.String":
		if recv != nil && e.exempt(recv, 0, map[ssa.Value]bool{}) {
			return 0
		}
		if !e.kindSafe(c, recv, "Type", scAddressMuxed) {
			m |= mAddr
		}
		if !e.kindSafe(c, recv, "Type", scAddressNonAccount) && (recv == nil || e.mayBeEvent(recv)) {
			m |= mKind // B… and L… come only from events (eventorigin.go)
		}
		return m
	case xp + "MuxedAccount.Address", xp + "MuxedAccount.GetAddress":
		if !e.kindSafe(c, recv, "Type", muxedAccountUnsafe) {
			return mAddr
		}
		return 0
	case xp + "SignerKey.Address", xp + "SignerKey.GetAddress":
		if !e.kindSafe(c, recv, "Type", signerKeyUnsafe) {
			return mKind
		}
		return 0
	}
	return addrSourceKinds[name]
}

func (e *engine) exemptField(t types.Type, i int) bool {
	name := e.fieldName(t, i)
	return catalogue.Has(name, catalogue.MetaWrittenAddr)
}

// exempt walks back from an ScAddress to where it was read.
func (e *engine) exempt(v ssa.Value, depth int, seen map[ssa.Value]bool) bool {
	if depth > 16 || seen[v] {
		return false
	}
	seen[v] = true
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op == token.MUL {
			return e.exempt(x.X, depth+1, seen)
		}
	case *ssa.FieldAddr:
		return e.exemptField(x.X.Type(), x.Field) || e.exempt(x.X, depth+1, seen)
	case *ssa.Field:
		return e.exemptField(x.X.Type(), x.Field) || e.exempt(x.X, depth+1, seen)
	case *ssa.IndexAddr:
		return e.exempt(x.X, depth+1, seen)
	case *ssa.Index:
		return e.exempt(x.X, depth+1, seen)
	case *ssa.Extract:
		return e.exempt(x.Tuple, depth+1, seen)
	case *ssa.TypeAssert:
		return e.exempt(x.X, depth+1, seen)
	case *ssa.ChangeType:
		return e.exempt(x.X, depth+1, seen)
	case *ssa.Call:
		_, name := e.callee(x.Common())
		if catalogue.Has(name, catalogue.MetaWrittenAddr) {
			return true
		}
		if recv, _ := splitArgs(x.Common()); recv != nil {
			return e.exempt(recv, depth+1, seen)
		}
	case *ssa.Phi:
		for _, ed := range x.Edges {
			if !e.exempt(ed, depth+1, seen) {
				return false
			}
		}
		return len(x.Edges) > 0
	case *ssa.Alloc:
		stored := false
		for _, r := range *x.Referrers() {
			if st, ok := r.(*ssa.Store); ok && st.Addr == x {
				if !e.exempt(st.Val, depth+1, seen) {
					return false
				}
				stored = true
			}
		}
		return stored
	}
	return false
}

// enumConsts returns the declared constants of the named type t, in value
// order, as exact strings.
func enumConsts(t types.Type) []string {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return nil
	}
	scope := n.Obj().Pkg().Scope()
	var vals []constant.Value
	for _, name := range scope.Names() {
		if c, ok := scope.Lookup(name).(*types.Const); ok && types.Identical(c.Type(), t) {
			vals = append(vals, c.Val())
		}
	}
	slices.SortFunc(vals, func(a, b constant.Value) int {
		if constant.Compare(a, token.LSS, b) {
			return -1
		}
		if constant.Compare(a, token.EQL, b) {
			return 0
		}
		return 1
	})
	var out []string
	for _, v := range vals {
		s := v.ExactString()
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// kindSafe reports whether, at instruction at, the discriminant field of
// recv provably holds none of the unsafe constants: a forward dataflow over
// the function's blocks of the values the discriminant can still have,
// narrowed by every == or != comparison of that field of the same object
// against a constant.
func (e *engine) kindSafe(at ssa.Instruction, recv ssa.Value, field string, unsafe []string) bool {
	if recv == nil || at.Block() == nil {
		return false
	}
	st := structOf(recv.Type())
	if st == nil {
		return false
	}
	fidx := -1
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == field {
			fidx = i
		}
	}
	if fidx < 0 {
		return false
	}
	ftype := st.Field(fidx).Type()
	vals := enumConsts(ftype)
	if len(vals) == 0 || len(vals) > 63 {
		return false
	}
	bit := map[string]uint64{}
	for i, v := range vals {
		bit[v] = 1 << uint(i)
	}
	universe := uint64(1)<<uint(len(vals)) - 1
	var bad uint64
	if n, ok := types.Unalias(ftype).(*types.Named); ok {
		for _, name := range unsafe {
			if c, ok := n.Obj().Pkg().Scope().Lookup(name).(*types.Const); ok {
				bad |= bit[c.Val().ExactString()]
			}
		}
	}
	if bad == 0 {
		return false
	}
	k := e.objKey(recv)
	fn := at.Parent()
	constraint := func(p, b *ssa.BasicBlock) uint64 {
		if len(p.Instrs) == 0 {
			return universe
		}
		iff, ok := p.Instrs[len(p.Instrs)-1].(*ssa.If)
		if !ok || len(p.Succs) != 2 || p.Succs[0] == p.Succs[1] {
			return universe
		}
		cmp, ok := iff.Cond.(*ssa.BinOp)
		if !ok || (cmp.Op != token.EQL && cmp.Op != token.NEQ) {
			return universe
		}
		x, c := cmp.X, cmp.Y
		if _, isConst := x.(*ssa.Const); isConst {
			x, c = c, x
		}
		cv, ok := c.(*ssa.Const)
		if !ok || cv.Value == nil || !e.isDiscRead(x, k, fidx) {
			return universe
		}
		cb, ok := bit[cv.Value.ExactString()]
		if !ok {
			return universe
		}
		taken := b == p.Succs[0] // the comparison held
		if (cmp.Op == token.EQL) == taken {
			return cb
		}
		return universe &^ cb
	}
	possible := map[*ssa.BasicBlock]uint64{}
	for changed := true; changed; {
		changed = false
		for _, b := range fn.Blocks {
			var in uint64
			if b.Index == 0 || b == fn.Recover {
				in = universe
			} else {
				for _, p := range b.Preds {
					in |= possible[p] & constraint(p, b)
				}
			}
			if in|possible[b] != possible[b] {
				possible[b] |= in
				changed = true
			}
		}
	}
	return possible[at.Block()]&bad == 0
}

// isDiscRead reports whether x reads field fidx of the object k.
func (e *engine) isDiscRead(x ssa.Value, k memKey, fidx int) bool {
	for {
		switch y := x.(type) {
		case *ssa.ChangeType:
			x = y.X
			continue
		case *ssa.Convert:
			x = y.X
			continue
		}
		break
	}
	switch y := x.(type) {
	case *ssa.UnOp:
		if fa, ok := y.X.(*ssa.FieldAddr); ok && y.Op == token.MUL && fa.Field == fidx {
			return e.key(fa.X) == k
		}
	case *ssa.Field:
		return y.Field == fidx && e.objKey(y.X) == k
	}
	return false
}

// findArms records the type-switch arms of fn that chose a memo arm that is
// not a routing ID.
func (e *engine) findArms(fn *ssa.Function) {
	for _, b := range fn.Blocks {
		if len(b.Instrs) == 0 || len(b.Succs) != 2 {
			continue
		}
		iff, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		ex, ok := iff.Cond.(*ssa.Extract)
		if !ok || ex.Index != 1 {
			continue
		}
		ta, ok := ex.Tuple.(*ssa.TypeAssert)
		if !ok || !ta.CommaOk || e.armRole(ta.AssertedType) != catalogue.MemoArmUnsafe {
			continue
		}
		e.arms[fn] = append(e.arms[fn], armRegion{entry: b.Succs[0], label: e.src[ta]})
	}
}

// sanitises returns the aspects a call removes from its result.
func (e *engine) sanitises(name string, c *ssa.CallCommon) aspectMask {
	var m aspectMask
	if catalogue.Has(name, catalogue.AddressNormaliser) || e.sanAddr[name] {
		m |= mAddress
	}
	if e.sanText[name] {
		m |= mText
	}
	_, args := splitArgs(c)
	switch name {
	case "strings.ToValidUTF8", "bytes.ToValidUTF8":
		m |= mUTF8
	case "strings.ReplaceAll", "bytes.ReplaceAll":
		if len(args) > 1 && isNULString(args[1]) {
			m |= mNUL
		}
	case "strings.Replace", "bytes.Replace":
		if len(args) > 3 && isNULString(args[1]) && constInt(args[3]) < 0 {
			m |= mNUL
		}
	case "encoding/base64.Encoding.EncodeToString", "encoding/hex.EncodeToString", "strconv.Quote", "strconv.QuoteToASCII":
		m |= mText
	case "strconv.ParseUint", "strconv.ParseInt", "strconv.Atoi", "strconv.ParseFloat", "strconv.ParseBool",
		"strconv.FormatUint", "strconv.FormatInt", "strconv.Itoa":
		// A number parsed from text, or rendered as digits, holds no text.
		m |= mText
	}
	return m
}

func stripConv(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		case *ssa.MakeInterface:
			v = x.X
		default:
			return v
		}
	}
}

func constOf(v ssa.Value) constant.Value {
	if c, ok := stripConv(v).(*ssa.Const); ok {
		return c.Value
	}
	return nil
}

// isNULString reports whether v is the constant "\x00" (or []byte("\x00")).
func isNULString(v ssa.Value) bool {
	c := constOf(v)
	return c != nil && c.Kind() == constant.String && constant.StringVal(c) == "\x00"
}

func containsNUL(v ssa.Value) bool {
	c := constOf(v)
	return c != nil && c.Kind() == constant.String && strings.Contains(constant.StringVal(c), "\x00")
}

// constInt returns v as an integer constant, or 1 when it is not one.
func constInt(v ssa.Value) int64 {
	c := constOf(v)
	if c == nil || c.Kind() != constant.Int {
		return 1
	}
	n, ok := constant.Int64Val(c)
	if !ok {
		return 1
	}
	return n
}

func isZero(v ssa.Value) bool {
	c := constOf(v)
	return c != nil && c.Kind() == constant.Int && constant.Sign(c) == 0
}

// collectDirectives reads //xdrlint:sink directives on functions, struct
// fields and type declarations of the package.
func (e *engine) collectDirectives() {
	var sinks []struct {
		pos  token.Pos
		kind string
	}
	for _, d := range e.p.Directives() {
		if d.Verb == "sink" && d.Problem == "" {
			kind, _, _ := strings.Cut(d.Arg, " ")
			sinks = append(sinks, struct {
				pos  token.Pos
				kind string
			}{d.Pos, kind})
		}
	}
	if len(sinks) == 0 {
		return
	}
	kindIn := func(groups ...*ast.CommentGroup) string {
		for _, g := range groups {
			if g == nil {
				continue
			}
			for _, s := range sinks {
				if g.Pos() <= s.pos && s.pos < g.End() {
					return s.kind
				}
			}
		}
		return ""
	}
	mark := func(id *ast.Ident, kind string) {
		if obj := e.p.TypesInfo.Defs[id]; obj != nil && kind != "" {
			e.sinkObjs[obj] = kind
		}
	}
	for _, f := range e.p.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				mark(n.Name, kindIn(n.Doc))
			case *ast.GenDecl:
				for _, sp := range n.Specs {
					if ts, ok := sp.(*ast.TypeSpec); ok {
						groups := []*ast.CommentGroup{ts.Doc, ts.Comment}
						if len(n.Specs) == 1 {
							groups = append(groups, n.Doc)
						}
						mark(ts.Name, kindIn(groups...))
					}
				}
			case *ast.Field:
				k := kindIn(n.Doc, n.Comment)
				for _, id := range n.Names {
					mark(id, k)
				}
			}
			return true
		})
	}
}
