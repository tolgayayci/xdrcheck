package xdr4xx

// XDR402: a wide integer narrowed without a range check, and stored.
//
// The ledger's integers are wider than the columns and native types many
// readers keep them in: muxed IDs, offer IDs and time bounds are uint64 and
// reach 2^64−1 on mainnet (a minimum sequence age is uint64 too, but core
// keeps it at or below the close time); token amounts and balances are
// i128 (SAC balances above 2^63 exist); signer weights were uint32 before
// core capped them. A conversion that cannot hold the source's range wraps or
// rounds silently.
//
// The rule works on the SSA form. It reports a conversion
//
//   - from uint64 to int64, int, int32, int16, int8, uint32, uint16, uint8,
//     float64 or float32; from int64 to int32 or smaller; from uint32 or
//     int32 to int16 or smaller (uint32 → int32 is not reported: ledger
//     sequences and indexes stay far below 2^31),
//   - of a value computed from a ledger field: on the way back through
//     arithmetic, conversions, loads, field reads and calls, a value of a
//     named integer type of the SDK's xdr package (xdr.Uint64, xdr.Duration,
//     xdr.TimePoint, xdr.Uint32, …), a field of a struct the SDK declares,
//     or the result of an SDK method,
//   - whose result is stored: written to a struct field, a map, a slice
//     element or a variable that escapes, appended, or passed to a database
//     call or a builder (With…, Set…, Add…), possibly after more arithmetic
//     or a conversion to text,
//
// unless a comparison of the converted value (or a value it was computed
// from) with a constant dominates the conversion (a range check). It also
// reports (*big.Int).Int64() and Uint64() without a dominating IsInt64() or
// IsUint64() (an i128 amount narrowed to 64 bits), and strconv.ParseFloat of
// a string read from an SDK field or method named like an amount (an i128
// amount rounded to float64), when the result is stored.

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var Analyzer402 = framework.Register(framework.Spec{
	Name:     "narrowing",
	Doc:      "narrowing reports wide ledger integers converted to a narrower type without a range check and stored (XDR402)",
	Rules:    []framework.Rule{XDR402},
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	Run:      run402,
})

type n402 struct {
	p       *framework.Pass
	aliases []string
}

func run402(p *framework.Pass) (any, error) {
	ssaRes := p.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	n := &n402{p: p, aliases: p.Config().XDRPackageAliases}
	for _, fn := range ssaRes.SrcFuncs {
		n.function(fn)
		for _, an := range fn.AnonFuncs {
			n.function(an)
		}
	}
	return nil, nil
}

func basicKind(t types.Type) types.BasicKind {
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Kind()
	}
	return types.Invalid
}

// narrowing returns the assumption key when a conversion from src to dst
// cannot hold every value of src (and is one the rule reports).
func narrowing(src, dst types.BasicKind) (string, framework.Severity, bool) {
	switch src {
	case types.Uint64, types.Uint, types.Uintptr:
		switch dst {
		case types.Int64, types.Int:
			return AssumeNarrowU64Int64, "", true
		case types.Int32, types.Int16, types.Int8, types.Uint32, types.Uint16, types.Uint8:
			return AssumeNarrowU64Int32, "", true
		case types.Float64, types.Float32:
			return AssumeNarrowU64Float, framework.SeverityWarning, true
		}
	case types.Int64:
		switch dst {
		case types.Int32, types.Int16, types.Int8, types.Uint32, types.Uint16, types.Uint8:
			return AssumeNarrowI64Int32, "", true
		}
	case types.Uint32, types.Int32:
		switch dst {
		case types.Int16, types.Int8, types.Uint16, types.Uint8:
			return AssumeNarrowU32Int16, "", true
		}
	}
	return "", "", false
}

func kindName(k types.BasicKind) string {
	return types.Typ[k].Name()
}

func (n *n402) function(fn *ssa.Function) {
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			switch x := in.(type) {
			case *ssa.Convert:
				src, dst := basicKind(x.X.Type()), basicKind(x.Type())
				key, sev, ok := narrowing(src, dst)
				if !ok {
					continue
				}
				origin := n.ledgerOrigin(x.X)
				if origin == "" || closeTime(origin) || (minSeqAge(origin) && wide(dst)) || n.rangeChecked(x, x.X) {
					continue
				}
				sink := n.stored(x, 0, map[ssa.Value]bool{})
				if sink == "" {
					continue
				}
				report(n.p, XDR402.ID, x.Pos(), key, sev, fmt.Sprintf(
					"%s(…) narrows %s (%s) to %s with no range check, and the result is stored in %s; a value outside the %s range %s",
					kindName(dst), origin, kindName(src), kindName(dst), sink, kindName(dst), effect(dst)))
			case *ssa.Call:
				n.call(x)
			}
		}
	}
}

func effect(dst types.BasicKind) string {
	switch dst {
	case types.Float64, types.Float32:
		return "is rounded"
	}
	return "wraps to another value (a negative one for a signed type)"
}

func (n *n402) call(c *ssa.Call) {
	callee := c.Common().StaticCallee()
	if callee == nil {
		return
	}
	name := callee.String()
	switch {
	case name == "(*math/big.Int).Int64" || name == "(*math/big.Int).Uint64":
		recv := c.Common().Args[0]
		if n.bigChecked(c, recv) || bitSplit(recv) {
			return
		}
		sink := n.stored(c, 0, map[ssa.Value]bool{})
		if sink == "" {
			return
		}
		report(n.p, XDR402.ID, c.Pos(), AssumeNarrowI128Int64, "", fmt.Sprintf(
			"big.Int.%s() narrows a wide integer to 64 bits with no IsInt64/IsUint64 check, and the result is stored in %s; an i128 amount ≥ 2^63 is silently wrong",
			callee.Name(), sink))
	case name == "strconv.ParseFloat":
		if len(c.Common().Args) == 0 || !n.amountString(c.Common().Args[0], 0, map[ssa.Value]bool{}) {
			return
		}
		var res ssa.Value = c
		for _, r := range *c.Referrers() {
			if ex, ok := r.(*ssa.Extract); ok && ex.Index == 0 {
				res = ex
			}
		}
		sink := n.stored(res, 0, map[ssa.Value]bool{})
		if sink == "" {
			return
		}
		report(n.p, XDR402.ID, c.Pos(), AssumeNarrowI128Float, framework.SeverityWarning, fmt.Sprintf(
			"strconv.ParseFloat rounds a token amount to float64, and the result is stored in %s; an amount above 2^53 raw units loses digits, and any scaling by a fixed number of decimals is wrong for a token with other decimals",
			sink))
	}
}

// ledgerOrigin names where v was read from when it comes from the ledger:
// a value of a named integer type of the xdr package, a field of an SDK
// struct, or the result of an SDK function. "" otherwise.
func (n *n402) ledgerOrigin(v ssa.Value) string {
	var out string
	seen := map[ssa.Value]bool{}
	var walk func(v ssa.Value, depth int)
	walk = func(v ssa.Value, depth int) {
		if out != "" || v == nil || depth > 12 || seen[v] {
			return
		}
		seen[v] = true
		if isCloseTimeRead(v) {
			out = closeTimeOrigin
			return
		}
		if n.isMinSeqAgeRead(v) {
			out = minSeqAgeOrigin
			return
		}
		if _, viaInterface := v.(*ssa.TypeAssert); viaInterface {
			return // out of an interface{} (a details map): not followed
		}
		if nt, ok := types.Unalias(v.Type()).(*types.Named); ok && xdrNamed(nt, n.aliases) != nil {
			if _, isBasic := nt.Underlying().(*types.Basic); isBasic {
				out = "xdr." + nt.Obj().Name()
				return
			}
		}
		switch x := v.(type) {
		case *ssa.Convert:
			walk(x.X, depth+1)
		case *ssa.ChangeType:
			walk(x.X, depth+1)
		case *ssa.BinOp:
			walk(x.X, depth+1)
			walk(x.Y, depth+1)
		case *ssa.UnOp:
			if x.Op == token.MUL {
				if fa, ok := x.X.(*ssa.FieldAddr); ok {
					if s := n.sdkField(fa.X.Type(), fa.Field); s != "" {
						out = s
						return
					}
				}
			}
			walk(x.X, depth+1)
		case *ssa.Field:
			if s := n.sdkField(x.X.Type(), x.Field); s != "" {
				out = s
				return
			}
		case *ssa.Phi:
			for _, e := range x.Edges {
				walk(e, depth+1)
			}
		case *ssa.Extract:
			walk(x.Tuple, depth+1)
		case *ssa.Lookup:
			walk(x.X, depth+1)
		case *ssa.Call:
			if f := x.Common().StaticCallee(); f != nil && f.Object() != nil && inSDK(f.Object(), n.aliases) {
				out = "the result of " + shortFunc(f)
			}
		}
	}
	walk(v, 0)
	return out
}

func shortFunc(f *ssa.Function) string {
	s := f.String()
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s + "()"
}

// sdkField names field i of struct type t when the struct is declared in the
// SDK module and the field is an integer.
func (n *n402) sdkField(t types.Type, i int) string {
	for {
		p, ok := t.Underlying().(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	nt, ok := types.Unalias(t).(*types.Named)
	if !ok || !inSDK(nt.Obj(), n.aliases) {
		return ""
	}
	st, ok := nt.Underlying().(*types.Struct)
	if !ok || i >= st.NumFields() {
		return ""
	}
	if _, ok := st.Field(i).Type().Underlying().(*types.Basic); !ok {
		return ""
	}
	pkg := nt.Obj().Pkg().Name()
	return pkg + "." + nt.Obj().Name() + "." + st.Field(i).Name()
}

// rangeChecked reports whether a comparison of the converted value, or of a
// value it was computed from, with a constant dominates the conversion.
func (n *n402) rangeChecked(at ssa.Instruction, v ssa.Value) bool {
	chain := map[ssa.Value]bool{}
	keys := map[string]bool{}
	var collect func(v ssa.Value, depth int)
	collect = func(v ssa.Value, depth int) {
		if v == nil || depth > 10 || chain[v] {
			return
		}
		chain[v] = true
		if k := loadKey(v); k != "" {
			keys[k] = true
		}
		switch x := v.(type) {
		case *ssa.Convert:
			collect(x.X, depth+1)
		case *ssa.ChangeType:
			collect(x.X, depth+1)
		case *ssa.UnOp:
			collect(x.X, depth+1)
		case *ssa.BinOp:
			collect(x.X, depth+1)
			collect(x.Y, depth+1)
		case *ssa.Phi:
			for _, e := range x.Edges {
				collect(e, depth+1)
			}
		}
	}
	collect(v, 0)
	inChain := func(x ssa.Value) bool {
		for i := 0; i < 4; i++ {
			if chain[x] {
				return true
			}
			if k := loadKey(x); k != "" && keys[k] {
				return true
			}
			switch y := x.(type) {
			case *ssa.Convert:
				x = y.X
				continue
			case *ssa.ChangeType:
				x = y.X
				continue
			}
			break
		}
		return false
	}
	for d := at.Block().Idom(); d != nil; d = d.Idom() {
		if len(d.Instrs) == 0 {
			continue
		}
		iff, ok := d.Instrs[len(d.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		cmp, ok := iff.Cond.(*ssa.BinOp)
		if !ok {
			continue
		}
		switch cmp.Op {
		case token.LSS, token.LEQ, token.GTR, token.GEQ: // a bound; == and != (a nil check) are not
		default:
			continue
		}
		_, xc := cmp.X.(*ssa.Const)
		_, yc := cmp.Y.(*ssa.Const)
		if (xc && inChain(cmp.Y)) || (yc && inChain(cmp.X)) {
			return true
		}
	}
	return false
}

// loadKey names the memory a load or field read reads: "root#path".
func loadKey(v ssa.Value) string {
	path := ""
	for i := 0; i < 8; i++ {
		switch x := v.(type) {
		case *ssa.UnOp:
			if x.Op != token.MUL {
				return ""
			}
			v = x.X
		case *ssa.FieldAddr:
			path = fmt.Sprintf("/%d", x.Field) + path
			v = x.X
		case *ssa.Field:
			path = fmt.Sprintf("/%d", x.Field) + path
			v = x.X
		case *ssa.Parameter, *ssa.Alloc, *ssa.Global, *ssa.FreeVar:
			if path == "" {
				return ""
			}
			return fmt.Sprintf("%p%s", x, path)
		default:
			return ""
		}
	}
	return ""
}

// bigChecked reports whether IsInt64, IsUint64, BitLen, Sign or Cmp of the
// same big.Int (any call on it whose result decides a dominating branch)
// dominates at.
func (n *n402) bigChecked(at ssa.Instruction, recv ssa.Value) bool {
	for d := at.Block().Idom(); d != nil; d = d.Idom() {
		if len(d.Instrs) == 0 {
			continue
		}
		if _, ok := d.Instrs[len(d.Instrs)-1].(*ssa.If); !ok {
			continue
		}
		for _, in := range d.Instrs {
			c, ok := in.(*ssa.Call)
			if !ok || c.Common().StaticCallee() == nil {
				continue
			}
			switch c.Common().StaticCallee().Name() {
			case "IsInt64", "IsUint64", "BitLen", "Cmp", "CmpAbs":
				if len(c.Common().Args) > 0 && c.Common().Args[0] == recv {
					return true
				}
			}
		}
	}
	return false
}

// amountString reports whether a string was read from an SDK field or
// method whose name says it is an amount.
func (n *n402) amountString(v ssa.Value, depth int, seen map[ssa.Value]bool) bool {
	if depth > 10 || seen[v] {
		return false
	}
	seen[v] = true
	switch x := v.(type) {
	case *ssa.UnOp:
		if fa, ok := x.X.(*ssa.FieldAddr); ok && n.amountField(fa.X.Type(), fa.Field) {
			return true
		}
		return n.amountString(x.X, depth+1, seen)
	case *ssa.Field:
		return n.amountField(x.X.Type(), x.Field) || n.amountString(x.X, depth+1, seen)
	case *ssa.Call:
		if f := x.Common().StaticCallee(); f != nil && f.Object() != nil && inSDK(f.Object(), n.aliases) &&
			(strings.Contains(f.Name(), "Amount") || strings.Contains(f.Name(), "128")) {
			return true
		}
		if f := x.Common().StaticCallee(); f != nil && (f.Name() == "String" || f.Name() == "Text") {
			// big.Int.String() of an i128 amount.
			for _, a := range x.Common().Args {
				if n.amountString(a, depth+1, seen) {
					return true
				}
			}
		}
	case *ssa.Phi:
		for _, e := range x.Edges {
			if n.amountString(e, depth+1, seen) {
				return true
			}
		}
	case *ssa.Extract:
		return n.amountString(x.Tuple, depth+1, seen)
	case *ssa.ChangeType:
		return n.amountString(x.X, depth+1, seen)
	}
	return false
}

func (n *n402) amountField(t types.Type, i int) bool {
	for {
		p, ok := t.Underlying().(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	nt, ok := types.Unalias(t).(*types.Named)
	if !ok || !inSDK(nt.Obj(), n.aliases) {
		return false
	}
	st, ok := nt.Underlying().(*types.Struct)
	return ok && i < st.NumFields() && strings.Contains(st.Field(i).Name(), "Amount")
}

// stored follows v forward to a place that keeps it and names that place, or
// returns "".
func (n *n402) stored(v ssa.Value, depth int, seen map[ssa.Value]bool) string {
	if depth > 8 || seen[v] || v.Referrers() == nil {
		return ""
	}
	seen[v] = true
	for _, r := range *v.Referrers() {
		switch x := r.(type) {
		case *ssa.Store:
			if x.Val != v {
				continue
			}
			switch a := x.Addr.(type) {
			case *ssa.FieldAddr:
				return "field " + fieldName(a.X.Type(), a.Field)
			case *ssa.IndexAddr:
				return "a slice element"
			case *ssa.Alloc:
				if a.Heap {
					return "a variable passed on (" + a.Comment + ")"
				}
				for _, rr := range *a.Referrers() {
					if ld, ok := rr.(*ssa.UnOp); ok {
						if s := n.stored(ld, depth+1, seen); s != "" {
							return s
						}
					}
				}
			case *ssa.Global:
				return "a package variable"
			}
		case *ssa.MapUpdate:
			if x.Value == v {
				return "a map"
			}
		case *ssa.Convert, *ssa.ChangeType, *ssa.BinOp, *ssa.Phi, *ssa.MakeInterface:
			if s := n.stored(r.(ssa.Value), depth+1, seen); s != "" {
				return s
			}
		case *ssa.Call:
			callee := x.Common().StaticCallee()
			if b, ok := x.Common().Value.(*ssa.Builtin); ok && b.Name() == "append" {
				return "a slice (append)"
			}
			if callee == nil {
				continue
			}
			name := callee.Name()
			switch {
			case strings.HasPrefix(name, "With"), strings.HasPrefix(name, "Set"), strings.HasPrefix(name, "Add"),
				strings.HasPrefix(name, "Insert"), strings.HasPrefix(name, "Exec"), strings.HasPrefix(name, "Copy"):
				return "the argument of " + callee.Name() + "()"
			}
			if pkg := callee.Package(); pkg != nil {
				// Through a conversion to text or a wrapper (strconv, fmt,
				// math/big, a nullable column type such as null.IntFrom):
				// what it returns is stored in its place.
				path := pkg.Pkg.Path()
				if path == "strconv" || path == "fmt" || path == "math/big" || len(x.Common().Args) == 1 && !strings.HasPrefix(path, "github.com/stellar/") {
					if s := n.stored(x, depth+1, seen); s != "" {
						return s
					}
				}
			}
		case *ssa.Return:
			// A result: stored by the caller; followed one level for a
			// same-package function's only call sites is out of scope.
		}
	}
	return ""
}

func fieldName(t types.Type, i int) string {
	for {
		p, ok := t.Underlying().(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || i >= st.NumFields() {
		return "?"
	}
	name := st.Field(i).Name()
	if nt, ok := types.Unalias(t).(*types.Named); ok {
		return nt.Obj().Name() + "." + name
	}
	return name
}

// bitSplit reports whether a big.Int is the result of a shift or a mask
// (splitting a 128-bit value into its 64-bit halves, which fit by
// construction).
func bitSplit(v ssa.Value) bool {
	c, ok := v.(*ssa.Call)
	if !ok || c.Common().StaticCallee() == nil {
		return false
	}
	switch c.Common().StaticCallee().Name() {
	case "Rsh", "And", "AndNot":
		return true
	}
	return false
}

// closeTime reports an origin that is a ledger close time stellar-core
// wrote (a sequence-number time, a header close time): seconds since 1970,
// far below 2^63.
func closeTime(origin string) bool { return origin == closeTimeOrigin }

const closeTimeOrigin = "a ledger close time"

// minSeqAge reports an origin that is a transaction's minimum sequence age
// (PreconditionsV2.MinSeqAge). The submitter writes it, but stellar-core
// admits a transaction only while minSeqAge <= the ledger's close time
// (TransactionFrame::isTooEarlyForAccount: minSeqAge > lowerBoundCloseTime is
// txBAD_MIN_SEQ_AGE_OR_GAP, checked for every transaction of a nominated set,
// and PRECOND_V2 is txNOT_SUPPORTED before protocol 19), so every value a
// ledger holds is a close time or less, far below 2^63. It still does not fit
// 32 bits for long, so only a 64-bit destination is exempt.
func minSeqAge(origin string) bool { return origin == minSeqAgeOrigin }

const minSeqAgeOrigin = "a minimum sequence age (xdr.Duration)"

// wide reports a signed 64-bit destination: int64 or int.
func wide(k types.BasicKind) bool { return k == types.Int64 || k == types.Int }

// isMinSeqAgeRead reports a read of a minimum sequence age: the MinSeqAge
// field of the SDK's xdr.PreconditionsV2, or the value the MinSeqAge()
// accessor of an SDK type (xdr.TransactionEnvelope) points to.
func (n *n402) isMinSeqAgeRead(v ssa.Value) bool {
	field := func(t types.Type, i int) bool {
		nt := xdrNamed(t, n.aliases)
		return nt != nil && nt.Obj().Name() == "PreconditionsV2" && fieldName(t, i) == "PreconditionsV2.MinSeqAge"
	}
	switch x := v.(type) {
	case *ssa.Field:
		return field(x.X.Type(), x.Field)
	case *ssa.UnOp:
		switch y := x.X.(type) {
		case *ssa.FieldAddr:
			return field(y.X.Type(), y.Field)
		case *ssa.Call:
			f := y.Common().StaticCallee()
			if f == nil || f.Name() != "MinSeqAge" || f.Signature.Recv() == nil {
				return false
			}
			return xdrNamed(f.Signature.Recv().Type(), n.aliases) != nil
		}
	}
	return false
}

// isCloseTimeRead reports a read of SeqTime or CloseTime (a field, or the
// SeqTime() accessor).
func isCloseTimeRead(v ssa.Value) bool {
	name := ""
	switch x := v.(type) {
	case *ssa.Call:
		if f := x.Common().StaticCallee(); f != nil {
			name = f.Name()
		}
	case *ssa.Field:
		name = fieldName(x.X.Type(), x.Field)
	case *ssa.UnOp:
		if fa, ok := x.X.(*ssa.FieldAddr); ok {
			name = fieldName(fa.X.Type(), fa.Field)
		}
	}
	return name == "SeqTime" || strings.HasSuffix(name, ".SeqTime") || strings.HasSuffix(name, ".CloseTime")
}
