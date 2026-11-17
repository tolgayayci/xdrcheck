package xdr2xx

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// unlimitedAt is the smallest MaxDepth treated as "no limit".
var unlimitedAt = constant.MakeUint64(1 << 62)

// decoders implements XDR205 and the XDR207 check of decoder depth.
func (s *state) decoders() {
	for _, file := range s.pass.Files {
		ast.Inspect(file, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.Ident:
				if c, ok := s.info.Uses[x].(*types.Const); ok && c.Pkg() != nil &&
					catalogue.Canonical(c.Pkg().Path(), s.aliases) == catalogue.GoXDR && c.Name() == "DecodeUnlimitedDepth" {
					s.report(XDR205.ID, x.Pos(), "", "decoder depth limit disabled with DecodeUnlimitedDepth: input can nest until the stack is exhausted; use a limit at or above what stellar-core admits (go-xdr default 1500 units)")
				}
			case *ast.CompositeLit:
				s.decodeOptions(x)
			case *ast.CallExpr:
				s.unmarshalCall(x)
			}
			return true
		})
	}
}

func (s *state) isDecodeOptions(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Name() == "DecodeOptions" &&
		catalogue.Canonical(n.Obj().Pkg().Path(), s.aliases) == catalogue.GoXDR
}

// optionField returns the value given to field in a DecodeOptions literal.
func optionField(lit *ast.CompositeLit, field string) ast.Expr {
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
				return kv.Value
			}
		}
	}
	return nil
}

func (s *state) decodeOptions(lit *ast.CompositeLit) {
	if !s.isDecodeOptions(s.info.TypeOf(lit)) {
		return
	}
	v := optionField(lit, "MaxDepth")
	if v == nil {
		return
	}
	c := s.constInt(v)
	if c == nil {
		return
	}
	if constant.Compare(c, token.GEQ, unlimitedAt) {
		if !s.usesUnlimitedConst(v) { // the named constant is reported where it is used
			s.report(XDR205.ID, v.Pos(), "", "decoder depth limit set to an unlimited value: input can nest until the stack is exhausted; use a limit at or above what stellar-core admits (go-xdr default 1500 units)")
		}
		return
	}
	n, _ := constant.Int64Val(c)
	fl := s.decodeFloor()
	if n > 0 && n < int64(fl.levels) && s.decodesMeta(lit) {
		s.report(XDR207.ID, v.Pos(), framework.SeverityWarning,
			"decoder MaxDepth %d is below the %d %s a reader of ledger meta needs (%s); this decoder rejects valid ledgers", n, fl.levels, fl.unit, fl.source)
	}
}

func (s *state) usesUnlimitedConst(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok {
			if c, ok := s.info.Uses[id].(*types.Const); ok && c.Name() == "DecodeUnlimitedDepth" {
				found = true
			}
		}
		return !found
	})
	return found
}

// decodesMeta reports whether a DecodeOptions literal configures a decode
// of ledger meta: its function is fed from meta, or a call it is passed to
// decodes into a meta type.
func (s *state) decodesMeta(lit *ast.CompositeLit) bool {
	if n := s.nodeAt(lit.Pos()); n != nil && s.fed[n] {
		return true
	}
	file := s.fileOf(lit.Pos())
	meta := false
	ast.Inspect(file, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok || meta {
			return !meta
		}
		uses := false
		for _, a := range call.Args {
			if ast.Unparen(a) == lit {
				uses = true
			}
		}
		if uses {
			for _, a := range call.Args {
				if s.isMetaType(s.info.TypeOf(a)) {
					meta = true
				}
			}
		}
		return true
	})
	return meta
}

// unmarshalCall is XDR205 (b): decoding from a reader of unknown length
// with no MaxInputLen.
func (s *state) unmarshalCall(call *ast.CallExpr) {
	callee := s.callee(call)
	if callee == nil || len(call.Args) < 2 {
		return
	}
	name := s.qname(callee)
	switch name {
	case catalogue.XDR + ".Unmarshal":
	case catalogue.XDR + ".UnmarshalWithOptions":
		if len(call.Args) < 3 {
			return
		}
		lit, ok := ast.Unparen(call.Args[2]).(*ast.CompositeLit)
		if !ok || optionField(lit, "MaxInputLen") != nil {
			return // options from a variable are not examined
		}
	default:
		return
	}
	r := call.Args[0]
	if hasLen(s.info.TypeOf(r)) {
		return
	}
	s.report(XDR205.ID, call.Pos(), framework.SeverityWarning,
		"%s reads from %s, whose length the decoder cannot see, with no MaxInputLen: a length prefix can request more memory than the input holds; decode from bytes (SafeUnmarshal) or set DecodeOptions.MaxInputLen",
		callee.Name(), types.ExprString(r))
}

// hasLen reports whether t has a method Len() int, which the decoder uses
// to bound allocations.
func hasLen(t types.Type) bool {
	if t == nil {
		return false
	}
	obj, _, _ := types.LookupFieldOrMethod(t, true, nil, "Len")
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig := fn.Type().(*types.Signature)
	return sig.Params().Len() == 0 && sig.Results().Len() == 1 && isInteger(sig.Results().At(0).Type())
}
