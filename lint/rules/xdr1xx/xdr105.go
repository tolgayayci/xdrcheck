package xdr1xx

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// XDR105 (opt-in): Must<Arm>() on a union of the SDK's xdr package with more
// than one arm, where no comparison of the union's discriminant (its first
// field: Type, V, Code, …) on the same value dominates the call. Must<Arm>
// panics when the value holds another arm.
//
// A union is a type with an ArmForSwitch method; its arms are the Get<Arm>
// methods returning (T, bool) that have a Must<Arm> counterpart.

type unionInfo struct {
	arms int
	disc string
	has  map[string]bool // arm suffixes
}

func (e *engine) unionOf(n *types.Named) *unionInfo {
	if u, ok := e.unions[n]; ok {
		return u
	}
	var u *unionInfo
	defer func() { e.unions[n] = u }()
	st, ok := n.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return nil
	}
	ms := types.NewMethodSet(types.NewPointer(n))
	if ms.Lookup(n.Obj().Pkg(), "ArmForSwitch") == nil {
		return nil
	}
	info := &unionInfo{disc: st.Field(0).Name(), has: map[string]bool{}}
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i).Obj()
		suffix, ok := strings.CutPrefix(m.Name(), "Get")
		if !ok || suffix == "" {
			continue
		}
		sig, _ := m.Type().(*types.Signature)
		if sig == nil || sig.Results().Len() != 2 {
			continue
		}
		if b, ok := sig.Results().At(1).Type().(*types.Basic); !ok || b.Kind() != types.Bool {
			continue
		}
		if ms.Lookup(n.Obj().Pkg(), "Must"+suffix) == nil {
			continue
		}
		info.has[suffix] = true
		info.arms++
	}
	u = info
	return u
}

func (e *engine) checkMustArm() {
	for _, fn := range e.funcs {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				c, ok := in.(*ssa.Call)
				if !ok || c.Common().IsInvoke() {
					continue
				}
				callee, ok := c.Common().Value.(*ssa.Function)
				if !ok || callee.Signature.Recv() == nil || len(c.Common().Args) == 0 {
					continue
				}
				suffix, ok := strings.CutPrefix(callee.Name(), "Must")
				if !ok || suffix == "" {
					continue
				}
				n, ok := types.Unalias(deref(callee.Signature.Recv().Type())).(*types.Named)
				if !ok || n.Obj().Pkg() == nil || catalogue.Canonical(n.Obj().Pkg().Path(), e.aliases) != catalogue.XDR {
					continue
				}
				u := e.unionOf(n)
				if u == nil || u.arms < 2 || !u.has[suffix] {
					continue
				}
				if e.discChecked(c, e.objKey(c.Common().Args[0])) {
					continue
				}
				e.emit(XDR105.ID, c.Pos(), "", fmt.Sprintf(
					"xdr.%s.%s() on a union with %d arms, with no dominating check of its %s field on the same value; it panics when the value holds another arm",
					n.Obj().Name(), callee.Name(), u.arms, u.disc))
			}
		}
	}
}

// discChecked reports whether a comparison of the discriminant (field 0)
// of the object k dominates the call.
func (e *engine) discChecked(c *ssa.Call, k memKey) bool {
	for d := c.Block().Idom(); d != nil; d = d.Idom() {
		if len(d.Instrs) == 0 {
			continue
		}
		iff, ok := d.Instrs[len(d.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		cmp, ok := iff.Cond.(*ssa.BinOp)
		if !ok || (cmp.Op != token.EQL && cmp.Op != token.NEQ) {
			continue
		}
		if e.isDiscRead(cmp.X, k, 0) || e.isDiscRead(cmp.Y, k, 0) {
			return true
		}
	}
	return false
}
