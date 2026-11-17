package xdr1xx

// Call resolution. Besides static calls of functions and methods, the
// engine follows two dynamic forms whose targets the package itself shows:
//
//   - method values and method expressions: `f := addr.String; f()` calls
//     the bound-method wrapper of xdr.ScAddress.String with addr as its
//     receiver, and `xdr.ScAddress.String(addr)` calls a thunk whose first
//     argument is the receiver;
//   - interface calls: `a.String()` on an interface value reaches the
//     method of every concrete type the package converts to that same
//     interface type (`var a addresser = scAddr`).
//
// Method values passed to other functions and interface values built in
// other packages are not followed.

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// boundMethod returns the bound-method wrapper a call goes through, and the
// receiver bound into it.
func boundMethod(c *ssa.CallCommon) (*ssa.Function, ssa.Value) {
	if c.IsInvoke() {
		return nil, nil
	}
	mc, ok := c.Value.(*ssa.MakeClosure)
	if !ok || len(mc.Bindings) != 1 {
		return nil, nil
	}
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn.Synthetic == "" || !strings.HasSuffix(fn.Name(), "$bound") {
		return nil, nil
	}
	return fn, mc.Bindings[0]
}

// isThunk reports whether fn is the wrapper of a method expression: it has
// a method's object but no receiver, the receiver being its first parameter.
func isThunk(fn *ssa.Function) bool {
	obj, ok := fn.Object().(*types.Func)
	if !ok || fn.Signature.Recv() != nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	return ok && sig.Recv() != nil
}

// boxed records, per interface type, the concrete types the package
// converts to it.
type boxedType struct {
	iface    types.Type
	concrete types.Type
}

func (e *engine) collectBoxed() {
	seen := map[[2]string]bool{}
	for _, fn := range e.funcs {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				mi, ok := in.(*ssa.MakeInterface)
				if !ok {
					continue
				}
				k := [2]string{mi.Type().String(), mi.X.Type().String()}
				if seen[k] {
					continue
				}
				seen[k] = true
				e.boxed = append(e.boxed, boxedType{mi.Type(), mi.X.Type()})
			}
		}
	}
}

// invokeTargets returns the methods an interface call reaches through the
// concrete types the package converts to the receiver's interface type.
func (e *engine) invokeTargets(c *ssa.CallCommon) []*ssa.Function {
	if !c.IsInvoke() || len(e.funcs) == 0 {
		return nil
	}
	prog := e.funcs[0].Prog
	var out []*ssa.Function
	for _, bx := range e.boxed {
		if !types.Identical(bx.iface, c.Value.Type()) {
			continue
		}
		sel := prog.MethodSets.MethodSet(bx.concrete).Lookup(c.Method.Pkg(), c.Method.Name())
		if sel == nil {
			continue
		}
		if fn := prog.MethodValue(sel); fn != nil {
			out = append(out, fn)
		}
	}
	return out
}

// calleeInfo is one possible target of a call, by object and catalogue name.
type calleeInfo struct {
	obj  types.Object
	name string
}

// callees returns every target of a call the engine can name: the static
// callee (through a bound method or thunk too), or the interface method and
// the methods of the concrete types that reach it.
func (e *engine) callees(c *ssa.CallCommon) []calleeInfo {
	obj, name := e.callee(c)
	var out []calleeInfo
	if obj != nil {
		out = append(out, calleeInfo{obj, name})
	}
	for _, fn := range e.invokeTargets(c) {
		if o := fn.Object(); o != nil {
			out = append(out, calleeInfo{o, catalogue.Name(o, e.aliases)})
		}
	}
	return out
}

// callTarget is a same-package function a call reaches, with the values
// bound to its parameters in order (the receiver first for a method).
type callTarget struct {
	fn   *ssa.Function
	args []ssa.Value
}

// inPkgTargets returns the same-package functions a call reaches: the
// static callee or closure, the method behind a bound method value, or the
// methods an interface call reaches.
func (e *engine) inPkgTargets(c *ssa.CallCommon) []callTarget {
	if fn := e.inPkgCallee(c); fn != nil {
		return []callTarget{{fn, c.Args}}
	}
	if w, recv := boundMethod(c); w != nil {
		if obj, ok := w.Object().(*types.Func); ok {
			if fn := w.Prog.FuncValue(obj); fn != nil && e.inPkg[fn] {
				return []callTarget{{fn, append([]ssa.Value{recv}, c.Args...)}}
			}
		}
		return nil
	}
	var out []callTarget
	for _, fn := range e.invokeTargets(c) {
		if o := fn.Origin(); o != nil {
			fn = o
		}
		if e.inPkg[fn] {
			out = append(out, callTarget{fn, append([]ssa.Value{c.Value}, c.Args...)})
		}
	}
	return out
}
