package xdr1xx

// Field-sensitive struct values. The labels of a struct value (val) are the
// union of its fields' labels, which is what a sink that takes the whole
// value needs. A field read needs only that field: a decoded entry that
// carries a contract-supplied name in one field and a decimal amount in
// another must not taint the amount. A shape maps a field path below a
// struct value ("/3", "/3/0", "/2/[]") to the labels stored there; the path
// "" holds labels that apply to every field (a whole value copied in from
// somewhere that was not tracked field by field).
//
// Shapes are computed from memory for loads of a struct, and are carried
// into same-package callees (struct parameters) and out of them (struct
// results), and through field reads of struct fields and phis. A pointer's
// target is one location per allocation and field path, and what a pointer
// field points to is conflated. A struct pointer passed to a same-package
// callee (a method receiver) hands the callee the caller's memory below it,
// path by path, so the callee's field reads stay field by field.

import (
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

type shape map[string]set

func (sh shape) add(path string, s set) bool {
	if s.empty() {
		return false
	}
	cur := sh[path]
	grew := cur.union(s)
	if grew {
		sh[path] = cur
	}
	return grew
}

func (sh shape) addAll(o shape) bool {
	grew := false
	for p, s := range o {
		if sh.add(p, s) {
			grew = true
		}
	}
	return grew
}

// sub returns the shape of the field at path f (for example "/3").
func (sh shape) sub(f string) shape {
	out := shape{}
	for p, s := range sh {
		switch {
		case p == f || strings.HasPrefix(p, f+"/"):
			out.add(p[len(f):], s)
		case p == "" || strings.HasPrefix(f, p+"/"):
			out.add("", s)
		}
	}
	return out
}

// minus returns a copy of sh without the labels in o.
func (sh shape) minus(o set) shape {
	if o.empty() {
		return sh
	}
	out := shape{}
	for p, s := range sh {
		out.add(p, s.minus(o))
	}
	return out
}

// dropAspects returns a copy of sh without the aspects in m.
func (sh shape) dropAspects(m aspectMask) shape {
	if m == 0 {
		return sh
	}
	out := shape{}
	for p, s := range sh {
		out.add(p, s.drop(m))
	}
	return out
}

func (sh shape) labels() set {
	var out set
	for _, s := range sh {
		out.union(s)
	}
	return out
}

func isStruct(t types.Type) bool {
	_, ok := t.Underlying().(*types.Struct)
	return ok
}

// shapeOf returns the shape of a struct-typed value.
func (e *engine) shapeOf(v ssa.Value, depth int) shape {
	whole := shape{}
	if depth > 6 || !isStruct(v.Type()) {
		whole.add("", e.val[v])
		return whole
	}
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op != token.MUL {
			break
		}
		k := e.key(x.X)
		out := shape{}
		out.add("", e.use(x, x.X))
		for p, s := range e.mem[k.root] {
			switch {
			case p == k.path || strings.HasPrefix(p, k.path+"/"):
				out.add(p[len(k.path):], s)
			case p == "" || strings.HasPrefix(k.path, p+"/"):
				out.add("", s)
			}
		}
		return out
	case *ssa.Parameter:
		out := shape{}
		out.addAll(e.pshape[x])
		out.add("", e.src[x])
		return out
	case *ssa.Extract:
		if c, ok := x.Tuple.(*ssa.Call); ok {
			if targets := e.inPkgTargets(c.Common()); len(targets) > 0 {
				out := shape{}
				for _, t := range targets {
					out.addAll(e.rshape[t.fn][x.Index].minus(e.foreign(c, t)).dropAspects(e.callDrop(c)))
				}
				out.add("", e.src[c])
				return out
			}
		}
	case *ssa.Call:
		if targets := e.inPkgTargets(x.Common()); len(targets) > 0 {
			out := shape{}
			for _, t := range targets {
				out.addAll(e.rshape[t.fn][0].minus(e.foreign(x, t)).dropAspects(e.callDrop(x)))
			}
			out.add("", e.src[x])
			return out
		}
	case *ssa.Field:
		return e.shapeOf(x.X, depth+1).sub("/" + strconv.Itoa(x.Field))
	case *ssa.Phi:
		out := shape{}
		for _, ed := range x.Edges {
			out.addAll(e.shapeOf(ed, depth+1))
		}
		return out
	}
	whole.add("", e.val[v])
	return whole
}

// fieldRead returns the labels of field i of the struct value x, read at at.
func (e *engine) fieldRead(at ssa.Instruction, x ssa.Value, i int) set {
	s := e.shapeOf(x, 0).sub("/" + strconv.Itoa(i)).labels()
	if s.any(mText) && e.hasGuards(x) {
		s = s.drop(e.guardedAt(at, x))
	}
	return s
}

// storeShape stores a struct value field by field.
func (e *engine) storeShape(k memKey, v ssa.Value) bool {
	grew := false
	for p, s := range e.shapeOf(v, 0) {
		if e.addMem(memKey{root: k.root, path: k.path + p}, s) {
			grew = true
		}
	}
	return grew
}

func (e *engine) addPShape(p *ssa.Parameter, sh shape) bool {
	cur := e.pshape[p]
	if cur == nil {
		cur = shape{}
		e.pshape[p] = cur
	}
	return cur.addAll(sh)
}

func (e *engine) addRShape(fn *ssa.Function, i int, sh shape) bool {
	m := e.rshape[fn]
	if m == nil {
		m = map[int]shape{}
		e.rshape[fn] = m
	}
	cur := m[i]
	if cur == nil {
		cur = shape{}
		m[i] = cur
	}
	return cur.addAll(sh)
}
