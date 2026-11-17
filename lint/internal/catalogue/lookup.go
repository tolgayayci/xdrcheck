package catalogue

import (
	"go/types"
	"slices"
	"sort"
	"strings"
)

var index = func() map[string][]Entry {
	m := map[string][]Entry{}
	for _, en := range Entries {
		m[en.Name] = append(m[en.Name], en)
	}
	return m
}()

// Lookup returns the entries for a fully qualified name (already canonical).
func Lookup(name string) []Entry { return index[name] }

// Has reports whether name carries role.
func Has(name string, role Role) bool {
	for _, en := range index[name] {
		if slices.Contains(en.Roles, role) {
			return true
		}
	}
	return false
}

// ByRole returns the entries carrying role, in catalogue order.
func ByRole(role Role) []Entry {
	var out []Entry
	for _, en := range Entries {
		if slices.Contains(en.Roles, role) {
			out = append(out, en)
		}
	}
	return out
}

// Canonical maps a package path onto the catalogue's path: the pre-split
// module github.com/stellar/go and each configured alias of the SDK's xdr
// package (configuration key xdrpackagealiases) map onto the SDK's paths.
func Canonical(pkgPath string, xdrAliases []string) string {
	if slices.Contains(xdrAliases, pkgPath) {
		return XDR
	}
	if rest, ok := strings.CutPrefix(pkgPath, PreSplitModule+"/"); ok {
		return SDKModule + "/" + rest
	}
	return pkgPath
}

// Name returns the fully qualified name of a package-level object or of a
// method (receiver type name + method), with a canonical package path. It
// returns "" for a field (use SelectionName or FieldName: a types.Var does
// not know its struct) and for local objects.
func Name(obj types.Object, xdrAliases []string) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	pkg := Canonical(obj.Pkg().Path(), xdrAliases)
	switch o := obj.(type) {
	case *types.Func:
		sig, _ := o.Type().(*types.Signature)
		if sig != nil && sig.Recv() != nil {
			if tn := typeName(sig.Recv().Type()); tn != nil {
				return pkg + "." + tn.Name() + "." + o.Name()
			}
			return ""
		}
		return pkg + "." + o.Name()
	case *types.Var:
		if o.IsField() || o.Parent() != o.Pkg().Scope() {
			return ""
		}
	default:
		if obj.Parent() != obj.Pkg().Scope() {
			return ""
		}
	}
	return pkg + "." + obj.Name()
}

// FieldName returns the fully qualified name of field of the named struct
// type t ("…/xdr.MuxedAccountMed25519.Id"), for composite literals.
func FieldName(t types.Type, field string, xdrAliases []string) string {
	tn := typeName(t)
	if tn == nil || tn.Pkg() == nil {
		return ""
	}
	return Canonical(tn.Pkg().Path(), xdrAliases) + "." + tn.Name() + "." + field
}

// SelectionName returns the fully qualified name of the field or method a
// selector expression selects, following promoted fields to the struct
// that declares them.
func SelectionName(sel *types.Selection, xdrAliases []string) string {
	if sel == nil {
		return ""
	}
	switch sel.Kind() {
	case types.MethodVal, types.MethodExpr:
		return Name(sel.Obj(), xdrAliases)
	case types.FieldVal:
		owner := sel.Recv()
		idx := sel.Index()
		for _, i := range idx[:len(idx)-1] {
			st, ok := deref(owner).Underlying().(*types.Struct)
			if !ok {
				return ""
			}
			owner = st.Field(i).Type()
		}
		return FieldName(owner, sel.Obj().Name(), xdrAliases)
	}
	return ""
}

func deref(t types.Type) types.Type {
	for {
		p, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return types.Unalias(t)
		}
		t = p.Elem()
	}
}

func typeName(t types.Type) *types.TypeName {
	if n, ok := deref(t).(*types.Named); ok {
		return n.Obj()
	}
	return nil
}

// RecursiveTypes computes the recursive-type set of a package: every exported named
// type of pkg that lies on a cycle of the type graph, where an edge goes
// from a named type to each named type of the same package reachable
// through its structure (fields, pointers, slices, arrays, maps) without
// passing through another named type. It returns qualified names, sorted.
// The rules use this set rather than a hard-coded list, so new recursive
// arms of a future SDK are picked up; TestRecursiveTypes pins the v0.9.0
// result to the RecursiveType rows of the catalogue.
func RecursiveTypes(pkg *types.Package) []string {
	scope := pkg.Scope()
	edges := map[*types.Named][]*types.Named{}
	var nodes []*types.Named
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() || !tn.Exported() {
			continue
		}
		n, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		nodes = append(nodes, n)
		seen := map[types.Type]bool{}
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if seen[t] {
				return
			}
			seen[t] = true
			switch u := types.Unalias(t).(type) {
			case *types.Named:
				if u.Obj().Pkg() == pkg {
					edges[n] = append(edges[n], u)
				}
			case *types.Pointer:
				walk(u.Elem())
			case *types.Slice:
				walk(u.Elem())
			case *types.Array:
				walk(u.Elem())
			case *types.Map:
				walk(u.Key())
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					walk(u.Field(i).Type())
				}
			}
		}
		walk(n.Underlying())
	}

	// Tarjan's strongly connected components.
	idx, low := map[*types.Named]int{}, map[*types.Named]int{}
	onStack := map[*types.Named]bool{}
	var stack []*types.Named
	var out []string
	counter := 0
	var strong func(v *types.Named)
	strong = func(v *types.Named) {
		idx[v], low[v] = counter, counter
		counter++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range edges[v] {
			if _, ok := idx[w]; !ok {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], idx[w])
			}
		}
		if low[v] != idx[v] {
			return
		}
		var comp []*types.Named
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			comp = append(comp, w)
			if w == v {
				break
			}
		}
		if len(comp) > 1 || slices.Contains(edges[v], v) {
			for _, c := range comp {
				out = append(out, pkg.Path()+"."+c.Obj().Name())
			}
		}
	}
	for _, v := range nodes {
		if _, ok := idx[v]; !ok {
			strong(v)
		}
	}
	sort.Strings(out)
	return out
}
