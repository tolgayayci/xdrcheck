package xdr2xx

// The package's call graph over function declarations and function
// literals, its strongly connected components, the recursive-type set, and
// which functions are fed from ledger meta.

import (
	"go/ast"
	"go/types"
	"slices"
	"sync"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// node is a function: a declaration, or a literal inside one.
type node struct {
	decl  *ast.FuncDecl // the declaration, or the one enclosing the literal
	lit   *ast.FuncLit  // nil for a declaration
	obj   *types.Func   // declarations only
	name  string        // for messages
	ftype *ast.FuncType
	body  *ast.BlockStmt
	calls []edge
	// facts about the body, without nested literals
	readsMeta bool
}

type edge struct {
	call *ast.CallExpr
	to   *node
}

func (n *node) params() []*ast.Field {
	if n.ftype.Params == nil {
		return nil
	}
	return n.ftype.Params.List
}

// collectNodes builds the nodes and the static call edges between them.
// A call through a variable that is assigned a function literal (the
// `var walk func(…); walk = func(…) { … walk(…) }` idiom) is an edge to
// that literal.
func (s *state) collectNodes() {
	s.byObj = map[*types.Func]*node{}
	s.byLit = map[*ast.FuncLit]*node{}
	litOfVar := map[types.Object]*node{}
	for _, file := range s.pass.Files {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			obj, _ := s.info.Defs[fd.Name].(*types.Func)
			n := &node{decl: fd, obj: obj, name: fd.Name.Name, ftype: fd.Type, body: fd.Body}
			s.nodes = append(s.nodes, n)
			if obj != nil {
				s.byObj[obj] = n
			}
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				if lit, ok := x.(*ast.FuncLit); ok {
					ln := &node{decl: fd, lit: lit, name: "a closure in " + fd.Name.Name, ftype: lit.Type, body: lit.Body}
					s.nodes = append(s.nodes, ln)
					s.byLit[lit] = ln
				}
				return true
			})
			// name closures after the variable they are assigned to
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				as, ok := x.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					return true
				}
				for i, r := range as.Rhs {
					lit, ok := ast.Unparen(r).(*ast.FuncLit)
					id, isID := as.Lhs[i].(*ast.Ident)
					if !ok || !isID {
						continue
					}
					if obj := s.info.ObjectOf(id); obj != nil {
						ln := s.byLit[lit]
						ln.name = id.Name + " (a closure in " + fd.Name.Name + ")"
						litOfVar[obj] = ln
					}
				}
				return true
			})
		}
	}
	for _, n := range s.nodes {
		s.walkBody(n, func(x ast.Node) {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return
			}
			if callee := s.callee(call); callee != nil {
				if to := s.byObj[callee]; to != nil {
					n.calls = append(n.calls, edge{call, to})
				}
				return
			}
			if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
				if to := litOfVar[s.info.Uses[id]]; to != nil {
					n.calls = append(n.calls, edge{call, to})
				}
			}
		})
	}
}

// walkBody visits n's body without descending into nested literals.
func (s *state) walkBody(n *node, f func(ast.Node)) {
	ast.Inspect(n.body, func(x ast.Node) bool {
		if lit, ok := x.(*ast.FuncLit); ok && lit != n.lit {
			return false
		}
		if x != nil {
			f(x)
		}
		return true
	})
}

func (s *state) callee(call *ast.CallExpr) *types.Func {
	fn, _ := typeutil.Callee(s.info, call).(*types.Func)
	if fn != nil {
		fn = fn.Origin()
	}
	return fn
}

func (s *state) qname(f *types.Func) string { return catalogue.Name(f, s.aliases) }

// components returns the strongly connected components that recurse: more
// than one member, or a member that calls itself.
func (s *state) components() [][]*node {
	idx, low := map[*node]int{}, map[*node]int{}
	on := map[*node]bool{}
	var stack []*node
	var out [][]*node
	counter := 0
	var strong func(v *node)
	strong = func(v *node) {
		idx[v], low[v] = counter, counter
		counter++
		stack = append(stack, v)
		on[v] = true
		for _, e := range v.calls {
			w := e.to
			if _, seen := idx[w]; !seen {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if on[w] {
				low[v] = min(low[v], idx[w])
			}
		}
		if low[v] != idx[v] {
			return
		}
		var comp []*node
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			on[w] = false
			comp = append(comp, w)
			if w == v {
				break
			}
		}
		self := slices.ContainsFunc(v.calls, func(e edge) bool { return e.to == v })
		if len(comp) > 1 || self {
			out = append(out, comp)
		}
	}
	for _, v := range s.nodes {
		if _, seen := idx[v]; !seen {
			strong(v)
		}
	}
	return out
}

var (
	recMu    sync.Mutex
	recCache = map[*types.Package]map[string]bool{}
)

// recursiveSet returns the recursive-type set of the SDK's xdr package as
// imported (directly or not) by the package under analysis; nil if it does
// not reach the xdr package.
func (s *state) recursiveSet() map[string]bool {
	var xdrPkg *types.Package
	seen := map[*types.Package]bool{}
	var visit func(p *types.Package)
	visit = func(p *types.Package) {
		if p == nil || seen[p] || xdrPkg != nil {
			return
		}
		seen[p] = true
		if catalogue.Canonical(p.Path(), s.aliases) == catalogue.XDR {
			xdrPkg = p
			return
		}
		for _, q := range p.Imports() {
			visit(q)
		}
	}
	visit(s.pass.Pkg)
	if xdrPkg == nil {
		return nil
	}
	recMu.Lock()
	defer recMu.Unlock()
	if m, ok := recCache[xdrPkg]; ok {
		return m
	}
	m := map[string]bool{}
	for _, name := range catalogue.RecursiveTypes(xdrPkg) {
		m[catalogue.Canonical(xdrPkg.Path(), s.aliases)+name[len(xdrPkg.Path()):]] = true
	}
	recCache[xdrPkg] = m
	return m
}

// recursiveType returns the recursive xdr type t holds (through pointers,
// slices, arrays and map values), or "".
func (s *state) recursiveType(t types.Type) string {
	for depth := 0; t != nil && depth < 8; depth++ {
		switch u := types.Unalias(t).(type) {
		case *types.Pointer:
			t = u.Elem()
			continue
		case *types.Slice:
			t = u.Elem()
			continue
		case *types.Array:
			t = u.Elem()
			continue
		case *types.Map:
			t = u.Elem()
			continue
		case *types.Named:
			if u.Obj().Pkg() != nil {
				name := catalogue.Canonical(u.Obj().Pkg().Path(), s.aliases) + "." + u.Obj().Name()
				if s.recSet[name] {
					return u.Obj().Name()
				}
			}
			return ""
		}
		return ""
	}
	return ""
}

// isMetaType reports whether t (through pointers and slices) is a
// catalogued meta type, a contract event, or a ledger close meta.
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
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	pkg := catalogue.Canonical(n.Obj().Pkg().Path(), s.aliases)
	name := n.Obj().Name()
	if pkg == catalogue.XDR && (name == "LedgerCloseMeta" || name == "LedgerCloseMetaBatch") {
		return true
	}
	for _, e := range catalogue.Lookup(pkg + "." + name) {
		if e.Kind == catalogue.KindType && (slices.Contains(e.Roles, catalogue.MetaSource) || slices.Contains(e.Roles, catalogue.EventSource)) {
			return true
		}
	}
	return false
}

// metaFed marks the nodes fed from ledger meta: a node that reads meta
// (itself or through a callee), a literal inside a declaration that does,
// and anything such a node calls.
func (s *state) metaFed() map[*node]bool {
	for _, n := range s.nodes {
		s.walkBody(n, func(x ast.Node) {
			switch x := x.(type) {
			case *ast.CallExpr:
				if c := s.callee(x); c != nil && catalogue.Has(s.qname(c), catalogue.MetaSource) {
					n.readsMeta = true
				}
			case *ast.SelectorExpr:
				if sel, ok := s.info.Selections[x]; ok && sel.Kind() == types.FieldVal &&
					catalogue.Has(catalogue.SelectionName(sel, s.aliases), catalogue.MetaSource) {
					n.readsMeta = true
				}
			}
			if e, ok := x.(ast.Expr); ok && s.isMetaType(s.info.TypeOf(e)) {
				n.readsMeta = true
			}
		})
	}
	// a function that calls a meta reader reads meta too
	for changed := true; changed; {
		changed = false
		for _, n := range s.nodes {
			if n.readsMeta {
				continue
			}
			for _, e := range n.calls {
				if e.to.readsMeta {
					n.readsMeta = true
					changed = true
					break
				}
			}
		}
	}
	fed := map[*node]bool{}
	for _, n := range s.nodes {
		if n.readsMeta {
			fed[n] = true
		}
	}
	for _, n := range s.nodes { // a literal is fed when its declaration is
		if n.lit != nil && fed[s.byObj[s.declObj(n)]] {
			fed[n] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, n := range s.nodes {
			if !fed[n] {
				continue
			}
			for _, e := range n.calls {
				if !fed[e.to] {
					fed[e.to] = true
					changed = true
				}
			}
			if n.lit == nil { // literals of a fed declaration
				for _, m := range s.nodes {
					if m.lit != nil && m.decl == n.decl && !fed[m] {
						fed[m] = true
						changed = true
					}
				}
			}
		}
	}
	return fed
}

func (s *state) declObj(n *node) *types.Func {
	obj, _ := s.info.Defs[n.decl.Name].(*types.Func)
	return obj
}
