package xdr2xx

// Where the values a recursive walk starts from come from. XDR207 holds a
// walk over values the host wrote into the meta (contract events, contract
// data, return values) to the host's own depth limit, and a walk that can
// also see the envelope to the decoder's.
//
// The test is syntactic and local to the package: for every call into the
// recursion from outside it, the argument of the recursive type is traced
// back through local variables (their assignments and range statements) and
// through the parameters of the calling function to its own callers, a few
// steps deep. A trace is host-written when the xdr types it passes through
// include a host-written container and no envelope type. A walk with no
// call into it in the package, or a trace that ends anywhere else, is not
// host-written.

import (
	"go/ast"
	"go/types"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// Containers of values the host wrote: event bodies, contract data entries
// and the Soroban meta that carries a call's return value.
var hostWrittenTypes = map[string]bool{
	"ContractEvent": true, "ContractEventBody": true, "ContractEventV0": true,
	"DiagnosticEvent": true, "TransactionEvent": true,
	"ContractDataEntry":      true,
	"SorobanTransactionMeta": true, "SorobanTransactionMetaV2": true,
	"InvokeHostFunctionSuccessPreImage": true,
}

// Envelope types: values in them never passed the host's limit when the
// transaction failed.
var envelopeTypes = map[string]bool{
	"TransactionEnvelope": true, "TransactionV0Envelope": true, "TransactionV1Envelope": true,
	"FeeBumpTransactionEnvelope": true, "Transaction": true, "TransactionV0": true,
	"Operation": true, "OperationBody": true, "InvokeHostFunctionOp": true, "HostFunction": true,
	"InvokeContractArgs": true, "SorobanAuthorizationEntry": true, "SorobanAuthorizedInvocation": true,
	"SorobanAuthorizedFunction": true, "CreateContractArgs": true, "CreateContractArgsV2": true,
}

const provenanceDepth = 4

// hostWrittenOnly reports whether every call into the component from outside
// it starts the walk from a host-written value.
func (s *state) hostWrittenOnly(comp []*node) bool {
	in := map[*node]bool{}
	for _, n := range comp {
		in[n] = true
	}
	entries := 0
	for _, m := range s.nodes {
		if in[m] {
			continue
		}
		for _, e := range m.calls {
			if !in[e.to] {
				continue
			}
			arg := s.recursiveArgExpr(e.call)
			if arg == nil || !s.hostWritten(arg, m, 0) {
				return false
			}
			entries++
		}
	}
	return entries > 0
}

// recursiveArgExpr returns the argument (or receiver) of a call whose type is
// in the recursive-type set.
func (s *state) recursiveArgExpr(call *ast.CallExpr) ast.Expr {
	for _, a := range call.Args {
		if s.recursiveType(s.info.TypeOf(a)) != "" {
			return a
		}
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection, ok := s.info.Selections[sel]; ok && selection.Kind() == types.MethodVal &&
			s.recursiveType(s.info.TypeOf(sel.X)) != "" {
			return sel.X
		}
	}
	return nil
}

// hostWritten classifies an expression evaluated in n.
func (s *state) hostWritten(e ast.Expr, n *node, depth int) bool {
	host, env := false, false
	var idents []*ast.Ident
	ast.Inspect(e, func(x ast.Node) bool {
		if _, ok := x.(*ast.FuncLit); ok {
			return false
		}
		ex, ok := x.(ast.Expr)
		if !ok {
			return true
		}
		if name := s.xdrTypeName(s.info.TypeOf(ex)); name != "" {
			host = host || hostWrittenTypes[name]
			env = env || envelopeTypes[name]
		}
		if id, ok := ex.(*ast.Ident); ok {
			idents = append(idents, id)
		}
		return true
	})
	if env {
		return false
	}
	if host {
		return true
	}
	if depth >= provenanceDepth {
		return false
	}
	// No marks: the value came through a local variable or a parameter.
	traced := false
	for _, id := range idents {
		v, ok := s.info.Uses[id].(*types.Var)
		if !ok || v.IsField() || v.Pkg() != s.pass.Pkg || v.Parent() == v.Pkg().Scope() {
			continue
		}
		if i := paramIndex(n, v); i >= 0 {
			callers := 0
			for _, m := range s.nodes {
				for _, ed := range m.calls {
					if ed.to != n || i >= len(ed.call.Args) {
						continue
					}
					if m == n || !s.hostWritten(ed.call.Args[i], m, depth+1) {
						return false
					}
					callers++
				}
			}
			if callers == 0 {
				return false
			}
			traced = true
			continue
		}
		defs := s.definitions(n, v)
		if len(defs) == 0 {
			return false
		}
		for _, d := range defs {
			if !s.hostWritten(d, n, depth+1) {
				return false
			}
		}
		traced = true
	}
	return traced
}

// xdrTypeName returns the name of the xdr type t holds (through pointers,
// slices and arrays), or "".
func (s *state) xdrTypeName(t types.Type) string {
	for i := 0; t != nil && i < 8; i++ {
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
		case *types.Named:
			if u.Obj().Pkg() != nil && catalogue.Canonical(u.Obj().Pkg().Path(), s.aliases) == catalogue.XDR {
				return u.Obj().Name()
			}
		}
		return ""
	}
	return ""
}

// paramIndex returns the index of v among n's parameters, or -1.
func paramIndex(n *node, v *types.Var) int {
	i := 0
	for _, f := range n.params() {
		if len(f.Names) == 0 {
			i++
			continue
		}
		for _, name := range f.Names {
			if name.Pos() == v.Pos() {
				return i
			}
			i++
		}
	}
	return -1
}

// definitions returns the expressions assigned to v in the declaration that
// holds n: the right-hand side of an assignment or declaration (the single
// call of a multi-value assignment), or the ranged expression of a range
// statement that declares it.
func (s *state) definitions(n *node, v *types.Var) []ast.Expr {
	var out []ast.Expr
	is := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && (s.info.Defs[id] == v || s.info.Uses[id] == v)
	}
	ast.Inspect(n.decl.Body, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				if !is(l) {
					continue
				}
				if len(x.Lhs) == len(x.Rhs) {
					out = append(out, x.Rhs[i])
				} else if len(x.Rhs) == 1 {
					out = append(out, x.Rhs[0])
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if s.info.Defs[name] != v {
					continue
				}
				if len(x.Names) == len(x.Values) {
					out = append(out, x.Values[i])
				} else if len(x.Values) == 1 {
					out = append(out, x.Values[0])
				}
			}
		case *ast.RangeStmt:
			if x.Key != nil && is(x.Key) || x.Value != nil && is(x.Value) {
				out = append(out, x.X)
			}
		}
		return true
	})
	return out
}
