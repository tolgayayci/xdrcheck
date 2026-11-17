package xdr1xx

// Account-key types that normalise on their own (XDR102).
//
// A configured account-key type (sinksaccountkey) is often a string type
// whose driver.Valuer turns the strkey into the stored key. When that
// Value() method decodes the strkey (strkey.DecodeAny or strkey.Decode),
// reduces the muxed kinds (it names strkey.VersionByteMuxedAccount) and
// refuses any payload that is not a 32-byte key (a comparison of a length
// with 32), then storing an unnormalised address in the type does not split
// an account into many keys: an M… or W… address is stored as its G… or C…
// key, and a B… or P… address is refused with an error instead of being
// stored. Such a conversion is not an XDR102 sink.
//
// The same holds for a function whose string parameter is used only as the
// operand of a conversion to such a type (a setter such as
// `func (b Builder) WithAccount(id string) Builder { b.AccountID = AddressBytea(id); … }`):
// passing an address to that parameter, even when the function is configured
// as a participant or account-key sink, stores its base key.
//
// The Value() method usually lives in another package than the conversion,
// so the analyzer below records the property as a fact on the type or
// function, for every package (dependencies included), and returns what it
// knows of to the "unvalidated" analyzer.

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// normalisingKey is the fact: the type's Value() method normalises a strkey
// to a 32-byte account or contract key.
type normalisingKey struct{}

func (*normalisingKey) AFact()         {}
func (*normalisingKey) String() string { return "normalisingKey" }

// normalisingParams is the fact on a function: the parameters (by index,
// receiver excluded) that are only converted to a normalising key type.
type normalisingParams struct{ Params []int }

func (*normalisingParams) AFact()         {}
func (*normalisingParams) String() string { return "normalisingParams" }

// normInfo is the result of Normalisers.
type normInfo struct {
	types  map[*types.TypeName]bool
	params map[*types.Func]map[int]bool
}

// Normalisers finds account-key types whose Value() normalises (see the
// package comment above). Its result is the set of such types visible from
// the package: map[*types.TypeName]bool.
var Normalisers = &analysis.Analyzer{
	Name:       "xdrlintnormalisers",
	Doc:        "records string types whose driver.Valuer reduces muxed strkeys and refuses other payloads (used by XDR102)",
	FactTypes:  []analysis.Fact{(*normalisingKey)(nil), (*normalisingParams)(nil)},
	ResultType: reflect.TypeOf((*normInfo)(nil)),
	Run:        runNormalisers,
}

func runNormalisers(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil || fd.Name.Name != "Value" || len(fd.Recv.List) != 1 {
				continue
			}
			obj, ok := pass.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			recv := obj.Type().(*types.Signature).Recv()
			n, ok := types.Unalias(deref(recv.Type())).(*types.Named)
			if !ok || n.Obj().Pkg() != pass.Pkg {
				continue
			}
			if b, ok := n.Underlying().(*types.Basic); !ok || b.Info()&types.IsString == 0 {
				continue
			}
			if normalisesStrkey(pass.TypesInfo, fd.Body) {
				pass.ExportObjectFact(n.Obj(), &normalisingKey{})
			}
		}
	}
	info := &normInfo{types: map[*types.TypeName]bool{}, params: map[*types.Func]map[int]bool{}}
	collect := func() {
		for _, of := range pass.AllObjectFacts() {
			switch f := of.Fact.(type) {
			case *normalisingKey:
				if tn, ok := of.Object.(*types.TypeName); ok {
					info.types[tn] = true
				}
			case *normalisingParams:
				if fn, ok := of.Object.(*types.Func); ok {
					info.params[fn] = map[int]bool{}
					for _, i := range f.Params {
						info.params[fn][i] = true
					}
				}
			}
		}
	}
	collect()
	// Functions of this package whose string parameters only feed a
	// normalising conversion.
	for _, f := range pass.Files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn, ok := pass.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			var idx []int
			i := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					i++
					continue
				}
				for _, n := range names {
					if v, ok := pass.TypesInfo.Defs[n].(*types.Var); ok && onlyNormalised(pass.TypesInfo, fd.Body, v, info.types) {
						idx = append(idx, i)
					}
					i++
				}
			}
			if len(idx) > 0 {
				pass.ExportObjectFact(fn, &normalisingParams{Params: idx})
			}
		}
	}
	collect()
	return info, nil
}

// onlyNormalised reports whether every use of v in body is the operand of a
// conversion to a normalising key type, and there is at least one.
func onlyNormalised(info *types.Info, body *ast.BlockStmt, v *types.Var, norm map[*types.TypeName]bool) bool {
	if b, ok := v.Type().Underlying().(*types.Basic); !ok || b.Info()&types.IsString == 0 {
		return false
	}
	converted := map[*ast.Ident]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return true
		}
		tv, ok := info.Types[c.Fun]
		if !ok || !tv.IsType() {
			return true
		}
		nt, ok := types.Unalias(tv.Type).(*types.Named)
		if !ok || !norm[nt.Obj()] {
			return true
		}
		if id, ok := ast.Unparen(c.Args[0]).(*ast.Ident); ok && info.Uses[id] == v {
			converted[id] = true
		}
		return true
	})
	uses, all := 0, true
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == v {
			uses++
			if !converted[id] {
				all = false
			}
		}
		return true
	})
	return uses > 0 && all
}

// normalisesStrkey reports whether a Value() body decodes a strkey, names
// the muxed-account version byte and compares a length with 32.
func normalisesStrkey(info *types.Info, body *ast.BlockStmt) bool {
	var decodes, muxed, len32 bool
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fn, ok := calleeObj(info, x).(*types.Func); ok && fn.Pkg() != nil &&
				catalogue.Canonical(fn.Pkg().Path(), nil) == catalogue.Strkey && (fn.Name() == "DecodeAny" || fn.Name() == "Decode") {
				decodes = true
			}
		case *ast.Ident:
			if c, ok := info.Uses[x].(*types.Const); ok && c.Pkg() != nil &&
				catalogue.Canonical(c.Pkg().Path(), nil) == catalogue.Strkey && c.Name() == "VersionByteMuxedAccount" {
				muxed = true
			}
		case *ast.BinaryExpr:
			if (x.Op == token.NEQ || x.Op == token.EQL) && (isLenCall(x.X) && isLit(x.Y, "32") || isLenCall(x.Y) && isLit(x.X, "32")) {
				len32 = true
			}
		}
		return true
	})
	return decodes && muxed && len32
}

func calleeObj(info *types.Info, c *ast.CallExpr) types.Object {
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		return info.Uses[f]
	case *ast.SelectorExpr:
		return info.Uses[f.Sel]
	}
	return nil
}

func isLenCall(e ast.Expr) bool {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == "len"
}

func isLit(e ast.Expr, v string) bool {
	l, ok := ast.Unparen(e).(*ast.BasicLit)
	return ok && strings.TrimSpace(l.Value) == v
}
