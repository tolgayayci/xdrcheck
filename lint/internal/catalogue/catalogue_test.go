package catalogue

import (
	"go/types"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

var (
	loadOnce sync.Once
	loaded   map[string]*types.Package
	loadErr  error
)

// sdkPackages loads every package the catalogue names, at the versions in
// lint/go.mod (go-stellar-sdk v0.9.0), with types only.
func sdkPackages(t *testing.T) map[string]*types.Package {
	t.Helper()
	loadOnce.Do(func() {
		paths := map[string]bool{}
		for _, en := range Entries {
			paths[pkgOf(en)] = true
		}
		var patterns []string
		for p := range paths {
			patterns = append(patterns, p)
		}
		slices.Sort(patterns)
		pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedModule}, patterns...)
		if err != nil {
			loadErr = err
			return
		}
		loaded = map[string]*types.Package{}
		for _, p := range pkgs {
			for _, e := range p.Errors {
				t.Errorf("loading %s: %v", p.PkgPath, e)
			}
			loaded[p.PkgPath] = p.Types
			if strings.HasPrefix(p.PkgPath, SDKModule+"/") && (p.Module == nil || p.Module.Version != SDKVersion) {
				t.Errorf("%s loaded from module %+v, want %s %s", p.PkgPath, p.Module, SDKModule, SDKVersion)
			}
		}
	})
	if loadErr != nil {
		t.Fatalf("loading the SDK: %v", loadErr)
	}
	return loaded
}

// pkgOf splits the package path off a catalogue name. Package paths contain
// dots only in their first element (github.com, golang.org), so the package
// ends at the first dot after the last slash.
func pkgOf(en Entry) string {
	slash := strings.LastIndex(en.Name, "/")
	dot := strings.Index(en.Name[slash+1:], ".")
	return en.Name[:slash+1+dot]
}

func members(en Entry) []string {
	return strings.Split(en.Name[len(pkgOf(en))+1:], ".")
}

// TestCatalogueResolves is the guard against SDK drift: every catalogued
// type, field, method, function, constant and variable must exist in
// go-stellar-sdk v0.9.0 (or the standard library) with the catalogued kind.
func TestCatalogueResolves(t *testing.T) {
	pkgs := sdkPackages(t)
	seen := map[string]bool{}
	for _, en := range Entries {
		key := en.Name + "|" + string(en.Kind)
		if seen[key] {
			t.Errorf("%s: listed twice", en.Name)
		}
		seen[key] = true
		if len(en.Roles) == 0 || len(en.Rules) == 0 {
			t.Errorf("%s: needs at least one role and one rule", en.Name)
		}
		pkg := pkgs[pkgOf(en)]
		if pkg == nil {
			t.Errorf("%s: package %s not loaded", en.Name, pkgOf(en))
			continue
		}
		if err := resolve(pkg, en); err != nil {
			t.Errorf("%s: %v", en.Name, err)
		}
	}
	t.Logf("%d catalogue entries resolved against %s %s", len(Entries), SDKModule, SDKVersion)
}

type resolveError string

func (e resolveError) Error() string { return string(e) }

func resolve(pkg *types.Package, en Entry) error {
	m := members(en)
	obj := pkg.Scope().Lookup(m[0])
	if obj == nil {
		return resolveError("no " + m[0] + " in " + pkg.Path())
	}
	if len(m) == 1 {
		var ok bool
		switch en.Kind {
		case KindType:
			_, ok = obj.(*types.TypeName)
		case KindFunc:
			_, ok = obj.(*types.Func)
		case KindConst:
			_, ok = obj.(*types.Const)
		case KindVar:
			_, ok = obj.(*types.Var)
		}
		if !ok {
			return resolveError("is a " + objKind(obj) + ", catalogued as " + string(en.Kind))
		}
		return nil
	}
	if len(m) != 2 {
		return resolveError("a name has at most one member (Type.Member)")
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return resolveError(m[0] + " is not a type")
	}
	member, _, _ := types.LookupFieldOrMethod(types.NewPointer(tn.Type()), true, pkg, m[1])
	if member == nil {
		member, _, _ = types.LookupFieldOrMethod(tn.Type(), true, pkg, m[1])
	}
	if member == nil {
		return resolveError("type " + m[0] + " has no field or method " + m[1])
	}
	switch o := member.(type) {
	case *types.Var:
		if en.Kind != KindField || !o.IsField() {
			return resolveError(m[1] + " is a field, catalogued as " + string(en.Kind))
		}
	case *types.Func:
		if en.Kind != KindMethod {
			return resolveError(m[1] + " is a method, catalogued as " + string(en.Kind))
		}
	}
	return nil
}

func objKind(o types.Object) string {
	switch o.(type) {
	case *types.TypeName:
		return "type"
	case *types.Func:
		return "func"
	case *types.Const:
		return "const"
	case *types.Var:
		return "var"
	}
	return "object"
}

// TestResolveRejects makes sure the resolution check can fail.
func TestResolveRejects(t *testing.T) {
	pkg := sdkPackages(t)[XDR]
	for _, en := range []Entry{
		{Name: XDR + ".NoSuchType", Kind: KindType},
		{Name: XDR + ".MuxedAccount.NoSuchMember", Kind: KindMethod},
		{Name: XDR + ".MuxedAccount.Address", Kind: KindField},               // a method
		{Name: XDR + ".Memo.Text", Kind: KindMethod},                         // a field
		{Name: XDR + ".SafeUnmarshal", Kind: KindConst},                      // a func
		{Name: XDR + ".DecodeUnlimitedDepth", Kind: KindConst},               // lives in go-xdr, not here
		{Name: XDR + ".ContractExecutable.ExternalRef.Tag", Kind: KindField}, // two members
	} {
		if err := resolve(pkg, en); err == nil {
			t.Errorf("%s (%s) resolved, want an error", en.Name, en.Kind)
		}
	}
}

// TestRecursiveTypes checks the computed recursive-type set of the SDK's xdr
// package against the RecursiveType rows of the catalogue, exactly.
func TestRecursiveTypes(t *testing.T) {
	pkgs := sdkPackages(t)
	got := RecursiveTypes(pkgs[XDR])
	var want []string
	for _, en := range ByRole(RecursiveType) {
		want = append(want, en.Name)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("recursive-type set of %s %s:\n got  %v\n want %v", XDR, SDKVersion, got, want)
	}
}

// TestNames checks the name functions the rules use on real SDK objects.
func TestNames(t *testing.T) {
	pkgs := sdkPackages(t)
	xdrPkg := pkgs[XDR]
	ma := xdrPkg.Scope().Lookup("MuxedAccount").(*types.TypeName)
	addr, _, _ := types.LookupFieldOrMethod(types.NewPointer(ma.Type()), true, xdrPkg, "Address")
	if got, want := Name(addr, nil), XDR+".MuxedAccount.Address"; got != want {
		t.Errorf("Name(method) = %q, want %q", got, want)
	}
	if !Has(Name(addr, nil), AddressSource) {
		t.Errorf("MuxedAccount.Address is not an address source")
	}
	toAcc, _, _ := types.LookupFieldOrMethod(ma.Type(), true, xdrPkg, "ToAccountId")
	if !Has(Name(toAcc, nil), AddressNormaliser) {
		t.Errorf("MuxedAccount.ToAccountId is not a normaliser")
	}
	med := xdrPkg.Scope().Lookup("MuxedAccountMed25519").(*types.TypeName)
	if got, want := FieldName(med.Type(), "Id", nil), XDR+".MuxedAccountMed25519.Id"; got != want {
		t.Errorf("FieldName = %q, want %q", got, want)
	}
	safe := xdrPkg.Scope().Lookup("SafeUnmarshal")
	if got := Name(safe, nil); !Has(got, DecodeEntry) {
		t.Errorf("Name(SafeUnmarshal) = %q, not a decode entry", got)
	}
	if got := Canonical("github.com/stellar/go/xdr", nil); got != XDR {
		t.Errorf("Canonical(pre-split) = %q", got)
	}
	if got := Canonical("example.com/fork/xdr", []string{"example.com/fork/xdr"}); got != XDR {
		t.Errorf("Canonical(alias) = %q", got)
	}
}
