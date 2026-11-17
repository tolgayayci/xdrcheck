package framework_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// TestCheckNames: configured names are checked against the packages that
// are loaded; names in other packages, and bare names, are skipped.
func TestCheckNames(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", `package p
type Builder struct{ Account string }
func (b *Builder) WithAccount(a string) *Builder { return b }
func AddressBytea(s string) string { return s }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/m/p", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lookup := framework.PackageLookup([]*types.Package{pkg}, nil)

	good := &framework.Config{
		SinksParticipant: []string{"example.com/m/p.Builder.WithAccount", "example.com/m/p.Builder.Account"},
		SinksAccountKey:  []string{"example.com/m/p.AddressBytea", "example.com/other.NotLoaded"},
		OverflowFlags:    []string{"Truncated"},
	}
	if err := good.CheckNames(lookup); err != nil {
		t.Errorf("valid names rejected: %v", err)
	}

	bad := &framework.Config{
		SinksParticipant:  []string{"example.com/m/p.Builder.WithCreator"},
		SinksAccountKey:   []string{"example.com/m/p.AddressByte"},
		SanitizersAddress: []string{"example.com/m/p.AddressBytea.Value"},
	}
	err = bad.CheckNames(lookup)
	if err == nil {
		t.Fatal("unknown names accepted")
	}
	for _, want := range []string{
		"sinksparticipant: example.com/m/p.Builder.WithCreator: type example.com/m/p.Builder has no field or method WithCreator",
		"sinksaccountkey: example.com/m/p.AddressByte: package example.com/m/p has no AddressByte",
		"sanitizersaddress: example.com/m/p.AddressBytea.Value: example.com/m/p.AddressBytea is not a type",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// TestLoadsSourcePackage: a run is about go-stellar-sdk code only when the
// SDK's xdr package is loaded, directly or as an import, under its own path,
// the pre-split module path or a configured alias.
func TestLoadsSourcePackage(t *testing.T) {
	other := types.NewPackage("example.com/m/p", "p")
	if framework.LoadsSourcePackage(framework.PackageLookup([]*types.Package{other}, nil)) {
		t.Error("a package that imports no SDK counts as a source package")
	}
	for _, c := range []struct {
		path    string
		aliases []string
	}{
		{"github.com/stellar/go-stellar-sdk/xdr", nil},
		{"github.com/stellar/go/xdr", nil},
		{"example.com/fork/xdr", []string{"example.com/fork/xdr"}},
	} {
		xdr := types.NewPackage(c.path, "xdr")
		user := types.NewPackage("example.com/m/indexer", "indexer")
		user.SetImports([]*types.Package{xdr})
		if !framework.LoadsSourcePackage(framework.PackageLookup([]*types.Package{user}, c.aliases)) {
			t.Errorf("%s imported (aliases %v): not recognised", c.path, c.aliases)
		}
	}
}
