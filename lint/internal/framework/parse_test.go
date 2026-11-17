package framework_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func parseFile(t *testing.T, fset *token.FileSet, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
