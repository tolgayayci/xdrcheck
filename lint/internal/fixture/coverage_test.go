package fixture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var wantRule = regexp.MustCompile(`// want .*\bXDR[0-9]{3}\b`)

// TestEveryDefaultRuleHasFixtures: each rule of the default set has at
// least one violating fixture (a `// want` naming it, in its own fixture
// directory testdata/<family>/<rule>…/) and one compliant fixture (in that
// directory, a good.go, or a function no `// want` falls inside), and the
// real-code regression fixtures under testdata/regress name at least one
// default rule. The rule tests themselves check that the expectations hold.
func TestEveryDefaultRuleHasFixtures(t *testing.T) {
	root := filepath.Join(fixture.ModuleRoot(t), "testdata")
	for _, id := range framework.DefaultRuleIDs {
		fam := strings.ToLower(id[:4]) + "xx"
		dirs, _ := filepath.Glob(filepath.Join(root, fam, strings.ToLower(id)+"*"))
		violating, compliant := false, false
		for _, dir := range dirs {
			files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
			for _, f := range files {
				v, c := classify(t, f, id)
				violating = violating || v
				compliant = compliant || c || filepath.Base(f) == "good.go"
			}
		}
		if !violating {
			t.Errorf("%s: no violating fixture (a `// want` naming it) under testdata/%s/%s*", id, fam, strings.ToLower(id))
		}
		if !compliant {
			t.Errorf("%s: no compliant fixture under testdata/%s/%s*", id, fam, strings.ToLower(id))
		}
	}
	regress := 0
	_ = filepath.WalkDir(filepath.Join(root, "regress"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") {
			data, _ := os.ReadFile(p)
			regress += len(wantRule.FindAll(data, -1))
		}
		return nil
	})
	if regress == 0 {
		t.Error("no expectations in testdata/regress")
	}
}

// classify reports whether a fixture file expects rule id somewhere, and
// whether it holds a function with no expectation inside it.
func classify(t *testing.T, path, id string) (violating, compliant bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var wantLines []int
	for _, g := range f.Comments {
		for _, c := range g.List {
			if strings.HasPrefix(c.Text, "// want") {
				line := fset.Position(c.Pos()).Line
				wantLines = append(wantLines, line)
				if strings.Contains(c.Text, id) {
					violating = true
				}
			}
		}
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		from, to := fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line
		clean := true
		for _, l := range wantLines {
			if l >= from-1 && l <= to {
				clean = false
			}
		}
		if clean {
			compliant = true
		}
	}
	return violating, compliant
}
