// Package fixture runs an analyzer over fixture packages in lint/testdata
// with analysistest, against the real go-stellar-sdk module.
//
// Fixtures are ordinary packages of the lint module under
// lint/testdata/<family>/<case>/ (for example testdata/xdr3xx/xdr301), so
// they import github.com/stellar/go-stellar-sdk/... at the version lint/go.mod
// pins (v0.9.0). analysistest switches to module mode when the directory it
// is given holds a go.mod; Run gives it the lint module root, so packages are
// loaded with GOPROXY=off from the module cache (`go mod download` in lint/
// fetches what is needed). No stub SDK package is used.
//
// Expectations are analysistest's `// want "regexp"` comments. A message
// starts with the rule ID and severity, so `// want "XDR201"` matches any
// XDR201 report and `// want "XDR201 \\(warning\\): unbounded"` a precise one.
// To expect a report on a line that holds a //xdrlint: directive, put
// `// want +1 "…"` on the line above (a directive's reason runs to the end of
// its line).
package fixture

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// Run runs a over each directory (relative to lint/testdata) and checks the
// `// want` comments. The configuration environment variables are cleared,
// so a fixture sees the configuration its test sets with SetConfig, or the
// defaults.
func Run(t testing.TB, a *analysis.Analyzer, dirs ...string) []*analysistest.Result {
	t.Helper()
	for _, env := range []string{framework.EnvConfig, framework.EnvProfile, framework.EnvOverlay} {
		t.Setenv(env, "")
	}
	root := ModuleRoot(t)
	var patterns []string
	for _, d := range dirs {
		patterns = append(patterns, "./"+filepath.ToSlash(filepath.Join("testdata", d)))
	}
	return analysistest.Run(t, root, a, patterns...)
}

// ModuleRoot returns the directory of lint/go.mod.
func ModuleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
