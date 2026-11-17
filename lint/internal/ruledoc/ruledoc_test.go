package ruledoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// lintRoot is the lint module root, two levels above this package.
func lintRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestPagesUpToDate is what "the rule pages build" means: every source is
// valid (a fragment per rule, known guide anchors and corpus entries,
// examples naming existing fixture functions) and the committed pages equal
// a fresh build. Rebuild with `go run ./cmd/xdrlint-docs` in lint/.
func TestPagesUpToDate(t *testing.T) {
	diffs, err := Check(lintRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range diffs {
		t.Error(d)
	}
}

func TestEveryRuleHasAPage(t *testing.T) {
	pages, err := Build(lintRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range framework.Default.Rules() {
		page := string(pages["docs/"+r.ID+".md"])
		if page == "" {
			t.Errorf("%s: no page", r.ID)
			continue
		}
		for _, want := range []string{"# " + r.ID + ": " + r.Title, "```go", "## Configure and suppress"} {
			if !strings.Contains(page, want) {
				t.Errorf("%s: page lacks %q", r.ID, want)
			}
		}
		if strings.Contains(page, "// want") || strings.Contains(page, "<!-- example") {
			t.Errorf("%s: page keeps a fixture annotation or an unexpanded directive", r.ID)
		}
		if r.Corpus != "" && !strings.Contains(page, r.Corpus) {
			t.Errorf("%s: page does not name its corpus entry %s", r.ID, r.Corpus)
		}
	}
}

// TestBrokenSourcesFail: a wrong source stops the build instead of producing
// a page.
func TestBrokenSourcesFail(t *testing.T) {
	root := lintRoot(t)
	tmp := t.TempDir()
	// A copy of the module root's docs and fixtures, with the guide and
	// plan reachable at the same relative paths.
	lint := filepath.Join(tmp, "lint")
	for _, p := range []string{"docs/src", "testdata/xdr1xx/xdr101"} {
		copyDir(t, filepath.Join(root, p), filepath.Join(lint, p))
	}
	for _, p := range []string{"guide/indexer-hardening.mdx", "corpus/plan.json"} {
		copyFile(t, filepath.Join(root, "..", p), filepath.Join(tmp, p))
	}
	src := filepath.Join(lint, "docs/src/XDR101.md")
	data, _ := os.ReadFile(src)
	broken := strings.Replace(string(data), "destinationFromSwitch", "noSuchFunction", 1)
	if err := os.WriteFile(src, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(lint); err == nil || !strings.Contains(err.Error(), "no function noSuchFunction") {
		t.Errorf("example naming no function: %v", err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			copyFile(t, filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
