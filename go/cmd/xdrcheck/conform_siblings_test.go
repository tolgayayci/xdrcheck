package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// siblingsRepo makes a fake repository holding the issuer-ordering records, the draft templates and the
// fixture matrix, changes into it, and returns its root and an overlay directory outside it.
func siblingsRepo(t *testing.T) (root, overlay string) {
	t.Helper()
	t.Setenv("XDRCHECK_OVERLAY", "")
	root = fakeRepo(t)
	for _, id := range []string{"F-0016", "F-0023", "F-0027", "F-0028"} {
		copyFile(t, filepath.Join(repoAbs, "findings", id, "finding.json"), filepath.Join(root, "findings", id, "finding.json"))
	}
	tmpl, _ := filepath.Glob(filepath.Join(repoAbs, "findings", "templates", "*"))
	for _, f := range tmpl {
		copyFile(t, f, filepath.Join(root, "findings", "templates", filepath.Base(f)))
	}
	copyFile(t, filepath.Join(repoAbs, "go", "internal", "conform", "siblings", "testdata", "matrix.json"), filepath.Join(root, "reports", "conformance", "matrix.json"))
	copySets(t, repoAbs, root)
	overlay = t.TempDir()
	return root, overlay
}

// githubAPI is a fixture GitHub API with today's upstream state of the issuer-ordering defect. It records
// every request.
func githubAPI(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/search/issues":
			if strings.HasPrefix(r.URL.Query().Get("q"), "repo:Beans-BV/dotnet-stellar-sdk ") {
				w.Write([]byte(`{"items":[{"number":272,"title":"fix: liquidity pool parameters ordering","state":"open","pull_request":{"merged_at":null}},{"number":257,"title":"Liquidity pool parameters reject the asset order","state":"open"}]}`))
				return
			}
			w.Write([]byte(`{"items":[]}`))
		case "/repos/Beans-BV/dotnet-stellar-sdk/issues/257":
			w.Write([]byte(`{"number":257,"title":"Liquidity pool parameters reject the asset order","state":"open"}`))
		case "/repos/lightsail-network/java-stellar-sdk/issues/832":
			w.Write([]byte(`{"number":832,"title":"fix","state":"closed","pull_request":{"merged_at":"2026-11-05T09:00:00Z"}}`))
		case "/repos/lightsail-network/java-stellar-sdk/releases/latest":
			w.Write([]byte(`{"tag_name":"6.0.0","published_at":"2026-10-28T12:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// fakeGH puts a `gh` (and a `curl`) on PATH that would leave a marker file if anything ran it, and returns the
// marker's path.
func fakeGH(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "gh-was-run")
	for _, name := range []string{"gh", "curl"} {
		script := "#!/bin/sh\necho \"$0 $*\" >> '" + marker + "'\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// `xdrcheck conform siblings --finding F-0016` with the .NET manual evidence: drafts for Java (release request) and
// .NET (evidence comment on its open issue), prints the commands that would file them, and runs none of them:
// a fake gh on PATH is never invoked, and the API sees only GET requests.
func TestConformSiblingsFilesNothing(t *testing.T) {
	marker := fakeGH(t)
	// Control: the fake gh on PATH does leave the marker when something runs it.
	if err := exec.Command("gh", "issue", "list").Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the fake gh left no marker: %v", err)
	}
	os.Remove(marker)

	root, overlay := siblingsRepo(t)
	srv, seen := githubAPI(t)
	manual := filepath.Join(root, "findings", "templates", "manual-evidence.example.json")
	var out, errb bytes.Buffer
	code := conformSiblings([]string{"--finding", "F-0016", "--manual", manual, "--overlay", overlay, "--github-api", srv.URL, "--date", "2026-11-12"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("a command was executed: %s", b)
	}
	for _, s := range seen() {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("non-GET request %s", s)
		}
	}
	o := out.String()
	for _, want := range []string{
		"go       fixed",
		"python   fixed",
		"java     affected",
		"rust     not-exercised",
		"dotnet   affected",
		"# NOT RUN. Nothing is filed by this tool.",
		`gh issue create --repo lightsail-network/java-stellar-sdk --title "Release request: `,
		"--body-file findings/F-0028/issue-java-stellar-sdk.md",
		"gh issue comment 257 --repo Beans-BV/dotnet-stellar-sdk --body-file findings/F-0029/issue-dotnet-stellar-sdk.md",
		"possibly related open pull request https://github.com/Beans-BV/dotnet-stellar-sdk/pull/272",
		"F-0028 (java, existing record): release-request draft written to findings/F-0028/issue-java-stellar-sdk.md",
		"F-0029 (dotnet, new candidate record): comment-on-existing draft written to findings/F-0029/issue-dotnet-stellar-sdk.md",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("output lacks %q:\n%s", want, o)
		}
	}
	for _, f := range []string{"findings/F-0028/issue-java-stellar-sdk.md", "findings/F-0029/issue-dotnet-stellar-sdk.md", "findings/F-0029/finding.json"} {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if ents, _ := os.ReadDir(overlay); len(ents) != 0 {
		t.Errorf("the overlay was written: %v", ents)
	}
	// java@6.0.0 is not a column of the public sets file: the public draft gives no command for it and says who
	// runs it.
	java, _ := os.ReadFile(filepath.Join(root, "findings/F-0028/issue-java-stellar-sdk.md"))
	if strings.Contains(string(java), "--columns java@") || !strings.Contains(string(java), "java@6.0.0 column is run by the maintainer outside the public repository") {
		t.Errorf("java draft corpus block:\n%s", java)
	}

	// The records still check.
	out.Reset()
	errb.Reset()
	if code := findingsMain([]string{"list"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "F-0029") {
		t.Errorf("findings list after the run: %d %s %s", code, out.String(), errb.String())
	}
}

// --plan prints the same plan and writes nothing; bad arguments exit 2.
func TestConformSiblingsPlanAndArgs(t *testing.T) {
	marker := fakeGH(t)
	root, _ := siblingsRepo(t)
	srv, _ := githubAPI(t)
	before := tree(t, root)
	var out, errb bytes.Buffer
	if code := conformSiblings([]string{"--finding", "F-0016", "--plan", "--github-api", srv.URL}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "plan only: nothing was written") || !strings.Contains(out.String(), "dotnet   no-column") {
		t.Errorf("plan output:\n%s", out.String())
	}
	if after := tree(t, root); after != before {
		t.Errorf("--plan wrote files:\n%s", after)
	}
	for _, args := range [][]string{{}, {"--finding", "F-0016", "--divergence", "https://x"}, {"--finding", "F-9999", "--plan"}, {"--finding", "F-0016", "extra"}} {
		if code := conformSiblings(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a command was executed")
	}
}

func tree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b.WriteString(p + " " + strconv.FormatInt(info.Size(), 10) + "\n")
		}
		return nil
	})
	return b.String()
}

// The command file starts no process.
func TestConformSiblingsNoExec(t *testing.T) {
	af, err := parser.ParseFile(token.NewFileSet(), "conform_siblings.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range af.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" {
			t.Error("conform_siblings.go imports os/exec")
		}
	}
}
