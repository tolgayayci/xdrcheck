package overlay

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The history fixture is fictional too: a made-up record, entry and overlay file.

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", msg)
	return gitIn(t, dir, "rev-parse", "HEAD")
}

const leak = "private run output, line one\nline two\n"

// historyFixture is a repository whose second commit holds an overlay file's content at a public path, a
// planted record ID and a recipe of a held-back entry; the third commit removes all three.
func historyFixture(t *testing.T) (repo, ov string, commits []string) {
	repo, ov = t.TempDir(), t.TempDir()
	gitIn(t, repo, "init", "-q", "-b", "main")
	put(t, ov, "findings/F-5901/finding.json", `{"id": "F-5901", "visibility": "embargoed", "state": "draft",
		"entries": [{"id": "x/held"}], "evidence": {"transcripts": ["evidence/private/run.txt"]}}`)
	put(t, ov, "findings/F-5902/finding.json", `{"id": "F-5902", "visibility": "public", "state": "filed",
		"upstream": {"url": "https://example.invalid/issues/1"}, "entries": [{"id": "x/shown"}]}`)
	put(t, ov, "evidence/private/run.txt", leak)
	put(t, ov, "corpus/recipes/x/held.json", `{"entry": "x/held"}`)
	put(t, ov, "lint/xdrlint.yml", "sinkstext:\n  - example.com/m.Sink.Field\n")
	put(t, ov, "reports/run.json", "{}\n") // reports/ is never compared or hashed

	put(t, repo, "corpus/manifest/x/shown.json", "{}\n")
	put(t, repo, "docs/readme.md", "public text\n")
	put(t, repo, "reports-copy/run.json", "{}\n")
	commits = append(commits, commitAll(t, repo, "first"))
	put(t, repo, "docs/run-log.txt", leak)
	put(t, repo, "docs/notes.md", "see F-5901\n")
	put(t, repo, "corpus/recipes/x/held.json", `{"entry": "x/held"}`)
	put(t, repo, "empty.txt", "")
	commits = append(commits, commitAll(t, repo, "second"))
	for _, f := range []string{"docs/run-log.txt", "docs/notes.md", "corpus/recipes/x/held.json"} {
		os.Remove(filepath.Join(repo, f))
	}
	commits = append(commits, commitAll(t, repo, "third"))
	return repo, ov, commits
}

func TestAuditRevsFindsAPlantedBlob(t *testing.T) {
	repo, ov, commits := historyFixture(t)
	revs, err := RevList(repo, "main")
	if err != nil || len(revs) != 3 || revs[0] != commits[2] {
		t.Fatalf("rev-list: %v %v", revs, err)
	}
	got := map[string][]string{}
	err = AuditRevs(repo, ov, revs, func(rev string, res *Result) error {
		got[rev] = strs(res.Problems)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"- blob-id docs/run-log.txt = overlay evidence/private/run.txt",
		"- recipe-without-entry corpus/recipes/x/held.json",
		"- same-file corpus/recipes/x/held.json",
		"F-5901 entry-named corpus/recipes/x/held.json",
		"F-5901 public-recipe corpus/recipes/x/held.json",
		"F-5901 record-id docs/notes.md",
	}
	if !reflect.DeepEqual(got[commits[1]], want) {
		t.Errorf("second commit:\n got %q\nwant %q", got[commits[1]], want)
	}
	if len(got[commits[0]]) != 0 || len(got[commits[2]]) != 0 {
		t.Errorf("clean commits: %q %q", got[commits[0]], got[commits[2]])
	}
	// The working tree (the third commit) agrees with the commit's audit.
	res, err := Audit(repo, ov)
	if err != nil || len(res.Problems) != 0 {
		t.Errorf("working tree: %v %q", err, strs(res.Problems))
	}
	// An allowed id is not a problem.
	put(t, ov, BlobAllowFile, "# reason\n"+HashObject([]byte(leak))+" shared on purpose\n")
	err = AuditRevs(repo, ov, []string{commits[1]}, func(rev string, res *Result) error {
		for _, p := range res.Problems {
			if p.Kind == KindBlobID {
				t.Errorf("allowed blob reported: %s", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBlobIDInTheWorkingTree(t *testing.T) {
	root, ov := t.TempDir(), t.TempDir()
	put(t, ov, "data/private.txt", leak)
	put(t, ov, "data/same.txt", "same\n")
	put(t, root, "elsewhere/copy.txt", leak)
	put(t, root, "data/same.txt", "same\n")
	res, err := Audit(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"- blob-id elsewhere/copy.txt = overlay data/private.txt", "- same-file data/same.txt"}
	if got := strs(res.Problems); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
	if HashObject(nil) != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" || EmptyBlob != HashObject([]byte{}) {
		t.Error("HashObject differs from git hash-object")
	}
}

func TestRevListRefusesAnOption(t *testing.T) {
	repo, _, _ := historyFixture(t)
	for _, bad := range []string{"", "--all", "-n1"} {
		if _, err := RevList(repo, bad); err == nil {
			t.Errorf("RevList(%q) accepted", bad)
		}
		if _, err := ResolveCommit(repo, bad); err == nil {
			t.Errorf("ResolveCommit(%q) accepted", bad)
		}
	}
}

func TestEmitTokens(t *testing.T) {
	repo, ov, _ := historyFixture(t)
	toks, err := EmitTokens(repo, ov)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		got = append(got, strings.Join([]string{tk.Value, tk.Kind, map[bool]string{true: "public", false: "-"}[tk.Public], strings.Join(tk.Records, ",")}, " "))
	}
	want := []string{
		"x/held entry - F-5901:embargoed/draft",
		"x/shown entry public F-5902:public/filed/url",
		"evidence/private/run.txt evidence - F-5901:embargoed/draft",
		"example.com/m.Sink.Field lint-sink - ",
		"F-5901 record-id - F-5901:embargoed/draft",
		"F-5902 record-id - F-5902:public/filed/url",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tokens:\n got %q\nwant %q", got, want)
	}
}
