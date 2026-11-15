package overlay

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixture is fictional: record IDs from F-5901, entries under x/, a made-up linter target and sink. No
// record carries a title or description.

func put(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repoPins is the repository's own pins.toml, so the fixture pins real conformance versions.
func repoPins(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const setsPublic = `[sets]
pr = ["js@1"]

[columns."js@1"]
sdk = "js"
kind = "sdk"
ecosystem = "npm"
package = "p"
target = "p"
version = "1"
role = "required"
dir = "drivers/js/1"
run = ["bin/xdrcheck-driver"]
`

const setsOverlay = `[sets]
private = ["@pr", "python@17.0.0"]

[columns."python@17.0.0"]
sdk = "python"
kind = "sdk"
ecosystem = "pypi"
package = "p"
target = "p"
version = "17.0.0"
role = "extra"
dir = "drivers/python/17.0.0"
run = ["bin/xdrcheck-driver"]
`

const embargoed = `{
  "id": "F-5901",
  "visibility": "embargoed",
  "entries": [{"id": "x/public-row"}, {"id": "x/kept"}, {"id": "x/orphan"}, {"id": "x/fam.moved"}],
  "evidence": {
    "transcripts": ["evidence/run/out.txt", "overlay: reports/private.json"],
    "report_rows": [
      "conform:x/public-row:none:js@1:L0",
      "conform:x/kept:none:python@17.0.0:L0",
      "lint:example.com/m@abc123:XDR999:pkg/file.go:F"
    ]
  }
}`

// fixture writes a public tree with one trace of every kind and an overlay that holds the private side.
func fixture(t *testing.T) (root, ov string) {
	root, ov = t.TempDir(), t.TempDir()
	put(t, root, "pins.toml", repoPins(t))
	put(t, root, "drivers/sets.toml", setsPublic)
	put(t, root, "drivers/python/17.0.0/Makefile", "all:\n")
	put(t, root, "corpus/manifest/x/public-row.json", "{}\n")
	put(t, root, "corpus/manifest/x/kept.json", "{}\n")
	put(t, root, "corpus/recipes/x/public-row.json", `{"entry": "x/public-row"}`)
	put(t, root, "corpus/recipes/x/orphan.json", `{"entry": "x/orphan"}`)
	put(t, root, "lint/profiles/default.yml", "sinkstext:\n  - example.com/m.Sink.Field\n")
	put(t, root, "lint/expected/target/abc123.pending.json", `{"pending": [{"rule": "XDR999", "file": "pkg/file.go"}]}`)
	put(t, root, "evidence/run/out.txt", "output\n")
	put(t, root, "docs/notes.md", "See F-5902 and x/orphan for details; x/kept is fine.\n")
	put(t, root, "corpus/plan.json", `[{"id": "x/fam", "members": ["kept-member", "moved"]}, {"id": "x/kept"}]`)
	put(t, root, "data/table.jsonl", "{\"a\": 1}\n{\"b\": 2}\n")
	put(t, root, "data/same.txt", "same\n")
	put(t, root, "data/other.jsonl", "{\"z\": 9}\n")

	put(t, ov, "findings/F-5901/finding.json", embargoed)
	put(t, ov, "findings/F-5902/finding.json", `{"id": "F-5902", "visibility": "embargoed", "entries": []}`)
	put(t, ov, "findings/F-5903/finding.json", `{"id": "F-5903", "visibility": "public", "entries": [{"id": "x/public-row"}],
		"evidence": {"report_rows": ["conform:x/public-row:none:js@1:L0"]}}`)
	put(t, ov, "drivers/sets.toml", setsOverlay)
	put(t, ov, "lint/xdrlint.yml", "# overlay layer\nsinkstext:\n  - example.com/m.Sink.Field # private\n")
	put(t, ov, "data/table.jsonl", "{\"a\": 1}\n{\"b\": 2}\n{\"c\": 3}\n")
	put(t, ov, "data/same.txt", "same\n")
	put(t, ov, "data/other.jsonl", "{\"y\": 8}\n{\"x\": 7}\n")
	return root, ov
}

func strs(ps []Problem) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestAuditFindsEveryTrace(t *testing.T) {
	root, ov := fixture(t)
	res, err := Audit(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"- recipe-without-entry corpus/recipes/x/orphan.json",
		"- row-subset data/table.jsonl",
		"- same-file data/same.txt",
		"F-5901 column-driver drivers/python/17.0.0/",
		"F-5901 column-pinned pins.toml [conformance.columns] python 17.0.0",
		"F-5901 entry-named corpus/recipes/x/orphan.json",
		"F-5901 entry-named docs/notes.md",
		"F-5901 evidence-file evidence/run/out.txt",
		"F-5901 lint-row lint/expected/target/abc123.pending.json",
		"F-5901 lint-sink lint/profiles/default.yml",
		"F-5901 planned corpus/plan.json x/fam.moved",
		"F-5901 public-recipe corpus/recipes/x/orphan.json",
		"F-5901 public-row corpus/manifest/x/public-row.json × js@1",
		"F-5902 record-id docs/notes.md",
	}
	if got := strs(res.Problems); !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n got %q\nwant %q", got, want)
	}
	if got := strs(res.Kept); !reflect.DeepEqual(got, []string{"F-5901 kept corpus/manifest/x/kept.json"}) {
		t.Errorf("kept %q", got)
	}
	if res.Records != 3 || !reflect.DeepEqual(res.Embargoed, []string{"F-5901", "F-5902"}) {
		t.Errorf("records %d, embargoed %v", res.Records, res.Embargoed)
	}
}

func TestAuditCleanTree(t *testing.T) {
	root, ov := fixture(t)
	for _, rel := range []string{
		"drivers/python/17.0.0/Makefile", "corpus/manifest/x/public-row.json", "corpus/recipes/x/public-row.json",
		"corpus/recipes/x/orphan.json", "lint/expected/target/abc123.pending.json", "evidence/run/out.txt",
		"docs/notes.md", "data/table.jsonl", "data/same.txt",
	} {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
	}
	put(t, root, "lint/profiles/default.yml", "sinkstext: []\n")
	put(t, root, "corpus/plan.json", `[{"id": "x/fam", "members": ["kept-member"]}, {"id": "x/kept"}]`)
	pins := strings.Replace(repoPins(t), `python = ["17.0.1", "17.0.0"]`, `python = ["17.0.1"]`, 1)
	if pins == repoPins(t) {
		t.Fatal("the fixture expects pins.toml to pin python 17.0.0")
	}
	put(t, root, "pins.toml", pins)
	res, err := Audit(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Errorf("problems in a clean tree: %q", strs(res.Problems))
	}
	if len(res.Kept) != 1 {
		t.Errorf("kept %q", strs(res.Kept))
	}
}

// A column the overlay's sets file defines must not be a public column too; the rows it serves then count as
// public rows.
func TestAuditOverlayColumnAlsoPublic(t *testing.T) {
	root, ov := fixture(t)
	python := strings.SplitN(setsOverlay, "\n\n", 2)[1] // the [columns."python@17.0.0"] table
	put(t, root, "drivers/sets.toml", strings.Replace(setsPublic, `pr = ["js@1"]`, `pr = ["js@1", "python@17.0.0"]`, 1)+"\n"+python)
	res, err := Audit(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(strs(res.Problems), "\n")
	for _, want := range []string{"- column-public drivers/sets.toml python@17.0.0", "F-5901 public-row corpus/manifest/x/kept.json × python@17.0.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// An embargoed record's replay trigger (an entry with scope "replay", or a replay report row) must not name a
// public entry: the replay adapters are public. Once the entries are out of the tree, only their names count.
func TestAuditReplayTriggers(t *testing.T) {
	root, ov := fixture(t)
	put(t, root, "corpus/manifest/x/replayed.json", "{}\n")
	put(t, root, "corpus/manifest/x/replay-row.json", "{}\n")
	put(t, ov, "findings/F-5904/finding.json", `{"id": "F-5904", "visibility": "embargoed",
		"entries": [{"id": "x/replayed", "scope": "replay"}, {"id": "x/kept", "scope": "L0"}],
		"evidence": {"report_rows": ["replay:example/pipeline@abc123:x/replay-row:pubnet@30:single"]}}`)
	put(t, ov, "findings/F-5905/finding.json", `{"id": "F-5905", "visibility": "public",
		"entries": [{"id": "x/kept", "scope": "replay"}]}`)
	res, err := Audit(root, ov)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(strs(res.Problems), "\n")
	for _, want := range []string{
		"F-5904 public-replay corpus/manifest/x/replay-row.json",
		"F-5904 public-replay corpus/manifest/x/replayed.json",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, not := range []string{"public-replay corpus/manifest/x/kept.json", "F-5905"} {
		if strings.Contains(got, not) {
			t.Errorf("unexpected %q in:\n%s", not, got)
		}
	}

	// Held back: the entries leave the public tree, and the audit then looks only for their names.
	for _, rel := range []string{"corpus/manifest/x/replayed.json", "corpus/manifest/x/replay-row.json"} {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
	}
	put(t, root, "docs/replay.md", "Replay x/replayed to see it.\n")
	if res, err = Audit(root, ov); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(strs(res.Problems), "\n")
	if strings.Contains(got, "public-replay") || !strings.Contains(got, "F-5904 entry-named docs/replay.md") {
		t.Errorf("after the hold-back:\n%s", got)
	}
}

func TestAuditRefusesAnOverlayInsideTheTree(t *testing.T) {
	root, _ := fixture(t)
	if _, err := Audit(root, filepath.Join(root, "data")); err == nil {
		t.Error("an overlay inside the tree was accepted")
	}
}

func TestRowParsers(t *testing.T) {
	if e, c, ok := conformRow("conform:a/b.c:pubnet@29:rust@30.0.0:limits-none:L0"); !ok || e != "a/b.c" || c != "rust@30.0.0:limits-none" {
		t.Errorf("conform row: %q %q %v", e, c, ok)
	}
	if e, c, ok := conformRow("conform:a/b:-:js@1:L4"); !ok || e != "a/b" || c != "js@1" {
		t.Errorf("conform row: %q %q %v", e, c, ok)
	}
	if e, ok := replayRow("replay:example/pipeline@abc123:a/b.c:pubnet@30:chain"); !ok || e != "a/b.c" {
		t.Errorf("replay row: %q %v", e, ok)
	}
	if _, ok := replayRow("replay:a@1:b"); ok {
		t.Error("a short replay row was accepted")
	}
	if v, r, f, ok := lintRow("lint:example.com/m@abc123:XDR999:pkg/file.go:F"); !ok || v != "abc123" || r != "XDR999" || f != "pkg/file.go" {
		t.Errorf("lint row: %q %q %q %v", v, r, f, ok)
	}
	if !properSubset([]string{"a", "b"}, []string{"b", "a", "c"}) || properSubset([]string{"a", "a"}, []string{"a", "b", "c"}) ||
		properSubset([]string{"a"}, []string{"a"}) || properSubset(nil, []string{"a"}) {
		t.Error("properSubset")
	}
}
