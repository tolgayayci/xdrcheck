package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// TestConformOffline runs the built xdrcheck in a scratch repository whose `pr` set is the stub column: `conform
// fetch`, then `conform build` and `conform run` inside a network namespace with loopback only
// (scripts/offline-run.sh), as `make verify OFFLINE=1` runs them.
func TestConformOffline(t *testing.T) {
	wd, _ := os.Getwd()
	repo := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	offline := filepath.Join(repo, "scripts", "offline-run.sh")
	if err := exec.Command(offline, "true").Run(); err != nil {
		t.Skipf("no network namespace here (%v)", err)
	}
	tmp := t.TempDir()
	xdrcheck := filepath.Join(tmp, "xdrcheck")
	if out, err := exec.Command("go", "build", "-o", xdrcheck, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// A scratch root: the real pins and corpus, the stub driver's sources, and a sets file whose pr set is the stub.
	root := filepath.Join(tmp, "root")
	for _, f := range []string{"pins.toml", "drivers/stub/main.go", "drivers/stub/go.mod", "drivers/stub/Makefile"} {
		copyFile(t, filepath.Join(repo, f), filepath.Join(root, f))
	}
	if err := os.Symlink(filepath.Join(repo, "corpus"), filepath.Join(root, "corpus")); err != nil {
		t.Fatal(err)
	}
	sets := `[sets]
pr = ["stub@0.1.0"]
[columns."stub@0.1.0"]
sdk = "stub"
kind = "selftest"
ecosystem = "other"
package = "xdrcheck-driver-stub"
target = "xdrcheck-driver-stub"
version = "0.1.0"
role = "selftest"
dir = "drivers/stub"
run = ["bin/xdrcheck-driver"]
`
	if err := os.WriteFile(filepath.Join(root, "drivers", "sets.toml"), []byte(sets), 0o644); err != nil {
		t.Fatal(err)
	}

	xdrcheckRun := func(cache string, offlineRun bool, args ...string) (int, string) {
		argv := append([]string{xdrcheck, "conform"}, args...)
		if offlineRun {
			argv = append([]string{offline}, argv...)
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "XDRCHECK_CACHE="+cache)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return 0, out.String()
		case errors.As(err, &ee):
			return ee.ExitCode(), out.String()
		}
		t.Fatalf("%v: %v", argv, err)
		return -1, ""
	}

	// Building before fetching fails: the cache is empty.
	if code, out := xdrcheckRun(filepath.Join(tmp, "empty-cache"), true, "build", "--set", "pr"); code != 2 {
		t.Errorf("build without fetch: exit %d\n%s", code, out)
	}

	cache := filepath.Join(tmp, "cache")
	if code, out := xdrcheckRun(cache, false, "fetch", "--set", "pr"); code != 0 {
		t.Fatalf("fetch: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, true, "build", "--set", "pr"); code != 0 {
		t.Fatalf("offline build: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "drivers", "stub", "bin", "xdrcheck-driver")); err != nil {
		t.Fatalf("the build produced no driver: %v", err)
	}

	// The identity stub reports no L1 facts and no L2 pinpoints; L0 and L1 are what it can pass.
	rep := filepath.Join(tmp, "report")
	// The identity stub accepts everything, so only entries a reader must accept are run.
	c, err := manifest.Load(filepath.Join(repo, "corpus"), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	var positive []string
	for _, e := range c.Entries {
		if !e.Negative {
			positive = append(positive, e.ID)
		}
	}
	code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0,L1", "--entries", strings.Join(positive, ","), "--report", rep)
	if code != 0 {
		t.Fatalf("offline run: exit %d\n%s", code, out)
	}
	r, err := report.ReadAll(filepath.Join(rep, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) < 30 || r.Header.Mode.Offline != "network namespace, loopback only" || r.Header.Mode.Suite != "pr" ||
		r.Header.Tool.Name != "xcc conform" || r.Header.Corpus.Version == "unversioned" {
		t.Errorf("report: %d rows, header %+v", len(r.Rows), r.Header)
	}
	for _, row := range r.Rows {
		if row.Conform.Verdict != "conform" || row.Conform.Check != "conform" || row.Expectation != "expected" {
			t.Errorf("row %s: %+v", row.RowID, row.Conform)
		}
	}
	if sum, err := os.ReadFile(filepath.Join(rep, "SUMMARY.md")); err != nil || !strings.Contains(string(sum), "0 new, 0 known but not yet triaged, 0 known divergences") {
		t.Errorf("SUMMARY.md of a clean run: %v\n%s", err, sum)
	}
	if !strings.Contains(out, "Conformance summary: 0 new") {
		t.Errorf("the console summary is missing:\n%s", out)
	}

	// The identity stub accepts what a negative entry says must be refused: those cells fail. An expected-failure
	// list written from that run passes it; the same list fails a run in which a listed cell conforms (an
	// unexpected pass) and a run with a failure it does not list.
	var negative string
	for _, e := range c.Entries {
		if e.Negative && e.Kind == "xdr" {
			negative = e.ID
			break
		}
	}
	list := filepath.Join(tmp, "stub.failures")
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", negative, "--write-expected-failures", list); code != 0 {
		t.Fatalf("--write-expected-failures: exit %d\n%s", code, out)
	}
	written, _ := os.ReadFile(list)
	if !strings.Contains(string(written), negative+" ") {
		t.Fatalf("the written list lacks %s:\n%s", negative, written)
	}
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", negative, "--expected-failures", list); code != 0 || !strings.Contains(out, "0 new failures, 0 new unread, 0 unexpected passes") {
		t.Errorf("the run against its own list: exit %d\n%s", code, out)
	}
	stale := filepath.Join(tmp, "stale.failures")
	os.WriteFile(stale, append(written, []byte(positive[0]+" "+c.Entry(positive[0]).VariantKey(c.Entry(positive[0]).Variants[0])+" L0\n")...), 0o644)
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", negative+","+positive[0], "--expected-failures", stale); code != 1 || !strings.Contains(out, "UNEXPECTED-PASS "+positive[0]) {
		t.Errorf("a listed cell that conforms: exit %d\n%s", code, out)
	}
	empty := filepath.Join(tmp, "empty.failures")
	os.WriteFile(empty, []byte("# nothing expected to fail\n"), 0o644)
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", negative, "--expected-failures", empty); code != 1 || !strings.Contains(out, "NEW-FAILURE   "+negative) {
		t.Errorf("a failure the list does not name: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", positive[0], "--require-all-read"); code != 0 {
		t.Errorf("--require-all-read on a column that read every entry: exit %d\n%s", code, out)
	}

	// With --overlay, the overlay's corpus/ is merged with the public one: an entry only the overlay holds is run
	// (its blob and sidecar read from the overlay), the report is marked as an overlay run, and an entry ID in
	// both corpora refuses the run.
	overlay := filepath.Join(tmp, "overlay")
	src := c.Entry("cap-0020/bucket-metaentry-first-record")
	if src == nil || len(src.Variants) != 1 {
		t.Fatal("the cloned public entry changed shape")
	}
	const ovID = "cap-0020/fictional-overlay-entry"
	var ovDoc map[string]any
	raw, err := os.ReadFile(filepath.Join(repo, "corpus", "manifest", src.ID+".json"))
	if err != nil || json.Unmarshal(raw, &ovDoc) != nil {
		t.Fatalf("reading %s: %v", src.ID, err)
	}
	ovDoc["id"] = ovID
	ovEntry, _ := json.MarshalIndent(ovDoc, "", "  ")
	v := src.Variants[0]
	copyFile(t, filepath.Join(repo, "corpus", filepath.FromSlash(v.Blob.Path)), filepath.Join(overlay, "corpus", filepath.FromSlash(v.Blob.Path)))
	copyFile(t, filepath.Join(repo, "corpus", filepath.FromSlash(v.Decoded)), filepath.Join(overlay, "corpus", filepath.FromSlash(v.Decoded)))
	ovManifest := filepath.Join(overlay, "corpus", "manifest", filepath.FromSlash(ovID)+".json")
	os.MkdirAll(filepath.Dir(ovManifest), 0o755)
	os.WriteFile(ovManifest, ovEntry, 0o644)
	ovRep := filepath.Join(tmp, "report-overlay")
	code, out = xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--overlay", overlay, "--entries", ovID, "--report", ovRep)
	if code != 0 || !strings.Contains(out, ovID) {
		t.Fatalf("overlay run: exit %d\n%s", code, out)
	}
	if r, err := report.ReadAll(filepath.Join(ovRep, "report.json")); err != nil || !r.Header.Mode.Overlay || len(r.Rows) == 0 {
		t.Errorf("overlay report: %v, %+v", err, r)
	}
	if _, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--entries", ovID); strings.Contains(out, ovID) {
		t.Errorf("the overlay entry ran without --overlay:\n%s", out)
	}
	os.WriteFile(filepath.Join(overlay, "corpus", "manifest", filepath.FromSlash(src.ID)+".json"), raw, 0o644)
	if code, out := xdrcheckRun(cache, true, "run", "--set", "pr", "--levels", "L0", "--overlay", overlay, "--entries", ovID, "--report", ovRep); code != 2 || !strings.Contains(out, "both") {
		t.Errorf("an ID in both corpora: exit %d\n%s", code, out)
	}

	// check, diff and readiness on the run's matrix and on a copy with one regressed cell.
	matrix := filepath.Join(rep, "matrix.json")
	if code, out := xdrcheckRun(cache, false, "check", matrix); code != 0 {
		t.Errorf("check on a clean matrix: exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(matrix)
	if err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(tmp, "broken.json")
	doctored := strings.Replace(string(data), `"verdict": "conform",
   "check": "conform"`, `"verdict": "diverge",
   "check": "undeclared"`, 1)
	if doctored == string(data) {
		t.Fatal("could not doctor the matrix")
	}
	os.WriteFile(broken, []byte(doctored), 0o644)
	if code, out := xdrcheckRun(cache, false, "check", broken); code != 1 || !strings.Contains(out, "new divergence") {
		t.Errorf("check on an undeclared divergence: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, false, "diff", matrix, broken); code != 1 || !strings.Contains(out, "conform/conform -> diverge/undeclared") {
		t.Errorf("diff: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, false, "diff", matrix, matrix); code != 0 {
		t.Errorf("diff of a matrix with itself: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, false, "readiness", "--protocol", "30", matrix); code != 0 || !strings.Contains(out, "Protocol 30 readiness") {
		t.Errorf("readiness: exit %d\n%s", code, out)
	}

	code, out = xdrcheckRun(cache, false, "describe", "--columns", "stub*")
	if code != 0 || !strings.Contains(out, `"column": "stub@0.1.0"`) || !strings.Contains(out, `"package": "xdrcheck-driver-stub"`) {
		t.Errorf("describe: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, false, "check", "no-such-matrix.json"); code != 2 {
		t.Errorf("check of a missing file: exit %d\n%s", code, out)
	}
	// sdk-regression needs the JavaScript pins, which this scratch root's sets file does not have.
	if code, out := xdrcheckRun(cache, false, "sdk-regression"); code != 2 || !strings.Contains(out, "js@17.2.0") {
		t.Errorf("sdk-regression without its columns: exit %d\n%s", code, out)
	}

	// An undeclared cell in the pending list is reported as pending finding review and passes in development
	// mode, fails in acceptance mode; an item for another variant does not cover it; an item whose cell is no
	// longer undeclared is stale and fails.
	var doc struct {
		Cells []struct{ Entry, Variant, Column, Level, Verdict, Check string }
	}
	bd, _ := os.ReadFile(broken)
	if err := json.Unmarshal(bd, &doc); err != nil {
		t.Fatal(err)
	}
	item := map[string]string{}
	for _, c := range doc.Cells {
		if c.Check == "undeclared" {
			item = map[string]string{"entry": c.Entry, "variant": c.Variant, "column": c.Column, "level": c.Level}
		}
	}
	pending := filepath.Join(tmp, "conformance.json")
	writeList := func(items ...map[string]string) {
		b, _ := json.Marshal(map[string]any{"pending": items})
		os.WriteFile(pending, b, 0o644)
	}
	writeList(item)
	if code, out := xdrcheckRun(cache, false, "check", "--pending", pending, broken); code != 0 || !strings.Contains(out, "known divergence, not yet triaged") {
		t.Errorf("check with the cell pending finding review: exit %d\n%s", code, out)
	}
	if code, out := xdrcheckRun(cache, false, "check", "--mode", "acceptance", "--pending", pending, broken); code != 1 || !strings.Contains(out, "not yet triaged") {
		t.Errorf("acceptance check with the cell pending finding review: exit %d\n%s", code, out)
	}
	other := map[string]string{"entry": item["entry"], "variant": "elsewhere", "column": item["column"], "level": item["level"]}
	writeList(other)
	if code, out := xdrcheckRun(cache, false, "check", "--pending", pending, broken); code != 1 || !strings.Contains(out, "new divergence: no entry declares it") {
		t.Errorf("check with an item for another variant: exit %d\n%s", code, out)
	}
	writeList(item)
	if code, out := xdrcheckRun(cache, false, "check", "--pending", pending, matrix); code != 1 || !strings.Contains(out, "STALE") {
		t.Errorf("check with a stale pending item: exit %d\n%s", code, out)
	}
	if code, _ := xdrcheckRun(cache, false, "run", "--set", "nope"); code != 2 {
		t.Errorf("unknown set: exit %d", code)
	}
}

// copySets copies drivers/sets.toml and its fragments in drivers/sets.d/ from one root to another.
func copySets(t *testing.T, from, to string) {
	t.Helper()
	copyFile(t, filepath.Join(from, "drivers", "sets.toml"), filepath.Join(to, "drivers", "sets.toml"))
	frags, err := filepath.Glob(filepath.Join(from, "drivers", "sets.d", "*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frags {
		copyFile(t, f, filepath.Join(to, "drivers", "sets.d", filepath.Base(f)))
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

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "1024": 1024, "1K": 1 << 10, "512M": 512 << 20, "1G": 1 << 30, "1GiB": 1 << 30, "2gb": 2 << 30} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1", "1Q"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
