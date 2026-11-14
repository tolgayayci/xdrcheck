package conform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// The tests drive the real stub driver (drivers/stub), built once into a temporary directory, over the three
// vendored corpus entries (six variants, levels L0–L2: 18 cells per column).

var (
	repoRoot string
	stubBin  string
)

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	repoRoot = filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	tmp, err := os.MkdirTemp("", "xdrcheck-conform-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	stubBin = filepath.Join(tmp, "xdrcheck-driver")
	build := exec.Command("go", "build", "-o", stubBin, ".")
	build.Dir = filepath.Join(repoRoot, "drivers", "stub")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the stub driver: %v\n%s", err, out)
		os.Exit(2)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

const cellsPerColumn = 18

// threeEntries are the corpus's first three vendored entries, which the tests are written against.
var threeEntries, _ = CompileGlobs("cap-0038/pool-issuers-order-by-bytes-not-strkey,cap-0040/signed-payload-signer-added,cap-0073/sac-trust-creates-trustline")

func loadCorpus(t *testing.T) *manifest.Corpus {
	t.Helper()
	c, err := manifest.Load(testcorpus.Build(t, testcorpus.Original, testcorpus.Options{}), manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range c.Entries {
		if threeEntries.Match(e.ID) {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want the three first vendored entries, got %d", n)
	}
	return c
}

func validator(t *testing.T) *Validator {
	t.Helper()
	ops, err := LoadAPIOps(filepath.Join(repoRoot, "corpus", "schema", "manifest-entry.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Validator{APIOps: ops}
}

// stubColumn is a selftest column running the stub with the given configuration.
func stubColumn(t *testing.T, id string, cfg map[string]any) *Column {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sdk, version, _ := strings.Cut(id, "@")
	return &Column{ID: id, SDK: sdk, Kind: "selftest", Ecosystem: "other", Package: "xdrcheck-driver-stub", Target: "xdrcheck-driver-stub",
		Version: version, Role: "selftest", Dir: filepath.Dir(stubBin), Run: []string{stubBin, "--config", path}}
}

func rules(rs ...map[string]any) map[string]any { return map[string]any{"rules": rs} }

func run(t *testing.T, limits Limits, jobs int, cols ...*Column) *Result {
	t.Helper()
	if limits.Timeout == 0 {
		limits.Timeout = 20 * time.Second
	}
	var log bytes.Buffer
	res, err := Run(context.Background(), Options{
		Sets: &Sets{Root: repoRoot}, Columns: cols, Corpus: loadCorpus(t), Entries: threeEntries, Jobs: jobs, Limits: limits,
		Validator: validator(t), Log: &log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if log.Len() > 0 {
		t.Logf("orchestrator log:\n%s", log.String())
	}
	res.Apply(ObservedJudge{})
	return res
}

func find(t *testing.T, res *Result, entry, level string) []*Observation {
	t.Helper()
	var out []*Observation
	for _, o := range res.Observations {
		if strings.HasPrefix(o.Cell.Entry.ID, entry) && o.Cell.Level == level {
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no cell %s %s", entry, level)
	}
	return out
}

// others asserts that every cell outside the selected entry and level was answered ok by the driver.
func others(t *testing.T, res *Result, entry, level string) {
	t.Helper()
	for _, o := range res.Observations {
		if strings.HasPrefix(o.Cell.Entry.ID, entry) && o.Cell.Level == level {
			continue
		}
		if o.Outcome != "ok" || o.Source != "driver" {
			t.Errorf("%s: outcome %q source %q crash %+v protocol %q not-run %q", o.Cell.RowID(), o.Outcome, o.Source, o.Crash, o.ProtocolError, o.NotRun)
		}
	}
}

func TestAllOK(t *testing.T) {
	res := run(t, Limits{}, 1, stubColumn(t, "stub@0.1.0", nil))
	if len(res.Observations) != cellsPerColumn {
		t.Fatalf("%d cells, want %d", len(res.Observations), cellsPerColumn)
	}
	others(t, res, "-", "-")
	for _, o := range res.Observations {
		a := o.Response.Actual
		if a == nil || a.ReencodedSHA256 == nil || *a.ReencodedSHA256 != o.Cell.Variant.Blob.SHA256 || *a.ConsumedBytes != o.Cell.Variant.Blob.Bytes {
			t.Errorf("%s: the identity stub should echo the blob's hash and size: %+v", o.Cell.RowID(), a)
		}
		if o.Judgement.Verdict != "conform" || o.Judgement.Expectation != "expected" {
			t.Errorf("%s: judgement %+v", o.Cell.RowID(), o.Judgement)
		}
		if o.Request.Level == "L2" && len(o.Request.Input.Pinpoints) == 0 {
			t.Errorf("%s: L2 request without the entry's pinpoints", o.Cell.RowID())
		}
	}
	if p := res.Columns[0].Processes; p != 1 {
		t.Errorf("one long-lived process expected, got %d", p)
	}
	if errs := res.InfraErrors(); len(errs) > 0 {
		t.Errorf("infrastructure errors: %v", errs)
	}

	dir := t.TempDir()
	h, err := Header(loadCorpus(t), loadPins(t), []*Column{res.Columns[0].Column}, "selftest", "curated")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := WriteOutputs(dir, res, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Judged != cellsPerColumn || sum.Report.Rows != cellsPerColumn || sum.Report.Failures != 0 {
		t.Errorf("summary %+v", sum)
	}
	rep, err := report.ReadAll(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	r0 := rep.Rows[0]
	if r0.Tool != "conform" || r0.Target.Kind != "selftest" || r0.Conform.Outcome != "ok" || r0.Conform.Verdict != "conform" || r0.Conform.Check != "" {
		t.Errorf("row %+v %+v", r0, r0.Conform)
	}
	if lines := countLines(t, filepath.Join(dir, CellsFile)); lines != cellsPerColumn {
		t.Errorf("%s has %d lines", CellsFile, lines)
	}
}

func loadPins(t *testing.T) *pins.Pins {
	t.Helper()
	p, err := pins.Load(filepath.Join(repoRoot, "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func countLines(t *testing.T, path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("\n"))
}

func TestCannedOutcomes(t *testing.T) {
	col := stubColumn(t, "stub@0.1.0", rules(
		map[string]any{"entry": "cap-0038/*", "level": "L1", "do": "reject", "code": "ordering", "message": "Assets are not in lexicographic order"},
		map[string]any{"entry": "cap-0040/*", "level": "L0", "do": "diverge", "code": "reencode_mismatch"},
		map[string]any{"entry": "cap-0040/*", "level": "L2", "do": "crash", "code": "panic"},
		map[string]any{"entry": "cap-0073/*", "level": "L1", "do": "n_a", "code": "no_object_layer"},
	))
	res := run(t, Limits{}, 1, col)
	want := map[string][2]string{
		"cap-0038 L1": {"reject", "reject_valid"},
		"cap-0040 L0": {"diverge", "diverge"},
		"cap-0040 L2": {"crash", "crash"},
		"cap-0073 L1": {"n_a", "n_a"},
	}
	for k, w := range want {
		e, l, _ := strings.Cut(k, " ")
		for _, o := range find(t, res, e, l) {
			if o.Outcome != w[0] || o.Judgement.Verdict != w[1] || o.Source != "driver" {
				t.Errorf("%s: outcome %s verdict %s source %s, want %v", o.Cell.RowID(), o.Outcome, o.Judgement.Verdict, o.Source, w)
			}
		}
	}
	// A crash the driver caught in-process does not cost the process.
	if p := res.Columns[0].Processes; p != 1 {
		t.Errorf("processes %d, want 1", p)
	}
}

func TestMalformedResponseIsNotTrusted(t *testing.T) {
	for _, how := range []string{"unknown_field", "missing_reason", "wrong_id", "wrong_entry", "not_json", "bad_sha"} {
		t.Run(how, func(t *testing.T) {
			col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0040/*", "level": "L0", "do": "malformed", "malformed": how}))
			res := run(t, Limits{}, 1, col)
			o := find(t, res, "cap-0040", "L0")[0]
			if o.ProtocolError == "" || o.Response != nil || o.Outcome != "" || o.Judgement != nil || o.Judged() {
				t.Fatalf("malformed response was trusted: %+v", o)
			}
			if len(res.InfraErrors()) != 1 {
				t.Errorf("infrastructure errors %v", res.InfraErrors())
			}
			others(t, res, "cap-0040", "L0")
			// The process that broke the protocol was replaced.
			if p := res.Columns[0].Processes; p != 2 {
				t.Errorf("processes %d, want 2", p)
			}
			dir := t.TempDir()
			h, _ := Header(loadCorpus(t), loadPins(t), []*Column{col}, "selftest", "curated")
			sum, err := WriteOutputs(dir, res, h, nil)
			if err != nil {
				t.Fatal(err)
			}
			if sum.ProtocolErrors != 1 || sum.Report.Rows != cellsPerColumn-1 {
				t.Errorf("summary %+v", sum)
			}
			data, _ := os.ReadFile(filepath.Join(dir, CellsFile))
			if !bytes.Contains(data, []byte(`"status":"protocol_error"`)) {
				t.Errorf("%s does not record the protocol error", CellsFile)
			}
		})
	}
}

func TestBadDescribe(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"malformed":        {"describe_malformed": true},
		"version-mismatch": {"sdk_version": "9.9.9"},
	} {
		t.Run(name, func(t *testing.T) {
			res := run(t, Limits{}, 1, stubColumn(t, "stub@0.1.0", cfg))
			for _, o := range res.Observations {
				if o.NotRun == "" || o.Judged() {
					t.Errorf("%s ran with an untrusted driver: %+v", o.Cell.RowID(), o)
				}
			}
			if errs := res.InfraErrors(); len(errs) != 1 {
				t.Errorf("errors %v", errs)
			}
		})
	}
}

func TestCrashContinues(t *testing.T) {
	for _, do := range []string{"exit", "abort"} {
		t.Run(do, func(t *testing.T) {
			col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0040/*", "level": "L1", "do": do, "exit_code": 3}))
			res := run(t, Limits{}, 1, col)
			o := find(t, res, "cap-0040", "L1")[0]
			if o.Outcome != "crash" || o.Source != "orchestrator" || o.Crash == nil || o.Crash.Reason != "process_died" {
				t.Fatalf("crash cell %+v crash %+v", o, o.Crash)
			}
			switch do {
			case "exit":
				if o.Crash.ExitCode != 3 {
					t.Errorf("exit code %d", o.Crash.ExitCode)
				}
			case "abort":
				if o.Crash.Signal != "aborted" {
					t.Errorf("signal %q", o.Crash.Signal)
				}
			}
			if !strings.Contains(o.Crash.StderrTail, "on cap-0040/signed-payload-signer-added L1") {
				t.Errorf("stderr tail %q", o.Crash.StderrTail)
			}
			if o.Judgement.Verdict != "crash" {
				t.Errorf("verdict %s", o.Judgement.Verdict)
			}
			others(t, res, "cap-0040", "L1")
			if p := res.Columns[0].Processes; p != 2 {
				t.Errorf("processes %d, want 2", p)
			}
			after := find(t, res, "cap-0040", "L2")[0]
			if after.Process != 2 {
				t.Errorf("the cell after the crash ran on process %d, want a fresh process 2", after.Process)
			}
			if len(res.InfraErrors()) != 0 {
				t.Errorf("a crash is an SDK outcome, not an infrastructure error: %v", res.InfraErrors())
			}
		})
	}
}

func TestHangIsKilledAtTimeout(t *testing.T) {
	col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0038/*", "level": "L0", "do": "hang"}))
	t0 := time.Now()
	res := run(t, Limits{Timeout: time.Second}, 1, col)
	o := find(t, res, "cap-0038", "L0")[0]
	if o.Outcome != "crash" || o.Crash == nil || o.Crash.Reason != "timeout" || !o.Crash.TimedOut || o.Crash.Signal != "killed" {
		t.Fatalf("hang cell %+v crash %+v", o, o.Crash)
	}
	if o.WallMS < 900 || o.WallMS > 5000 {
		t.Errorf("killed after %.0f ms, want about 1000", o.WallMS)
	}
	if el := time.Since(t0); el > 20*time.Second {
		t.Errorf("run took %s", el)
	}
	others(t, res, "cap-0038", "L0")
}

func TestMemoryCap(t *testing.T) {
	col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0073/*", "level": "L2", "do": "alloc", "mib": 0}))
	// A Go child reserves far more address space than it uses, so RLIMIT_AS stays generous here; the cap under
	// test is the memory cap (cgroup memory.max, or polled RSS).
	res := run(t, Limits{MemoryMax: 128 << 20, AddressSpaceMax: 64 << 30}, 1, col)
	for _, o := range find(t, res, "cap-0073", "L2") {
		if o.Outcome != "crash" || o.Crash == nil || o.Crash.Reason != "out_of_memory" || !o.Crash.MemoryCapHit {
			t.Fatalf("%s: %+v crash %+v", o.Cell.RowID(), o, o.Crash)
		}
		t.Logf("%s: killed under %s, group peak %d bytes, notes %v", o.Cell.RowID(), o.Crash.Mechanism, o.Crash.GroupPeakBytes, o.Crash.Notes)
	}
	others(t, res, "cap-0073", "L2")
	// Each of the four variants' L2 cell killed the process it ran on; the cell after it started the next one.
	if p := res.Columns[0].Processes; p != 4 {
		t.Errorf("processes %d, want 4", p)
	}
}

func TestAddressSpaceCap(t *testing.T) {
	if proc.Available() == proc.None {
		t.Skip("no limit mechanism on this host")
	}
	col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0038/*", "level": "L2", "do": "alloc", "mib": 4096}))
	res := run(t, Limits{AddressSpaceMax: 2 << 30}, 1, col)
	o := find(t, res, "cap-0038", "L2")[0]
	// The allocation fails inside the child: the Go runtime reports it and exits 2.
	if o.Outcome != "crash" || o.Crash == nil || o.Crash.Reason != "process_died" || o.Crash.ExitCode != 2 ||
		!strings.Contains(o.Crash.StderrTail, "fatal error: out of memory") {
		t.Fatalf("%+v crash %+v", o, o.Crash)
	}
	others(t, res, "cap-0038", "L2")
}

func TestParallelDeterministic(t *testing.T) {
	mk := func() []*Column {
		var cols []*Column
		for i, delays := range [][2]int{{30, 1}, {1, 25}, {15, 15}, {2, 40}} {
			cols = append(cols, stubColumn(t, fmt.Sprintf("stub%d@0.1.0", i), rules(
				map[string]any{"entry": "cap-0038/*", "delay_ms": delays[0]},
				map[string]any{"entry": "cap-0040/*", "level": "L1", "do": "reject", "code": "ordering", "delay_ms": delays[1]},
				map[string]any{"entry": "cap-0073/*", "level": "L0", "do": "exit", "exit_code": i + 1},
			)))
		}
		return cols
	}
	write := func(jobs int) []byte {
		cols := mk()
		res := run(t, Limits{}, jobs, cols...)
		dir := t.TempDir()
		h, err := Header(loadCorpus(t), loadPins(t), cols, "selftest", "curated")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := WriteOutputs(dir, res, h, nil); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, ReportFile))
		if err != nil {
			t.Fatal(err)
		}
		// Column paths differ per call (fresh config files); the report does not contain them.
		return data
	}
	serial, parallel := write(1), write(4)
	if !bytes.Equal(serial, parallel) {
		t.Fatalf("reports differ between --jobs 1 and --jobs 4:\n%s\n---\n%s", serial, parallel)
	}
	var ids []string
	if _, _, err := report.Read(bytes.NewReader(parallel), func(r *report.Row) error { ids = append(ids, r.RowID); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4*cellsPerColumn {
		t.Fatalf("%d rows", len(ids))
	}
	if ids[0] != "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:stub0@0.1.0:L0" ||
		ids[1] != "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:stub0@0.1.0:L1" ||
		ids[3] != "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:stub1@0.1.0:L0" {
		t.Errorf("order: %v", ids[:4])
	}
}

func TestIsolatedEntryGetsItsOwnProcess(t *testing.T) {
	c := loadCorpus(t)
	e := c.Entry("cap-0040/signed-payload-signer-added")
	saved := e.Conformance.KnownDivergences
	e.Conformance.KnownDivergences = append(append([]manifest.KnownDivergence(nil), saved...), manifest.KnownDivergence{Target: "xdrcheck-driver-stub", Versions: "*", Level: "L0", Outcome: "crash", Reference: "https://example.org/"})
	defer func() { e.Conformance.KnownDivergences = saved }()
	if !Isolated(e) {
		t.Fatal("an entry with a known crash must be isolated")
	}
	col := stubColumn(t, "stub@0.1.0", nil)
	res, err := Run(context.Background(), Options{Sets: &Sets{}, Columns: []*Column{col}, Corpus: c, Entries: threeEntries, Jobs: 1, Validator: validator(t)})
	if err != nil {
		t.Fatal(err)
	}
	procs := map[int]bool{}
	for _, o := range res.Observations {
		if o.Cell.Entry == e {
			if procs[o.Process] {
				t.Errorf("isolated cell %s shares process %d", o.Cell.RowID(), o.Process)
			}
			procs[o.Process] = true
		}
	}
	if got := res.Columns[0].Processes; got != 4 {
		t.Errorf("processes %d, want 1 batch + 3 isolated", got)
	}
}

// A driver that answers and then exits on its own is a driver bug, not the next cell's crash.
func TestExitBetweenRequests(t *testing.T) {
	col := stubColumn(t, "stub@0.1.0", rules(map[string]any{"entry": "cap-0040/*", "level": "L0", "exit_after": true}))
	res := run(t, Limits{}, 1, col)
	others(t, res, "-", "-")
	// Seen either before the next request or as a status-0 exit instead of its answer (then retried).
	if errs := res.InfraErrors(); len(errs) != 1 || !strings.Contains(errs[0], "process 1 exited") {
		t.Errorf("errors %v", errs)
	}
	if o := find(t, res, "cap-0040", "L1")[0]; o.Process != 2 {
		t.Errorf("the next cell ran on process %d", o.Process)
	}
}

func TestLevelNotDeclaredIsNA(t *testing.T) {
	res := run(t, Limits{}, 1, stubColumn(t, "stub@0.1.0", map[string]any{"levels": []string{"L0"}}))
	for _, o := range res.Observations {
		want := "ok"
		if o.Cell.Level != "L0" {
			want = "n_a"
		}
		if o.Outcome != want || (want == "n_a" && (o.Source != "orchestrator" || o.Request != nil || o.Reason != "level_not_supported")) {
			t.Errorf("%s: %+v", o.Cell.RowID(), o)
		}
	}
}

func TestPlanLevels(t *testing.T) {
	c := loadCorpus(t)
	cols := []*Column{{ID: "a@1"}, {ID: "b@1"}}
	cells := Plan(c, cols, threeEntries, map[string]bool{"L0": true, "L2": true, "L4": true})
	if len(cells) != 6*2*2 {
		t.Fatalf("%d cells", len(cells))
	}
	g, _ := CompileGlobs("cap-0038/*,cap-0073/*trustline")
	if n := len(Plan(c, cols, g, nil)); n != 5*2*3 {
		t.Errorf("glob plan has %d cells", n)
	}
	api := &manifest.Entry{ID: "x/api", Kind: "api"}
	neg := &manifest.Entry{ID: "x/neg", Kind: "xdr", Negative: true}
	if got := EntryLevels(api, nil); !reflect.DeepEqual(got, []string{"L4"}) {
		t.Errorf("api levels %v", got)
	}
	if got := EntryLevels(neg, nil); !reflect.DeepEqual(got, []string{"L0", "L1", "L3"}) {
		t.Errorf("negative xdr levels %v", got)
	}
}

func TestRealSets(t *testing.T) {
	s, err := LoadSets(filepath.Join(repoRoot, "drivers", "sets.toml"), repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPins(loadPins(t)); err != nil {
		t.Fatal(err)
	}
	ids := func(name string) []string {
		cols, err := s.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cols {
			out = append(out, c.ID)
		}
		return out
	}
	want := map[string][]string{
		"required":   {"go@v0.9.0", "js@17.4.0", "rust@30.0.0:limits-default", "rust@30.0.0:limits-none"},
		"acceptance": {"go@v0.9.0", "js@17.2.0", "js@17.2.1", "js@17.3.0", "js@17.4.0", "rust@30.0.0:limits-default", "rust@30.0.0:limits-none"},
		"pr": {"go@v0.7.1", "go@v0.7.2", "go@v0.7.3", "go@v0.8.0", "go@v0.9.0", "js@17.2.0", "js@17.2.1", "js@17.3.0", "js@17.4.0",
			"python@17.0.1", "rust@28.0.0:limits-default", "rust@28.0.0:limits-none", "rust@28.0.1:limits-default", "rust@28.0.1:limits-none",
			"rust@30.0.0:limits-default", "rust@30.0.0:limits-none"},
	}
	for name, w := range want {
		if got := ids(name); !reflect.DeepEqual(got, w) {
			t.Errorf("set %s:\n got %v\nwant %v", name, got, w)
		}
	}
	all := ids("all")
	public := ids("public")
	if !reflect.DeepEqual(all, public) {
		t.Errorf("all %v differs from public %v: every column of the repository is public", all, public)
	}
	for _, id := range []string{"js@16.3.0", "js@16.3.1", "js@16.4.1", "python@17.0.0", "core@30.0.0"} {
		if !contains(public, id) {
			t.Errorf("public lacks %s", id)
		}
	}
	if private := s.PrivateColumns(); len(private) != 0 {
		t.Errorf("the repository's own sets file has private columns %v", private)
	}
	pubCols, _ := s.Resolve("public")
	if err := s.CheckOverlay("public", pubCols, false); err != nil {
		t.Errorf("set public without the overlay: %v", err)
	}
	if contains(all, "stub@0.1.0") {
		t.Errorf("the stub is in an SDK set")
	}
	if g, err := s.Match("rust@30*"); err != nil || len(g) != 2 {
		t.Errorf("--columns rust@30*: %v %v", g, err)
	}
	if _, err := s.Select("", ""); err != nil {
		t.Errorf("default set: %v", err)
	}
	// A version that is not pinned is refused.
	s.Columns["js@17.4.0"].Version = "17.9.9"
	if err := s.CheckPins(loadPins(t)); err == nil || !strings.Contains(err.Error(), "17.9.9") {
		t.Errorf("unpinned version accepted: %v", err)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// An overlay's sets file adds columns (directories relative to the overlay, versions pinned by its own [pins]),
// new sets, and members of the repository's sets; a selection that includes one of its columns needs --overlay.
func TestOverlaySets(t *testing.T) {
	repo, ov := t.TempDir(), t.TempDir()
	col := func(id, sdk, ver, dir string) string {
		return fmt.Sprintf("[columns.%q]\nsdk=%q\nversion=%q\nkind=\"sdk\"\nrole=\"extra\"\necosystem=\"npm\"\npackage=\"p\"\ntarget=\"p\"\ndir=%q\nrun=[\"bin/x\"]\n", id, sdk, ver, dir)
	}
	pub := filepath.Join(repo, "sets.toml")
	os.WriteFile(pub, []byte("[sets]\npr = [\"js@1\"]\nall = [\"@pr\"]\n"+col("js@1", "js", "1", "drivers/js/1")), 0o644)
	os.MkdirAll(filepath.Join(ov, "drivers"), 0o755)
	write := func(body string) { os.WriteFile(OverlaySetsPath(ov), []byte(body), 0o644) }
	write("[pins]\nzz = [\"9\"]\n[sets]\nextra = [\"@all\", \"zz@9\"]\n[extend]\nall = [\"zz@9\"]\n" + col("zz@9", "zz", "9", "drivers/zz/9"))

	// Without an overlay the file is not read.
	s, err := LoadSetsWithOverlay(pub, repo, "")
	if err != nil || s.Columns["zz@9"] != nil || len(s.PrivateColumns()) != 0 {
		t.Fatalf("no overlay: %v %v", err, s.PrivateColumns())
	}
	s, err = LoadSetsWithOverlay(pub, repo, ov)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.PrivateColumns(); !reflect.DeepEqual(got, []string{"zz@9"}) {
		t.Errorf("private columns %v", got)
	}
	zz := s.Columns["zz@9"]
	if want := filepath.Join(ov, "drivers", "zz", "9"); s.AbsDir(zz) != want {
		t.Errorf("overlay column dir %s, want %s", s.AbsDir(zz), want)
	}
	if s.AbsDir(s.Columns["js@1"]) != filepath.Join(repo, "drivers", "js", "1") {
		t.Errorf("repository column dir %s", s.AbsDir(s.Columns["js@1"]))
	}
	for _, name := range []string{"all", "extra"} {
		cols, err := s.Resolve(name)
		if err != nil || len(cols) != 2 {
			t.Fatalf("set %s: %v %v", name, cols, err)
		}
		if err := s.CheckOverlay(name, cols, false); err == nil || !strings.Contains(err.Error(), "pass --overlay") {
			t.Errorf("set %s without --overlay: %v", name, err)
		}
		if err := s.CheckOverlay(name, cols, true); err != nil {
			t.Errorf("set %s with --overlay: %v", name, err)
		}
	}
	pr, _ := s.Resolve("pr")
	if err := s.CheckOverlay("pr", pr, false); err != nil {
		t.Errorf("set pr: %v", err)
	}
	// The overlay's [pins] pins its own columns only.
	p := &pins.Pins{}
	p.Conformance.Columns = map[string][]string{"js": {"1"}}
	if err := s.CheckPins(p); err != nil {
		t.Errorf("pins: %v", err)
	}
	s.Columns["js@1"].SDK, s.Columns["js@1"].Version = "zz", "9"
	if err := s.CheckPins(p); err == nil {
		t.Errorf("a repository column pinned only by the overlay was accepted")
	}

	for name, body := range map[string]string{
		"redefined column": col("js@1", "js", "1", "d"),
		"redefined set":    "[sets]\npr = []\n",
		"extend unknown":   "[extend]\nnope = [\"js@1\"]\n",
		"unknown key":      "bogus = 1\n",
	} {
		write(body)
		if _, err := LoadSetsWithOverlay(pub, repo, ov); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSetsFileErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":    "[sets]\nx = []\n[columns.\"a@1\"]\nsdk=\"a\"\nversion=\"1\"\nbogus=1\n",
		"id mismatch":    "[sets]\nx = [\"a@1\"]\n[columns.\"a@1\"]\nsdk=\"b\"\nversion=\"1\"\nkind=\"sdk\"\nrole=\"extra\"\necosystem=\"npm\"\npackage=\"p\"\ntarget=\"p\"\ndir=\"d\"\nrun=[\"r\"]\n",
		"unknown member": "[sets]\nx = [\"nope@1\"]\n",
		"cycle":          "[sets]\nx = [\"@y\"]\ny = [\"@x\"]\n",
	} {
		p := filepath.Join(t.TempDir(), "sets.toml")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := LoadSets(p, "."); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
