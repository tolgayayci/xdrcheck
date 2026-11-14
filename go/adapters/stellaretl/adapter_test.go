package stellaretl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// The test binary has three roles: the tests; the adapter (XDRCHECK_STELLARETL_MAIN=1); and, when started under the
// name fakeETL, a stand-in for stellar-etl. The stand-in reads every ledger of the range from the GCS emulator
// exactly where stellar-etl reads it (failing like stellar-etl when the object is missing) and then writes the
// fixture rows of testdata/out for the command. Tests that need the real tool are in real_test.go.
const fakeETL = "stellar-etl-fake"

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == fakeETL {
		os.Exit(fakeMain(os.Args[1:]))
	}
	if os.Getenv("XDRCHECK_STELLARETL_MAIN") == "1" {
		os.Exit(Main(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// A target that looks like a commit, so the adapter needs no clone to resolve it.
const fakeCommit = "2b24ec89ddce7fc0beb7795de982c93e6895eaf3"

func fakeMain(args []string) int {
	if len(args) == 0 {
		return 2
	}
	cmd := args[0]
	var start, end int64
	var out, dsPath, network = "", "", "pubnet"
	for i := 1; i < len(args); i++ {
		next := func() string { i++; return args[i] }
		switch args[i] {
		case "-s":
			start, _ = strconv.ParseInt(next(), 10, 64)
		case "-e":
			end, _ = strconv.ParseInt(next(), 10, 64)
		case "-o":
			out = next()
		case "--datastore-path":
			dsPath = next()
		case "--testnet":
			network = "testnet"
		}
	}
	host := os.Getenv("STORAGE_EMULATOR_HOST")
	bucket, prefix, _ := strings.Cut(dsPath, "/")
	for seq := start; seq <= end; seq++ {
		part := seq / 64000 * 64000
		key := fmt.Sprintf("%s/%s/%08X--%d-%d/%08X--%d.xdr.zst", prefix, network, uint32(0xFFFFFFFF-part), part, part+63999, uint32(0xFFFFFFFF-seq), seq)
		resp, err := http.Get("http://" + host + "/" + bucket + "/" + url.PathEscape(key))
		if err != nil {
			fmt.Fprintln(os.Stderr, "level=fatal msg=", err)
			return 1
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "level=fatal msg=\"unable to get ledger %d from backend: %s: file does not exist\"\n", seq, key)
			return 1
		}
	}
	_, file, _, _ := runtime.Caller(0)
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "testdata", "out", cmd, "*.txt"))
	for _, f := range files {
		in, err := os.Open(f)
		if err != nil {
			return 1
		}
		dst, err := os.Create(filepath.Join(out, fmt.Sprintf("%d-%d-%s", start, end, filepath.Base(f)[len("64558277-64558277-"):])))
		if err != nil {
			return 1
		}
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			var r struct {
				Seq    int64 `json:"ledger_sequence"`
				Ledger int64 `json:"sequence"`
			}
			json.Unmarshal(sc.Bytes(), &r)
			if s := max(r.Seq, r.Ledger); s >= start && s <= end {
				dst.Write(append(sc.Bytes(), '\n'))
			}
		}
		in.Close()
		dst.Close()
	}
	fmt.Fprintln(os.Stderr, `level=info msg="No cloud provider specified for upload. Skipping upload."`)
	return 0
}

// fakeBinary links the test binary under the stand-in's name.
func fakeBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), fakeETL)
	if err := os.Symlink(exe, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func adapterConfig(t *testing.T, extra ...string) adapter.Config {
	args := append([]string{os.Args[0], "--etl-binary", fakeBinary(t), "--cache-dir", t.TempDir(), "--offline"}, extra...)
	return adapter.Config{Argv: args, Env: append(os.Environ(), "XDRCHECK_STELLARETL_MAIN=1"), Name: "stellaretl-test", Stderr: testWriter{t}}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("adapter stderr: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

// lakeLayout writes a SEP-54 directory holding the captured lake object of pubnet ledger 64558277.
func lakeLayout(t *testing.T) string {
	t.Helper()
	obj := filepath.Join(testcorpus.Vendored(), "objects", "pubnet", "64558277", "FC26EB3A--64558277.xdr.zst")
	b, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "lake")
	part := filepath.Join(dir, "FC279FFF--64512000-64575999")
	if err := os.MkdirAll(part, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, "FC26EB3A--64558277.xdr.zst"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `{"networkPassphrase":"Public Global Stellar Network ; September 2015","version":"1.0","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}`
	if err := os.WriteFile(filepath.Join(dir, ".config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

var pubnet = adapter.Network{Name: "pubnet", Passphrase: "Public Global Stellar Network ; September 2015"}

func layoutInput(dir string) adapter.Input {
	return adapter.Input{Kind: "sep54-dir", Path: dir, Schema: &adapter.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}}
}

func TestSelftest(t *testing.T) {
	work := filepath.Join(t.TempDir(), "work")
	rep := adapter.Selftest(context.Background(), adapter.SelftestConfig{
		Adapter: adapterConfig(t), HarnessVersion: "test", TargetVersion: fakeCommit, Network: pubnet, Workdir: work,
		Probe: &adapter.SelftestProbe{Input: layoutInput(lakeLayout(t)), Range: adapter.Range{Start: fixtureLedger, End: fixtureLedger},
			Unit: "single", DeadlineMS: 60000},
	})
	for _, c := range rep.Checks {
		t.Logf("%-18s %s %s %s", c.Name, c.Status, c.Reason, c.Detail)
	}
	if f := rep.FirstFailure(); f != nil {
		t.Fatalf("selftest failed: %+v", *f)
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Errorf("teardown left %d entries in the work directory", len(entries))
	}
}

// startSession runs prepare and ingest on a fresh adapter and returns the client and the ingest result.
func startSession(t *testing.T, lake string, rng adapter.Range, extra ...string) (*adapter.Client, *adapter.IngestResult) {
	t.Helper()
	ctx := context.Background()
	c, err := adapter.Start(ctx, adapterConfig(t, extra...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: "test", ProtocolVersions: []string{adapter.Protocol}, TargetVersion: fakeCommit}); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(t.TempDir(), "s-1")
	if _, err := c.Prepare(ctx, adapter.PrepareParams{Session: "s-1", TargetVersion: fakeCommit, Network: pubnet, Workdir: work}); err != nil {
		t.Fatal(err)
	}
	ing, err := c.Ingest(ctx, adapter.IngestParams{Session: "s-1", Input: layoutInput(lake), Range: rng, Network: pubnet, Unit: "single", DeadlineMS: 60000})
	if err != nil {
		t.Fatal(err)
	}
	return c, ing
}

func TestIngestCompleted(t *testing.T) {
	ctx := context.Background()
	c, ing := startSession(t, lakeLayout(t), adapter.Range{Start: fixtureLedger, End: fixtureLedger})
	if ing.Status != adapter.StatusCompleted || ing.LastLedger == nil || *ing.LastLedger != fixtureLedger {
		t.Fatalf("ingest: %+v", ing)
	}
	obs, err := c.Observe(ctx, adapter.ObserveParams{Session: "s-1", Range: adapter.Range{Start: fixtureLedger, End: fixtureLedger}, Kinds: adapter.AllKinds})
	if err != nil {
		t.Fatal(err)
	}
	want := fixtureObservation(t)
	a, _ := json.Marshal(obs)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Errorf("observation through the protocol differs from the rows' mapping:\n%s\n%s", a, b)
	}
	if _, err := c.Teardown(ctx, adapter.TeardownParams{Session: "s-1"}); err != nil {
		t.Fatal(err)
	}
}

// A ledger the emulator does not hold makes stellar-etl exit 1 before writing anything: halted, nothing written.
func TestIngestHalted(t *testing.T) {
	ctx := context.Background()
	c, ing := startSession(t, lakeLayout(t), adapter.Range{Start: fixtureLedger + 1, End: fixtureLedger + 1})
	fl, _ := ing.Signals.FailingLedger.Get()
	rows, _ := ing.Signals.RowsForFailingLedger.Get()
	code, _ := ing.Signals.ExitCode.Get()
	if ing.Status != adapter.StatusHalted || fl != fixtureLedger+1 || rows != 0 || code != 1 || *ing.LastLedger != fixtureLedger {
		t.Fatalf("ingest: %+v", ing)
	}
	obs, err := c.Observe(ctx, adapter.ObserveParams{Session: "s-1", Range: adapter.Range{Start: fixtureLedger + 1, End: fixtureLedger + 1}, Kinds: adapter.AllKinds})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Ledgers) != 0 {
		t.Errorf("a halted ledger was seen: %+v", obs.Ledgers)
	}
}

// The halt oracle names the ledger an export fails on even when the export wrote no rows before it: over
// fixtureLedger..fixtureLedger+1 the stand-in fails on the second ledger before writing anything, which rows alone
// would place at the range start; the single-ledger probe places it on fixtureLedger+1.
func TestHaltOracleProbesTheFailingLedger(t *testing.T) {
	oracle := filepath.Join(t.TempDir(), "halt-oracle.ndjson")
	_, ing := startSession(t, lakeLayout(t), adapter.Range{Start: fixtureLedger, End: fixtureLedger + 1}, "--halt-oracle", oracle)
	if ing.Status != adapter.StatusHalted {
		t.Fatalf("ingest: %+v", ing)
	}
	b, err := os.ReadFile(oracle)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r HaltOracleRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		want, by := "ok", ""
		if r.Ledger == fixtureLedger+1 {
			want, by = "halted", "probe"
		}
		if r.Status != want || r.FailingBy != by {
			t.Errorf("%s ledger %d: %s by %q, want %s by %q", r.Export, r.Ledger, r.Status, r.FailingBy, want, by)
		}
		n++
	}
	if n != 2*len(exportCommands) {
		t.Errorf("%d rows, want %d", n, 2*len(exportCommands))
	}
}

func TestIngestRefusesUnknownPassphrase(t *testing.T) {
	ctx := context.Background()
	c, err := adapter.Start(ctx, adapterConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: "test", ProtocolVersions: []string{adapter.Protocol}}); err != nil {
		t.Fatal(err)
	}
	standalone := adapter.Network{Name: "core-test", Passphrase: "Standalone Network ; February 2017"}
	if _, err := c.Prepare(ctx, adapter.PrepareParams{Session: "s-1", TargetVersion: fakeCommit, Network: standalone, Workdir: filepath.Join(t.TempDir(), "s-1")}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Ingest(ctx, adapter.IngestParams{Session: "s-1", Input: layoutInput(lakeLayout(t)), Range: adapter.Range{Start: 2, End: 2}, Network: standalone, DeadlineMS: 10000})
	var ae *adapter.AdapterError
	if !errors.As(err, &ae) || ae.Code != "unsupported_input" {
		t.Fatalf("want unsupported_input, got %v", err)
	}
}

// Known divergences name commit ranges; prepare answers each against a clone's first-parent history.
func TestResolveRanges(t *testing.T) {
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=xdrcheck test", "GIT_AUTHOR_EMAIL=test@invalid", "GIT_COMMITTER_NAME=xdrcheck test",
			"GIT_COMMITTER_EMAIL=test@invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--quiet", "--initial-branch=master")
	tree := git("mktree")
	var commits []string // first-parent history, oldest first; built with plumbing, so no hooks run
	parent := ""
	for i := 0; i < 4; i++ {
		args := []string{"commit-tree", tree, "-m", fmt.Sprintf("c%d", i)}
		if parent != "" {
			args = append(args, "-p", parent)
		}
		parent = git(args...)
		commits = append(commits, parent)
	}
	git("update-ref", "refs/heads/master", parent)
	git("tag", "v1.0.0", commits[1])

	ctx := context.Background()
	c, err := adapter.Start(ctx, adapterConfig(t, "--repo", repo))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: "test", ProtocolVersions: []string{adapter.Protocol}}); err != nil {
		t.Fatal(err)
	}
	ranges := []string{
		commits[1] + ".." + commits[2], // contains commits[2]
		commits[1] + ".." + commits[1], // just commits[1]
		".." + commits[1],              // up to commits[1]
		commits[3] + ".." + commits[3], // after
		"v1.0.0..master",               // tag and branch names resolve too
	}
	pr, err := c.Prepare(ctx, adapter.PrepareParams{Session: "s-1", TargetVersion: commits[2], Network: pubnet, Workdir: filepath.Join(t.TempDir(), "s-1"), ResolveRanges: ranges})
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, false, false, false, true}
	if len(pr.Ranges) != len(ranges) {
		t.Fatalf("answers: %+v", pr.Ranges)
	}
	for i, a := range pr.Ranges {
		if a.Range != ranges[i] || a.Contains != want[i] {
			t.Errorf("range %s: contains %v, want %v", ranges[i], a.Contains, want[i])
		}
	}
}
