package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/objstore"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/plan"
)

// The test binary doubles as the adapter (and, re-executed by it, as the indexer): with XDRCHECK_BASELINE_MAIN set it
// runs Main. The adapter passes XDRCHECK_ variables to the indexer, so the child dispatches the same way.
func TestMain(m *testing.M) {
	if os.Getenv("XDRCHECK_BASELINE_MAIN") == "1" {
		os.Exit(Main(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const (
	repo       = "../../.."
	corpusRoot = repo + "/corpus"
)

func adapterConfig(t *testing.T, extra ...string) adapter.Config {
	return adapter.Config{
		Argv:   append([]string{os.Args[0]}, extra...),
		Env:    append(os.Environ(), "XDRCHECK_BASELINE_MAIN=1"),
		Name:   "baseline-test",
		Stderr: testWriter{t},
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("adapter stderr: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

func loadPlan(t *testing.T, desc *adapter.DescribeResult) (*manifest.Corpus, *plan.Plan) {
	t.Helper()
	c, err := manifest.Load(corpusRoot, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var env plan.Envelope
	b, _ := json.Marshal(desc.Envelope)
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	p, err := plan.Build(c, plan.Options{Units: desc.Units, Envelope: &env})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func TestSelftest(t *testing.T) {
	d := Describe(indexer.DefaultGates)
	_, p := loadPlan(t, &d)
	var unit *plan.Unit
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			if len(u.Entries) > 0 && u.Entries[0].Entry == "cap-0040/signed-payload-signer-added" {
				unit = u
			}
		}
	}
	if unit == nil {
		t.Fatal("cap-0040 unit not planned")
	}
	dir := t.TempDir()
	if _, err := unit.WriteLayout(filepath.Join(dir, "lake")); err != nil {
		t.Fatal(err)
	}
	rep := adapter.Selftest(context.Background(), adapter.SelftestConfig{
		Adapter: adapterConfig(t), HarnessVersion: "test", TargetVersion: Version,
		Network: adapter.Network{Name: unit.Network, Passphrase: unit.Passphrase}, Workdir: filepath.Join(dir, "work"),
		Probe: &adapter.SelftestProbe{
			Input: adapter.Input{Kind: "sep54-dir", Path: filepath.Join(dir, "lake"), Schema: &adapter.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}},
			Range: adapter.Range{Start: int64(unit.First()), End: int64(unit.Last())}, Unit: unit.Kind, DeadlineMS: 60000,
		},
	})
	for _, c := range rep.Checks {
		t.Logf("%-18s %s %s %s", c.Name, c.Status, c.Reason, c.Detail)
	}
	if f := rep.FirstFailure(); f != nil {
		t.Fatalf("selftest failed: %+v", *f)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "work")); len(entries) != 0 {
		t.Errorf("teardown left %d entries in the work directory", len(entries))
	}
}

// served is one unit published on one input.
type served struct {
	input adapter.Input
	close func()
}

func TestEveryReplayableEntryMatches(t *testing.T) {
	ctx := context.Background()
	c, err := adapter.Start(ctx, adapterConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	desc, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: "test", ProtocolVersions: []string{adapter.Protocol}})
	if err != nil {
		t.Fatal(err)
	}
	corpus, p := loadPlan(t, desc)
	// A unit the planner puts outside the declared envelope (transactions below protocol 10, by the lower of the
	// variant's and the header's protocol) is run to probe the indexer's gate: the indexer either refuses it by a
	// declared gate, the one the planner named, and the entry is counted as refused, or ingests it, and its facts
	// must match.
	probes := map[string]string{} // unit ID -> the planner's reason
	for _, it := range p.Items {
		if it.Status != plan.StatusRun {
			t.Errorf("%s %s planned %s: %s", it.Entry, it.Variant, it.Status, it.Detail)
		}
		if it.Probe {
			probes[it.Unit] = it.Detail
		}
	}

	inputs := []string{"sep54-dir", "rpc"}
	var store *objstore.Store
	if pn, err := pins.Load(repo + "/pins.toml"); err == nil && objstore.Available(pn.Images["seaweedfs"]) == nil {
		store, err = objstore.Launch(ctx, objstore.Options{Image: pn.Images["seaweedfs"], Log: lake.NewDeliveryLog(nil)})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		inputs = append(inputs, "sep54-s3")
	} else {
		t.Log("object store not available here; sep54-s3 not exercised")
	}

	work := t.TempDir()
	entries := map[string]map[string]bool{} // input -> entry IDs matched
	refused := map[string]map[string]bool{} // input -> entry IDs of probe units refused by a gate
	session := 0
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			layout, err := u.WriteLayout(filepath.Join(work, "lake", u.ID))
			if err != nil {
				t.Fatal(err)
			}
			for _, in := range inputs {
				var srv served
				switch in {
				case "sep54-dir":
					srv = served{input: adapter.Input{Kind: in, Path: layout.Dir, Schema: &adapter.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}}, close: func() {}}
				case "sep54-s3":
					if err := store.Upload(ctx, u.ID, layout); err != nil {
						t.Fatal(err)
					}
					srv = served{input: adapter.Input{Kind: in, EndpointURL: store.Endpoint, BucketPath: store.Bucket + "/" + u.ID, Region: objstore.Region,
						AccessKeyID: objstore.AccessKey, SecretAccessKey: objstore.SecretKey,
						Schema: &adapter.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}}, close: func() {}}
				case "rpc":
					rs, err := u.RPCServer("test", lake.NewDeliveryLog(nil))
					if err != nil {
						t.Fatal(err)
					}
					hs, url, err := rs.Listen("127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					srv = served{input: adapter.Input{Kind: in, URL: url}, close: func() { hs.Close() }}
				}
				session++
				obs := runSession(t, c, u, srv.input, fmt.Sprintf("s-%04d", session), filepath.Join(work, "sessions", fmt.Sprintf("s-%04d", session)), probes[u.ID])
				srv.close()
				if obs == nil {
					if refused[in] == nil {
						refused[in] = map[string]bool{}
					}
					for _, sc := range u.Entries {
						refused[in][sc.Entry] = true
						t.Logf("%s on %s: refused by the gate the planner named: %s", sc.Entry, in, probes[u.ID])
					}
					continue
				}
				for _, sc := range u.Entries {
					e := corpus.Entry(sc.Entry)
					var v *manifest.Variant
					for _, x := range e.Variants {
						if x.Network == u.Network && e.VariantKey(x) == sc.Variant {
							v = x
						}
					}
					res, err := match.MatchVariant(v, &desc.Observations, obs)
					if err != nil {
						t.Fatal(err)
					}
					for _, prob := range problems(res) {
						t.Errorf("%s %s on %s: %s", sc.Entry, sc.Variant, in, prob)
					}
					if entries[in] == nil {
						entries[in] = map[string]bool{}
					}
					entries[in][sc.Entry] = true
				}
			}
		}
	}
	want := 0
	for _, e := range corpus.Entries {
		if e.Kind == "ledger" && e.IndexerScope() != "sdk-only" {
			want++
		}
	}
	for _, in := range inputs {
		if len(entries[in])+len(refused[in]) != want {
			t.Errorf("%s: %d entries matched and %d refused by a gate, want %d", in, len(entries[in]), len(refused[in]), want)
		}
		t.Logf("%s: %d replayable entries matched with no missing or wrong facts, %d outside the envelope refused by a gate", in, len(entries[in]), len(refused[in]))
	}
}

// runSession ingests and observes one unit. A probe unit (probe is the planner's reason it is outside the declared
// envelope) may instead be refused by the gate that reason names; runSession then returns nil.
func runSession(t *testing.T, c *adapter.Client, u *plan.Unit, in adapter.Input, id, workdir, probe string) *adapter.Observation {
	t.Helper()
	ctx := context.Background()
	net := adapter.Network{Name: u.Network, Passphrase: u.Passphrase}
	if _, err := c.Prepare(ctx, adapter.PrepareParams{Session: id, TargetVersion: Version, Network: net, Workdir: workdir}); err != nil {
		t.Fatal(err)
	}
	rng := adapter.Range{Start: int64(u.First()), End: int64(u.Last())}
	res, err := c.Ingest(ctx, adapter.IngestParams{Session: id, Input: in, Range: rng, Network: net, Unit: u.Kind, DeadlineMS: 120000})
	if err != nil {
		t.Fatal(err)
	}
	if probe != "" && res.Status == adapter.StatusRefused && res.Refusal != nil {
		if res.Refusal.Gate == "" || !strings.Contains(probe, res.Refusal.Gate) {
			t.Errorf("%s on %s: refused by gate %q, but the planner put it outside the envelope for another reason: %s", u.ID, in.Kind, res.Refusal.Gate, probe)
		}
		if _, err := c.Teardown(ctx, adapter.TeardownParams{Session: id}); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if res.Status != adapter.StatusCompleted {
		tail, _ := res.Signals.StderrTail.Get()
		t.Fatalf("%s on %s: ingest %s: %s", u.ID, in.Kind, res.Status, tail)
	}
	obs, err := c.Observe(ctx, adapter.ObserveParams{Session: id, Range: rng, Kinds: adapter.AllKinds})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Teardown(ctx, adapter.TeardownParams{Session: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workdir); err == nil {
		t.Errorf("teardown left %s behind", workdir)
	}
	return obs
}

func problems(r *match.Result) []string {
	var out []string
	if !r.LedgerObserved {
		out = append(out, "ledger not observed")
	}
	for _, f := range r.Facts {
		if f.Status == match.Missing || f.Status == match.Wrong {
			out = append(out, fmt.Sprintf("%s %s: %s %v", f.Status, f.Label, f.Reason, f.Diffs))
		}
	}
	for _, e := range r.Extras {
		if e.Status != match.Ignored {
			out = append(out, fmt.Sprintf("%s %s[%d]: %s", e.Status, e.Kind, e.Index, e.Reason))
		}
	}
	return out
}

func TestGateRefusal(t *testing.T) {
	// Built with a lower maximum protocol, the indexer refuses a Protocol 29 ledger through its declared gate.
	ctx := context.Background()
	c, err := adapter.Start(ctx, adapterConfig(t, "--max-protocol", "28"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	desc, err := c.Describe(ctx, adapter.DescribeParams{HarnessVersion: "test", ProtocolVersions: []string{adapter.Protocol}})
	if err != nil {
		t.Fatal(err)
	}
	if *desc.Envelope.MaxProtocol != 28 {
		t.Fatalf("envelope %+v", desc.Envelope)
	}
	d := Describe(indexer.DefaultGates)
	_, p := loadPlan(t, &d)
	var u *plan.Unit
	for _, pass := range p.Passes {
		for _, x := range pass.Units {
			if x.Entries[0].Entry == "cap-0038/pool-issuers-order-by-bytes-not-strkey" {
				u = x
			}
		}
	}
	layout, err := u.WriteLayout(filepath.Join(t.TempDir(), "lake"))
	if err != nil {
		t.Fatal(err)
	}
	net := adapter.Network{Name: u.Network, Passphrase: u.Passphrase}
	work := filepath.Join(t.TempDir(), "s")
	if _, err := c.Prepare(ctx, adapter.PrepareParams{Session: "s", TargetVersion: Version, Network: net, Workdir: work}); err != nil {
		t.Fatal(err)
	}
	rng := adapter.Range{Start: int64(u.First()), End: int64(u.Last())}
	res, err := c.Ingest(ctx, adapter.IngestParams{Session: "s", Input: adapter.Input{Kind: "sep54-dir", Path: layout.Dir,
		Schema: &adapter.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000}}, Range: rng, Network: net, DeadlineMS: 60000})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := res.Signals.RowsForFailingLedger.Get()
	if res.Status != adapter.StatusRefused || res.Refusal == nil || res.Refusal.Gate != "max_protocol" || string(res.Refusal.Observed) != "29" ||
		res.LastLedger != nil || rows != 0 {
		t.Fatalf("ingest %+v refusal %+v", res, res.Refusal)
	}
	obs, err := c.Observe(ctx, adapter.ObserveParams{Session: "s", Range: rng, Kinds: adapter.AllKinds})
	if err != nil || len(obs.Ledgers) != 0 {
		t.Fatalf("a refused ledger was stored: %v %+v", err, obs)
	}
}
