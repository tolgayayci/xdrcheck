package bugs_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapters/baseline"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/bugs"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/classify"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/run"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// The test binary doubles as the baseline adapter and, re-executed by it, as the indexer.
func TestMain(m *testing.M) {
	if os.Getenv("XDRCHECK_BASELINE_MAIN") == "1" {
		os.Exit(baseline.Main(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestTableListsEveryBug(t *testing.T) {
	tab, err := bugs.LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range tab.Bugs {
		names = append(names, b.Bug)
		if len(b.Expect) == 0 {
			t.Errorf("%s: no expectations", b.Bug)
		}
		for _, it := range b.Expect {
			class, _, _ := strings.Cut(it.Result, "·")
			switch class {
			case classify.Pass, classify.Mishandled, classify.Dropped, classify.NotReached:
			default:
				t.Errorf("%s: result %q is not a class an indexer can be put in", b.Bug, it.Result)
			}
		}
	}
	if want := append(bugs.Names(), bugs.None); !slices.Equal(names, want) {
		t.Errorf("table.json lists %v; the registry is %v", names, want)
	}
	if b, err := bugs.Lookup("no-such-bug"); err == nil || b != nil {
		t.Error("an unknown bug name is accepted")
	}
	if b, err := bugs.Lookup(bugs.None); err != nil || b != nil {
		t.Error("none is not the baseline")
	}
}

func one(n int) *int { return &n }

func TestCheck(t *testing.T) {
	b := bugs.TableBug{Bug: "x", Expect: []bugs.Item{
		{Entry: "a/one", Result: "mishandled·halt", Note: "partial_write"},
		{Entry: "a/two", Result: "pass"},
		{Entry: "a/later", Result: "dropped·silent"},
	}}
	rows := []bugs.Row{
		{Entry: "a/one", Variant: "testnet", Result: "mishandled·halt", Notes: []string{"partial_write"}},
		{Entry: "a/two", Variant: "testnet@28", Result: "pass"},
		{Entry: "a/two", Variant: "testnet@30", Result: "pass"},
	}
	if v := b.Check(rows, []string{"a/later"}); v.Status != bugs.OK || len(v.Pending) != 1 {
		t.Errorf("all as documented, one pending: %+v", v)
	}
	bad := append(slices.Clone(rows[1:]), bugs.Row{Entry: "a/one", Result: "mishandled·halt"})
	if v := b.Check(bad, nil); v.Status != bugs.Fail || len(v.Problems) != 3 {
		t.Errorf("missing note, and a/later absent: %+v", v)
	}
	if v := b.Check(nil, []string{"a/one", "a/two", "a/later"}); v.Status != bugs.NotDemonstrated {
		t.Errorf("no entry in the corpus: %+v", v)
	}
	if v := b.Check(nil, nil); v.Status != bugs.Fail {
		t.Errorf("no rows at all: %+v", v)
	}

	hole := bugs.TableBug{Bug: "h", Expect: []bugs.Item{
		{Entry: "*", Result: "mishandled·crash", Max: 1, Hole: "known"},
		{Entry: "*", Result: "not_reached", Min: one(0)},
	}}
	if v := hole.Check([]bugs.Row{{Entry: "a/b", Result: "harness_fault"}}, nil); v.Status != bugs.KnownHole || len(v.Problems) != 0 {
		t.Errorf("a mismatch on a known hole: %+v", v)
	}
	ok := hole.Check([]bugs.Row{{Entry: "a/b", Result: "mishandled·crash"}, {Entry: "a/c", Result: "not_reached"}}, nil)
	if ok.Status != bugs.OK || len(ok.Notes) != 1 {
		t.Errorf("a closed hole is reported: %+v", ok)
	}
	if v := hole.Check([]bugs.Row{{Entry: "a/b", Result: "mishandled·crash"}, {Entry: "a/c", Result: "mishandled·crash"}}, nil); v.Status != bugs.KnownHole {
		t.Errorf("more than max: %+v", v)
	}
}

// TestSeededBugsOnFixtureCorpus replays, in process, every bug whose table entries the fixture corpus holds and
// checks it against the table: the same check `make harness-selftest` makes through the command line over the
// whole table.
func TestSeededBugsOnFixtureCorpus(t *testing.T) {
	root := testcorpus.Build(t, testcorpus.Original, testcorpus.Options{})
	c, err := manifest.Load(root, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	have := func(id string) bool { return c.Entry(id) != nil }
	tab, err := bugs.LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, b := range tab.Bugs {
		if b.Bug == "memory-hog" || b.Bug == "loop-forever" || slices.Contains(b.Entries, "*") {
			continue // a stream under a memory cap and a deadline-long hang: make harness-selftest runs them
		}
		entries, pending := b.Plan(have)
		if len(entries) == 0 {
			continue
		}
		t.Run(b.Bug, func(t *testing.T) {
			work := t.TempDir()
			path := filepath.Join(work, "report.json")
			w, err := report.Create(path, report.Header{Tool: report.Tool{Name: "xcc replay", Version: "test"},
				Corpus: report.CorpusRef{Version: "test", ManifestSHA256: strings.Repeat("0", 64), Schema: manifest.EntrySchema, Tier: "curated"},
				Pins:   report.PinsRef{FileSHA256: strings.Repeat("0", 64), Values: map[string]string{}}, Mode: report.Mode{Suite: "replay"}})
			if err != nil {
				t.Fatal(err)
			}
			res, err := run.Run(context.Background(), run.Options{
				Corpus:         c,
				Adapter:        adapter.Config{Argv: []string{os.Args[0], "--bug", b.Bug}, Env: append(os.Environ(), "XDRCHECK_BASELINE_MAIN=1")},
				HarnessVersion: "test", TargetVersion: tab.TargetVersion, Entries: entries, Input: "sep54-dir", KeepGoing: true,
				WorkDir: filepath.Join(work, "run"), Report: w,
			})
			if cerr := w.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Target.Name != "xdrcheck/"+b.Bug || res.Target.Kind != "selftest" {
				t.Errorf("target %+v, want xdrcheck/%s as a selftest target", res.Target, b.Bug)
			}
			rows, err := bugs.ReadRows(path)
			if err != nil {
				t.Fatal(err)
			}
			v := b.Check(rows, pending)
			t.Logf("%s: %s %v", b.Bug, v.Status, v.Results)
			if v.Status == bugs.Fail || (v.Status == bugs.NotDemonstrated && len(rows) > 0) {
				t.Errorf("%s: %s: %v %v", b.Bug, v.Status, v.Problems, v.Holes)
			}
		})
		ran++
	}
	if ran == 0 {
		t.Fatal("no seeded bug has an entry in the fixture corpus")
	}
}

// TestCreditFromForgedEvent shows the forged-event bug landing in mishandled·wrong_value without the corpus
// entry built for it: a real Stellar Asset Contract transfer event is re-attributed to an unrelated contract
// (only the emitter changes; the transaction hash covers the envelope, not the meta), and the expectation is the
// forged-event entry's own: no movement of the classic asset (count 0).
func TestCreditFromForgedEvent(t *testing.T) {
	const id = "cap-0067/sac-transfer-to-muxed-account"
	root := testcorpus.Build(t, []string{id}, testcorpus.Options{})
	c, err := manifest.Load(root, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v := c.Entry(id).Variants[0]
	raw, err := os.ReadFile(filepath.Join(root, v.Blob.Path))
	if err != nil {
		t.Fatal(err)
	}
	// The classic-asset transfer the entry expects in its focus transaction: its asset and amount.
	asset, amount := "", ""
	for _, mv := range v.Resolved.Movements {
		if mv.Kind == "transfer" && mv.Asset != "native" {
			asset, amount = mv.Asset, mv.Amount
		}
	}
	if asset == "" {
		t.Fatal("no classic-asset transfer expected in " + id)
	}
	forge := func() xdr.LedgerCloseMeta {
		var lcm xdr.LedgerCloseMeta
		if err := lcm.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		forged := xdr.ContractId(sha256.Sum256([]byte("an unrelated contract")))
		n := 0
		for i := range lcm.V2.TxProcessing {
			m := lcm.V2.TxProcessing[i].TxApplyProcessing
			if m.V != 4 || lcm.V2.TxProcessing[i].Result.TransactionHash.HexString() != v.Focus.TxHash {
				continue
			}
			for j := range m.V4.Operations {
				for k := range m.V4.Operations[j].Events {
					e := &m.V4.Operations[j].Events[k]
					if e.Body.V0 == nil || len(e.Body.V0.Topics) != 4 {
						continue
					}
					top := e.Body.V0.Topics
					if top[0].Sym == nil || *top[0].Sym != "transfer" || top[3].Str == nil || string(*top[3].Str) == "native" {
						continue
					}
					if string(*top[3].Str) == asset {
						e.ContractId = &forged
						n++
					}
				}
			}
		}
		if n == 0 {
			t.Fatal("no transfer event of " + asset + " to forge in " + id)
		}
		return lcm
	}
	lcm := forge()
	expect := &manifest.Expect{Movements: []manifest.Movement{{Kind: "transfer", Asset: asset, Amount: amount, Count: one(0)}}}
	d := baseline.Describe(indexer.DefaultGates)

	outcome := func(doc *indexer.Doc) classify.Outcome {
		seq := doc.LedgerSeq
		obs := &adapter.Observation{Schema: adapter.ObservationSchema, Range: adapter.Range{Start: seq, End: seq}, Ledgers: []adapter.Ledger{doc.Facts}}
		for _, k := range adapter.AllKinds {
			*obs.Kinds.Kind(k) = adapter.KindStatus{Status: "provided"}
		}
		m, err := match.Match(match.Input{Expect: expect, LedgerSeq: seq, FocusTxHash: v.Focus.TxHash, Passphrase: v.Passphrase,
			Declared: &d.Observations, Observation: obs})
		if err != nil {
			t.Fatal(err)
		}
		ing := &adapter.IngestResult{Status: adapter.StatusCompleted, LastLedger: &seq, Signals: adapter.Signals{CursorAfter: &seq}}
		return classify.Classify(classify.Input{Seq: uint32(seq), UnitFirst: uint32(seq), UnitLast: uint32(seq), Expect: expect,
			Envelope: &d.Envelope, Ingest: ing, Delivery: classify.DeliveryNone, Observed: obs, Match: m})
	}

	doc, err := indexer.Derive(lcm, v.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, mv := range doc.Facts.Movements {
		if mv.Asset == asset && mv.Kind == "transfer" {
			t.Fatalf("the baseline credited %s from a forged event: %+v", asset, mv)
		}
	}
	if o := outcome(doc); o.Class == classify.Mishandled {
		t.Errorf("baseline on the forged ledger: %s", o)
	}

	bug, _ := bugs.Lookup("credit-from-forged-event")
	lcm = forge()
	doc, err = indexer.Derive(lcm, v.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	bug.Seed().Ledger(lcm, doc, v.Passphrase)
	if o := outcome(doc); o.String() != "mishandled·wrong_value" {
		t.Errorf("credit-from-forged-event: %s, want mishandled·wrong_value (%v)", o, o.Notes)
	}
}
