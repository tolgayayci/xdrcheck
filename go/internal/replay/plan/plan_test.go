package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

const corpusRoot = "../../../../corpus"

const (
	trust = "cap-0073/sac-trust-creates-trustline"
	pool  = "cap-0038/pool-issuers-order-by-bytes-not-strkey"
	sp    = "cap-0040/signed-payload-signer-added"
)

func load(t *testing.T) *manifest.Corpus {
	t.Helper()
	c, err := manifest.Load(testcorpus.Build(t, testcorpus.Original, testcorpus.Options{}), manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func build(t *testing.T, c *manifest.Corpus, o Options) *Plan {
	t.Helper()
	p, err := Build(c, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func items(p *Plan) map[string]Item {
	m := map[string]Item{}
	for _, it := range p.Items {
		m[it.Entry+" "+it.Variant] = it
	}
	return m
}

func intp(n int) *int { return &n }

func TestDefaultPlan(t *testing.T) {
	c := load(t)
	p := build(t, c, Options{})
	got := items(p)
	want := []string{pool + " testnet", sp + " testnet", trust + " pubnet@28", trust + " pubnet@30", trust + " testnet@28", trust + " testnet@30"}
	if len(got) != len(want) {
		t.Fatalf("items %v", got)
	}
	for _, k := range want {
		if it, ok := got[k]; !ok || it.Status != StatusRun || it.UnitKind != Single {
			t.Errorf("%s: %+v", k, it)
		}
	}
	if len(p.Passes) != 2 || p.Passes[0].Network != "pubnet" || p.Passes[1].Network != "testnet" {
		t.Fatalf("passes %+v", p.Passes)
	}
	var ids []string
	for _, u := range p.Passes[1].Units {
		ids = append(ids, fmt.Sprintf("%s %d-%d", u.ID, u.First(), u.Last()))
	}
	wantIDs := []string{"testnet-single-15-fe7ebd94 15-15", "testnet-single-28-86b9e4e5 28-28", "testnet-single-4437357-582e694b 4437357-4437357", "testnet-single-5521432-85eddc3b 5521432-5521432"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("testnet units %v", ids)
	}
	hist := p.Passes[1].Units[2]
	if hist.Ledgers[0].Original == nil || hist.Ledgers[0].Original.Key != "FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst" ||
		hist.Entries[0].Entry != sp || hist.Passphrase != "Test SDF Network ; September 2015" {
		t.Errorf("history unit %+v %+v", hist, hist.Ledgers[0].Original)
	}
	// Every ledger loads, checked against its blob.
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			raw, err := u.Ledgers[0].Load()
			if err != nil {
				t.Fatal(err)
			}
			if h, err := lake.Inspect(raw); err != nil || h.Seq != u.First() {
				t.Errorf("%s: %v %d", u.ID, err, h.Seq)
			}
		}
	}
	// Deterministic.
	if again := build(t, c, Options{}); !reflect.DeepEqual(summary(again), summary(p)) {
		t.Error("two builds differ")
	}
}

func summary(p *Plan) string {
	b, _ := json.Marshal(p.Items)
	s := string(b)
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			s += fmt.Sprintf("|%s %v %d", u.ID, u.Entries, len(u.Ledgers))
		}
	}
	return s
}

func TestProtocol29Envelope(t *testing.T) {
	c := load(t)
	p := build(t, c, Options{Envelope: &Envelope{Enforcement: "sdk_limit", MaxProtocol: intp(29), LedgerCloseMetaVersions: []int{0, 1, 2}}})
	got := items(p)
	for _, k := range []string{trust + " testnet@30", trust + " pubnet@30"} {
		if it := got[k]; it.Status != StatusNotApplicable || it.Qualifier != OutsideEnvelope || it.Unit != "" ||
			it.Detail != "protocol 30 is above max_protocol 29" {
			t.Errorf("%s: %+v", k, it)
		}
	}
	for _, k := range []string{trust + " testnet@28", trust + " pubnet@28", sp + " testnet", pool + " testnet"} {
		if it := got[k]; it.Status != StatusRun {
			t.Errorf("%s: %+v", k, it)
		}
	}
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			if u.First() == 28 {
				t.Errorf("the Protocol 30 ledger was planned: %s", u.ID)
			}
		}
	}

	// An indexer with its own gate is probed by default, and skipped on request.
	gate := &Envelope{Enforcement: "indexer_gate", MaxProtocol: intp(29)}
	if it := items(build(t, c, Options{Envelope: gate}))[trust+" testnet@30"]; it.Status != StatusRun || !it.Probe {
		t.Errorf("probe: %+v", it)
	}
	if it := items(build(t, c, Options{Envelope: gate, OutOfEnvelope: "skip"}))[trust+" testnet@30"]; it.Status != StatusNotApplicable {
		t.Errorf("skip: %+v", it)
	}
}

func TestStreamIsTransformed(t *testing.T) {
	c := load(t)
	p := build(t, c, Options{Unit: Stream, Networks: []string{"testnet"}, Repeat: 2})
	if len(p.Passes) != 1 || len(p.Passes[0].Units) != 1 {
		t.Fatalf("passes %+v", p.Passes)
	}
	u := p.Passes[0].Units[0]
	if u.Kind != Stream || !u.Transformed || u.First() != 1000 || u.Last() != 1007 || len(u.Entries) != 8 {
		t.Fatalf("stream unit %s %v %d-%d, %d entries", u.Kind, u.Transformed, u.First(), u.Last(), len(u.Entries))
	}
	for _, it := range p.Items {
		if it.Status != StatusRun || !it.Transformed || it.Unit != u.ID {
			t.Errorf("item %+v", it)
		}
	}
	for i, l := range u.Ledgers {
		if !l.Transformed() || l.Original != nil {
			t.Errorf("ledger %d not marked transformed", i)
		}
		raw, err := l.Load()
		if err != nil {
			t.Fatal(err)
		}
		h, err := lake.Inspect(raw)
		if err != nil || h.Seq != l.Seq {
			t.Fatalf("stream ledger %d: header seq %d, %v", l.Seq, h.Seq, err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) == l.BlobSHA256 {
			t.Errorf("stream ledger %d has the corpus bytes", l.Seq)
		}
	}
	// The stream is consecutive, so it publishes as one layout.
	if _, err := u.WriteLayout(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestChainUnits(t *testing.T) {
	c := load(t)
	p := build(t, c, Options{Unit: Chain})
	got := items(p)
	if it := got[trust+" testnet@28"]; it.UnitKind != Chain || it.Unit != "testnet-chain-sac-trust-p28-testnet" {
		t.Errorf("trust p28: %+v", it)
	}
	if it := got[sp+" testnet"]; it.UnitKind != Single {
		t.Errorf("a history ledger in no chain stays single: %+v", it)
	}
	var chain *Unit
	for _, u := range p.Passes[1].Units {
		if u.Kind == Chain {
			chain = u
		}
	}
	if chain == nil || len(chain.Ledgers) != 23 || chain.First() != 2 || chain.Last() != 24 || chain.Entries[0].Seq != 15 {
		t.Fatalf("chain unit %+v", chain)
	}
	l, err := chain.WriteLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Objects) != 23 {
		t.Errorf("%d objects", len(l.Objects))
	}

	// The upgrade ledger 2 is LedgerCloseMeta v0: an envelope without v0 excludes the whole chain.
	p = build(t, c, Options{Unit: Chain, Envelope: &Envelope{Enforcement: "sdk_limit", LedgerCloseMetaVersions: []int{1, 2}}})
	if it := items(p)[trust+" testnet@28"]; it.Status != StatusNotApplicable || it.Qualifier != OutsideEnvelope {
		t.Errorf("v0 chain: %+v", it)
	}
	// An adapter that cannot run chains.
	p = build(t, c, Options{Unit: Chain, Units: []string{Single}})
	if it := items(p)[trust+" testnet@28"]; it.Status != StatusNotApplicable || it.Qualifier != UnitNotSupported {
		t.Errorf("no chain support: %+v", it)
	}
	// xdrcheck serve --chain with a sub-range.
	p = build(t, c, Options{Chain: "sac-trust/p28-pubnet", Ledgers: [2]uint32{10, 16}})
	if len(p.Passes) != 1 || len(p.Passes[0].Units) != 1 || p.Passes[0].Units[0].First() != 10 || p.Passes[0].Units[0].Last() != 16 {
		t.Errorf("chain sub-range: %+v", p.Passes)
	}
}

func TestRequiresPriorState(t *testing.T) {
	c := load(t)
	yes := true
	c.Entry(trust).Replay.RequiresPriorState = &yes
	got := items(build(t, c, Options{}))
	if it := got[trust+" testnet@28"]; it.UnitKind != Chain {
		t.Errorf("p28 must be replayed inside its chain: %+v", it)
	}
	if it := got[trust+" testnet@30"]; it.Status != StatusNotApplicable || it.Qualifier != NoChain {
		t.Errorf("p30 has no chain: %+v", it)
	}
	if it := items(build(t, c, Options{Unit: Single}))[trust+" pubnet@28"]; it.UnitKind != Chain {
		t.Errorf("a forced single unit must not take it out of its chain: %+v", it)
	}
	if it := items(build(t, c, Options{Unit: Stream}))[trust+" pubnet@28"]; it.Status != StatusNotApplicable {
		t.Errorf("never in a stream: %+v", it)
	}
}

func TestFilters(t *testing.T) {
	c := load(t)
	if p := build(t, c, Options{Entries: []string{"cap-0040/*"}}); len(p.Items) != 1 || p.Items[0].Entry != sp {
		t.Errorf("glob: %+v", p.Items)
	}
	if p := build(t, c, Options{Caps: []int{38}}); len(p.Items) != 1 || p.Items[0].Entry != pool {
		t.Errorf("caps: %+v", p.Items)
	}
	if p := build(t, c, Options{Networks: []string{"pubnet"}}); len(p.Items) != 2 || len(p.Passes) != 1 {
		t.Errorf("network: %+v", p.Items)
	}
	if _, err := Build(c, Options{Unit: "mesh"}); err == nil {
		t.Error("unknown unit accepted")
	}
}
