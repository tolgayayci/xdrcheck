// Package plan turns the corpus into replay units (replay-harness.md §3–§4): which ledgers are served
// together, on which passphrase, under which sequence numbers, and which entries each unit scores.
//
//   - Only `ledger` entries whose replay.indexer_scope is not `sdk-only` are planned.
//   - One pass per passphrase (network): every variant of an entry is planned in the pass of its network.
//   - single: one ledger at its real sequence, verbatim (the default). Entries sharing one ledger share a unit.
//   - chain: a whole local-core scenario run (chains/<id>.json), ledgers in order, verbatim. Used when the entry
//     says replay.unit "chain" or requires_prior_state, or when chain units are asked for. An entry with
//     requires_prior_state is never served outside its chain.
//   - stream: every planned ledger of the pass renumbered into one consecutive run starting at a base sequence
//     (default 1000). The bytes are transformed (lake.Renumber); the unit and its items say so, and stream results
//     are never acceptance evidence or findings.
//   - The adapter's envelope (describe.envelope) is applied from manifest facts only, never by decoding: with
//     enforcement sdk_limit, or --out-of-envelope skip, an out-of-envelope variant is not run and is reported
//     not_applicable (outside_declared_envelope); with indexer_gate it is run, to probe the gate.
//
// Units are ordered deterministically: pass by network, then unit kind (single, chain, stream), first served
// sequence, first entry ID.
package plan

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Unit kinds.
const (
	Single = "single"
	Chain  = "chain"
	Stream = "stream"
)

// Item statuses and not_applicable qualifiers.
const (
	StatusRun           = "run"
	StatusNotApplicable = "not_applicable"

	OutsideEnvelope  = "outside_declared_envelope" // the adapter's envelope excludes the variant
	UnitNotSupported = "unit_not_supported"        // the unit the variant needs is not one the adapter runs
	NoChain          = "no_chain"                  // requires_prior_state, but no chain index holds the ledger
)

// Envelope is an adapter's declared envelope, with the JSON names of describe.envelope
// (adapter-protocol.schema.json). A nil field is not limited. operation_types cannot be checked from the
// manifest and is not applied.
type Envelope struct {
	MinProtocol                 *int     `json:"min_protocol,omitempty"`
	MaxProtocol                 *int     `json:"max_protocol,omitempty"`
	MinProtocolWithTransactions *int     `json:"min_protocol_with_transactions,omitempty"`
	LedgerCloseMetaVersions     []int    `json:"ledger_close_meta_versions,omitempty"`
	TransactionMetaVersions     []int    `json:"transaction_meta_versions,omitempty"`
	OperationTypes              []string `json:"operation_types,omitempty"`
	Enforcement                 string   `json:"enforcement"` // indexer_gate, sdk_limit, none
	Basis                       string   `json:"basis,omitempty"`
}

// Options select and shape the plan.
type Options struct {
	Networks      []string  // passes to plan; nil means every network in the corpus
	Entries       []string  // entry ID globs (path.Match); nil means all
	Caps          []int     // entries touching any of these CAPs; nil means all
	Chain         string    // plan exactly this chain as one chain unit (xdrcheck serve --chain)
	Ledgers       [2]uint32 // when [1] > 0: only variants whose ledger_seq is in [0]..[1]; with Chain, the chain is cut to it
	Unit          string    // "" or "auto", single, chain, stream
	Units         []string  // units the adapter runs (describe.units); nil means all
	Envelope      *Envelope
	OutOfEnvelope string // "probe" (default) or "skip"; only matters for indexer_gate
	StreamBase    uint32 // first sequence of a stream unit; default 1000
	Repeat        int    // stream: how many times the pass's ledgers are repeated; default 1
}

// Plan is the result: passes of units, and one item per planned entry variant.
type Plan struct {
	Passes []*Pass
	Items  []Item
}

// Pass is every unit of one passphrase.
type Pass struct {
	Network    string
	Passphrase string
	Units      []*Unit
}

// Unit is what one replay session serves.
type Unit struct {
	ID          string // path-safe, unique in the plan, for example testnet-single-4437357-582e694b
	Kind        string
	Network     string
	Passphrase  string
	Chain       string // chain units
	Transformed bool   // stream units: the bytes are renumbered
	Ledgers     []Ledger
	Entries     []Scored // entries this unit scores, in order
}

// Scored is an entry variant scored by a unit, at the sequence it is served under.
type Scored struct {
	Entry       string
	Variant     string
	Seq         uint32 // as served
	OriginalSeq uint32
}

// Item is the planner's decision for one entry variant.
type Item struct {
	Entry     string
	Variant   string
	Network   string
	Protocol  int
	Status    string // run, not_applicable
	Qualifier string // for not_applicable
	Detail    string
	Unit      string // unit ID when run
	UnitKind  string
	Probe     bool // run although outside an indexer_gate envelope, to probe the gate
	// Transformed is true for stream items: never acceptance evidence, never a finding.
	Transformed bool
}

// First and Last return a unit's served range.
func (u *Unit) First() uint32 { return u.Ledgers[0].Seq }
func (u *Unit) Last() uint32  { return u.Ledgers[len(u.Ledgers)-1].Seq }

// candidate is one entry variant that passed selection.
type candidate struct {
	e   *manifest.Entry
	v   *manifest.Variant
	key string
}

// Build plans a corpus.
func Build(c *manifest.Corpus, o Options) (*Plan, error) {
	if o.StreamBase == 0 {
		o.StreamBase = 1000
	}
	if o.Repeat <= 0 {
		o.Repeat = 1
	}
	if o.Unit == "auto" {
		o.Unit = ""
	}
	switch o.Unit {
	case "", Single, Chain, Stream:
	default:
		return nil, fmt.Errorf("plan: unknown unit %q", o.Unit)
	}
	if o.Chain != "" && c.Chain(o.Chain) == nil {
		return nil, fmt.Errorf("plan: no chain %q in the corpus", o.Chain)
	}
	b := &builder{c: c, o: o, src: newSources(c), units: map[string]*Unit{}}

	byNetwork := map[string][]candidate{}
	for _, e := range c.Entries {
		if e.Kind != "ledger" || e.IndexerScope() == "sdk-only" || !b.selected(e) {
			continue
		}
		for _, v := range e.Variants {
			if len(o.Networks) > 0 && !contains(o.Networks, v.Network) {
				continue
			}
			if o.Chain != "" {
				if !c.InChain(v.Blob.SHA256, o.Chain) {
					continue
				}
			} else if o.Ledgers[1] > 0 && (uint32(v.LedgerSeq) < o.Ledgers[0] || uint32(v.LedgerSeq) > o.Ledgers[1]) {
				continue
			}
			byNetwork[v.Network] = append(byNetwork[v.Network], candidate{e, v, e.VariantKey(v)})
		}
	}
	networks := make([]string, 0, len(byNetwork))
	for n := range byNetwork {
		networks = append(networks, n)
	}
	sort.Strings(networks)

	p := &Plan{}
	for _, n := range networks {
		pass := &Pass{Network: n, Passphrase: byNetwork[n][0].v.Passphrase}
		var streamIn []candidate
		for _, cand := range byNetwork[n] {
			item, kind, chain := b.decide(cand)
			if item.Status != StatusRun {
				p.Items = append(p.Items, item)
				continue
			}
			switch kind {
			case Stream:
				streamIn = append(streamIn, cand)
				p.Items = append(p.Items, item) // the unit is filled in below
			case Chain:
				u, err := b.chainUnit(pass, chain)
				if err != nil {
					return nil, err
				}
				item.Unit, item.UnitKind = u.ID, Chain
				u.Entries = append(u.Entries, Scored{Entry: cand.e.ID, Variant: cand.key, Seq: uint32(cand.v.LedgerSeq), OriginalSeq: uint32(cand.v.LedgerSeq)})
				p.Items = append(p.Items, item)
			default:
				u, err := b.singleUnit(pass, cand)
				if err != nil {
					return nil, err
				}
				item.Unit, item.UnitKind = u.ID, Single
				u.Entries = append(u.Entries, Scored{Entry: cand.e.ID, Variant: cand.key, Seq: u.First(), OriginalSeq: u.First()})
				p.Items = append(p.Items, item)
			}
		}
		if len(streamIn) > 0 {
			u, err := b.streamUnit(pass, streamIn)
			if err != nil {
				return nil, err
			}
			for i := range p.Items {
				it := &p.Items[i]
				if it.Network == n && it.Status == StatusRun && it.UnitKind == Stream {
					it.Unit, it.Transformed = u.ID, true
				}
			}
		}
		sortUnits(pass.Units)
		if len(pass.Units) > 0 || len(byNetwork[n]) > 0 {
			p.Passes = append(p.Passes, pass)
		}
	}
	sort.SliceStable(p.Items, func(i, j int) bool {
		if p.Items[i].Entry != p.Items[j].Entry {
			return p.Items[i].Entry < p.Items[j].Entry
		}
		return p.Items[i].Variant < p.Items[j].Variant
	})
	return p, nil
}

type builder struct {
	c     *manifest.Corpus
	o     Options
	src   *sources
	units map[string]*Unit
}

func (b *builder) selected(e *manifest.Entry) bool {
	if len(b.o.Entries) > 0 {
		ok := false
		for _, g := range b.o.Entries {
			if m, _ := path.Match(g, e.ID); m || g == e.ID {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(b.o.Caps) > 0 {
		for _, want := range b.o.Caps {
			for _, have := range e.Caps {
				if want == have {
					return true
				}
			}
		}
		return false
	}
	return true
}

// decide picks the unit kind for a variant and applies the envelope.
func (b *builder) decide(cand candidate) (Item, string, *manifest.ChainIndex) {
	e, v := cand.e, cand.v
	it := Item{Entry: e.ID, Variant: cand.key, Network: v.Network, Protocol: v.Protocol, Status: StatusRun}
	na := func(q, detail string) (Item, string, *manifest.ChainIndex) {
		it.Status, it.Qualifier, it.Detail = StatusNotApplicable, q, detail
		return it, "", nil
	}
	needsChain := e.RequiresPriorState() || (e.Replay != nil && e.Replay.Unit == Chain)
	ch, _, inChain := b.c.ChainForBlob(v.Blob.SHA256)

	kind := Single
	switch {
	case b.o.Chain != "":
		kind = Chain
	case b.o.Unit == Stream:
		if e.RequiresPriorState() {
			return na(UnitNotSupported, "requires_prior_state: replayed only inside its chain, never in a stream")
		}
		kind = Stream
	case needsChain || b.o.Unit == Chain:
		if inChain {
			kind = Chain
		} else if e.RequiresPriorState() {
			return na(NoChain, "requires_prior_state, but no chain index holds this variant's ledger")
		}
	}
	if len(b.o.Units) > 0 && !contains(b.o.Units, kind) {
		return na(UnitNotSupported, fmt.Sprintf("needs a %s unit; the adapter runs %v", kind, b.o.Units))
	}

	if why := b.outside(v, e); why != "" {
		if kind == Chain && ch != nil {
			why = fmt.Sprintf("%s (chain %s)", why, ch.ID)
		}
		if b.o.Envelope.Enforcement == "indexer_gate" && b.o.OutOfEnvelope != "skip" {
			it.Probe, it.Detail = true, "outside the declared envelope, run to probe the indexer's gate: "+why
		} else {
			return na(OutsideEnvelope, why)
		}
	}
	if kind == Chain {
		if why := b.chainOutside(ch); why != "" {
			if b.o.Envelope.Enforcement == "indexer_gate" && b.o.OutOfEnvelope != "skip" {
				it.Probe, it.Detail = true, "chain outside the declared envelope, run to probe the indexer's gate: "+why
			} else {
				return na(OutsideEnvelope, why)
			}
		}
	}
	it.UnitKind = kind
	return it, kind, ch
}

// outside returns why the envelope excludes a variant, or "".
func (b *builder) outside(v *manifest.Variant, e *manifest.Entry) string {
	env := b.o.Envelope
	if env == nil || env.Enforcement == "none" {
		return ""
	}
	lo, hi := v.Protocol, v.Protocol
	if v.HeaderProtocol != nil {
		lo, hi = min(lo, *v.HeaderProtocol), max(hi, *v.HeaderProtocol)
	}
	if env.MaxProtocol != nil && hi > *env.MaxProtocol {
		return fmt.Sprintf("protocol %d is above max_protocol %d", hi, *env.MaxProtocol)
	}
	if env.MinProtocol != nil && lo < *env.MinProtocol {
		return fmt.Sprintf("protocol %d is below min_protocol %d", lo, *env.MinProtocol)
	}
	if env.MinProtocolWithTransactions != nil && lo < *env.MinProtocolWithTransactions {
		if e.Expect.Ledger == nil || e.Expect.Ledger.Transactions == nil || *e.Expect.Ledger.Transactions > 0 {
			return fmt.Sprintf("protocol %d with transactions is below min_protocol_with_transactions %d", lo, *env.MinProtocolWithTransactions)
		}
	}
	if v.Meta != nil {
		if m := v.Meta.LedgerCloseMetaVersion; m != nil && len(env.LedgerCloseMetaVersions) > 0 && !containsInt(env.LedgerCloseMetaVersions, *m) {
			return fmt.Sprintf("LedgerCloseMeta v%d is not in ledger_close_meta_versions %v", *m, env.LedgerCloseMetaVersions)
		}
		if m := v.Meta.TransactionMetaVersion; m != nil && len(env.TransactionMetaVersions) > 0 && !containsInt(env.TransactionMetaVersions, *m) {
			return fmt.Sprintf("TransactionMeta v%d is not in transaction_meta_versions %v", *m, env.TransactionMetaVersions)
		}
	}
	return ""
}

// chainOutside applies the envelope to every ledger of a chain: its protocol and each ledger's meta version.
func (b *builder) chainOutside(ch *manifest.ChainIndex) string {
	env := b.o.Envelope
	if env == nil || env.Enforcement == "none" || ch == nil {
		return ""
	}
	if env.MaxProtocol != nil && ch.Protocol > *env.MaxProtocol {
		return fmt.Sprintf("chain %s runs protocol %d, above max_protocol %d", ch.ID, ch.Protocol, *env.MaxProtocol)
	}
	if env.MinProtocol != nil && ch.Protocol < *env.MinProtocol {
		return fmt.Sprintf("chain %s runs protocol %d, below min_protocol %d", ch.ID, ch.Protocol, *env.MinProtocol)
	}
	if len(env.LedgerCloseMetaVersions) > 0 {
		for _, l := range ch.Ledgers {
			if l.LedgerCloseMetaVersion != nil && !containsInt(env.LedgerCloseMetaVersions, *l.LedgerCloseMetaVersion) {
				return fmt.Sprintf("chain %s ledger %d is LedgerCloseMeta v%d, not in %v", ch.ID, l.Seq, *l.LedgerCloseMetaVersion, env.LedgerCloseMetaVersions)
			}
		}
	}
	return ""
}

func (b *builder) singleUnit(pass *Pass, cand candidate) (*Unit, error) {
	v := cand.v
	id := fmt.Sprintf("%s-single-%d-%s", pass.Network, v.LedgerSeq, v.Blob.SHA256[:8])
	if u := b.units[id]; u != nil {
		return u, nil
	}
	if v.LedgerSeq <= 0 {
		return nil, fmt.Errorf("plan: %s %s: variant has no ledger_seq", cand.e.ID, cand.key)
	}
	led, err := b.src.variantLedger(v)
	if err != nil {
		return nil, fmt.Errorf("plan: %s %s: %w", cand.e.ID, cand.key, err)
	}
	u := &Unit{ID: id, Kind: Single, Network: pass.Network, Passphrase: pass.Passphrase, Ledgers: []Ledger{led}}
	b.units[id] = u
	pass.Units = append(pass.Units, u)
	return u, nil
}

func (b *builder) chainUnit(pass *Pass, ch *manifest.ChainIndex) (*Unit, error) {
	id := pass.Network + "-chain-" + strings.ReplaceAll(ch.ID, "/", "-")
	if u := b.units[id]; u != nil {
		return u, nil
	}
	if ch.Network != pass.Network {
		return nil, fmt.Errorf("plan: chain %s is on %s, not %s", ch.ID, ch.Network, pass.Network)
	}
	lo, hi := b.o.Ledgers[0], b.o.Ledgers[1]
	u := &Unit{ID: id, Kind: Chain, Network: pass.Network, Passphrase: ch.Passphrase, Chain: ch.ID}
	for _, l := range ch.Ledgers {
		if b.o.Chain == ch.ID && hi > 0 && (uint32(l.Seq) < lo || uint32(l.Seq) > hi) {
			continue
		}
		led, err := b.src.chainLedger(ch, l)
		if err != nil {
			return nil, fmt.Errorf("plan: chain %s ledger %d: %w", ch.ID, l.Seq, err)
		}
		u.Ledgers = append(u.Ledgers, led)
	}
	if len(u.Ledgers) == 0 {
		return nil, fmt.Errorf("plan: chain %s has no ledgers in %d..%d", ch.ID, lo, hi)
	}
	b.units[id] = u
	pass.Units = append(pass.Units, u)
	return u, nil
}

// streamUnit renumbers the pass's ledgers (one per distinct blob, in entry order), Repeat times.
func (b *builder) streamUnit(pass *Pass, cands []candidate) (*Unit, error) {
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].e.ID != cands[j].e.ID {
			return cands[i].e.ID < cands[j].e.ID
		}
		return cands[i].key < cands[j].key
	})
	u := &Unit{ID: pass.Network + "-stream", Kind: Stream, Network: pass.Network, Passphrase: pass.Passphrase, Transformed: true}
	seq := b.o.StreamBase
	for r := 0; r < b.o.Repeat; r++ {
		placed := map[string]uint32{}
		for _, cand := range cands {
			at, ok := placed[cand.v.Blob.SHA256]
			if !ok {
				led, err := b.src.variantLedger(cand.v)
				if err != nil {
					return nil, fmt.Errorf("plan: %s %s: %w", cand.e.ID, cand.key, err)
				}
				led.Original = nil // a stream never serves the lake's object: its bytes are renumbered
				led.Seq, at = seq, seq
				placed[cand.v.Blob.SHA256] = seq
				u.Ledgers = append(u.Ledgers, led)
				seq++
			}
			u.Entries = append(u.Entries, Scored{Entry: cand.e.ID, Variant: cand.key, Seq: at, OriginalSeq: uint32(cand.v.LedgerSeq)})
		}
	}
	pass.Units = append(pass.Units, u)
	return u, nil
}

var kindOrder = map[string]int{Single: 0, Chain: 1, Stream: 2}

func sortUnits(us []*Unit) {
	sort.SliceStable(us, func(i, j int) bool {
		a, b := us[i], us[j]
		if kindOrder[a.Kind] != kindOrder[b.Kind] {
			return kindOrder[a.Kind] < kindOrder[b.Kind]
		}
		if a.First() != b.First() {
			return a.First() < b.First()
		}
		return firstEntry(a) < firstEntry(b)
	})
	for _, u := range us {
		sort.SliceStable(u.Entries, func(i, j int) bool {
			if u.Entries[i].Seq != u.Entries[j].Seq {
				return u.Entries[i].Seq < u.Entries[j].Seq
			}
			return u.Entries[i].Entry < u.Entries[j].Entry
		})
	}
}

func firstEntry(u *Unit) string {
	if len(u.Entries) == 0 {
		return ""
	}
	return u.Entries[0].Entry
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

// LakeLedgers returns the unit's ledgers for lake.Write.
func (u *Unit) LakeLedgers() []lake.Ledger {
	out := make([]lake.Ledger, len(u.Ledgers))
	for i := range u.Ledgers {
		l := u.Ledgers[i]
		out[i] = lake.Ledger{Seq: l.Seq, Load: l.Load, Original: l.Original}
	}
	return out
}
