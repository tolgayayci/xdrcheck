package siblings

import (
	"context"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// Options are the inputs of Run besides the signature and the matrix.
type Options struct {
	Today     string   // YYYY-MM-DD
	Queries   []string // tracker search terms; default derived from each draft's title
	Confirm   []string // item URLs a person confirmed describe this defect
	Offline   bool     // the tracker is a Recorded one
	Templates Templates
	// PublicColumn says whether the public tree defines a column (drivers/sets.toml); nil treats every column
	// as public. A public draft gives no command for a column only the overlay's sets file adds.
	PublicColumn func(id string) bool
}

// Run analyses every sibling family, de-duplicates the affected ones against tr and builds the plan. It writes
// nothing; Apply does.
func Run(ctx context.Context, tr Tracker, store *findings.Store, sig *Signature, m *verdict.Matrix, manual []*Manual, o Options) (*Plan, error) {
	results, err := Analyse(sig, m, manual, store)
	if err != nil {
		return nil, err
	}
	group := Group(sig, results)
	decisions := map[string]*Decision{}
	for _, r := range results {
		if r.Status != Affected {
			continue
		}
		d, err := Dedup(ctx, tr, r, Title(store, sig, r, group), DedupOptions{Queries: o.Queries, Confirm: o.Confirm, Offline: o.Offline})
		if err != nil {
			return nil, err
		}
		decisions[r.Family.SDK] = d
	}
	return Build(store, sig, results, decisions, BuildOptions{Today: o.Today, Templates: o.Templates, Offline: o.Offline, PublicColumn: o.PublicColumn})
}

// RecordedFrom is the offline tracker: the upstream states the records, the matrix's known divergences and
// the confirmed URLs state. A record's state wins over a divergence status; a confirmed URL with no recorded
// state counts as open, because a person just confirmed it.
func RecordedFrom(store *findings.Store, m *verdict.Matrix, confirm []string) *Recorded {
	r := &Recorded{}
	for _, id := range store.IDs() {
		rec := store.Records[id].Record
		if u := rec.Upstream; u != nil && u.URL != "" {
			r.Add(u.URL, u.State)
		}
		if s := rec.UpstreamSearch; s != nil && s.Existing != "" {
			state := map[string]string{"existing-open": "open", "existing-closed": "fixed", "fix-merged-unreleased": "fix-merged-unreleased"}[s.Result]
			if state != "" {
				r.Add(s.Existing, state)
			}
		}
	}
	for _, c := range m.Cells {
		if k := c.KnownDivergence; k != nil && k.Status != "" {
			r.Add(k.Reference, k.Status)
		}
	}
	for _, u := range confirm {
		r.Add(u, "open")
	}
	return r
}
