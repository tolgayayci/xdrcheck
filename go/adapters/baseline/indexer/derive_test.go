package indexer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
)

const corpusRoot = "../../../../corpus"

// observationOf turns a stored document into the observation set the adapter would return, through JSON, the
// way it travels.
func observationOf(t *testing.T, doc *Doc) *adapter.Observation {
	t.Helper()
	provided := adapter.KindStatus{Status: "provided"}
	obs := adapter.Observation{Schema: adapter.ObservationSchema, Range: adapter.Range{Start: doc.LedgerSeq, End: doc.LedgerSeq},
		Kinds: adapter.KindsSet{Receipts: provided, Transactions: provided, Participants: provided, StateChanges: provided,
			Movements: provided, Addresses: provided},
		Ledgers: []adapter.Ledger{doc.Facts}}
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if errs := adapter.ValidateObservation(raw); len(errs) > 0 {
		t.Fatalf("observation does not validate: %v", errs)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var back adapter.Observation
	if err := dec.Decode(&back); err != nil {
		t.Fatal(err)
	}
	return &back
}

// Report lists a match result's problems.
func problems(r *match.Result) []string {
	var out []string
	for _, f := range r.Facts {
		if f.Status == match.Missing || f.Status == match.Wrong {
			out = append(out, fmt.Sprintf("%s %s: %s %s %v", f.Status, f.Label, f.Reason, f.TxHash, f.Diffs))
		}
	}
	for _, e := range r.Extras {
		if e.Status != match.Ignored {
			out = append(out, fmt.Sprintf("%s %s[%d]: %s", e.Status, e.Kind, e.Index, e.Reason))
		}
	}
	return out
}

func TestDeriveMatchesEveryLedgerEntry(t *testing.T) {
	c, err := manifest.Load(corpusRoot, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range c.Entries {
		if e.Kind != "ledger" || e.IndexerScope() == "sdk-only" {
			continue
		}
		for _, v := range e.Variants {
			name := e.ID + " " + e.VariantKey(v)
			t.Run(name, func(t *testing.T) {
				raw, err := os.ReadFile(c.BlobPath(v))
				if err != nil {
					t.Fatal(err)
				}
				var lcm xdr.LedgerCloseMeta
				if err := lcm.UnmarshalBinary(raw); err != nil {
					t.Fatal(err)
				}
				doc, err := Derive(lcm, v.Passphrase)
				if err != nil {
					t.Fatal(err)
				}
				res, err := match.MatchVariant(v, nil, observationOf(t, doc))
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range problems(res) {
					t.Error(p)
				}
				s := res.Summary()
				t.Logf("%d matched, %d not applicable", s.Matched, s.NotApplicable)
			})
			n++
		}
	}
	if n == 0 {
		t.Fatal("no ledger entries")
	}
}
