package conform_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// The sdk-regression assertions run against the repository's own entries and their known divergences, with each cell's
// driver answer as the JavaScript drivers report it on the pinned releases (the responses below are what the
// drivers return; the expectations are the entries'). They must all hold; removing any declared divergence a
// pre-fix row relies on from its entry, or reporting a different fact, must turn that row red.

const jsTarget = "@stellar/stellar-sdk"

func loadCorpus(t *testing.T) *manifest.Corpus {
	t.Helper()
	c, err := manifest.Load(filepath.Join("..", "..", "..", "corpus"), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsColumn(version string) *conform.Column {
	return &conform.Column{ID: "js@" + version, SDK: "js", Kind: "sdk", Ecosystem: "npm", Package: jsTarget, Target: jsTarget, Version: version, Role: "historical"}
}

// answer is a driver's response for one cell, as the JavaScript drivers report it on the pinned releases.
func answer(t *testing.T, e *manifest.Entry, v *manifest.Variant, column, level string) string {
	t.Helper()
	switch level {
	case "L0":
		return fmt.Sprintf(`{"outcome":"ok","actual":{"consumed_bytes":%d,"reencoded_sha256":%q}}`, v.Blob.Bytes, v.Blob.SHA256)
	case "L1":
		hashes, _ := v.Derived["tx_hashes"].([]any)
		if column == "js@17.2.0" {
			var kept []any
			for i, h := range hashes {
				if i != 2 {
					kept = append(kept, h)
				}
			}
			ob := map[string]any{"transactions": len(hashes), "envelopes_parsed": len(kept), "tx_hashes": kept,
				"envelopes_rejected": []any{map[string]any{"tx_index": 2, "tx_hash": hashes[2], "code": "ordering", "message": "Assets are not in lexicographic order"}}}
			return mustJSON(t, map[string]any{"outcome": "reject", "reason": map[string]any{"code": "ordering"}, "actual": map[string]any{"object": ob}})
		}
		l1, _ := v.Derived["l1"].(map[string]any)
		ob := map[string]any{"transactions": len(hashes), "envelopes_parsed": len(hashes), "operations": *v.Resolved.Ledger.Operations, "tx_hashes": hashes,
			"focus": map[string]any{"tx_hash": v.Derived["tx_hash"], "operation_types": []string{"change_trust"}, "derived": l1}}
		return mustJSON(t, map[string]any{"outcome": "ok", "actual": map[string]any{"object": ob}})
	case "L3":
		if column == "js@17.2.1" {
			return `{"outcome":"ok","actual":{"native":{"type":"Object","map_entries":1,"bytes_preserved":false}}}`
		}
		return `{"outcome":"reject","reason":{"code":"lossy_conversion_refused"}}`
	}
	// L4
	type res struct{ outcome, reason, value, xdr string }
	pre := map[string]bool{"js@17.2.0": true}
	if strings.Contains(e.ID, "offer-id") || strings.Contains(e.ID, "muxed-account-id") {
		pre = map[string]bool{"js@17.2.0": true, "js@17.2.1": true}
	}
	var r res
	switch e.ID {
	case "cap-0038/api-liquidity-pool-issuer-ordering.network-order":
		r = res{"reject", "ordering", "", ""}
		if !pre[column] {
			r = res{"ok", "", `"c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"`, ""}
		}
	case "cap-0038/api-liquidity-pool-issuer-ordering.reversed-order":
		r = res{"reject", "ordering", "", ""}
		if pre[column] {
			r = res{"ok", "", `"c1324f878b3d11af9f923abb7d692fc74e0a7bcfd9a4edefd564efe5fdae9fdb"`, ""}
		}
	case "cap-0046/api-scval-map-sort-order.u32-keys", "cap-0046/api-scval-map-sort-order.bytes-keys":
		var keys []string
		json.Unmarshal(e.API.ExpectValue, &keys)
		if pre[column] {
			keys[0], keys[1] = keys[1], keys[0]
		}
		x := e.API.ExpectXDRHex
		if pre[column] {
			x = "00" // a different encoding: the wrong order
		}
		r = res{"ok", "", mustJSON(t, keys), x}
	case "classic/api-offer-id-encoding.id-2-pow-53-plus-1-number":
		r = res{"reject", "value_out_of_range", "", ""}
		if pre[column] {
			r = res{"ok", "", `"9007199254740992"`, strings.TrimSuffix(e.API.ExpectXDRHex, "1") + "0"}
		}
	case "classic/api-offer-id-encoding.id-2-pow-53-plus-1-string":
		r = res{"ok", "", `"9007199254740993"`, e.API.ExpectXDRHex}
	case "cap-0027/api-muxed-account-id-encoding.id-hex-string":
		r = res{"reject", "value_out_of_range", "", ""}
		if pre[column] {
			r = res{"ok", "", `"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAACCRFU"`, "000001000000000000000010" + "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"}
		}
	case "classic/api-offer-id-encoding.id-negative":
		r = res{"reject", "value_out_of_range", "", ""}
		if pre[column] {
			r = res{"ok", "", `"-1"`, "00"}
		}
	default:
		t.Fatalf("no answer for %s", e.ID)
	}
	out := map[string]any{"outcome": r.outcome}
	if r.reason != "" {
		out["reason"] = map[string]any{"code": r.reason}
	}
	if r.outcome == "ok" {
		api := map[string]any{"value": json.RawMessage(r.value)}
		if r.xdr != "" {
			api["xdr_hex"], api["self_decode"] = r.xdr, "accepted"
		}
		out["actual"] = map[string]any{"api": api}
	}
	return mustJSON(t, out)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// observe builds and judges every cell the assertions need, from the given entries.
func observe(t *testing.T, entries map[string]*manifest.Entry) []*conform.Observation {
	t.Helper()
	res := &conform.Result{}
	for _, id := range conform.SDKRegressionEntries() {
		e := entries[id]
		if e == nil {
			t.Fatalf("the corpus has no entry %s", id)
		}
		variants := []*manifest.Variant{nil}
		if e.Kind != "api" {
			variants = nil
			for _, v := range e.Variants {
				if e.Kind == "xdr" || (v.Network == "testnet" && v.Protocol == 29) {
					variants = append(variants, v)
				}
			}
		}
		levels := conform.EntryLevels(e, nil)
		for _, v := range variants {
			for _, col := range conform.SDKRegressionColumns {
				for _, l := range levels {
					if l == "L2" {
						continue
					}
					cell := &conform.Cell{Entry: e, Variant: v, Level: l, Column: jsColumn(strings.TrimPrefix(col, "js@"))}
					if v != nil {
						cell.VariantKey = e.VariantKey(v)
					}
					var r conform.RunResponse
					if err := json.Unmarshal([]byte(answer(t, e, v, col, l)), &r); err != nil {
						t.Fatal(err)
					}
					res.Observations = append(res.Observations, &conform.Observation{Cell: cell, Response: &r, Outcome: r.OutcomeString(),
						Reason: r.ReasonCode(), Source: "driver"})
				}
			}
		}
	}
	res.Apply(verdict.Engine{})
	return res.Observations
}

func byID(c *manifest.Corpus) map[string]*manifest.Entry {
	m := map[string]*manifest.Entry{}
	for _, e := range c.Entries {
		m[e.ID] = e
	}
	return m
}

func TestSDKRegressionHolds(t *testing.T) {
	results := conform.AssertSDKRegression(observe(t, byID(loadCorpus(t))))
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.ID] = true
		if !r.Pass {
			t.Errorf("%s %s %s %s: %v (observed %s)", r.ID, r.Column, r.Entry, r.Level, r.Problems, r.Observed)
		}
	}
	for _, id := range strings.Fields("a1 a2 a3 a4 a5 a6 a7 b1 b2 b3 b4 b5 c1 c2 c3") {
		if !seen[id] {
			t.Errorf("assertion %s is missing", id)
		}
	}
}

// Removing the JavaScript divergence a pre-fix row relies on from its entry turns exactly that entry's
// pre-fix rows red.
func TestSDKRegressionFailsWithoutKnownDivergence(t *testing.T) {
	c := loadCorpus(t)
	for _, row := range conform.SDKRegressionRows() {
		if row.Want.Check != "known" {
			continue
		}
		t.Run(row.ID+" "+row.Columns[0], func(t *testing.T) {
			entries := byID(c)
			orig := entries[row.Entry]
			cut := *orig
			conf := *orig.Conformance
			conf.KnownDivergences = nil
			removed := 0
			for _, k := range orig.Conformance.KnownDivergences {
				ok, err := verdict.InRange(strings.TrimPrefix(row.Columns[0], "js@"), k.Versions)
				if err != nil {
					t.Fatal(err)
				}
				if k.Target == jsTarget && ok && (k.Level == "" || k.Level == row.Level) {
					removed++
					continue
				}
				conf.KnownDivergences = append(conf.KnownDivergences, k)
			}
			if removed == 0 {
				t.Fatalf("%s declares no divergence for %s at %s", row.Entry, row.Columns[0], row.Level)
			}
			cut.Conformance = &conf
			entries[row.Entry] = &cut
			for _, r := range conform.AssertSDKRegression(observe(t, entries)) {
				failing := r.Entry == row.Entry && r.Row.Want.Check == "known"
				if r.Pass == failing {
					t.Errorf("without the divergence: %s %s %s pass=%v %v", r.ID, r.Column, r.Entry, r.Pass, r.Problems)
				}
			}
		})
	}
}

// A different fact on a pre-fix row fails it even with the divergence declared: a1 is the ledger's focus
// transaction rejected among 18 parsed envelopes, not any rejection.
func TestSDKRegressionFactsMatter(t *testing.T) {
	obs := observe(t, byID(loadCorpus(t)))
	for _, o := range obs {
		if o.Cell.Entry.ID == "cap-0038/pool-issuers-order-by-bytes-not-strkey" && o.Cell.Column.ID == "js@17.2.0" && o.Cell.Level == "L1" {
			n := int64(17)
			o.Response.Actual.Object.EnvelopesParsed = &n
		}
	}
	for _, r := range conform.AssertSDKRegression(obs) {
		if r.ID == "a1" && r.Pass {
			t.Errorf("a1 passes with 17 envelopes parsed")
		}
	}
}
