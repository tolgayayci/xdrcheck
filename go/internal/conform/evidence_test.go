package conform

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Each case is a schema-valid answer that carried too little evidence (or the wrong n_a) and used to be judged
// as a pass. CheckEvidence must turn it into a protocol error.

var sha = strings.Repeat("a", 64)

func evidenceCase(t *testing.T, req *RunRequest, d *Describe, cell *Cell, resp string) error {
	t.Helper()
	line := []byte(`{"xcc":"xcc.driver/1","id":1,"op":"run","entry":"` + req.Entry + `","level":"` + req.Level + `",` + resp + `}`)
	req.ID = 1
	r, err := validator(t).ParseRun(line, req)
	if err != nil {
		t.Fatalf("not schema-valid (%v): %s", err, line)
	}
	return CheckEvidence(cell, req, d, r, line)
}

func sdkCell(level string, v *manifest.Variant) *Cell {
	e := &manifest.Entry{ID: "x/entry", Kind: "ledger"}
	if v != nil {
		e.Variants = []*manifest.Variant{v}
	}
	return &Cell{Entry: e, Variant: v, Level: level, Column: &Column{ID: "js@17.4.0", SDK: "js", Kind: "sdk"}}
}

func coreCell(level string) *Cell {
	return &Cell{Entry: &manifest.Entry{ID: "x/entry", Kind: "xdr"}, Level: level, Column: &Column{ID: "core@30.0.0", SDK: "core", Kind: "core"}}
}

func TestEvidenceRules(t *testing.T) {
	declares := &Describe{APIOps: []string{"liquidity_pool.id", "muxed_account.encode", "transaction.parse", "strkey.encode", "strkey.decode"}}
	coreDescribe := &Describe{APIOps: []string{}}
	api := func(op string, args map[string]any) *RunRequest {
		return &RunRequest{Entry: "x/entry", Level: "L4", Input: Input{Kind: "api", APIOp: op, Args: args}}
	}
	xdrIn := func(level, typ string, focus *ReqFocus) *RunRequest {
		return &RunRequest{Entry: "x/entry", Level: level, Input: Input{Kind: "xdr", XDRType: typ, Path: "/x", Focus: focus}}
	}
	envelopeIn := func(passphrase string) *RunRequest {
		return &RunRequest{Entry: "x/entry", Level: "L1", Input: Input{Kind: "xdr", XDRType: "TransactionEnvelope", Path: "/x", Passphrase: passphrase}}
	}
	two := 2
	ledgerOK := `"outcome":"ok","actual":{"object":{"transactions":2,"envelopes_parsed":2,"operations":3,"tx_hashes":["` + sha + `","` + sha + `"]`
	variantL1 := &manifest.Variant{XDRType: "LedgerCloseMeta", Derived: map[string]any{"l1": map[string]any{"pool_id": "ab"}}}
	cases := []struct {
		name string
		req  *RunRequest
		cell *Cell
		resp string
		bad  string // "" when the answer is acceptable; else a fragment of the error
	}{
		// A declared op is never "not supported".
		{"declared op answers op_not_supported", api("liquidity_pool.id", map[string]any{"asset_x": "native"}), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"op_not_supported"}`, "declares api op"},
		{"undeclared op answers op_not_supported", api("scval.sort_map", nil), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"op_not_supported"}`, ""},
		{"value_not_representable without a native tag", api("muxed_account.encode", map[string]any{"account": "G", "id": "1"}), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"value_not_representable"}`, "no argument carries"},
		{"value_not_representable for a tagged value", api("muxed_account.encode", map[string]any{"account": "G", "id": map[string]any{"native": "number", "value": "18446744073709551616"}}), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"value_not_representable"}`, ""},
		{"argument_type_not_accepted without a native tag", api("muxed_account.encode", map[string]any{"account": "G", "id": "1"}), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"argument_type_not_accepted"}`, "no argument carries"},
		{"argument_type_not_accepted for a tagged kind", api("muxed_account.encode", map[string]any{"account": "G", "id": map[string]any{"native": "bigint", "value": "16"}}), sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"argument_type_not_accepted"}`, ""},
		{"strkey text answered op_not_supported", &RunRequest{Entry: "x/entry", Level: "L4", Input: Input{Kind: "strkey", Text: "G"}}, sdkCell("L4", nil),
			`"outcome":"n_a","reason":{"code":"op_not_supported"}`, "strkey text"},
		// L0 ok carries its evidence.
		{"L0 ok without evidence", xdrIn("L0", "ScVal", nil), sdkCell("L0", nil), `"outcome":"ok"`, "L0 ok needs"},
		{"L0 ok with only the hash", xdrIn("L0", "ScVal", nil), sdkCell("L0", nil), `"outcome":"ok","actual":{"reencoded_sha256":"` + sha + `"}`, "L0 ok needs"},
		{"L0 ok with evidence", xdrIn("L0", "ScVal", nil), sdkCell("L0", nil), `"outcome":"ok","actual":{"reencoded_sha256":"` + sha + `","consumed_bytes":4}`, ""},
		// The stellar-core column never re-encodes: the consumed byte count is its L0 evidence.
		{"core L0 ok with the consumed count only", xdrIn("L0", "ScVal", nil), coreCell("L0"), `"outcome":"ok","actual":{"consumed_bytes":4}`, ""},
		{"core L0 ok without the consumed count", xdrIn("L0", "ScVal", nil), coreCell("L0"), `"outcome":"ok","actual":{}`, "L0 ok needs actual.consumed_bytes"},
		{"core L2 n_a/other", xdrIn("L2", "ScVal", nil), coreCell("L2"), `"outcome":"n_a","reason":{"code":"other"}`, ""},
		// L1 on a ledger carries its object facts.
		{"L1 ledger ok without facts", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil), `"outcome":"ok","actual":{"object":{}}`, "needs object.transactions"},
		{"L1 ledger ok, parsed fewer than the transactions", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil),
			`"outcome":"ok","actual":{"object":{"transactions":3,"envelopes_parsed":2,"operations":3,"tx_hashes":["` + sha + `","` + sha + `"]}}`, "envelopes_parsed 2 of 3"},
		{"L1 ledger ok, a focus transaction but no focus facts", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{TxIndex: &two}), sdkCell("L1", nil), ledgerOK + `}}`, "needs object.focus"},
		{"L1 ledger ok, a path-only focus", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{Path: "/v1"}), sdkCell("L1", nil), ledgerOK + `}}`, ""},
		{"L1 ledger ok with focus", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{TxIndex: &two}), sdkCell("L1", nil),
			ledgerOK + `,"focus":{"tx_hash":"` + sha + `","operation_types":["payment"],"derived":{}}}}`, ""},
		{"L1 ledger ok, a stated derived key not reported", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{TxIndex: &two}), sdkCell("L1", variantL1),
			ledgerOK + `,"focus":{"tx_hash":"` + sha + `","operation_types":["payment"],"derived":{}}}}`, "lacks pool_id"},
		{"derived key outside the closed list", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{TxIndex: &two}), sdkCell("L1", nil),
			ledgerOK + `,"focus":{"tx_hash":"` + sha + `","operation_types":["payment"],"derived":{"liquidity_pool_id":"ab"}}}}`, "closed list"},
		{"camelCase operation type", xdrIn("L1", "LedgerCloseMeta", &ReqFocus{TxIndex: &two}), sdkCell("L1", nil),
			ledgerOK + `,"focus":{"tx_hash":"` + sha + `","operation_types":["changeTrust"],"derived":{}}}}`, "snake_case"},
		{"L1 ledger reject without facts", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil), `"outcome":"reject","reason":{"code":"ordering"}`, "needs object.transactions"},
		{"L1 ledger reject, rejected envelope without hash", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil),
			`"outcome":"reject","reason":{"code":"ordering"},"actual":{"object":{"transactions":2,"envelopes_parsed":1,"tx_hashes":["` + sha + `"],"envelopes_rejected":[{"tx_index":1,"code":"ordering"}]}}`, "needs tx_hash"},
		{"L1 ledger reject with facts", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil),
			`"outcome":"reject","reason":{"code":"ordering"},"actual":{"object":{"transactions":2,"envelopes_parsed":1,"tx_hashes":["` + sha + `"],"envelopes_rejected":[{"tx_index":1,"tx_hash":"` + sha + `","code":"ordering"}]}}`, ""},
		{"L1 ledger that did not decode", xdrIn("L1", "LedgerCloseMeta", nil), sdkCell("L1", nil), `"outcome":"reject","reason":{"code":"union_arm_undeclared"}`, ""},
		{"L1 envelope ok without hash", xdrIn("L1", "TransactionEnvelope", nil), sdkCell("L1", nil), `"outcome":"ok","actual":{"object":{"derived":{}}}`, "TransactionEnvelope needs"},
		{"L1 envelope ok without hash under a passphrase", envelopeIn("p"), sdkCell("L1", nil),
			`"outcome":"ok","actual":{"object":{"operation_types":["payment"],"operations":1,"reencoded_sha256":"` + sha + `","derived":{}}}`, "TransactionEnvelope needs"},
		{"L1 passphrase-independent envelope without hash", envelopeIn(""), sdkCell("L1", nil),
			`"outcome":"ok","actual":{"object":{"operation_types":["payment"],"operations":1,"reencoded_sha256":"` + sha + `","derived":{}}}`, ""},
		// L3 and L4.
		{"L3 ok without native facts", xdrIn("L3", "ScVal", nil), sdkCell("L3", nil), `"outcome":"ok","actual":{"native":{"map_entries":1}}`, "L3 ok needs"},
		{"L4 ok without a value", api("liquidity_pool.id", nil), sdkCell("L4", nil), `"outcome":"ok","actual":{"api":{}}`, "needs actual.api.value"},
		{"L4 xdr without self_decode", api("muxed_account.encode", nil), sdkCell("L4", nil), `"outcome":"ok","actual":{"api":{"value":"M","xdr_hex":"00"}}`, "self_decode"},
		{"L4 transaction.parse value as a string", api("transaction.parse", nil), sdkCell("L4", nil),
			`"outcome":"ok","actual":{"api":{"value":"` + sha + `","xdr_hex":"00","self_decode":"accepted"}}`, "tx_hash"},
		{"L4 transaction.parse well formed", api("transaction.parse", nil), sdkCell("L4", nil),
			`"outcome":"ok","actual":{"api":{"value":{"tx_hash":"` + sha + `","operations":1},"xdr_hex":"00","self_decode":"accepted"}}`, ""},
		// The orchestrator's stub wraps no SDK: it is held to the op rules only.
		{"selftest L0 ok without evidence", xdrIn("L0", "ScVal", nil), &Cell{Entry: &manifest.Entry{ID: "x/entry"}, Level: "L0", Column: &Column{Kind: "selftest"}}, `"outcome":"ok"`, ""},
	}
	for _, c := range cases {
		err := evidenceCase(t, c.req, declares, c.cell, c.resp)
		switch {
		case c.bad == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.bad != "" && (err == nil || !IsProtocolError(err) || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s: error %v, want a protocol error mentioning %q", c.name, err, c.bad)
		}
	}
	// A driver that does not declare strkey.decode (the stellar-core column) may answer a strkey text n_a.
	strkeyIn := func() *RunRequest {
		return &RunRequest{Entry: "x/entry", Level: "L4", Input: Input{Kind: "strkey", Text: "G"}}
	}
	if err := evidenceCase(t, strkeyIn(), coreDescribe, coreCell("L4"), `"outcome":"n_a","reason":{"code":"op_not_supported"}`); err != nil {
		t.Errorf("core strkey text n_a/op_not_supported: %v", err)
	}
}

// The rebuild fact (docs/conformance-protocol.md, "The rebuild fact"): required on every focus transaction and
// every envelope parsed under a passphrase when describe declares object_rebuild, refused when it does not, and
// shaped by its outcome.
func TestEvidenceRebuildFact(t *testing.T) {
	two := 2
	rebuilds := &Describe{ObjectRebuild: "TransactionBuilder.cloneFrom"}
	silent := &Describe{}
	ledger := &RunRequest{Entry: "x/entry", Level: "L1", Input: Input{Kind: "xdr", XDRType: "LedgerCloseMeta", Path: "/x", Passphrase: "p", Focus: &ReqFocus{TxIndex: &two}}}
	envelope := func(passphrase string) *RunRequest {
		return &RunRequest{Entry: "x/entry", Level: "L1", Input: Input{Kind: "xdr", XDRType: "TransactionEnvelope", Path: "/x", Passphrase: passphrase}}
	}
	focus := func(rebuild string) string {
		r := ""
		if rebuild != "" {
			r = `,"rebuild":` + rebuild
		}
		return `"outcome":"ok","actual":{"object":{"transactions":2,"envelopes_parsed":2,"operations":3,"tx_hashes":["` + sha + `","` + sha +
			`"],"focus":{"tx_hash":"` + sha + `","operation_types":["payment"],"derived":{}` + r + `}}}`
	}
	env := func(rebuild string) string {
		r := ""
		if rebuild != "" {
			r = `,"rebuild":` + rebuild
		}
		return `"outcome":"ok","actual":{"object":{"tx_hash":"` + sha + `","operation_types":["payment"],"operations":1,"reencoded_sha256":"` + sha + `","derived":{}` + r + `}}`
	}
	rebuilt := `{"entry_point":"TransactionBuilder.cloneFrom","outcome":"rebuilt","tx_hash":"` + sha + `"}`
	cases := []struct {
		name string
		req  *RunRequest
		d    *Describe
		resp string
		bad  string
	}{
		{"declared, focus without the fact", ledger, rebuilds, focus(""), "needs object.focus.rebuild"},
		{"declared, focus rebuilt", ledger, rebuilds, focus(rebuilt), ""},
		{"declared, focus not rebuilt with a listed reason", ledger, rebuilds, focus(`{"entry_point":"TransactionBuilder.cloneFrom","outcome":"not_rebuilt","reason":"fee_bump"}`), ""},
		{"declared, focus refused with a message", ledger, rebuilds, focus(`{"entry_point":"TransactionBuilder.cloneFrom","outcome":"refused","message":"no"}`), ""},
		{"declared, another entry point", ledger, rebuilds, focus(`{"entry_point":"txnbuild.NewTransaction","outcome":"rebuilt","tx_hash":"` + sha + `"}`), "describe declares"},
		{"not declared, fact reported", ledger, silent, focus(rebuilt), "declares no object_rebuild"},
		{"not declared, no fact", ledger, silent, focus(""), ""},
		{"declared, envelope under a passphrase without the fact", envelope("p"), rebuilds, env(""), "needs object.rebuild"},
		{"declared, envelope without a passphrase", envelope(""), rebuilds, env(""), ""},
		{"declared, envelope rebuilt", envelope("p"), rebuilds, env(rebuilt), ""},
	}
	for _, c := range cases {
		err := evidenceCase(t, c.req, c.d, sdkCell("L1", nil), c.resp)
		switch {
		case c.bad == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.bad != "" && (err == nil || !IsProtocolError(err) || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s: error %v, want a protocol error mentioning %q", c.name, err, c.bad)
		}
	}
	// The schema and the shape rules: a rebuilt fact without a hash, a not_rebuilt reason outside the closed list.
	for _, bad := range []string{
		`{"entry_point":"x","outcome":"rebuilt"}`,
		`{"entry_point":"x","outcome":"not_rebuilt","reason":"other"}`,
		`{"entry_point":"x","outcome":"refused"}`,
	} {
		line := []byte(`{"xcc":"xcc.driver/1","id":1,"op":"run","entry":"x/entry","level":"L1",` + focus(bad) + `}`)
		req := *ledger
		req.ID = 1
		if _, err := validator(t).ParseRun(line, &req); err == nil {
			t.Errorf("rebuild %s: accepted, want a schema or shape error", bad)
		}
	}
}

// Through the orchestrator: an SDK column whose driver answers L1 ok with no object facts is a protocol error,
// not a judged cell.
func TestMissingEvidenceIsProtocolError(t *testing.T) {
	col := stubColumn(t, "stub@0.1.0", nil)
	col.Kind = "sdk"
	var log strings.Builder
	res, err := Run(context.Background(), Options{
		Sets: &Sets{Root: repoRoot}, Columns: []*Column{col}, Corpus: loadCorpus(t), Entries: threeEntries, Jobs: 1,
		Levels: map[string]bool{"L0": true, "L1": true}, Validator: validator(t), Log: &log,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res.Observations {
		switch o.Cell.Level {
		case "L0":
			if o.ProtocolError != "" || o.Outcome != "ok" {
				t.Errorf("%s: %+v", o.Cell.RowID(), o)
			}
		case "L1":
			if o.ProtocolError == "" || o.Judged() {
				t.Errorf("%s: an L1 ok without facts was trusted: %+v", o.Cell.RowID(), o)
			}
		}
	}
	if len(res.InfraErrors()) == 0 {
		t.Error("no infrastructure error recorded")
	}
	b, _ := json.Marshal(res.InfraErrors())
	if !strings.Contains(string(b), "L1 ok needs actual.object") {
		t.Errorf("errors %s", b)
	}
}
