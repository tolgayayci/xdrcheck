package xdrdef

import (
	"encoding/json"
	"strings"
	"testing"
)

const capsFixture = `schema = "xcc.caps/v1"

[[cap]]
file = "cap-0097.md"
title = "Flags"
status = "Draft"
reader_visible = false
reason = "Draft, not implemented"

[[cap]]
file = "cap-0098.md"
title = "LCM"
status = "Accepted"
protocol = 31
reader_visible = true
group = "cap-0098"
changed = "already described"
`

const armsFixture = `schema = "xcc.arms/v1"

[[arm]]
id = "LedgerCloseMeta::v1"
class = "in-ledger"
reason = "already classified"
`

const planFixture = "[\n {\n  \"id\": \"cap-0098/old\",\n  \"kind\": \"ledger\"\n }\n]\n"

func TestCandidates(t *testing.T) {
	r := fixtureDiff(t, "none", "all")
	in := CandidateInput{Diffs: []*Report{r}, NextProtocol: 31,
		CAPs:     map[string]CAPInfo{"CAP-0099": {Title: "Yellow", Status: "Draft", Protocol: "32"}},
		CapsToml: capsFixture, ArmsToml: armsFixture, PlanJSON: planFixture}
	out, err := Candidates(in)
	if err != nil {
		t.Fatal(err)
	}
	// CAP-0097 becomes reader-visible in place; CAP-0098 already is; CAP-0099 and CAP-0088 get new records.
	if !strings.Contains(out.CapsToml, "file = \"cap-0097.md\"\ntitle = \"Flags\"\nstatus = \"Draft\"\nreader_visible = true\ngroup = \"cap-0097\"\nchanged = \"CANDIDATE: `Account::flags`\"\n\n[[cap]]") {
		t.Errorf("cap-0097 not rewritten in place:\n%s", out.CapsToml)
	}
	if strings.Contains(out.CapsToml, "Draft, not implemented") || !strings.Contains(out.CapsToml, "changed = \"already described\"") {
		t.Errorf("caps.toml:\n%s", out.CapsToml)
	}
	if !strings.Contains(out.CapsToml, "file = \"cap-0099.md\"\ntitle = \"Yellow\"\nstatus = \"Draft\"\nprotocol = 32\nreader_visible = true\ngroup = \"cap-0099\"") {
		t.Errorf("no new cap-0099 record:\n%s", out.CapsToml)
	}
	if !strings.Contains(out.CapsToml, "file = \"cap-0088.md\"\ntitle = \"TODO\"") {
		t.Errorf("no new cap-0088 record:\n%s", out.CapsToml)
	}
	// Arms: every new arm once, the classified one left alone.
	if strings.Count(out.ArmsToml, "id = \"LedgerCloseMeta::v1\"") != 1 || !strings.Contains(out.ArmsToml, "id = \"Ext::v1\"\nclass = \"in-ledger\"\nreason = \"CANDIDATE") {
		t.Errorf("arms.toml:\n%s", out.ArmsToml)
	}
	// Plan rows: valid JSON, grouped by CAP, protocol from the CAP preamble.
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out.PlanJSON), &rows); err != nil {
		t.Fatalf("plan.json: %v\n%s", err, out.PlanJSON)
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r["id"].(string)] = r
	}
	if y := byID["cap-0099/body-yellow"]; y == nil || y["protocol_min"].(float64) != 32 || y["caps"].([]any)[0].(float64) != 99 {
		t.Errorf("cap-0099/body-yellow: %v", y)
	}
	if e := byID["cap-0088/ext-v1"]; e == nil || e["protocol_min"].(float64) != 31 {
		t.Errorf("cap-0088/ext-v1: %v", e)
	}
	if len(rows) != 1+7 {
		t.Errorf("%d plan rows, want the existing one and one per new arm (7)", len(rows))
	}
	// Running again on the output adds nothing.
	in.CapsToml, in.ArmsToml, in.PlanJSON = out.CapsToml, out.ArmsToml, out.PlanJSON
	again, err := Candidates(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Added) != 0 || again.CapsToml != out.CapsToml || again.ArmsToml != out.ArmsToml || again.PlanJSON != out.PlanJSON {
		t.Errorf("second run added %v", again.Added)
	}
}

// TestCandidatesUngatedArms files arms no gate explains under a protocol group and adds that group once.
func TestCandidatesUngatedArms(t *testing.T) {
	r := &Report{Schema: DiffSchema, Base: Side{Label: "a"}, Head: Side{Label: "lcm_v3"},
		NewArms: map[string][]ArmRef{"LedgerCloseMetaBatch": {{ID: "LedgerCloseMeta::v3", Class: "in-ledger"}, {ID: "XResult::X_MALFORMED", Class: "validation-only"}}}}
	out, err := Candidates(CandidateInput{Diffs: []*Report{r}, NextProtocol: 31, CapsToml: capsFixture, ArmsToml: armsFixture, PlanJSON: "[]\n"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.CapsToml, "[[group]]\ngroup = \"protocol-31\"") != 1 {
		t.Errorf("caps.toml:\n%s", out.CapsToml)
	}
	if !strings.Contains(out.ArmsToml, "id = \"XResult::X_MALFORMED\"\nclass = \"validation-only\"\nevidence = \"unverified\"") {
		t.Errorf("a validation-only candidate needs evidence = unverified:\n%s", out.ArmsToml)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out.PlanJSON), &rows); err != nil || len(rows) != 1 || rows[0]["id"] != "protocol-31/ledgerclosemeta-v3" {
		t.Errorf("plan rows (no row for a validation-only arm): %v %v", rows, err)
	}
}
