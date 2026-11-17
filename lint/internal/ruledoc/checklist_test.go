package ruledoc

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// TestChecklistSharesTheLintersTable: the table in the committed checklist
// page is byte-identical to the generated table, and so is the field
// summary. (TestPagesUpToDate already holds both files to a fresh build.)
func TestChecklistSharesTheLintersTable(t *testing.T) {
	root := lintRoot(t)
	page, err := os.ReadFile(filepath.Join(root, ChecklistPage))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ begin, file string }{{beginTable, ChecklistTable}, {beginSummary, FieldSummary}} {
		want, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := Embedded(page, c.begin)
		if !ok {
			t.Fatalf("%s: no block %s … %s", ChecklistPage, c.begin, endGenerated)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("the block %s in %s differs from %s", c.begin, ChecklistPage, c.file)
		}
	}
}

// TestEveryRuleHasOneItem: every registered rule other than the hygiene
// family names an item of the checklist, no two rules name the same item,
// and the page lists every item with its rule or as manual.
func TestEveryRuleHasOneItem(t *testing.T) {
	pages, err := Build(lintRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	table := string(pages[ChecklistTable])
	seen := map[string]string{}
	for _, r := range framework.Default.Rules() {
		if r.Family == framework.FamilyHygiene {
			continue
		}
		if other, dup := seen[r.Checklist]; dup {
			t.Errorf("%s and %s both name %s", r.ID, other, r.Checklist)
		}
		seen[r.Checklist] = r.ID
		if !strings.Contains(table, "| ["+r.Checklist+"](#"+strings.ToLower(r.Checklist)+") |") ||
			!strings.Contains(table, " | "+r.ID+" | ") {
			t.Errorf("%s: no row for %s naming the rule", r.ID, r.Checklist)
		}
	}
	manual := 0
	for _, it := range checklistItems {
		if it.Manual != nil {
			manual++
		}
	}
	if rows := strings.Count(table, "\n| [HC-"); rows != len(checklistItems) {
		t.Errorf("table has %d item rows, want %d", rows, len(checklistItems))
	}
	if got := strings.Count(table, " | manual | "); got != manual {
		t.Errorf("table marks %d items manual, want %d", got, manual)
	}
}

// TestChecklistSourcesMustAgree: each way the item table and the registry
// can disagree stops the build.
func TestChecklistSourcesMustAgree(t *testing.T) {
	anchors := map[string]string{"caps": "Caps", "keep-raw-xdr": "Keep the raw XDR"}
	entries := map[string]bool{"a/b": true, "a/c": true, "a/c\x00m": true}
	rule := framework.Rule{ID: "XDR201", Family: framework.FamilyCaps, Guide: "caps", Corpus: "a/b", Checklist: "HC-201"}
	linterItem := item{ID: "HC-201", Check: "bounded"}
	manualItem := item{ID: "HC-501", Check: "raw XDR kept", Manual: &manual{Why: "design", How: "look"}, Guide: []string{"keep-raw-xdr"}, NoEntry: "none: a design property"}

	if _, err := joinChecklist([]item{linterItem, manualItem}, []framework.Rule{rule}, anchors, entries); err != nil {
		t.Fatalf("consistent sources: %v", err)
	}
	withMember := linterItem
	withMember.Corpus = []string{"a/c.m"}
	if _, err := joinChecklist([]item{withMember}, []framework.Rule{rule}, anchors, entries); err != nil {
		t.Errorf("a row and one of its members is canonical: %v", err)
	}

	cases := []struct {
		name  string
		items []item
		rules []framework.Rule
		want  string
	}{
		{"rule names a missing item", []item{manualItem}, []framework.Rule{rule}, "names checklist item HC-201, which does not exist"},
		{"rule names no item", []item{manualItem}, []framework.Rule{{ID: "XDR202", Family: framework.FamilyCaps, Guide: "caps"}}, "rule XDR202 names no checklist item"},
		{"two rules, one item", []item{linterItem}, []framework.Rule{rule, {ID: "XDR202", Family: framework.FamilyCaps, Guide: "caps", Checklist: "HC-201"}}, "named by 2 rules"},
		{"linter item marked manual", []item{{ID: "HC-201", Check: "x", Manual: &manual{Why: "w", How: "h"}}}, []framework.Rule{rule}, "checked by XDR201 but marked manual"},
		{"item with neither rule nor reason", []item{{ID: "HC-502", Check: "x", Guide: []string{"caps"}, NoEntry: "none: x"}}, nil, "does not say why it is manual"},
		{"unknown anchor", []item{{ID: "HC-201", Check: "x", Guide: []string{"nowhere"}}}, []framework.Rule{rule}, `guide anchor "nowhere"`},
		{"unknown entry", []item{{ID: "HC-201", Check: "x", Corpus: []string{"a/zz"}}}, []framework.Rule{rule}, `corpus entry "a/zz"`},
		{"unknown member", []item{{ID: "HC-201", Check: "x", Corpus: []string{"a/c.zz"}}}, []framework.Rule{rule}, `corpus entry "a/c.zz"`},
		{"no entry and no reason", []item{{ID: "HC-501", Check: "x", Manual: &manual{Why: "w", How: "h"}, Guide: []string{"caps"}}}, nil, "no corpus entry and gives no reason"},
		{"out of order", []item{manualItem, linterItem}, []framework.Rule{rule}, "out of order"},
		{"hygiene rule with an item", []item{linterItem}, []framework.Rule{rule, {ID: "XDR000", Family: framework.FamilyHygiene, Checklist: "HC-201"}}, "documents the tool itself"},
	}
	for _, c := range cases {
		_, err := joinChecklist(c.items, c.rules, anchors, entries)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestEscapeForMDX(t *testing.T) {
	for in, want := range map[string]string{
		"a | b":                "a \\| b",
		"x < y {z}":            "x \\< y \\{z\\}",
		"`Limits { depth }` *": "`Limits { depth }` \\*",
		"`a|b`":                "`a\\|b`",
	} {
		if got := esc(in); got != want {
			t.Errorf("esc(%q) = %q, want %q", in, got, want)
		}
	}
}
