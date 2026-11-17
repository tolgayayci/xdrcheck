package ruledoc

// The checklist page of the guide is built here, from the same rule registry
// as the rule pages and from the item table in checklist_items.go:
//
//   - guide/generated/checklist-table.mdx, the checklist table: one row per
//     item, with the rule that checks it (from the registry) or why it is
//     manual and how to check it by hand;
//   - guide/generated/field-summary.mdx, a summary of the field-by-field
//     table, taken from the generated blocks of guide/indexer-hardening.mdx
//     (which `xdrcheck-corpus guide-table --check` holds to the corpus);
//   - guide/checklist.mdx, the page, which embeds both fragments byte for
//     byte between marker comments, then one section per item with its
//     search hints for other languages.
//
// Building checks the sources: every registered rule other than the
// hygiene family names exactly one item; an item that a rule names is not
// marked manual, and an item that no rule names is; every guide anchor is a
// heading of the guide page; every corpus entry is canonical (a row of
// corpus/plan.json, or a row and one of its members); every item names a
// corpus entry or says why there is none.

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// Output paths, relative to the lint module root.
const (
	ChecklistPage  = "../guide/checklist.mdx"
	ChecklistTable = "../guide/generated/checklist-table.mdx"
	FieldSummary   = "../guide/generated/field-summary.mdx"
)

// Where the guide pages are published on the documentation site.
const (
	guideURL     = "/docs/data/indexers/build-your-own/indexer-hardening"
	threatModels = "/docs/build/security-docs/threat-modeling"
)

// Marker comments around the embedded fragments.
const (
	beginTable   = "{/* BEGIN GENERATED: checklist table */}"
	beginSummary = "{/* BEGIN GENERATED: field summary */}"
	endGenerated = "{/* END GENERATED */}"
)

type item struct {
	ID      string   // HC-nnn
	Check   string   // what must hold, one or two sentences
	Manual  *manual  // set when no linter rule checks the item
	Guide   []string // guide section anchors, after the rule's own
	Corpus  []string // canonical corpus entry IDs, after the rule's own
	NoEntry string   // why no corpus entry shows the mistake ("none: …")
	Hints   hints
}

type manual struct {
	Why string // why the item cannot be checked mechanically
	How string // how to check it by hand, lower-case start ("find every …")
}

type hints struct{ JS, Rust, Python, Java []string }

var itemIDRe = regexp.MustCompile(`^HC-[1-5][0-9]{2}$`)

// checklistRow is an item joined with the rule that checks it.
type checklistRow struct {
	item
	rule   *framework.Rule
	guide  []string
	corpus []string
}

// joinChecklist joins the items with the registry and checks both.
func joinChecklist(items []item, rules []framework.Rule, anchors map[string]string, entries map[string]bool) ([]checklistRow, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf("checklist: "+format, a...)) }

	byItem := map[string][]framework.Rule{}
	for _, r := range rules {
		switch {
		case r.Family == framework.FamilyHygiene:
			if r.Checklist != "" {
				fail("%s documents the tool itself and has no checklist item, but names %s", r.ID, r.Checklist)
			}
		case r.Checklist == "":
			fail("rule %s names no checklist item", r.ID)
		default:
			byItem[r.Checklist] = append(byItem[r.Checklist], r)
		}
	}
	known := map[string]bool{}
	var rows []checklistRow
	prev := ""
	for _, it := range items {
		if !itemIDRe.MatchString(it.ID) {
			fail("item ID %q does not match HC-nnn", it.ID)
		}
		if it.ID <= prev {
			fail("item %s is out of order or repeated (after %s)", it.ID, prev)
		}
		prev = it.ID
		known[it.ID] = true
		row := checklistRow{item: it}
		rs := byItem[it.ID]
		switch {
		case len(rs) > 1:
			fail("item %s is named by %d rules; a rule has one item and an item at most one rule", it.ID, len(rs))
		case len(rs) == 1 && it.Manual != nil:
			fail("item %s is checked by %s but marked manual", it.ID, rs[0].ID)
		case len(rs) == 0 && it.Manual == nil:
			fail("item %s is named by no rule and does not say why it is manual", it.ID)
		case len(rs) == 1:
			r := rs[0]
			row.rule = &r
			row.guide = append(row.guide, r.Guide)
			if r.Corpus != "" {
				row.corpus = append(row.corpus, r.Corpus)
			}
		}
		if it.Manual != nil && (it.Manual.Why == "" || it.Manual.How == "") {
			fail("manual item %s needs both why it is manual and how to check it by hand", it.ID)
		}
		if strings.TrimSpace(it.Check) == "" {
			fail("item %s has no check text", it.ID)
		}
		for _, g := range it.Guide {
			if !slices.Contains(row.guide, g) {
				row.guide = append(row.guide, g)
			}
		}
		for _, c := range it.Corpus {
			if !slices.Contains(row.corpus, c) {
				row.corpus = append(row.corpus, c)
			}
		}
		if len(row.guide) == 0 {
			fail("item %s names no guide section", it.ID)
		}
		for _, g := range row.guide {
			if _, ok := anchors[g]; !ok {
				fail("item %s: guide anchor %q is not a heading of guide/indexer-hardening.mdx", it.ID, g)
			}
		}
		for _, c := range row.corpus {
			if !canonical(c, entries) {
				fail("item %s: corpus entry %q is not registered in corpus/plan.json", it.ID, c)
			}
		}
		switch {
		case len(row.corpus) == 0 && it.NoEntry == "":
			fail("item %s names no corpus entry and gives no reason", it.ID)
		case len(row.corpus) > 0 && it.NoEntry != "":
			fail("item %s names corpus entries and also a reason for having none", it.ID)
		}
		rows = append(rows, row)
	}
	for id, rs := range byItem {
		if !known[id] {
			fail("rule %s names checklist item %s, which does not exist", rs[0].ID, id)
		}
	}
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return rows, errors.Join(errs...)
}

// canonical reports whether id is a row of the plan, or a row and a member.
func canonical(id string, entries map[string]bool) bool {
	if entries[id] {
		return true
	}
	if i := strings.LastIndex(id, "."); i > 0 && entries[id[:i]] {
		return entries[id[:i]+"\x00"+id[i+1:]]
	}
	return false
}

// esc makes text safe in an MDX table cell or paragraph: `|` is escaped
// everywhere, and `{`, `}`, `<`, `>` and `*` outside code spans.
func esc(text string) string {
	var b strings.Builder
	for i, part := range strings.Split(text, "`") {
		if i > 0 {
			b.WriteByte('`')
		}
		for _, c := range part {
			switch {
			case c == '|':
				b.WriteString(`\|`)
			case i%2 == 0 && strings.ContainsRune("{}<>*", c):
				b.WriteByte('\\')
				b.WriteRune(c)
			case c == '\n':
				b.WriteByte(' ')
			default:
				b.WriteRune(c)
			}
		}
	}
	return b.String()
}

func code(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = "`" + id + "`"
	}
	return strings.Join(out, ", ")
}

func guideLinks(anchorIDs []string, anchors map[string]string) string {
	out := make([]string, len(anchorIDs))
	for i, a := range anchorIDs {
		out[i] = fmt.Sprintf("[%s](%s#%s)", esc(anchors[a]), guideURL, a)
	}
	return strings.Join(out, ", ")
}

func (r checklistRow) kind() string {
	switch {
	case r.rule == nil:
		return "manual"
	case r.rule.OptIn:
		return "linter (opt-in)"
	}
	return "linter"
}

func (r checklistRow) entries() string {
	if len(r.corpus) == 0 {
		return esc(r.NoEntry)
	}
	return code(r.corpus)
}

// checklistTable is the table the page shares with the linter: the
// generated fragment and the block between the page's markers are these
// bytes.
func checklistTable(rows []checklistRow, anchors map[string]string) string {
	var b strings.Builder
	b.WriteString("| Item | Check | Type | Linter rule, or why manual and how to check by hand | Guide section | Corpus entry that fails if you get it wrong |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range rows {
		how := ""
		if r.rule != nil {
			how = r.rule.ID
		} else {
			how = esc(r.Manual.Why) + " By hand: " + esc(r.Manual.How)
		}
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s | %s | %s |\n",
			r.ID, strings.ToLower(r.ID), esc(r.Check), r.kind(), how, guideLinks(r.guide, anchors), r.entries())
	}
	return b.String()
}

// fieldSummary is a four-column summary of the published lines of the
// guide's generated field table, each ID linking to its group there.
func fieldSummary(guide string) (string, error) {
	var b strings.Builder
	b.WriteString("| ID | Field | Status | You must not assume |\n| --- | --- | --- | --- |\n")
	group, inBlock, lines := "", false, 0
	for _, l := range strings.Split(guide, "\n") {
		switch {
		case strings.HasPrefix(l, "{/* BEGIN GENERATED: fields "):
			if group == "" {
				return "", errors.New("a generated field block has no heading with an anchor before it")
			}
			inBlock = true
		case l == endGenerated:
			inBlock = false
		case !inBlock:
			if m := headingRe.FindStringSubmatch(l); m != nil {
				group = m[2]
			}
		case strings.HasPrefix(l, "| VF-"):
			cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(l, "| "), " |"), " | ")
			if len(cells) != 9 {
				return "", fmt.Errorf("field table line has %d cells, want 9: %.60s", len(cells), l)
			}
			fmt.Fprintf(&b, "| [%s](%s#%s) | %s | %s | %s |\n", cells[0], guideURL, group, cells[1], cells[3], cells[6])
			lines++
		}
	}
	if lines == 0 {
		return "", errors.New("guide/indexer-hardening.mdx has no generated field table lines")
	}
	return b.String(), nil
}

func hintLines(h hints) []string {
	var out []string
	for _, l := range []struct {
		lang string
		v    []string
	}{{"JavaScript and TypeScript", h.JS}, {"Rust", h.Rust}, {"Python", h.Python}, {"Java", h.Java}} {
		if len(l.v) > 0 {
			out = append(out, fmt.Sprintf("- **Search hints, %s:** %s", l.lang, esc(strings.Join(l.v, "; "))))
		}
	}
	return out
}

const checklistFront = `---
title: "Indexer hardening checklist"
sidebarTitle: "Checklist"
description: "A self-audit checklist for code that reads Stellar ledger meta, transaction envelopes and contract events: what to check, how to check it by hand, and which test ledger shows each mistake."
---

{/* Generated by ` + "`go run ./cmd/xdrlint-docs`" + ` in lint/ from the rule registry and lint/internal/ruledoc/checklist_items.go; edit those, not this file. */}

`

// repoURL is the repository that publishes the corpus and the analyzer: BaseURL without the rule-page path.
var repoURL = strings.TrimSuffix(BaseURL, "/blob/main/lint/docs/")

// checklistPage builds the page around the two fragments.
func checklistPage(rows []checklistRow, anchors map[string]string, table, summary string) []byte {
	var b bytes.Buffer
	b.WriteString(checklistFront)
	fmt.Fprintf(&b, "Use this checklist to audit an indexer, explorer, wallet backend or analytics pipeline against the mistakes that [Harden your indexer against rare ledger shapes](%s) describes. ", guideURL)
	b.WriteString("Each item links to the guide section that explains it and names a corpus entry: a ledger or vector that a reader gets wrong when the item does not hold. ")
	fmt.Fprintf(&b, "The corpus and the `xdrlint` static analyzer are open source and published together ([repository](%s)). ", repoURL)
	b.WriteString("Each entry ID names a manifest, `corpus/manifest/<entry ID>.json`, that records where the entry's bytes came from and the values a correct reader produces from them; an ID without a member suffix, such as `strkey/sep-0023-v1.4.0-vectors`, names all of its members.\n\n")
	fmt.Fprintf(&b, "Items of type `linter` can also be checked in Go code by `xdrlint`, under the rule ID in the table ([rule pages](%sREADME.md)). ", BaseURL)
	b.WriteString("Items of type `manual` cannot be checked mechanically; the table says why and how to check them by hand. ")
	b.WriteString("Every rule of the analyzer has an item here; not every item has a rule. ")
	fmt.Fprintf(&b, "For the rest of a system, see [threat modeling](%s).\n\n", threatModels)

	b.WriteString("## Checklist {#checklist}\n\n")
	b.WriteString(beginTable + "\n\n" + table + "\n" + endGenerated + "\n\n")

	b.WriteString("## Items {#items}\n\n")
	b.WriteString("Search hints name types, functions and fields to look for in SDKs other than Go. They locate code to review; a match does not prove a mistake.\n\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "### %s {#%s}\n\n%s\n\n", r.ID, strings.ToLower(r.ID), esc(r.Check))
		var facts []string
		if r.rule != nil {
			set := "in the default rule set"
			if r.rule.OptIn {
				set = "opt-in"
			}
			facts = append(facts, fmt.Sprintf("- **Checked by:** linter rule %s (%s)", r.rule.ID, set))
		} else {
			facts = append(facts, "- **Checked by:** hand. "+esc(r.Manual.Why))
			facts = append(facts, "- **How:** "+esc(strings.ToUpper(r.Manual.How[:1])+r.Manual.How[1:]))
		}
		facts = append(facts, "- **Guide:** "+guideLinks(r.guide, anchors))
		facts = append(facts, "- **Corpus:** "+r.entries())
		facts = append(facts, hintLines(r.Hints)...)
		b.WriteString(strings.Join(facts, "\n") + "\n\n")
	}

	b.WriteString("## Field summary {#field-summary}\n\n")
	fmt.Fprintf(&b, "For each field your code reads, check that it does not rely on what the last column rules out. This summary of the [field-by-field table](%s#field-table) lists each published line with its status; the full table gives what stellar-core checks and where, the result code and the demonstrating entries, and also lists the lines that are not yet established.\n\n", guideURL)
	b.WriteString(beginSummary + "\n\n" + summary + "\n" + endGenerated + "\n")
	return b.Bytes()
}

// buildChecklist returns the checklist page and its two fragments.
func buildChecklist(guide string, rules []framework.Rule, anchors map[string]string, entries map[string]bool) (map[string][]byte, error) {
	rows, err := joinChecklist(checklistItems, rules, anchors, entries)
	if err != nil {
		return nil, err
	}
	summary, err := fieldSummary(guide)
	if err != nil {
		return nil, fmt.Errorf("field summary: %v", err)
	}
	table := checklistTable(rows, anchors)
	return map[string][]byte{
		ChecklistTable: []byte(table),
		FieldSummary:   []byte(summary),
		ChecklistPage:  checklistPage(rows, anchors, table, summary),
	}, nil
}

// Embedded returns the bytes between the marker comment begin and the next
// end marker in page, without the blank lines that pad them.
func Embedded(page []byte, begin string) ([]byte, bool) {
	_, rest, ok := bytes.Cut(page, []byte(begin+"\n\n"))
	if !ok {
		return nil, false
	}
	block, _, ok := bytes.Cut(rest, []byte("\n"+endGenerated))
	return block, ok
}
