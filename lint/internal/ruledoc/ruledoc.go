// Package ruledoc builds the rule pages under lint/docs from three sources,
// so that a page can never disagree with the linter it documents:
//
//   - the rule registry (ID, title, family, default severity, opt-in, guide
//     anchor, corpus entry, checklist item),
//
//   - one hand-written fragment per rule, lint/docs/src/<ID>.md (what the rule
//     reports, why, its limits), whose example directives
//
//     <!-- example xdr1xx/xdr101/bad.go destinationFromGetID -->
//
//     are replaced by that function's source from the rule's fixtures under
//     lint/testdata, with the fixture's `// want` annotations removed, and
//
//   - lint/docs/src/README.md, the index page, whose `<!-- rules -->` directive
//     becomes the table of rules.
//
// It also builds the guide's checklist page and its fragments (checklist.go).
//
// Building checks the sources too: every registered rule has a fragment and
// every fragment a rule; every guide anchor exists in
// guide/indexer-hardening.mdx (the hygiene family's anchor is a section of
// the index page); every corpus entry is registered in corpus/plan.json; every
// example names a function that exists. Check reports any difference between
// the built pages and the files on disk, so a test fails when a rule changes
// and its page was not rebuilt (`go run ./cmd/xdrlint-docs`).
package ruledoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	// Every rule package, so that the registry is complete.
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr1xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr2xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr3xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr4xx"
)

// BaseURL is where the rule pages are published; SARIF output links each
// rule to BaseURL + ID + ".md".
const BaseURL = "https://github.com/tolgayayci/xdrcheck/blob/main/lint/docs/"

// URL returns the published page of a rule.
func URL(id string) string { return BaseURL + id + ".md" }

// Paths, relative to the lint module root.
const (
	DocsDir   = "docs"
	SourceDir = "docs/src"
	guideFile = "../guide/indexer-hardening.mdx"
	planFile  = "../corpus/plan.json"
	// The hygiene family documents the tool itself; its anchor is a section
	// of the index page instead of the guide.
	hygieneAnchor = "linter-suppressions"
)

var familyTitle = map[framework.Family]string{
	framework.FamilyHygiene:      "XDR0xx: suppression hygiene",
	framework.FamilyUnvalidated:  "XDR1xx: trusting unvalidated fields",
	framework.FamilyCaps:         "XDR2xx: missing depth and size caps",
	framework.FamilyParticipants: "XDR3xx: participants from the envelope instead of the meta",
	framework.FamilyAssumptions:  "XDR4xx: assumptions about the ledger's form, ranges and outcomes",
}

var (
	headingRe = regexp.MustCompile(`(?m)^#{2,6} (.+?) \{#([a-z0-9-]+)\}\s*$`)
	exampleRe = regexp.MustCompile(`(?m)^<!-- example (\S+) (\S+) -->$`)
	wantRe    = regexp.MustCompile(`\s*// want .*$`)
)

// Build returns the pages, keyed by path relative to the lint module root.
func Build(lintRoot string) (map[string][]byte, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	guide, err := os.ReadFile(filepath.Join(lintRoot, guideFile))
	if err != nil {
		return nil, err
	}
	anchors := map[string]string{} // anchor → heading text
	for _, m := range headingRe.FindAllStringSubmatch(string(guide), -1) {
		anchors[m[2]] = m[1]
	}
	entries, err := planEntries(filepath.Join(lintRoot, planFile))
	if err != nil {
		return nil, err
	}

	rules := framework.Default.Rules()
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	pages := map[string][]byte{}
	known := map[string]bool{}
	for _, r := range rules {
		known[r.ID+".md"] = true
		src, err := os.ReadFile(filepath.Join(lintRoot, SourceDir, r.ID+".md"))
		if err != nil {
			fail("%s: no fragment %s/%s.md", r.ID, SourceDir, r.ID)
			continue
		}
		page, err := rulePage(lintRoot, r, string(src), anchors, entries)
		if err != nil {
			fail("%s: %v", r.ID, err)
			continue
		}
		pages[filepath.ToSlash(filepath.Join(DocsDir, r.ID+".md"))] = page
	}
	files, _ := os.ReadDir(filepath.Join(lintRoot, SourceDir))
	for _, f := range files {
		if n := f.Name(); strings.HasSuffix(n, ".md") && n != "README.md" && n != "assumptions.md" && !known[n] {
			fail("%s/%s documents no registered rule", SourceDir, n)
		}
	}
	index, err := indexPage(lintRoot, rules, anchors)
	if err != nil {
		fail("README: %v", err)
	} else {
		pages[filepath.ToSlash(filepath.Join(DocsDir, "README.md"))] = index
	}
	pages[filepath.ToSlash(filepath.Join(DocsDir, "assumptions.md"))] = assumptionsPage(rules)
	checklist, err := buildChecklist(string(guide), rules, anchors, entries)
	if err != nil {
		fail("%v", err)
	}
	for p, data := range checklist {
		pages[p] = data
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return pages, nil
}

func planEntries(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var plan []struct {
		ID      string   `json:"id"`
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	out := map[string]bool{}
	for _, e := range plan {
		out[e.ID] = true
		for _, m := range e.Members {
			out[e.ID+"\x00"+m] = true // a member, as canonical() looks it up
		}
	}
	return out, nil
}

const generated = "<!-- Generated by `go run ./cmd/xdrlint-docs` in lint/ from the rule registry and docs/src; edit those, not this file. -->\n\n"

func rulePage(lintRoot string, r framework.Rule, src string, anchors map[string]string, entries map[string]bool) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(generated)
	fmt.Fprintf(&b, "# %s: %s\n\n", r.ID, r.Title)
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Family | %s |\n", familyTitle[r.Family])
	if r.Fix == "" {
		return nil, fmt.Errorf("rule %s has no one-line fix (Rule.Fix), which every diagnostic prints", r.ID)
	}
	fmt.Fprintf(&b, "| How to fix | %s |\n", strings.ReplaceAll(r.Fix, "|", `\|`))
	fmt.Fprintf(&b, "| Default severity | %s (`severity: {%s: …}` changes it) |\n", r.Severity, r.ID)
	if r.OptIn {
		fmt.Fprintf(&b, "| Default rule set | no: opt-in, add %s to `rules` |\n", r.ID)
	} else {
		b.WriteString("| Default rule set | yes |\n")
	}
	switch {
	case r.Family == framework.FamilyHygiene:
		if r.Guide != hygieneAnchor {
			return nil, fmt.Errorf("hygiene rule anchor %q, want %q", r.Guide, hygieneAnchor)
		}
		fmt.Fprintf(&b, "| Documentation | [Configuring and suppressing](README.md#%s) |\n", hygieneAnchor)
	default:
		title, ok := anchors[r.Guide]
		if !ok {
			return nil, fmt.Errorf("guide anchor %q is not a heading of guide/indexer-hardening.mdx", r.Guide)
		}
		fmt.Fprintf(&b, "| Guide | [%s](../../guide/indexer-hardening.mdx#%s) |\n", title, r.Guide)
	}
	if r.Checklist != "" {
		fmt.Fprintf(&b, "| Self-audit checklist item | %s |\n", r.Checklist)
	}
	if r.Corpus != "" {
		if !entries[r.Corpus] {
			return nil, fmt.Errorf("corpus entry %q is not registered in corpus/plan.json", r.Corpus)
		}
		fmt.Fprintf(&b, "| Demonstrating corpus entry | `%s` (registered in [corpus/plan.json](../../corpus/plan.json)) |\n", r.Corpus)
	}
	fixtures := filepath.ToSlash(filepath.Join("testdata", strings.ToLower(string(r.Family)), strings.ToLower(r.ID)))
	if fi, err := os.Stat(filepath.Join(lintRoot, fixtures)); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("no fixture directory lint/%s", fixtures)
	}
	fmt.Fprintf(&b, "| Fixtures | [lint/%s](../%s) |\n\n", fixtures, fixtures)

	body, err := expandExamples(lintRoot, src)
	if err != nil {
		return nil, err
	}
	b.WriteString(strings.TrimSpace(body))
	b.WriteString("\n\n## Configure and suppress\n\n")
	fmt.Fprintf(&b, "Turn the rule off by leaving %s out of `rules` in `.xdrlint.yml` or a profile. "+
		"To accept one report, put `//xdrlint:ignore %s <reason>` on the reported line or on the enclosing function's doc comment "+
		"(under golangci-lint, `//nolint:xdrlint // <reason>`), or add an entry to an external suppression file for code you cannot edit. "+
		"A suppression needs a reason, and one that suppresses nothing is itself reported (XDR000). See [Configuring and suppressing](README.md#%s).\n",
		r.ID, r.ID, hygieneAnchor)
	return b.Bytes(), nil
}

// expandExamples replaces each example directive by the named function's
// source from a fixture file.
func expandExamples(lintRoot, src string) (string, error) {
	var errs []error
	out := exampleRe.ReplaceAllStringFunc(src, func(line string) string {
		m := exampleRe.FindStringSubmatch(line)
		code, err := funcSource(filepath.Join(lintRoot, "testdata", m[1]), m[2])
		if err != nil {
			errs = append(errs, fmt.Errorf("example %s %s: %v", m[1], m[2], err))
			return line
		}
		return fmt.Sprintf("```go\n// lint/testdata/%s\n%s\n```", m[1], code)
	})
	return out, errors.Join(errs...)
}

// funcSource returns the declaration of function name (or "Recv.Name") in
// file, with its doc comment and without `// want` annotations.
func funcSource(file, name string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, data, parser.ParseComments)
	if err != nil {
		return "", err
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || declName(fd) != name {
			continue
		}
		start := fd.Pos()
		if fd.Doc != nil {
			start = fd.Doc.Pos()
		}
		text := string(data[fset.Position(start).Offset:fset.Position(fd.End()).Offset])
		var lines []string
		for _, l := range strings.Split(text, "\n") {
			s := wantRe.ReplaceAllString(l, "")
			if strings.TrimSpace(s) == "" && strings.TrimSpace(l) != "" {
				continue // the line held only an annotation
			}
			lines = append(lines, s)
		}
		return strings.Join(lines, "\n"), nil
	}
	return "", fmt.Errorf("no function %s", name)
}

func declName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func indexPage(lintRoot string, rules []framework.Rule, anchors map[string]string) ([]byte, error) {
	src, err := os.ReadFile(filepath.Join(lintRoot, SourceDir, "README.md"))
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(src), "<!-- rules -->") {
		return nil, errors.New("docs/src/README.md has no <!-- rules --> directive")
	}
	if !strings.Contains(string(src), `id="`+hygieneAnchor+`"`) {
		return nil, fmt.Errorf("docs/src/README.md has no section with id %q", hygieneAnchor)
	}
	var t bytes.Buffer
	t.WriteString("| Rule | What it reports | Default severity | Default set | Guide section | Checklist |\n|---|---|---|---|---|---|\n")
	for _, r := range rules {
		set := "yes"
		if r.OptIn {
			set = "opt-in"
		}
		guide := "this page"
		if title, ok := anchors[r.Guide]; ok && r.Family != framework.FamilyHygiene {
			guide = fmt.Sprintf("[%s](../../guide/indexer-hardening.mdx#%s)", title, r.Guide)
		}
		check := r.Checklist
		if check == "" {
			check = "—"
		}
		fmt.Fprintf(&t, "| [%s](%s.md) | %s | %s | %s | %s | %s |\n", r.ID, r.ID, r.Title, r.Severity, set, guide, check)
	}
	body := strings.Replace(string(src), "<!-- rules -->", strings.TrimRight(t.String(), "\n"), 1)
	return append([]byte(generated), []byte(strings.TrimSpace(body)+"\n")...), nil
}

// Write builds the pages and writes them, removing pages of rules that no
// longer exist.
func Write(lintRoot string) error {
	pages, err := Build(lintRoot)
	if err != nil {
		return err
	}
	for _, stale := range stalePages(lintRoot, pages) {
		if err := os.Remove(filepath.Join(lintRoot, stale)); err != nil {
			return err
		}
	}
	for p, data := range pages {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(lintRoot, p)), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(lintRoot, p), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Check builds the pages and returns one line per difference from the files
// on disk (nil when they match).
func Check(lintRoot string) ([]string, error) {
	pages, err := Build(lintRoot)
	if err != nil {
		return nil, err
	}
	var diffs []string
	for p, want := range pages {
		got, err := os.ReadFile(filepath.Join(lintRoot, p))
		switch {
		case err != nil:
			diffs = append(diffs, "missing: "+repoPath(p))
		case !bytes.Equal(got, want):
			diffs = append(diffs, "out of date: "+repoPath(p))
		}
	}
	for _, stale := range stalePages(lintRoot, pages) {
		diffs = append(diffs, "documents no rule: lint/"+stale)
	}
	slices.Sort(diffs)
	return diffs, nil
}

// repoPath turns a path relative to the lint module root into one relative
// to the repository root.
func repoPath(p string) string { return filepath.ToSlash(filepath.Clean(filepath.Join("lint", p))) }

func stalePages(lintRoot string, pages map[string][]byte) []string {
	var out []string
	files, _ := os.ReadDir(filepath.Join(lintRoot, DocsDir))
	for _, f := range files {
		p := filepath.ToSlash(filepath.Join(DocsDir, f.Name()))
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") && pages[p] == nil {
			out = append(out, p)
		}
	}
	return out
}

// assumptionsPage is lint/docs/assumptions.md: every registered assumption
// key, the input that violates it, and the rules whose reports carry it by
// default.
func assumptionsPage(rules []framework.Rule) []byte {
	byKey := map[string][]string{}
	for _, r := range rules {
		byKey[r.Assumption] = append(byKey[r.Assumption], r.ID)
	}
	var b bytes.Buffer
	b.WriteString("<!-- Generated by `go run ./cmd/xdrlint-docs` in lint/ from the assumption registry; edit the rules, not this file. -->\n\n")
	b.WriteString("# Assumptions\n\n")
	b.WriteString("Every diagnostic carries an `assumption` key (in the JSON and SARIF output and in `-report` rows): the assumption\n")
	b.WriteString("about the ledger that the reported code makes. The key is stable, so a tool can map a diagnostic to a query for\n")
	b.WriteString("the ledger inputs that violate it. A rule reports its default key unless a report names a more precise one.\n\n")
	b.WriteString("| Key | Input that violates it | Default of |\n|---|---|---|\n")
	for _, a := range framework.Assumptions() {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", a.Key, a.Violation, strings.Join(byKey[a.Key], ", "))
	}
	return b.Bytes()
}
