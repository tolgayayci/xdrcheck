package siblings

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// Template files under findings/templates/, one per draft kind.
var templateFiles = map[string]string{
	KindNew:     "new-issue.md.tmpl",
	KindComment: "evidence-comment.md.tmpl",
	KindRelease: "release-request.md.tmpl",
}

// Templates are the parsed draft templates.
type Templates map[string]*template.Template

// LoadTemplates parses the draft templates in dir.
func LoadTemplates(dir string) (Templates, error) {
	t := Templates{}
	for kind, name := range templateFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		tt, err := template.New(name).Option("missingkey=error").Funcs(template.FuncMap{"join": strings.Join, "day": day}).Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		t[kind] = tt
	}
	return t, nil
}

// DraftData is what a template sees.
type DraftData struct {
	Kind          string
	Title         string
	Project       string
	Package       string
	Versions      []string // the package versions that show the defect
	Executed      bool     // the outcomes were observed by running the SDK (false: read from its source)
	FixedIn       string   // "n/a" when not fixed
	Summary       string
	Entries       []DraftEntry
	Method        string
	ExpectedBasis string
	Elsewhere     []string // the same defect in other projects, public items only
	SuggestedFix  string
	Corpus        []string // how to run the entries
	Target        *Item    // the item a comment goes to, or the fix a release request cites
	Release       *Release
}

// DraftEntry is one corpus cell in a draft.
type DraftEntry struct {
	ID, Variant, Level, Column, Observed, Expected string
}

// Draft is one sibling draft: the record it belongs to, the body and the command that would file it.
type Draft struct {
	SDK      string
	Record   *findings.Record
	New      bool   // the record is created by this run
	Overlay  bool   // the record and the body live in the private overlay
	Kind     string // issue_draft.kind
	File     string // body file name in the record directory
	BodyPath string // the body's path as the command names it: findings/<id>/<file>, relative to the repository or the overlay
	Body     string
	Command  string
	Notes    []string // for the reviewer; printed, never written into the body
}

// Plan is everything a sibling run found and would write.
type Plan struct {
	Signature *Signature
	Group     string
	Results   []*Result
	Decisions map[string]*Decision // by sdk
	Drafts    []*Draft
	Today     string
}

const toBeWritten = "_To be written by the reviewer before approval._"

var capRe = regexp.MustCompile(`^cap-([0-9]{4})/`)

// BuildOptions are the inputs of Build besides the analysis.
type BuildOptions struct {
	Today        string
	Templates    Templates
	Offline      bool
	PublicColumn func(id string) bool // nil: every column is public (Options.PublicColumn)
}

// Build turns the analysis and the decisions into records and drafts. New records get IDs from the store
// (public range, or overlay range for overlay records) and are added to it in memory; nothing is written.
func Build(store *findings.Store, sig *Signature, results []*Result, decisions map[string]*Decision, o BuildOptions) (*Plan, error) {
	p := &Plan{Signature: sig, Group: Group(sig, results), Results: results, Decisions: decisions, Today: o.Today}

	// Records first, so that every draft can link the others.
	for _, r := range results {
		d := decisions[r.Family.SDK]
		if r.Status != Affected || d == nil || d.Kind == "" {
			continue
		}
		// An unreported defect (a new issue, or any sibling of a defect that is not public) is drafted in the
		// private overlay only.
		private := sig.OriginalOverlay || !sig.Public || !d.PublicItem
		dr := &Draft{SDK: r.Family.SDK, Kind: d.Kind}
		if l := r.Record; l != nil {
			if private && !l.Overlay {
				d.Why += fmt.Sprintf("; %s is in the public tree, so no draft is written for it: an unreported defect is drafted only in the private overlay", l.Record.ID)
				d.Kind = ""
				continue
			}
			dr.Record, dr.Overlay = l.Record, l.Overlay
		} else {
			dr.New = true
			dr.Overlay = private
			rec := newRecord(store, store.NextID(dr.Overlay), sig, r, d, p.Group, dr.Overlay, o)
			dir := store.PublicDir
			if dr.Overlay {
				dir = store.OverlayDir
			}
			store.Records[rec.ID] = &findings.Loaded{Record: rec, Dir: filepath.Join(dir, rec.ID), Overlay: dr.Overlay}
			dr.Record = rec
		}
		if dr.Overlay && dr.Record.Visibility == "embargoed" {
			dr.Kind = "private-report"
		}
		p.Drafts = append(p.Drafts, dr)
	}

	// Siblings of the new records: the original, the group's existing records and the other new records. A
	// public record names public records only.
	for _, dr := range p.Drafts {
		if !dr.New {
			continue
		}
		var ids []string
		for _, id := range store.IDs() {
			l := store.Records[id]
			if id == dr.Record.ID || l.Overlay && !dr.Overlay {
				continue
			}
			inGroup := l.Record.DefectGroup != "" && l.Record.DefectGroup == p.Group
			if inGroup || sig.Original != nil && id == sig.Original.ID {
				ids = append(ids, id)
			}
		}
		dr.Record.Siblings = ids
	}

	for _, dr := range p.Drafts {
		r := resultFor(results, dr.SDK)
		d := decisions[dr.SDK]
		dr.File = "issue-" + path.Base(dr.Record.Target.Project) + ".md"
		dr.BodyPath = "findings/" + dr.Record.ID + "/" + dr.File
		data := draftData(store, sig, r, d, dr, p.Group, o.PublicColumn)
		kind := dr.Kind
		if kind == "private-report" {
			kind = KindNew
		}
		var buf bytes.Buffer
		if err := o.Templates[kind].Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("%s draft for %s: %w", kind, dr.SDK, err)
		}
		dr.Body = buf.String()
		dr.Command = command(dr, data, d)
		dr.Notes = notes(r, d, dr)
		dr.Record.IssueDraft = &findings.IssueDraft{Path: dr.File, Kind: dr.Kind, DryRunCommand: dr.Command}
	}
	return p, nil
}

func resultFor(results []*Result, sdk string) *Result {
	for _, r := range results {
		if r.Family.SDK == sdk {
			return r
		}
	}
	return nil
}

// reference is the record a family's draft takes its title and expectations from: the family's existing
// record, else the public group record whose entries match the family's cells best (so that a defect found
// together with an unrelated one in the original is described without it), else the original. It is nil
// when the run started from a known divergence and no record applies.
func reference(store *findings.Store, sig *Signature, r *Result, group string) *findings.Record {
	if r.Record != nil {
		return r.Record.Record
	}
	want := map[Key]bool{}
	for _, o := range r.Matches {
		want[o.Key] = true
	}
	var best *findings.Record
	bestScore := -1.0
	for _, id := range store.IDs() {
		rec := store.Records[id].Record
		if store.Records[id].Overlay || group == "" || rec.DefectGroup != group {
			continue
		}
		inter, union := 0, len(want)
		for _, e := range rec.Entries {
			if want[Key{e.ID, e.Variant, e.Scope}] {
				inter++
			} else {
				union++
			}
		}
		if s := float64(inter) / float64(union); union > 0 && s > bestScore {
			best, bestScore = rec, s
		}
	}
	if best != nil {
		return best
	}
	return sig.Original
}

// Title is the draft's title, the reference record's. Its first words are also the default tracker search.
func Title(store *findings.Store, sig *Signature, r *Result, group string) string {
	if ref := reference(store, sig, r, group); ref != nil {
		return ref.Title
	}
	return "Same defect as " + sig.Reference
}

// expectedBasis is why the expected outcome is right: the reference record's basis, else the original's.
func expectedBasis(ref *findings.Record, sig *Signature) string {
	for _, rec := range []*findings.Record{ref, sig.Original} {
		if rec != nil && rec.Evidence != nil && rec.Evidence.ExpectedBasis != "" {
			return rec.Evidence.ExpectedBasis
		}
	}
	return ""
}

func versions(r *Result) []string {
	var v []string
	for _, o := range append(append([]Observation{}, r.Earlier...), r.Matches...) {
		v = appendUnique(v, o.Version)
	}
	return v
}

func columns(r *Result) []string {
	var c []string
	for _, o := range append(append([]Observation{}, r.Earlier...), r.Matches...) {
		c = appendUnique(c, o.Column)
	}
	sort.Strings(c)
	return c
}

var classOfVerdict = map[string]string{"reject_valid": "rejects_valid", "accepts_invalid": "accepts_invalid", "diverge": "wrong_value", "crash": "crash"}

var verdictWords = map[string]string{
	"reject_valid":    "refuses input that stellar-core accepts",
	"accepts_invalid": "accepts input that stellar-core refuses",
	"diverge":         "returns a value that differs from stellar-core's",
	"crash":           "crashes",
}

func observed(o Observation, m *Manual) string {
	if o.Manual {
		if m != nil && m.Executed() {
			return fmt.Sprintf("Executed by hand on %s (the kit has no driver for this SDK): %s", o.Version, o.Observed)
		}
		return fmt.Sprintf("Not executed: source reading of %s (the kit has no driver for this SDK). %s", o.Version, o.Observed)
	}
	s := fmt.Sprintf("Executed on %s: outcome %s", o.Column, o.Outcome)
	if o.Reason != "" {
		s += " (" + o.Reason + ")"
	}
	if o.Message != "" {
		s += ", message " + strconv.Quote(o.Message)
	}
	return s + "; verdict " + o.Verdict + "."
}

// expected is the expected outcome of a cell: as the reference record states it, else as the original does.
func expected(ref *findings.Record, sig *Signature, k Key) string {
	if ref != nil {
		for _, e := range ref.Entries {
			if e.ID == k.Entry && e.Variant == k.Variant && e.Scope == k.Level && e.Expected != "" {
				return e.Expected
			}
		}
	}
	if e := sig.Expected[k]; e != "" {
		return e
	}
	return "conform: the outcome stellar-core gives"
}

func method(r *Result) string {
	if m := r.Manual; m != nil {
		if m.Executed() {
			return fmt.Sprintf("Executed by hand on %s %s (%s); the kit has no conformance driver for this SDK. %s", m.Package, m.Version, m.Date, m.Basis)
		}
		return fmt.Sprintf("Not executed: the kit has no conformance driver for this SDK. The outcomes above are read from the source of %s %s (%s). %s",
			m.Package, m.Version, m.Date, m.Basis)
	}
	return fmt.Sprintf("Executed through the kit's conformance runner (`xdrcheck conform run`) on %s.", strings.Join(columns(r), ", "))
}

func newRecord(store *findings.Store, id string, sig *Signature, r *Result, d *Decision, group string, overlay bool, o BuildOptions) *findings.Record {
	var entries []findings.Entry
	var rows []string
	var caps []int
	var verdictsSeen []string
	ref := reference(store, sig, r, group)
	for _, ob := range r.Matches {
		entries = append(entries, findings.Entry{ID: ob.Entry, Variant: ob.Variant, Scope: ob.Level, Expected: expected(ref, sig, ob.Key), Observed: observed(ob, r.Manual)})
		verdictsSeen = appendUnique(verdictsSeen, ob.Verdict)
		if m := capRe.FindStringSubmatch(ob.Entry); m != nil {
			n, _ := strconv.Atoi(m[1])
			if !containsInt(caps, n) {
				caps = append(caps, n)
			}
		}
	}
	for _, ob := range append(append([]Observation{}, r.Earlier...), r.Matches...) {
		if row := ob.RowID(); row != "" {
			rows = append(rows, row)
		}
	}
	sort.Strings(rows)
	sort.Ints(caps)

	class, severity, security := "", "", false
	if orig := sig.Original; orig != nil {
		for _, v := range verdictsSeen {
			if classOfVerdict[v] == orig.Class {
				class = orig.Class
			}
		}
		severity, security = orig.Severity, orig.SecurityRelevant
	}
	if class == "" {
		class = classOfVerdict[verdictsSeen[0]]
	}
	if severity == "" {
		severity = map[string]string{"crash": "critical", "wrong_value": "high"}[class]
		if severity == "" {
			severity = "medium"
		}
		security = severity == "critical" || severity == "high"
	}
	basis := "Provisional: the severity of the original finding for the same defect class; a reviewer confirms it for this project."
	if sig.Original == nil {
		basis = "Provisional: the worst plausible severity for the result class; a reviewer sets the severity."
	}

	tested := columns(r)
	affected := strings.Join(versions(r), ", ") + " (range not established)"
	if r.Manual != nil && r.Manual.VersionsAffected != "" {
		affected = r.Manual.VersionsAffected
	}
	origin := sig.Name()
	if sig.Original != nil {
		origin += " (" + sig.Original.Target.Project + ")"
	}
	how := fmt.Sprintf("%s shows the same outcome on %d corpus cell(s)", strings.Join(r.LatestColumns, ", "), len(r.Matches))
	if r.Manual != nil {
		how += " by manual evidence (" + r.Manual.Method + ")"
	}

	rec := &findings.Record{
		Schema:      findings.SchemaID,
		ID:          id,
		Title:       clip(Title(store, sig, r, group), 160),
		DefectGroup: group,
		Target: findings.Target{Project: r.Family.Project, Package: r.Family.Package, Ecosystem: r.Family.Ecosystem,
			VersionsAffected: affected, VersionsTested: tested},
		Component:        r.Family.Component,
		Class:            class,
		Severity:         severity,
		SeverityBasis:    basis,
		SecurityRelevant: security,
		Visibility:       "public",
		Caps:             caps,
		Entries:          entries,
		Evidence:         &findings.Evidence{PreFix: method(r), ReportRows: rows},
		State:            "candidate",
		History: []findings.HistoryItem{{Date: o.Today, State: "candidate",
			Note: "Created by xdrcheck conform siblings as a sibling of " + origin + ": " + how + "."}},
	}
	rec.Evidence.ExpectedBasis = expectedBasis(ref, sig)
	if !o.Offline && len(d.Queries) > 0 {
		rec.UpstreamSearch = &findings.UpstreamSearch{Date: o.Today, Queries: d.Queries, Result: d.SearchResult}
		if d.Target != nil {
			rec.UpstreamSearch.Existing = d.Target.URL
		}
	}
	switch d.Kind {
	case KindComment:
		rec.Upstream = &findings.Upstream{URL: d.Target.URL, State: "open", CheckedAt: o.Today}
	case KindRelease:
		rec.Upstream = &findings.Upstream{URL: d.Target.URL, State: "fix-merged-unreleased", CheckedAt: o.Today}
	}
	if o.Offline && rec.Upstream != nil {
		rec.Upstream.CheckedAt = ""
	}
	for _, it := range d.Confirmed {
		if d.Target == nil || it.URL != d.Target.URL {
			rec.Related = appendUnique(rec.Related, it.URL)
		}
	}
	if overlay && security {
		rec.Visibility = "embargoed"
		rec.Embargo = &findings.Embargo{
			Trigger: "severity-undetermined",
			Policy:  "not yet looked up",
			Channel: "not yet decided",
			LiftCondition: "The severity is shown not to warrant an embargo, or the defect is disclosed to its maintainers and " +
				"fixed, or 90 days pass from the report.",
		}
		rec.History = append(rec.History, findings.HistoryItem{Date: o.Today, State: "embargoed", Note: "Inherits the original's security relevance; embargoed by default."})
	}
	return rec
}

// clip shortens s to at most n runes.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func containsInt(list []int, n int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

func draftData(store *findings.Store, sig *Signature, r *Result, d *Decision, dr *Draft, group string, publicColumn func(string) bool) *DraftData {
	rec := dr.Record
	ref := reference(store, sig, r, group)
	data := &DraftData{Kind: dr.Kind, Title: rec.Title, Project: r.Family.Project, Package: r.Family.Package, Versions: versions(r),
		FixedIn: "n/a", Method: method(r), Target: d.Target, Release: d.Release, SuggestedFix: toBeWritten,
		Executed: r.Manual == nil || r.Manual.Executed()}
	if d.Kind == KindRelease {
		data.Title = "Release request: " + rec.Title
		data.FixedIn = "merged in " + d.Target.URL + ", not released"
	}
	for _, o := range r.Matches {
		data.Entries = append(data.Entries, DraftEntry{ID: o.Entry, Variant: o.Variant, Level: o.Level, Column: o.Column,
			Observed: observed(o, r.Manual), Expected: expected(ref, sig, o.Key)})
	}
	data.ExpectedBasis = expectedBasis(ref, sig)
	if data.ExpectedBasis == "" {
		data.ExpectedBasis = toBeWritten
	}

	// The same defect elsewhere: the original and the group's records, each with its public upstream item. A
	// public draft names nothing from the overlay.
	var fixes []string
	for _, id := range store.IDs() {
		l := store.Records[id]
		o := l.Record
		if l.Overlay && !dr.Overlay || strings.EqualFold(o.Target.Project, r.Family.Project) {
			continue
		}
		if !(sig.Original != nil && id == sig.Original.ID || group != "" && o.DefectGroup == group) {
			continue
		}
		u := ""
		if o.Upstream != nil && strings.HasPrefix(o.Upstream.URL, "https://") {
			u = o.Upstream.URL
		}
		if u == "" {
			if dr.Overlay {
				data.Elsewhere = append(data.Elsewhere, fmt.Sprintf("%s: not yet reported upstream (finding %s)", o.Target.Project, o.ID))
			}
			continue
		}
		line := o.Target.Project + ": " + u
		if o.Target.FixedIn != "" {
			line += ", fixed in " + o.Target.FixedIn
			fixes = append(fixes, u)
		} else if o.Upstream.State == "fix-merged-unreleased" {
			line += ", fix merged, not yet released"
			fixes = append(fixes, u)
		}
		data.Elsewhere = append(data.Elsewhere, line)
	}
	if sig.Original == nil && sig.Public {
		data.Elsewhere = append([]string{sig.Project + ": " + sig.Reference}, data.Elsewhere...)
		fixes = append(fixes, sig.Reference)
	}
	if len(fixes) > 0 {
		data.SuggestedFix = "Compare the way the fixed SDKs do; see " + strings.Join(fixes, ", ") + "."
	}

	var classes []string
	for _, o := range r.Matches {
		if w := verdictWords[o.Verdict]; w != "" {
			classes = appendUnique(classes, w)
		}
	}
	verb := "shows"
	if !data.Executed {
		verb = "by its source, shows"
	}
	data.Summary = fmt.Sprintf("%s %s %s this on the corpus cells below: the SDK %s.", r.Family.Package, strings.Join(data.Versions, ", "), verb,
		strings.Join(classes, ", and "))
	if len(fixes) > 0 {
		data.Summary += " Other SDKs had the same defect and fixed it (below)."
	}

	columns := "--columns " + r.LatestColumns[0] + " "
	switch {
	case r.Manual != nil:
		data.Corpus = []string{"# The kit has no driver for this SDK; these run the same cells on the SDKs it has drivers for:"}
		columns = ""
	case !dr.Overlay && publicColumn != nil && !publicColumn(r.LatestColumns[0]):
		// A column only the overlay's sets file adds cannot be run from the public repository: a public draft
		// names the cells and says who runs them, and gives no command a reader could not run.
		data.Corpus = []string{fmt.Sprintf("# The kit's %s column is run by the maintainer outside the public repository; the cells above come from that run.", r.LatestColumns[0])}
		return data
	}
	for _, o := range r.Matches {
		data.Corpus = appendUnique(data.Corpus, fmt.Sprintf("xdrcheck conform run %s--entries %s --levels %s --report out/", columns, o.Entry, o.Level))
	}
	return data
}

// command is the line that would file the draft. It is returned as text; nothing runs it.
func command(dr *Draft, data *DraftData, d *Decision) string {
	switch dr.Kind {
	case "private-report":
		rendered, err := findings.RenderIssue(dr.Record, "findings/"+dr.Record.ID)
		if err == nil {
			return rendered.Command
		}
		return "# private report — embargoed: do not open a public issue, comment or pull request"
	case KindComment:
		verb := "issue"
		if d.Target.PullRequest {
			verb = "pr"
		}
		return fmt.Sprintf("gh %s comment %d --repo %s --body-file %s", verb, d.Target.Number, d.Target.Repo, shellQuote(dr.BodyPath))
	}
	return fmt.Sprintf("gh issue create --repo %s --title %s --body-file %s", dr.Record.Target.Project, shellQuote(data.Title), shellQuote(dr.BodyPath))
}

func notes(r *Result, d *Decision, dr *Draft) []string {
	var n []string
	if r.Manual != nil && !r.Manual.Executed() {
		n = append(n, "evidence is a source reading, not an execution: reproduce it before the record leaves candidate")
	}
	for _, it := range d.Possible {
		kind := "issue"
		if it.PullRequest {
			kind = "pull request"
		}
		n = append(n, fmt.Sprintf("possibly related open %s %s: %s", kind, it.URL, it.Title))
	}
	for _, o := range r.Other {
		n = append(n, fmt.Sprintf("%s also fails %s with a different verdict (%s)", o.Column, o.Key, o.Verdict))
	}
	if dr.Overlay && dr.Record.Visibility != "embargoed" {
		n = append(n, "unreported defect: this draft stays in the private overlay until a maintainer approves it")
	}
	return n
}

// shellQuote quotes s for a POSIX shell: plain words stay bare; anything else goes in double quotes with ", \,
// $ and ` escaped.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")
	return `"` + r.Replace(s) + `"`
}

// Apply writes the plan: each record (validated against the record schema) and its draft body, public ones in
// the repository's findings/ and overlay ones in the overlay's. It refuses before writing anything when a draft
// belongs in the overlay and the store has none.
func Apply(store *findings.Store, p *Plan) ([]string, error) {
	for _, dr := range p.Drafts {
		if dr.Overlay && store.OverlayDir == "" {
			return nil, fmt.Errorf("the %s draft (%s) has no confirmed public upstream item, so it belongs in the private overlay: %w; give --overlay DIR",
				dr.SDK, dr.Record.ID, errNoOverlay)
		}
	}
	var written []string
	for _, dr := range p.Drafts {
		recPath, err := store.Write(dr.Record, dr.Overlay)
		if err != nil {
			return written, err
		}
		body := filepath.Join(filepath.Dir(recPath), dr.File)
		if err := os.WriteFile(body, []byte(dr.Body), 0o644); err != nil {
			return written, err
		}
		written = append(written, recPath, body)
	}
	return written, nil
}
