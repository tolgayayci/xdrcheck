package siblings

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
)

// Draft kinds, as the record's issue_draft.kind spells them.
const (
	KindComment = "comment-on-existing"
	KindRelease = "release-request"
	KindNew     = "new-issue"
)

// Decision is the outcome of de-duplicating one affected family against its tracker.
type Decision struct {
	Kind         string // KindComment, KindRelease, KindNew, or "" for no draft
	Why          string
	Target       *Item    // the item to comment on, or the merged fix a release request cites
	Release      *Release // the latest release, when a merged fix was checked against it
	Confirmed    []Item   // items confirmed to describe this defect, with their state today
	Possible     []Item   // open search hits not confirmed: possible duplicates for the reviewer
	Queries      []string // what was looked up, in a form a reviewer can repeat
	SearchResult string   // record upstream_search.result: none-found, existing-open, existing-closed, fix-merged-unreleased
	PublicItem   bool     // a confirmed public upstream item exists
	Searched     bool     // a tracker search was made (false offline)
}

// DedupOptions are the inputs of de-duplication besides the family.
type DedupOptions struct {
	Queries []string // search terms; default: derived from the draft title
	Confirm []string // item URLs a person confirmed describe this defect
	Offline bool     // the tracker is the recorded one: nothing was searched
}

// knownItems are the item URLs on the family's own tracker that are known to describe this defect.
func knownItems(r *Result, confirm []string) []string {
	var out []string
	add := func(u string) {
		if repo, _, _, ok := ParseItemURL(u); ok && strings.EqualFold(repo, r.Family.Project) {
			out = appendUnique(out, strings.TrimSuffix(u, "/"))
		}
	}
	for _, o := range append(append([]Observation{}, r.Matches...), r.Earlier...) {
		add(o.Reference)
	}
	if l := r.Record; l != nil {
		rec := l.Record
		if rec.Upstream != nil {
			add(rec.Upstream.URL)
		}
		if rec.UpstreamSearch != nil {
			add(rec.UpstreamSearch.Existing)
		}
		for _, u := range rec.Related {
			add(u)
		}
	}
	if r.Manual != nil {
		for _, u := range r.Manual.Upstream {
			add(u)
		}
	}
	for _, u := range confirm {
		add(u)
	}
	return out
}

// Dedup de-duplicates an affected family against its tracker and decides the kind of draft.
func Dedup(ctx context.Context, tr Tracker, r *Result, title string, o DedupOptions) (*Decision, error) {
	d := &Decision{Searched: !o.Offline}
	repo := r.Family.Project
	if l := r.Record; l != nil {
		rec := l.Record
		switch {
		case rec.State == "filed":
			d.Why = "already filed"
			if rec.Upstream != nil && rec.Upstream.URL != "" {
				d.Why += " as " + rec.Upstream.URL
			}
			return d, nil
		case rec.Upstream != nil && rec.Upstream.EvidenceAdded != nil && rec.Upstream.EvidenceAdded.Kind == "comment":
			d.Why = "evidence already added at " + rec.Upstream.EvidenceAdded.URL
			return d, nil
		}
	}

	for _, u := range knownItems(r, o.Confirm) {
		_, n, _, _ := ParseItemURL(u)
		it, err := tr.Item(ctx, repo, n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		if it == nil { // offline, and no state is recorded for it
			continue
		}
		d.Confirmed = append(d.Confirmed, *it)
		d.Queries = append(d.Queries, u)
	}
	terms := o.Queries
	if len(terms) == 0 {
		terms = []string{SearchTerms(title)}
	}
	if !o.Offline {
		for _, t := range terms {
			if t == "" {
				continue
			}
			hits, err := tr.Search(ctx, repo, t)
			if err != nil {
				return nil, fmt.Errorf("search %s for %q: %w", repo, t, err)
			}
			d.Queries = append(d.Queries, SearchURL(repo, t))
			for _, h := range hits {
				if h.State == "open" && !containsItem(d.Confirmed, h) && !containsItem(d.Possible, h) {
					d.Possible = append(d.Possible, h)
				}
			}
		}
	}
	sortItems(d.Confirmed)
	sortItems(d.Possible)
	defer func() { d.PublicItem = d.Kind == KindComment || d.Kind == KindRelease }()

	var openIssue, openPR, merged, closed *Item
	for i := range d.Confirmed {
		it := &d.Confirmed[i]
		switch {
		case it.State == "open" && !it.PullRequest && openIssue == nil:
			openIssue = it
		case it.State == "open" && it.PullRequest && openPR == nil:
			openPR = it
		case it.Merged() && (merged == nil || it.MergedAt > merged.MergedAt):
			merged = it
		case it.State == "closed" && closed == nil:
			closed = it
		}
	}

	regressed := false
	if merged != nil {
		rel, err := tr.LatestRelease(ctx, repo)
		if err != nil {
			return nil, fmt.Errorf("latest release of %s: %w", repo, err)
		}
		d.Release = rel
		switch {
		case rel != nil && after(rel.PublishedAt, merged.MergedAt) && newerVersion(rel.Tag, r.Latest):
			d.Why = fmt.Sprintf("the fix %s (merged %s) is in release %s (%s), newer than the %s checked; add a column for it and run again",
				merged.URL, day(merged.MergedAt), rel.Tag, day(rel.PublishedAt), r.Latest)
			return d, nil
		case rel != nil && after(rel.PublishedAt, merged.MergedAt):
			// The release that was checked contains the fix and still shows the defect: the fix did not hold.
			regressed = true
			if closed == nil {
				closed = merged
			}
		default:
			d.Kind, d.Target, d.SearchResult = KindRelease, merged, "fix-merged-unreleased"
			if rel != nil {
				d.Why = fmt.Sprintf("the fix %s was merged %s, after the latest release %s (%s)", merged.URL, day(merged.MergedAt), rel.Tag, day(rel.PublishedAt))
			} else {
				d.Why = fmt.Sprintf("the fix %s is merged and %s still shows the defect; no release information was available, so confirm that no newer release contains it", merged.URL, r.Latest)
			}
			return d, nil
		}
	}
	if target := firstNonNil(openIssue, openPR); target != nil {
		d.Kind, d.Target, d.SearchResult = KindComment, target, "existing-open"
		d.Why = fmt.Sprintf("%s is open; add the evidence there instead of opening a new issue", target.URL)
		return d, nil
	}
	d.Kind = KindNew
	if closed != nil {
		d.Target, d.SearchResult = closed, "existing-closed"
		d.Why = fmt.Sprintf("%s is closed but %s still shows the defect", closed.URL, r.Latest)
		if regressed {
			d.Why = fmt.Sprintf("the fix %s is in the release checked, %s, which still shows the defect", closed.URL, r.Latest)
		}
		d.Why += "; a new issue is an unreported defect and is drafted in the private overlay"
		return d, nil
	}
	d.SearchResult = "none-found"
	d.Why = "no upstream item is known to describe this defect; the new issue is drafted in the private overlay"
	if len(d.Possible) > 0 {
		d.Why += fmt.Sprintf("; %d open item(s) found by search may be duplicates: confirm one with --confirm URL", len(d.Possible))
	}
	return d, nil
}

func containsItem(list []Item, it Item) bool {
	for _, x := range list {
		if x.Repo == it.Repo && x.Number == it.Number {
			return true
		}
	}
	return false
}

func firstNonNil(items ...*Item) *Item {
	for _, it := range items {
		if it != nil {
			return it
		}
	}
	return nil
}

// newerVersion reports whether release tag is a later version than checked (a leading v is ignored). Tags
// that are not versions count as newer unless they equal checked, so that an unknown release is never taken
// as already checked.
func newerVersion(tag, checked string) bool {
	a, b := strings.TrimPrefix(tag, "v"), strings.TrimPrefix(checked, "v")
	d, err := verdict.CompareVersions(a, b)
	if err != nil {
		return a != b
	}
	return d > 0
}

// after reports whether time a is later than time b (RFC 3339); unparsable times are not later.
func after(a, b string) bool {
	ta, err1 := time.Parse(time.RFC3339, a)
	tb, err2 := time.Parse(time.RFC3339, b)
	return err1 == nil && err2 == nil && ta.After(tb)
}

// day is the date part of an RFC 3339 time.
func day(t string) string {
	if len(t) >= 10 && t[4] == '-' {
		return t[:10]
	}
	return t
}

var stopWords = map[string]bool{"the": true, "and": true, "for": true, "are": true, "not": true, "with": true, "its": true, "from": true,
	"that": true, "this": true, "than": true, "into": true, "instead": true, "compared": true, "when": true, "but": true}

// SearchTerms derives tracker search terms from a title: its first four significant words.
func SearchTerms(title string) string {
	if i := strings.IndexAny(title, ":;("); i > 0 {
		title = title[:i]
	}
	var words []string
	for _, w := range strings.FieldsFunc(strings.ToLower(title), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(w) < 3 || stopWords[w] {
			continue
		}
		words = append(words, w)
		if len(words) == 4 {
			break
		}
	}
	return strings.Join(words, " ")
}
