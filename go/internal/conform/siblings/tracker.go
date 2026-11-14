package siblings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Item is one issue or pull request on an upstream tracker.
type Item struct {
	Repo        string // owner/name
	Number      int
	URL         string // https://github.com/<repo>/issues/<n> or /pull/<n>
	Title       string
	PullRequest bool
	State       string // open, closed
	MergedAt    string // RFC 3339; set only for a merged pull request
	ClosedAt    string
}

// Merged reports whether the item is a merged pull request.
func (i *Item) Merged() bool { return i.PullRequest && i.MergedAt != "" }

// Release is a project's latest published release.
type Release struct {
	Tag         string
	PublishedAt string // RFC 3339
	URL         string
}

// Tracker is read-only access to an upstream tracker. Implementations never create, comment on, react to or
// change anything.
type Tracker interface {
	// Search returns the issues and pull requests of repo that match terms.
	Search(ctx context.Context, repo, terms string) ([]Item, error)
	// Item returns one issue or pull request.
	Item(ctx context.Context, repo string, number int) (*Item, error)
	// LatestRelease returns the latest published release, or nil when the project publishes none.
	LatestRelease(ctx context.Context, repo string) (*Release, error)
}

var itemURL = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(issues|pull)/([0-9]+)$`)

// ParseItemURL splits a GitHub issue or pull request URL into repository and number.
func ParseItemURL(u string) (repo string, number int, pull bool, ok bool) {
	m := itemURL.FindStringSubmatch(strings.TrimSuffix(u, "/"))
	if m == nil {
		return "", 0, false, false
	}
	n, err := strconv.Atoi(m[3])
	if err != nil {
		return "", 0, false, false
	}
	return m[1], n, m[2] == "pull", true
}

// SearchURL is the web form of a tracker search, stored in a record so that a reviewer can repeat it.
func SearchURL(repo, terms string) string {
	return "https://github.com/search?type=issues&q=" + url.QueryEscape("repo:"+repo+" "+terms)
}

// DefaultAPI is the GitHub REST API.
const DefaultAPI = "https://api.github.com"

// GitHub reads issues, pull requests and releases from the GitHub REST API without credentials: every request
// is an unauthenticated GET, so it can read public data and nothing else. The anonymous rate limit (60 requests
// an hour, 10 searches a minute) is enough for a sibling run, which makes a handful of requests per affected SDK.
type GitHub struct {
	API    string // base URL, DefaultAPI unless a test points it at a fixture server
	Client *http.Client
}

// NewGitHub returns a read-only GitHub tracker on api (DefaultAPI when empty).
func NewGitHub(api string) *GitHub {
	if api == "" {
		api = DefaultAPI
	}
	return &GitHub{API: strings.TrimSuffix(api, "/"), Client: &http.Client{Timeout: 30 * time.Second, Transport: readOnly{http.DefaultTransport}}}
}

// readOnly refuses every request that is not a GET and every request that carries credentials.
type readOnly struct{ next http.RoundTripper }

// ErrNotReadOnly is returned for a request the tracker must never make.
var ErrNotReadOnly = errors.New("refused: the tracker client only makes unauthenticated GET requests")

func (r readOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || req.Header.Get("Authorization") != "" || req.URL.User != nil {
		return nil, fmt.Errorf("%w (%s %s)", ErrNotReadOnly, req.Method, req.URL.Path)
	}
	return r.next.RoundTrip(req)
}

type ghIssue struct {
	Number      int     `json:"number"`
	Title       string  `json:"title"`
	State       string  `json:"state"`
	HTMLURL     string  `json:"html_url"`
	ClosedAt    *string `json:"closed_at"`
	PullRequest *struct {
		MergedAt *string `json:"merged_at"`
	} `json:"pull_request"`
}

func (g *ghIssue) item(repo string) Item {
	it := Item{Repo: repo, Number: g.Number, Title: g.Title, State: g.State, URL: g.HTMLURL}
	if g.ClosedAt != nil {
		it.ClosedAt = *g.ClosedAt
	}
	if g.PullRequest != nil {
		it.PullRequest = true
		if g.PullRequest.MergedAt != nil {
			it.MergedAt = *g.PullRequest.MergedAt
		}
	}
	kind := "issues"
	if it.PullRequest {
		kind = "pull"
	}
	it.URL = fmt.Sprintf("https://github.com/%s/%s/%d", repo, kind, g.Number)
	return it
}

// get fetches path under the API into v. A 404 returns found=false.
func (g *GitHub) get(ctx context.Context, path string, query url.Values, v any) (found bool, err error) {
	u := g.API + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return false, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return false, fmt.Errorf("GET %s: %s: %s", path, resp.Status, msg)
	}
	return true, json.Unmarshal(body, v)
}

// Search implements Tracker.
func (g *GitHub) Search(ctx context.Context, repo, terms string) ([]Item, error) {
	var res struct {
		Items []ghIssue `json:"items"`
	}
	q := url.Values{"q": {"repo:" + repo + " " + terms}, "per_page": {"20"}}
	if _, err := g.get(ctx, "/search/issues", q, &res); err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(res.Items))
	for i := range res.Items {
		out = append(out, res.Items[i].item(repo))
	}
	return out, nil
}

// Item implements Tracker. The issues endpoint serves pull requests too and reports merged_at for them.
func (g *GitHub) Item(ctx context.Context, repo string, number int) (*Item, error) {
	var gi ghIssue
	found, err := g.get(ctx, fmt.Sprintf("/repos/%s/issues/%d", repo, number), nil, &gi)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s#%d: not found", repo, number)
	}
	it := gi.item(repo)
	return &it, nil
}

// LatestRelease implements Tracker.
func (g *GitHub) LatestRelease(ctx context.Context, repo string) (*Release, error) {
	var r struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		HTMLURL     string `json:"html_url"`
	}
	found, err := g.get(ctx, "/repos/"+repo+"/releases/latest", nil, &r)
	if err != nil || !found {
		return nil, err
	}
	return &Release{Tag: r.TagName, PublishedAt: r.PublishedAt, URL: r.HTMLURL}, nil
}

// Recorded answers from what the kit already knows, without any network access: the upstream items and states
// stored in finding records, the matrix's known divergences and the manual evidence. It finds nothing by
// search and knows no releases, so a run with it (--offline) reports upstream states as recorded, not as
// checked today.
type Recorded struct {
	Items map[string]Item // by URL
}

// Search implements Tracker: an offline run finds nothing new.
func (r *Recorded) Search(context.Context, string, string) ([]Item, error) { return nil, nil }

// Item implements Tracker. An item with no recorded state is unknown (nil) and does not count.
func (r *Recorded) Item(_ context.Context, repo string, number int) (*Item, error) {
	for _, it := range r.Items {
		if it.Repo == repo && it.Number == number {
			it := it
			return &it, nil
		}
	}
	return nil, nil
}

// LatestRelease implements Tracker: unknown offline.
func (r *Recorded) LatestRelease(context.Context, string) (*Release, error) { return nil, nil }

// Add records an item's state from a recorded upstream state (finding record upstream.state, or a known
// divergence status). A state already recorded is kept.
func (r *Recorded) Add(u, state string) {
	repo, n, pull, ok := ParseItemURL(u)
	if !ok {
		return
	}
	if r.Items == nil {
		r.Items = map[string]Item{}
	}
	if _, seen := r.Items[u]; seen {
		return
	}
	it := Item{Repo: repo, Number: n, URL: u, PullRequest: pull, State: "open", Title: "(recorded state)"}
	switch state {
	case "fixed", "fix-merged-unreleased", "fixed_unreleased":
		it.State = "closed"
		if pull {
			it.MergedAt = "(date not checked offline)"
		}
	case "wont-fix", "wont_fix", "closed-other":
		it.State = "closed"
	}
	r.Items[u] = it
}

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		return items[i].Number < items[j].Number
	})
}
