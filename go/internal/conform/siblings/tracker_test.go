package siblings

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// githubFixture serves the three read-only endpoints the tracker uses from fixed JSON, and records every
// request it sees.
func githubFixture(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/search/issues":
			if !strings.HasPrefix(r.URL.Query().Get("q"), "repo:Beans-BV/dotnet-stellar-sdk ") {
				w.Write([]byte(`{"items":[]}`))
				return
			}
			w.Write([]byte(`{"total_count":2,"items":[
				{"number":272,"title":"fix: liquidity pool parameters ordering","state":"open","html_url":"x","closed_at":null,"pull_request":{"merged_at":null}},
				{"number":257,"title":"Liquidity pool parameters reject the asset order","state":"open","html_url":"x","closed_at":null}]}`))
		case "/repos/Beans-BV/dotnet-stellar-sdk/issues/257":
			w.Write([]byte(`{"number":257,"title":"Liquidity pool parameters reject the asset order","state":"open","closed_at":null}`))
		case "/repos/lightsail-network/java-stellar-sdk/issues/832":
			w.Write([]byte(`{"number":832,"title":"fix","state":"closed","closed_at":"2026-11-05T09:00:00Z","pull_request":{"merged_at":"2026-11-05T09:00:00Z"}}`))
		case "/repos/lightsail-network/java-stellar-sdk/releases/latest":
			w.Write([]byte(`{"tag_name":"6.0.0","published_at":"2026-10-28T12:00:00Z","html_url":"x"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestGitHubTracker(t *testing.T) {
	srv, seen := githubFixture(t)
	gh := NewGitHub(srv.URL)
	ctx := context.Background()

	hits, err := gh.Search(ctx, "Beans-BV/dotnet-stellar-sdk", "liquidity pool asset order")
	if err != nil || len(hits) != 2 || !hits[0].PullRequest || hits[0].URL != "https://github.com/Beans-BV/dotnet-stellar-sdk/pull/272" || hits[1].PullRequest {
		t.Fatalf("search: %v %+v", err, hits)
	}
	it, err := gh.Item(ctx, "lightsail-network/java-stellar-sdk", 832)
	if err != nil || !it.Merged() || it.URL != "https://github.com/lightsail-network/java-stellar-sdk/pull/832" {
		t.Fatalf("item: %v %+v", err, it)
	}
	if _, err := gh.Item(ctx, "lightsail-network/java-stellar-sdk", 1); err == nil {
		t.Error("a missing item is not an error")
	}
	rel, err := gh.LatestRelease(ctx, "lightsail-network/java-stellar-sdk")
	if err != nil || rel.Tag != "6.0.0" {
		t.Fatalf("release: %v %+v", err, rel)
	}
	if rel, err := gh.LatestRelease(ctx, "x/none"); err != nil || rel != nil {
		t.Errorf("no release: %v %+v", err, rel)
	}
	for _, s := range *seen {
		if !strings.HasPrefix(s, "GET ") || !strings.HasSuffix(s, " auth=") {
			t.Errorf("request %s: only unauthenticated GETs are allowed", s)
		}
	}
}

// The transport refuses anything but an unauthenticated GET before it leaves the process.
func TestReadOnlyTransport(t *testing.T) {
	srv, seen := githubFixture(t)
	gh := NewGitHub(srv.URL)
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, srv.URL+"/repos/a/b/issues/1/comments", strings.NewReader(`{"body":"x"}`))
		if _, err := gh.Client.Do(req); !errors.Is(err, ErrNotReadOnly) {
			t.Errorf("%s: %v", method, err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/search/issues", nil)
	req.Header.Set("Authorization", "token x")
	if _, err := gh.Client.Do(req); !errors.Is(err, ErrNotReadOnly) {
		t.Errorf("authenticated GET: %v", err)
	}
	if len(*seen) != 0 {
		t.Errorf("refused requests reached the server: %v", *seen)
	}
}

// The whole sibling run against the HTTP fixture: the same drafts as with the fake tracker.
func TestRunOverHTTP(t *testing.T) {
	srv, seen := githubFixture(t)
	store := newStore(t, issuerRecords, nil, true)
	m := fixtureMatrix(t)
	sig, _ := FromFinding(m, store.Records["F-0016"])
	p := run(t, NewGitHub(srv.URL), store, sig, m, []*Manual{dotnetEvidence(t)}, Options{})
	if len(p.Drafts) != 2 || draftOf(p, "java").Kind != KindRelease || draftOf(p, "dotnet").Kind != KindComment {
		t.Fatalf("drafts %+v", p.Drafts)
	}
	for _, s := range *seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("request %s", s)
		}
	}
}
