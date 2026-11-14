package pins

// Latest published versions of the pins that follow an upstream release.
//
// A pin that tracks a published package carries a comment on the line above it, in the format Renovate's
// regex manager reads (renovate.json), so the bot and `xdrcheck pins latest` see the same list:
//
//	# renovate: datasource=npm depName=@stellar/stellar-sdk
//	stellar_sdk = "17.4.0"
//
// Optional fields: versioning=<scheme> (Renovate only) and extractVersion=<regexp with a "version" group>,
// which turns a tag into a version (stellar-core's tag v30.0.0 is the pin 30.0.0). Datasources looked up here:
// npm, pypi, go (the module proxy), crate (crates.io), github-tags and github-releases (both read the
// repository's tags with `git ls-remote`, which needs no token and has no API rate limit; the newest stable
// tag stands for the newest release). Every lookup is a read-only GET or ls-remote of a public source.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Tracked is one annotated pin.
type Tracked struct {
	Key            string `json:"key"` // dotted pins.toml key, for example js.stellar_sdk
	Line           int    `json:"line"`
	Datasource     string `json:"datasource"`
	DepName        string `json:"dep_name"`
	ExtractVersion string `json:"extract_version,omitempty"`
	Current        string `json:"current"`
}

var (
	annotationRE = regexp.MustCompile(`^\s*#\s*renovate:\s*(.+?)\s*$`)
	sectionRE    = regexp.MustCompile(`^\s*\[\[?([A-Za-z0-9_."-]+)\]\]?\s*(#.*)?$`)
	assignRE     = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"`)
)

// TrackedPins reads the annotated pins from the text of a pins file. An annotation not followed by a
// `key = "value"` line, or without datasource or depName, is an error.
func TrackedPins(text string) ([]Tracked, error) {
	var out []Tracked
	section := ""
	var pending *Tracked
	sc := bufio.NewScanner(strings.NewReader(text))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if m := annotationRE.FindStringSubmatch(line); m != nil {
			t := Tracked{Line: n}
			for _, f := range strings.Fields(m[1]) {
				k, v, ok := strings.Cut(f, "=")
				if !ok {
					return nil, fmt.Errorf("line %d: renovate annotation field %q is not key=value", n, f)
				}
				switch k {
				case "datasource":
					t.Datasource = v
				case "depName":
					t.DepName = v
				case "extractVersion":
					t.ExtractVersion = v
				case "versioning":
				default:
					return nil, fmt.Errorf("line %d: unknown renovate annotation field %q", n, k)
				}
			}
			if t.Datasource == "" || t.DepName == "" {
				return nil, fmt.Errorf("line %d: renovate annotation needs datasource and depName", n)
			}
			if t.ExtractVersion != "" {
				re, err := regexp.Compile(t.ExtractVersion)
				if err != nil || re.SubexpIndex("version") < 0 {
					return nil, fmt.Errorf("line %d: extractVersion %q is not a regexp with a version group", n, t.ExtractVersion)
				}
			}
			pending = &t
			continue
		}
		if m := sectionRE.FindStringSubmatch(line); m != nil {
			if pending != nil {
				return nil, fmt.Errorf("line %d: renovate annotation is not followed by a pin", pending.Line)
			}
			section = m[1]
			continue
		}
		if pending == nil {
			continue
		}
		m := assignRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d: renovate annotation is not followed by a key = \"value\" line", pending.Line)
		}
		pending.Key = section + "." + m[1]
		pending.Current = m[2]
		pending.Line = n
		out = append(out, *pending)
		pending = nil
	}
	if pending != nil {
		return nil, fmt.Errorf("line %d: renovate annotation at the end of the file", pending.Line)
	}
	return out, sc.Err()
}

// Registries are the endpoints the lookups use; tests point them at a local server.
type Registries struct {
	NPM, PyPI, GoProxy, Crates string
	// Tags lists a GitHub repository's tags (owner/name); the default runs git ls-remote.
	Tags   func(ctx context.Context, repo string) ([]string, error)
	Client *http.Client
}

// DefaultRegistries are the public registries.
func DefaultRegistries() *Registries {
	return &Registries{
		NPM:     "https://registry.npmjs.org",
		PyPI:    "https://pypi.org",
		GoProxy: "https://proxy.golang.org",
		Crates:  "https://crates.io",
		Tags:    gitTags,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func gitTags(ctx context.Context, repo string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--tags", "--refs", "https://github.com/"+repo).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote %s: %v", repo, err)
	}
	var tags []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			tags = append(tags, strings.TrimPrefix(f[1], "refs/tags/"))
		}
	}
	return tags, nil
}

func (r *Registries) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// crates.io refuses requests without a User-Agent; this one names no person or project.
	req.Header.Set("User-Agent", "pins-latest-check (read-only)")
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("GET %s: %v", url, err)
	}
	return nil
}

// Latest looks up the newest stable published version of t.
func (r *Registries) Latest(ctx context.Context, t Tracked) (string, error) {
	switch t.Datasource {
	case "npm":
		var v struct {
			Version string `json:"version"`
		}
		err := r.getJSON(ctx, r.NPM+"/"+t.DepName+"/latest", &v)
		return v.Version, err
	case "pypi":
		var v struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
		err := r.getJSON(ctx, r.PyPI+"/pypi/"+t.DepName+"/json", &v)
		return v.Info.Version, err
	case "go":
		var v struct {
			Version string `json:"Version"`
		}
		err := r.getJSON(ctx, r.GoProxy+"/"+escapeModule(t.DepName)+"/@latest", &v)
		return v.Version, err
	case "crate":
		var v struct {
			Crate struct {
				MaxStableVersion string `json:"max_stable_version"`
			} `json:"crate"`
		}
		err := r.getJSON(ctx, r.Crates+"/api/v1/crates/"+t.DepName, &v)
		return v.Crate.MaxStableVersion, err
	case "github-tags", "github-releases":
		tags, err := r.Tags(ctx, t.DepName)
		if err != nil {
			return "", err
		}
		return NewestStable(tags, t.ExtractVersion, t.Current)
	}
	return "", fmt.Errorf("datasource %q is not looked up by xdrcheck pins latest", t.Datasource)
}

// escapeModule is the module proxy's case encoding (an upper-case letter is "!" and the letter).
func escapeModule(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

var stableTagRE = regexp.MustCompile(`^v?(\d+(?:\.\d+){1,2})$`)

// NewestStable picks the highest stable version among tags. With extract, a tag counts only when it matches
// and the version is its "version" group; without, a tag counts when it is a plain version (v30.0.1, 30.0.1,
// v30.0) and keeps the current pin's form (a leading v or not).
func NewestStable(tags []string, extract, current string) (string, error) {
	var re *regexp.Regexp
	if extract != "" {
		re = regexp.MustCompile(extract)
	}
	best, bestKey := "", []int(nil)
	for _, tag := range tags {
		v := ""
		if re != nil {
			m := re.FindStringSubmatch(tag)
			if m == nil {
				continue
			}
			v = m[re.SubexpIndex("version")]
			if !stableTagRE.MatchString(v) {
				continue
			}
		} else {
			if !stableTagRE.MatchString(tag) {
				continue
			}
			v = strings.TrimPrefix(tag, "v")
			if strings.HasPrefix(current, "v") {
				v = "v" + v
			}
		}
		k := versionKey(v)
		if bestKey == nil || CompareVersions(k, bestKey) > 0 {
			best, bestKey = v, k
		}
	}
	if best == "" {
		return "", fmt.Errorf("no stable tag among %d tags", len(tags))
	}
	return best, nil
}

// versionKey is the numeric parts of a version (v1.2.3-rc.1 is 1 2 3; the pre-release is ignored).
func versionKey(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var k []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		k = append(k, n)
	}
	return k
}

// CompareVersions compares two version keys part by part (a missing part is 0).
func CompareVersions(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Behind reports whether latest is a newer version than current. A pre-release pin is behind the release of
// the same number (30.0.0-rc.1 is behind 30.0.0).
func Behind(current, latest string) bool {
	switch CompareVersions(versionKey(latest), versionKey(current)) {
	case 1:
		return true
	case 0:
		return strings.Contains(current, "-") && !strings.Contains(latest, "-")
	}
	return false
}
