package xdrdef

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The upgrade watch: every source of not-yet-released XDR, diffed against the pinned definitions.
//
//	main      stellar-xdr main with every #ifdef on, against the pinned commit with none on: what the next
//	          protocol adds, each change attributed to its gate and CAP
//	branch    every other branch of stellar-xdr (not curr or next, which main generates), against its merge
//	          base with main, both with every feature on: what the branch would add
//	pr        every open pull request, the same way (a pull request whose head is a branch is reported once,
//	          on the branch)
//	cap       the XDR diff inside every CAP document of stellar-protocol that is not yet Implemented or Final,
//	          applied to the stellar-xdr commit the document names (`mddiffcheck.base=`), against that commit
//	standing  branches watched by name whether or not they changed (default lcm_v3: LedgerCloseMeta v3), with
//	          their state: open, merged into main, or gone
//
// Output, under the output directory: watch-log.jsonl (the previous log's lines, then one line per item of
// this run), digest.md (everything), digest-p<N>.md (one per upcoming protocol, the body of that protocol's
// tracking issue), caps.json (the preamble of every CAP the items name), candidates.txt (the diff reports the
// candidate rows are made from: main and the CAP documents), items.json, and diffs/<item>.{json,md}.
//
// A source that cannot be read is an item with status `blocked`; findings never make the run fail.

// WatchConfig configures a watch run.
type WatchConfig struct {
	XDR      *Repo
	Protocol *Repo
	// RepoSlug is the XDR repository on GitHub (owner/name), for the pull-request listing.
	RepoSlug string
	API      string
	Token    string
	// Pinned is the pinned stellar-xdr commit, PinnedLabel its tag.
	Pinned, PinnedLabel string
	NextProtocol        int
	Standing            []string
	// Skip names parts not to run: main, branches, prs, caps.
	Skip     map[string]bool
	Out      string
	Previous string
	Now      time.Time
	HTTP     *http.Client

	protocolCommit string
}

// WatchItem is one watched source.
type WatchItem struct {
	Time          string   `json:"time"`
	Kind          string   `json:"kind"`
	Name          string   `json:"name"`
	Title         string   `json:"title,omitempty"`
	URL           string   `json:"url,omitempty"`
	Ref           string   `json:"ref,omitempty"`
	Commit        string   `json:"commit,omitempty"`
	BaseCommit    string   `json:"base_commit,omitempty"`
	Updated       string   `json:"updated,omitempty"`
	Status        string   `json:"status"`
	Detail        string   `json:"detail,omitempty"`
	Protocol      int      `json:"protocol"`
	CAPs          []string `json:"caps"`
	Changes       int      `json:"changes"`
	ReaderChanges int      `json:"reader_changes"`
	NewArms       []string `json:"new_arms"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	// New is true when no earlier line of the log has this item with this fingerprint.
	New    bool   `json:"new"`
	Report string `json:"report,omitempty"`
}

// WatchResult is what a run produced.
type WatchResult struct {
	Items     []*WatchItem
	CAPs      map[string]CAPInfo
	Protocols []int
}

var (
	capPreamble = regexp.MustCompile(`(?m)^(Title|Status|Protocol version):\s*(.*?)\s*$`)
	capDiff     = regexp.MustCompile("(?s)```diff([^\n]*)\n(.*?)```")
	diffBase    = regexp.MustCompile(`mddiffcheck\.base=([0-9a-f]{7,40})`)
	capFileName = regexp.MustCompile(`^core/cap-(\d{4})\.md$`)
)

// doneStatus are CAP statuses whose XDR is already merged or will never be.
var doneStatus = []string{"final", "implemented", "rejected", "abandoned", "superseded", "obsolete", "withdrawn"}

// ParseCAPPreamble reads a CAP document's title, status and protocol.
func ParseCAPPreamble(text string) CAPInfo {
	var c CAPInfo
	head := text
	if len(head) > 4000 {
		head = head[:4000]
	}
	for _, m := range capPreamble.FindAllStringSubmatch(head, -1) {
		switch m[1] {
		case "Title":
			if c.Title == "" {
				c.Title = m[2]
			}
		case "Status":
			if c.Status == "" {
				c.Status = m[2]
			}
		case "Protocol version":
			if c.Protocol == "" {
				c.Protocol = m[2]
			}
		}
	}
	return c
}

// CAPXDRPatches extracts the XDR patches of a CAP document: each ```diff block that touches a .x file, with
// the stellar-xdr commit it says it is based on ("" when it names none).
func CAPXDRPatches(text string) (patches []string, bases []string) {
	for _, m := range capDiff.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[2], ".x\n") && !strings.Contains(m[2], ".x\t") {
			continue
		}
		patches = append(patches, m[2])
		b := ""
		if bm := diffBase.FindStringSubmatch(m[1]); bm != nil {
			b = bm[1]
		}
		bases = append(bases, b)
	}
	return
}

func (c *WatchConfig) skip(part string) bool { return c.Skip[part] }

// Watch runs every part and writes the outputs.
func Watch(c *WatchConfig) (*WatchResult, error) {
	if c.Now.IsZero() {
		c.Now = time.Now().UTC()
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if err := os.MkdirAll(filepath.Join(c.Out, "diffs"), 0o755); err != nil {
		return nil, err
	}
	res := &WatchResult{CAPs: map[string]CAPInfo{}}
	stamp := c.Now.Format(time.RFC3339)
	add := func(it *WatchItem) {
		it.Time = stamp
		if it.CAPs == nil {
			it.CAPs = []string{}
		}
		if it.NewArms == nil {
			it.NewArms = []string{}
		}
		res.Items = append(res.Items, it)
	}
	var candidates []string

	pinned, perr := c.load(c.Pinned)
	if perr != nil {
		return nil, fmt.Errorf("the pinned definitions (%s): %w", short(c.Pinned), perr)
	}
	pinned.Side.Label = c.PinnedLabel

	// CAP documents first: their preambles name the protocol of every gate found later.
	capItems := []*WatchItem{}
	if !c.skip("caps") {
		capItems = c.watchCAPs(res, pinned)
	}

	mainCommit := ""
	if !c.skip("main") {
		it := &WatchItem{Kind: "main", Name: "main", Ref: "main"}
		head, err := c.loadRef("main")
		if err != nil {
			it.Status, it.Detail = "blocked", err.Error()
		} else {
			mainCommit = head.Side.Commit
			it.Commit, it.BaseCommit = head.Side.Commit, c.Pinned
			it.Updated = c.commitDate(head.Side.Commit)
			r, err := DiffInputs(pinned, head, "none", "all", DiffOptions{})
			if err != nil {
				it.Status, it.Detail = "blocked", err.Error()
			} else {
				c.record(it, r, res)
				candidates = append(candidates, it.Report+".json")
			}
		}
		add(it)
	}
	for _, it := range capItems {
		add(it)
		if it.Status == "ok" && it.Report != "" {
			candidates = append(candidates, it.Report+".json")
		}
	}

	heads := map[string]string{}
	if !c.skip("branches") || len(c.Standing) > 0 {
		var err error
		if heads, err = c.XDR.Heads(); err != nil {
			add(&WatchItem{Kind: "branch", Name: "*", Status: "blocked", Detail: err.Error()})
			heads = map[string]string{}
		}
	}
	if mainCommit == "" && heads["main"] != "" {
		if cm, err := c.XDR.Resolve("main"); err == nil {
			mainCommit = cm
		}
	}
	branchOf := map[string]string{}
	if !c.skip("branches") {
		for _, b := range sortedKeys(heads) {
			if b == "main" || b == "curr" || b == "next" || contains(c.Standing, b) {
				continue
			}
			it := c.sideItem("branch", b, b, mainCommit, res)
			branchOf[it.Commit] = b
			add(it)
		}
	}
	for _, b := range c.Standing {
		it := &WatchItem{Kind: "standing", Name: b, Ref: b, Protocol: c.NextProtocol}
		if _, ok := heads[b]; !ok {
			it.Status, it.Detail = "gone", "the branch no longer exists on stellar-xdr"
			add(it)
			continue
		}
		it = c.sideItem("standing", b, b, mainCommit, res)
		if it.Status == "ok" && mainCommit != "" {
			if _, err := c.XDR.git("merge-base", "--is-ancestor", it.Commit, mainCommit); err == nil {
				it.Status, it.Detail = "merged", "the branch head is part of main"
			} else if out, err := c.XDR.git("rev-list", "--left-right", "--count", mainCommit+"..."+it.Commit); err == nil {
				f := strings.Fields(out)
				if len(f) == 2 {
					it.Detail = fmt.Sprintf("open, %s commits ahead of main, %s behind", f[1], f[0])
				}
			}
		}
		branchOf[it.Commit] = b
		add(it)
	}
	if !c.skip("prs") {
		prs, err := c.openPRs()
		if err != nil {
			add(&WatchItem{Kind: "pr", Name: "*", Status: "blocked", Detail: err.Error()})
		}
		for _, pr := range prs {
			name := "#" + strconv.Itoa(pr.Number)
			if b, ok := branchOf[pr.Head.SHA]; ok {
				for _, it := range res.Items {
					if it.Name == b && (it.Kind == "branch" || it.Kind == "standing") {
						it.URL, it.Title = pr.HTMLURL, strings.TrimSpace(it.Title+" (pull request "+name+")")
					}
				}
				continue
			}
			it := c.sideItem("pr", name, "refs/pull/"+strconv.Itoa(pr.Number)+"/head", mainCommit, res)
			it.Title, it.URL = pr.Title, pr.HTMLURL
			add(it)
		}
	}

	// Each item's tracking protocol: the protocol its CAPs name when they agree and it is upcoming, else the
	// next one.
	for _, it := range res.Items {
		if it.Protocol != 0 {
			continue
		}
		it.Protocol = c.NextProtocol
		ps := map[int]bool{}
		for _, cp := range it.CAPs {
			if p, err := strconv.Atoi(res.CAPs[cp].Protocol); err == nil && p >= c.NextProtocol {
				ps[p] = true
			}
		}
		if len(ps) == 1 {
			for p := range ps {
				it.Protocol = p
			}
		}
	}
	return res, c.write(res, candidates)
}

// load reads a commit (or ref) of the XDR repository.
func (c *WatchConfig) load(ref string) (*Input, error) {
	return LoadInput(ref, c.XDR, c.Pinned)
}

func (c *WatchConfig) loadRef(ref string) (*Input, error) {
	in, err := c.load(ref)
	if err != nil {
		return nil, err
	}
	return in, nil
}

// sideItem diffs a branch or pull-request head against its merge base with main, both with every feature on.
func (c *WatchConfig) sideItem(kind, name, ref, mainCommit string, res *WatchResult) *WatchItem {
	it := &WatchItem{Kind: kind, Name: name, Ref: ref}
	head, err := c.loadRef(ref)
	if err != nil {
		it.Status, it.Detail = "blocked", err.Error()
		return it
	}
	it.Commit = head.Side.Commit
	it.Updated = c.commitDate(it.Commit)
	baseRef := mainCommit
	if baseRef == "" {
		baseRef = c.Pinned
	}
	baseLabel := ""
	mb, err := c.XDR.MergeBase(baseRef, it.Commit)
	if err != nil {
		// No common history with main (a pull request from an unrelated fork): compare with the pinned commit.
		mb, baseLabel = c.Pinned, "pinned "+short(c.Pinned)
		it.Detail = "no common history with main; compared with the pinned definitions"
	}
	it.BaseCommit = mb
	base, err := c.load(mb)
	if err != nil {
		it.Status, it.Detail = "blocked", err.Error()
		return it
	}
	base.Side.Label = "merge base " + short(mb)
	if baseLabel != "" {
		base.Side.Label = baseLabel
	}
	head.Side.Label = name
	r, err := DiffInputs(base, head, "all", "all", DiffOptions{})
	if err != nil {
		it.Status, it.Detail = "blocked", err.Error()
		return it
	}
	c.record(it, r, res)
	return it
}

// record fills an item from its diff and writes the diff's JSON and Markdown.
func (c *WatchConfig) record(it *WatchItem, r *Report, res *WatchResult) {
	it.Status = "ok"
	it.Changes = len(r.Changes)
	caps := map[string]bool{}
	h := sha256.New()
	for _, ch := range r.Changes {
		if len(ch.Reach) > 0 {
			it.ReaderChanges++
		}
		for _, cp := range ch.CAPs {
			caps[cp] = true
		}
		fmt.Fprintf(h, "%s|%s|%s|%s|%s\n", ch.Kind, ch.Def, ch.Member, ch.Old, ch.New)
	}
	for _, a := range r.NewArms["LedgerCloseMetaBatch"] {
		it.NewArms = append(it.NewArms, a.ID)
		fmt.Fprintf(h, "arm|%s\n", a.ID)
	}
	it.CAPs = sortedKeys(caps)
	it.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
	for _, cp := range it.CAPs {
		if _, ok := res.CAPs[cp]; !ok {
			if info, ok := c.readCAP(cp); ok {
				res.CAPs[cp] = info
			}
		}
	}
	it.Report = filepath.ToSlash(filepath.Join("diffs", it.Kind+"-"+slug(it.Name)))
	if b, err := json.MarshalIndent(r, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(c.Out, it.Report+".json"), append(b, '\n'), 0o644)
	}
	var md bytes.Buffer
	r.WriteMarkdown(&md, it.Kind+" "+it.Name)
	_ = os.WriteFile(filepath.Join(c.Out, it.Report+".md"), md.Bytes(), 0o644)
}

func (c *WatchConfig) commitDate(commit string) string {
	out, err := c.XDR.git("log", "-1", "--format=%cs", commit)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// protocolHead is the stellar-protocol master commit, fetched once per run.
func (c *WatchConfig) protocolHead() (string, error) {
	if c.protocolCommit != "" {
		return c.protocolCommit, nil
	}
	cm, err := c.Protocol.Resolve("master")
	if err == nil {
		c.protocolCommit = cm
	}
	return cm, err
}

// readCAP reads one CAP's preamble from stellar-protocol.
func (c *WatchConfig) readCAP(cp string) (CAPInfo, bool) {
	if c.Protocol == nil || c.skip("caps") {
		return CAPInfo{}, false
	}
	m := capNum.FindStringSubmatch(cp)
	if m == nil {
		return CAPInfo{}, false
	}
	head, err := c.protocolHead()
	if err != nil {
		return CAPInfo{}, false
	}
	text, err := c.Protocol.ReadFile(head, "core/cap-"+m[1]+".md")
	if err != nil {
		return CAPInfo{}, false
	}
	return ParseCAPPreamble(text), true
}

// watchCAPs applies the XDR diff of every pending CAP document to the commit it names.
func (c *WatchConfig) watchCAPs(res *WatchResult, pinned *Input) []*WatchItem {
	var items []*WatchItem
	head, err := c.protocolHead()
	if err != nil {
		return []*WatchItem{{Kind: "cap", Name: "*", Status: "blocked", Detail: err.Error()}}
	}
	out, err := c.Protocol.git("ls-tree", "--name-only", head, "core/")
	if err != nil {
		return []*WatchItem{{Kind: "cap", Name: "*", Status: "blocked", Detail: err.Error()}}
	}
	for _, f := range strings.Fields(out) {
		m := capFileName.FindStringSubmatch(f)
		if m == nil {
			continue
		}
		text, err := c.Protocol.ReadFile(head, f)
		if err != nil {
			continue
		}
		cp := "CAP-" + m[1]
		info := ParseCAPPreamble(text)
		res.CAPs[cp] = info
		st := strings.ToLower(info.Status)
		done := false
		for _, d := range doneStatus {
			if strings.HasPrefix(st, d) {
				done = true
			}
		}
		patches, bases := CAPXDRPatches(text)
		if done || len(patches) == 0 {
			continue
		}
		it := &WatchItem{Kind: "cap", Name: cp, Title: info.Title + " (" + info.Status + ")",
			URL: "https://github.com/stellar/stellar-protocol/blob/" + head + "/" + f, Ref: head}
		if p, err := strconv.Atoi(info.Protocol); err == nil && p >= c.NextProtocol {
			it.Protocol = p
		}
		for i := range patches {
			patches[i] = normalizePatchPaths(patches[i])
		}
		base := bases[0]
		if base == "" {
			base = c.Pinned
			it.Detail = "the document names no base commit; applied to the pinned definitions"
		}
		items = append(items, it)
		baseCommit, err := c.XDR.Resolve(base)
		if err != nil && base != c.Pinned {
			// Older CAPs name a stellar-core commit (the XDR lived there before stellar-xdr).
			it.Detail = "base " + short(base) + " is not a stellar-xdr commit; applied to the pinned definitions"
			baseCommit, err = c.XDR.Resolve(c.Pinned)
		}
		if err != nil {
			it.Status, it.Detail = "blocked", err.Error()
			continue
		}
		it.BaseCommit = baseCommit
		files, err := c.XDR.ReadFiles(baseCommit, ".x")
		if err != nil {
			it.Status, it.Detail = "blocked", err.Error()
			continue
		}
		patched, err := applyPatches(filepath.Join(c.Out, ".patch"), files, patches)
		if err != nil {
			it.Status, it.Detail = "not-applied", strings.TrimSpace(it.Detail+"; "+err.Error())
			it.Detail = strings.TrimPrefix(it.Detail, "; ")
			continue
		}
		bs, err1 := ParseFiles(files)
		hs, err2 := ParseFiles(patched)
		if err1 != nil || err2 != nil {
			it.Status, it.Detail = "blocked", fmt.Sprint("parse: ", err1, err2)
			continue
		}
		r, err := DiffInputs(&Input{bs, Side{Label: "stellar-xdr " + short(baseCommit), Commit: baseCommit, Gates: bs.Features()}},
			&Input{hs, Side{Label: cp + " applied", Gates: hs.Features()}}, "all", "all", DiffOptions{CAP: cp})
		if err != nil {
			it.Status, it.Detail = "blocked", err.Error()
			continue
		}
		c.record(it, r, res)
		if base != c.Pinned && !strings.HasPrefix(c.Pinned, base) && it.Detail == "" {
			it.Detail = "based on stellar-xdr " + short(baseCommit)
		}
	}
	_ = pinned
	return items
}

var patchPath = regexp.MustCompile(`\b([ab])/(?:src/(?:protocol-(?:curr|next)/)?xdr/|xdr/)`)

// normalizePatchPaths rewrites file paths of a patch written against stellar-core's tree (`src/xdr/X.x`,
// `src/protocol-curr/xdr/X.x`) or an `xdr/` directory to stellar-xdr's top level.
func normalizePatchPaths(p string) string {
	lines := strings.Split(p, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "diff --git ") || strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") {
			lines[i] = patchPath.ReplaceAllString(l, "$1/")
		}
	}
	return strings.Join(lines, "\n")
}

// applyPatches applies unified diffs to a copy of the files with `git apply` in a scratch directory (dir,
// emptied first and removed after).
func applyPatches(dir string, files map[string]string, patches []string) (map[string]string, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for n, t := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(t), 0o644); err != nil {
			return nil, err
		}
	}
	for i, p := range patches {
		pf := filepath.Join(dir, fmt.Sprintf(".patch-%d", i))
		if err := os.WriteFile(pf, []byte(p), 0o644); err != nil {
			return nil, err
		}
		cmd := exec.Command("git", "apply", "--recount", "--whitespace=nowarn", pf)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
		var eb bytes.Buffer
		cmd.Stderr = &eb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("diff block %d does not apply: %s", i+1, strings.TrimSpace(eb.String()))
		}
	}
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".x") {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			out[e.Name()] = string(b)
		}
	}
	return out, nil
}

type pullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		SHA string `json:"sha"`
		Ref string `json:"ref"`
	} `json:"head"`
}

// openPRs lists the XDR repository's open pull requests (read-only API call).
func (c *WatchConfig) openPRs() ([]pullRequest, error) {
	var all []pullRequest
	for page := 1; page <= 5; page++ {
		url := fmt.Sprintf("%s/repos/%s/pulls?state=open&per_page=100&page=%d", strings.TrimRight(c.API, "/"), c.RepoSlug, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "xdrcheck-xdr-watch")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return all, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return all, err
		}
		if resp.StatusCode != 200 {
			return all, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		var prs []pullRequest
		if err := json.Unmarshal(b, &prs); err != nil {
			return all, err
		}
		all = append(all, prs...)
		if len(prs) < 100 {
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Number < all[j].Number })
	return all, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// write appends to the log and writes the digests, caps.json, candidates.txt and items.json.
func (c *WatchConfig) write(res *WatchResult, candidates []string) error {
	seen := map[string]bool{}
	var log bytes.Buffer
	if c.Previous != "" {
		if b, err := os.ReadFile(c.Previous); err == nil {
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) > 20000 {
				lines = lines[len(lines)-20000:]
			}
			for _, l := range lines {
				var it WatchItem
				if json.Unmarshal([]byte(l), &it) != nil {
					continue
				}
				seen[it.Kind+"\x00"+it.Name+"\x00"+it.Fingerprint+"\x00"+it.Status] = true
				log.WriteString(l + "\n")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, it := range res.Items {
		it.New = !seen[it.Kind+"\x00"+it.Name+"\x00"+it.Fingerprint+"\x00"+it.Status]
		b, _ := json.Marshal(it)
		log.Write(append(b, '\n'))
	}
	if err := os.WriteFile(filepath.Join(c.Out, "watch-log.jsonl"), log.Bytes(), 0o644); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(res.CAPs, "", "  ")
	if err := os.WriteFile(filepath.Join(c.Out, "caps.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	b, _ = json.MarshalIndent(res.Items, "", "  ")
	if err := os.WriteFile(filepath.Join(c.Out, "items.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.Out, "candidates.txt"), []byte(strings.Join(candidates, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	protos := map[int]bool{c.NextProtocol: true}
	for _, it := range res.Items {
		protos[it.Protocol] = true
	}
	for p := range protos {
		res.Protocols = append(res.Protocols, p)
	}
	sort.Ints(res.Protocols)
	var all bytes.Buffer
	for _, p := range res.Protocols {
		var d bytes.Buffer
		c.digest(&d, res, p)
		if err := os.WriteFile(filepath.Join(c.Out, fmt.Sprintf("digest-p%d.md", p)), d.Bytes(), 0o644); err != nil {
			return err
		}
		all.Write(d.Bytes())
		all.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(c.Out, "digest.md"), all.Bytes(), 0o644)
}

// DigestTitle is the title of the tracking issue for a protocol.
func DigestTitle(p int) string { return fmt.Sprintf("Protocol %d: XDR watch", p) }

// digest writes the Markdown body of one protocol's tracking issue.
func (c *WatchConfig) digest(w io.Writer, res *WatchResult, p int) {
	fmt.Fprintf(w, "# %s\n\n", DigestTitle(p))
	fmt.Fprintf(w, "Updated %s by the nightly XDR watch (`make nightly-xdr-watch`). Pinned definitions: stellar-xdr %s (`%s`). "+
		"Each source is diffed with `xdrcheck xdr diff`; \"readers\" counts changes in types reachable from `LedgerCloseMetaBatch` or "+
		"`TransactionEnvelope`. **new** marks a source whose result changed since the previous run.\n\n",
		c.Now.Format("2006-01-02"), c.PinnedLabel, short(c.Pinned))
	var mine []*WatchItem
	for _, it := range res.Items {
		if it.Protocol == p {
			mine = append(mine, it)
		}
	}
	fmt.Fprintf(w, "## Standing items\n\n")
	any := false
	for _, it := range mine {
		if it.Kind != "standing" {
			continue
		}
		any = true
		state := it.Status
		if it.Detail != "" {
			state += ": " + it.Detail
		}
		fmt.Fprintf(w, "- **`%s`** on stellar-xdr: %s", it.Name, state)
		if it.Commit != "" {
			fmt.Fprintf(w, "; head `%s` (%s)", short(it.Commit), it.Updated)
		}
		if it.Status == "ok" || it.Status == "merged" {
			fmt.Fprintf(w, "; %d changes against its merge base, %d in reader types; new arms: %s", it.Changes, it.ReaderChanges, armList(it.NewArms))
		}
		if it.URL != "" {
			fmt.Fprintf(w, " ([pull request](%s))", it.URL)
		}
		fmt.Fprintf(w, "\n")
	}
	if !any {
		fmt.Fprintf(w, "None.\n")
	}
	fmt.Fprintf(w, "\n## Sources\n\n| Source | Status | CAPs | Changes | Readers | New arms | |\n|---|---|---|---|---|---|---|\n")
	var notApplied []*WatchItem
	for _, it := range mine {
		if it.Kind == "standing" {
			continue
		}
		if it.Status == "not-applied" {
			notApplied = append(notApplied, it)
			continue
		}
		name := it.Kind + " `" + it.Name + "`"
		if it.URL != "" {
			name = it.Kind + " [`" + it.Name + "`](" + it.URL + ")"
		}
		if it.Title != "" {
			name += " " + mdCell(it.Title)
		}
		status := it.Status
		if it.Detail != "" {
			status += ": " + mdCell(it.Detail)
		}
		mark := ""
		if it.New {
			mark = "**new**"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %d | %d | %d | %s |\n", name, status, orDash(strings.Join(it.CAPs, ", ")), it.Changes, it.ReaderChanges, len(it.NewArms), mark)
	}
	fmt.Fprintf(w, "\n## New arms per source\n\n")
	n := 0
	for _, it := range mine {
		if len(it.NewArms) == 0 {
			continue
		}
		n++
		fmt.Fprintf(w, "- %s `%s`: %s\n", it.Kind, it.Name, armList(it.NewArms))
	}
	if n == 0 {
		fmt.Fprintf(w, "None.\n")
	}
	if len(notApplied) > 0 {
		fmt.Fprintf(w, "\n## CAP documents whose XDR diff does not apply\n\n")
		for _, it := range notApplied {
			d := it.Detail
			if i := strings.Index(d, "\n"); i >= 0 {
				d = d[:i]
			}
			fmt.Fprintf(w, "- [%s](%s) %s: %s\n", it.Name, it.URL, it.Title, d)
		}
	}
	fmt.Fprintf(w, "\nThe per-source diffs (JSON and Markdown) are in the run's `xdr-watch` artefact under `diffs/`. "+
		"Candidate corpus rows from main and the CAP documents: `xdrcheck xdr candidates`.\n")
}

func armList(a []string) string {
	if len(a) == 0 {
		return "none"
	}
	if len(a) > 12 {
		return "`" + strings.Join(a[:12], "`, `") + fmt.Sprintf("` and %d more", len(a)-12)
	}
	return "`" + strings.Join(a, "`, `") + "`"
}
