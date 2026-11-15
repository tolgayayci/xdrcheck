// Package find turns a question (a token, a token class, a value tag, a CAP, a linter assumption key, an
// operation type, a named set) into example transactions, from the dataset's plain index files: the locate
// index when it is built, the value tags, and the kept-ledger index meanwhile. No query engine is involved.
package find

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/dataset"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/issues"
)

// Query is one question. Exactly one selector is set.
type Query struct {
	Token         string // token text (K|class|path) or 32-hex token id
	Class         string // K|class
	TokenContains string // substring of the token text
	Tag           string // value tag; a trailing * matches a prefix
	Cap           int
	Assumption    string
	Op            string // operation type, e.g. PAYMENT
	Set           string
	Order         string // first, last, rarest, random
	Limit         int
	Seed          uint64
	Source        string // auto, locate, kept
}

// Hit is one example.
type Hit struct {
	Ledger uint32 `json:"ledger"`
	Tx     *int   `json:"tx"`
	Match  string `json:"match"`
	Occ    int64  `json:"occurrences,omitempty"` // census occurrences of the rarest matched token (rarity)
	Source string `json:"source"`
}

// Result is the answer.
type Result struct {
	Hits    []Hit
	Matched int    // transactions matched before ordering and limit
	Source  string // what answered
	Notes   []string
}

//go:embed assumptions.json
var assumptionsJSON []byte

// AssumptionSelector maps a linter assumption key to a selector of the inputs that violate it.
type AssumptionSelector struct {
	Key           string `json:"key"`
	Class         string `json:"class,omitempty"`
	TokenContains string `json:"token_contains,omitempty"`
	Tag           string `json:"tag,omitempty"`
	Op            string `json:"op,omitempty"`
	Why           string `json:"why"`
}

// Assumptions returns the embedded assumption map.
func Assumptions() ([]AssumptionSelector, error) {
	var f struct {
		Assumptions []AssumptionSelector `json:"assumptions"`
	}
	err := json.Unmarshal(assumptionsJSON, &f)
	return f.Assumptions, err
}

// Run answers a query.
func Run(m *dataset.Manifest, corpus string, q Query) (*Result, error) {
	if q.Limit <= 0 {
		q.Limit = 20
	}
	if q.Order == "" {
		q.Order = "first"
	}
	switch q.Order {
	case "first", "last", "rarest", "random":
	default:
		return nil, fmt.Errorf("--order must be first, last, rarest or random")
	}
	if q.Assumption != "" {
		as, err := Assumptions()
		if err != nil {
			return nil, err
		}
		var sel *AssumptionSelector
		for i := range as {
			if as[i].Key == q.Assumption {
				sel = &as[i]
			}
		}
		if sel == nil {
			var keys []string
			for _, a := range as {
				keys = append(keys, a.Key)
			}
			return nil, hunt.Missing("ledger selector for assumption "+q.Assumption, "mapped keys: "+strings.Join(keys, ", "))
		}
		q.Class, q.TokenContains, q.Tag, q.Op = sel.Class, sel.TokenContains, sel.Tag, sel.Op
		res, err := Run(m, corpus, Query{Class: q.Class, TokenContains: q.TokenContains, Tag: q.Tag, Op: q.Op, Order: q.Order, Limit: q.Limit, Seed: q.Seed, Source: q.Source})
		if res != nil {
			res.Notes = append(res.Notes, "assumption "+sel.Key+": "+sel.Why)
		}
		return res, err
	}
	switch {
	case q.Cap > 0:
		return byCap(m, corpus, q)
	case q.Set != "":
		if m == nil {
			return nil, hunt.Missing("dataset manifest", "--set needs a dataset")
		}
		refs, err := m.SetRefs(q.Set)
		if err != nil {
			return nil, err
		}
		var hits []Hit
		for _, r := range refs {
			hits = append(hits, hit(r.Ledger, r.Tx, "set:"+q.Set, 0, "set"))
		}
		return finish(hits, q, "set "+q.Set), nil
	}
	if m == nil {
		return nil, hunt.Missing("dataset manifest", "give --dataset DIR or set "+hunt.EnvName("DATASET"))
	}
	switch {
	case q.Tag != "":
		return byTag(m, q)
	case q.Token != "" || q.Class != "" || q.TokenContains != "":
		if q.Source != "kept" && q.TokenContains == "" {
			if res, err := byLocate(m, q); err == nil {
				return res, nil
			} else if q.Source == "locate" {
				return nil, err
			} else {
				r, err2 := byKept(m, q)
				if r != nil {
					r.Notes = append(r.Notes, "locate index: "+err.Error()+"; answered from the kept-ledger index (kept ledgers only)")
				}
				return r, err2
			}
		}
		return byKept(m, q)
	case q.Op != "":
		return byKept(m, q)
	}
	return nil, fmt.Errorf("give one of --token, --class, --token-contains, --tag, --cap, --assumption, --op, --set")
}

func hit(l uint32, tx int, match string, occ int64, src string) Hit {
	h := Hit{Ledger: l, Match: match, Occ: occ, Source: src}
	if tx >= 0 {
		t := tx
		h.Tx = &t
	}
	return h
}

func txOr(h Hit) int {
	if h.Tx == nil {
		return -1
	}
	return *h.Tx
}

// finish dedups by transaction, orders and limits.
func finish(hits []Hit, q Query, src string) *Result {
	seen := map[string]bool{}
	var u []Hit
	for _, h := range hits {
		k := fmt.Sprintf("%d:%d", h.Ledger, txOr(h))
		if !seen[k] {
			seen[k] = true
			u = append(u, h)
		}
	}
	res := &Result{Matched: len(u), Source: src}
	switch q.Order {
	case "first":
		sort.SliceStable(u, func(i, j int) bool {
			if u[i].Ledger != u[j].Ledger {
				return u[i].Ledger < u[j].Ledger
			}
			return txOr(u[i]) < txOr(u[j])
		})
	case "last":
		sort.SliceStable(u, func(i, j int) bool {
			if u[i].Ledger != u[j].Ledger {
				return u[i].Ledger > u[j].Ledger
			}
			return txOr(u[i]) < txOr(u[j])
		})
	case "rarest":
		sort.SliceStable(u, func(i, j int) bool {
			if u[i].Occ != u[j].Occ {
				return u[i].Occ < u[j].Occ
			}
			return u[i].Ledger < u[j].Ledger
		})
	case "random":
		r := rand.New(rand.NewPCG(q.Seed, q.Seed^0x9e3779b97f4a7c15))
		r.Shuffle(len(u), func(i, j int) { u[i], u[j] = u[j], u[i] })
	}
	if len(u) > q.Limit {
		u = u[:q.Limit]
	}
	res.Hits = u
	return res
}

// ---- tokens: the census token table (id, text, class, occurrences)

type token struct {
	id, kind, class, text string
	occ                   int64
}

func tokens(m *dataset.Manifest, match func(token) bool) ([]token, error) {
	var out []token
	err := m.ScanTable("tokens", func(c map[string]int, row []string) bool {
		t := token{id: dataset.Col(c, row, "token_id"), kind: dataset.Col(c, row, "kind"), class: dataset.Col(c, row, "class"), text: dataset.Col(c, row, "token")}
		t.occ, _ = strconv.ParseInt(dataset.Col(c, row, "occurrences"), 10, 64)
		if match(t) {
			out = append(out, t)
		}
		return true
	})
	return out, err
}

// tokenMatcher matches every condition the query sets (token, class, substring).
func tokenMatcher(q Query) func(token) bool {
	if q.Token == "" && q.Class == "" && q.TokenContains == "" {
		return func(token) bool { return false }
	}
	k, c, _ := strings.Cut(q.Class, "|")
	return func(t token) bool {
		switch {
		case q.Token != "" && isHex32(q.Token) && t.id != strings.ToLower(q.Token):
			return false
		case q.Token != "" && !isHex32(q.Token) && t.text != q.Token:
			return false
		case q.Class != "" && (t.kind != k || c != "" && t.class != c):
			return false
		case q.TokenContains != "" && !strings.Contains(t.text, q.TokenContains):
			return false
		}
		return true
	}
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ---- the locate index, through xdrcheck-corpus scan locate

// CorpusTool returns the xdrcheck-corpus command: $<TOOL>_CORPUS, else xdrcheck-corpus on PATH.
func CorpusTool() (string, error) {
	if v := hunt.Env("CORPUS"); v != "" {
		return v, nil
	}
	if p, err := exec.LookPath(hunt.Tool + "-corpus"); err == nil {
		return p, nil
	}
	return "", hunt.Missing(hunt.Tool+"-corpus", "set "+hunt.EnvName("CORPUS")+" or put "+hunt.Tool+"-corpus on PATH")
}

func byLocate(m *dataset.Manifest, q Query) (*Result, error) {
	paths, err := m.TablePaths("locate")
	if err != nil {
		return nil, err
	}
	tool, err := CorpusTool()
	if err != nil {
		return nil, err
	}
	toks, err := tokens(m, tokenMatcher(q))
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return &Result{Source: "locate index", Notes: []string{"no token matches"}}, nil
	}
	if len(toks) > 200 {
		return nil, fmt.Errorf("%d tokens match; narrow the class or use --token", len(toks))
	}
	idx := filepath.Dir(paths[0])
	per := q.Limit
	if q.Order != "first" {
		per = 0 // every stored posting: ordering needs them all
	}
	var hits []Hit
	for _, t := range toks {
		args := []string{"scan", "locate", "--index", idx, "--token", t.id}
		if per > 0 {
			args = append(args, "--limit", strconv.Itoa(per))
		}
		var out, errb bytes.Buffer
		cmd := exec.Command(tool, args...)
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("%s %s: %v: %s", tool, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
		}
		for i, line := range strings.Split(out.String(), "\n") {
			f := strings.Split(line, "\t")
			if i == 0 || len(f) < 4 {
				continue
			}
			s, err := strconv.ParseUint(f[2], 10, 32)
			if err != nil {
				continue
			}
			tx := -1
			if n, err := strconv.Atoi(f[3]); err == nil {
				tx = n
			}
			hits = append(hits, hit(uint32(s), tx, t.text, t.occ, "locate"))
		}
	}
	res := finish(hits, q, "locate index")
	res.Notes = append(res.Notes, "keys above the index's cap store their first, last and evenly spaced postings only")
	return res, nil
}

// ---- the kept-ledger index: components (with their tokens) and transactions (with their components)

func byKept(m *dataset.Manifest, q Query) (*Result, error) {
	var comps map[string]int64 // kind:id → rarity (smallest census occurrences of a matched token)
	if q.Op == "" {
		toks, err := tokens(m, tokenMatcher(q))
		if err != nil {
			return nil, err
		}
		occ := map[string]int64{}
		for _, t := range toks {
			occ[t.text] = t.occ
		}
		if len(occ) == 0 {
			return &Result{Source: "kept-ledger index", Notes: []string{"no token matches"}}, nil
		}
		comps = map[string]int64{}
		err = m.ScanTable("kept_components", func(c map[string]int, row []string) bool {
			best := int64(-1)
			for _, tk := range strings.Fields(dataset.Col(c, row, "tokens")) {
				if o, ok := occ[tk]; ok && (best < 0 || o < best) {
					best = o
				}
			}
			if best >= 0 {
				comps[dataset.Col(c, row, "kind")+":"+dataset.Col(c, row, "component_id")] = best
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		if len(comps) == 0 {
			return &Result{Source: "kept-ledger index", Notes: []string{fmt.Sprintf("%d tokens match; none occurs in a kept ledger", len(occ))}}, nil
		}
	}
	op := strings.ToUpper(strings.TrimPrefix(q.Op, "OperationType"))
	var hits []Hit
	early, stopped := q.Order == "first", false
	err := m.ScanTable("kept_tx_shapes", func(c map[string]int, row []string) bool {
		s, err := strconv.ParseUint(dataset.Col(c, row, "seq"), 10, 32)
		if err != nil {
			return true
		}
		tx, _ := strconv.Atoi(dataset.Col(c, row, "tx_index"))
		if op != "" {
			for _, o := range strings.Split(dataset.Col(c, row, "op_types"), ",") {
				if o == op {
					hits = append(hits, hit(uint32(s), tx, "op:"+op, 0, "kept"))
					break
				}
			}
		} else {
			best := int64(-1)
			for _, ci := range strings.Split(dataset.Col(c, row, "component_ids"), ",") {
				if i := strings.IndexByte(ci, '*'); i >= 0 {
					ci = ci[:i]
				}
				if o, ok := comps[ci]; ok && (best < 0 || o < best) {
					best = o
				}
			}
			if best >= 0 {
				hits = append(hits, hit(uint32(s), tx, matchLabel(q), best, "kept"))
			}
		}
		// the index is in ledger order (checked over the whole file): the first N matches are the answer
		if early && len(hits) >= q.Limit {
			stopped = true
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	res := finish(hits, q, "kept-ledger index")
	if stopped {
		res.Notes = append(res.Notes, "stopped at the first matches in ledger order: the matched count is a lower bound (use --order last or rarest for the full count)")
	}
	return res, nil
}

func matchLabel(q Query) string {
	switch {
	case q.Token != "":
		return q.Token
	case q.Class != "":
		return "class:" + q.Class
	}
	return "contains:" + q.TokenContains
}

// ---- value tags

func byTag(m *dataset.Manifest, q Query) (*Result, error) {
	prefix := strings.HasSuffix(q.Tag, "*")
	want := strings.TrimSuffix(q.Tag, "*")
	var hits []Hit
	err := m.ScanTable("tags", func(c map[string]int, row []string) bool {
		t := dataset.Col(c, row, "tag")
		if t == want || prefix && strings.HasPrefix(t, want) {
			s, err := strconv.ParseUint(dataset.Col(c, row, "seq"), 10, 32)
			if err == nil {
				tx, err := strconv.Atoi(dataset.Col(c, row, "tx"))
				if err != nil {
					tx = -1
				}
				hits = append(hits, hit(uint32(s), tx, t+" "+dataset.Col(c, row, "path"), 0, "tags"))
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	res := finish(hits, q, "value tags")
	if q.Order == "rarest" {
		res.Notes = append(res.Notes, "tags carry no rarity; rarest is ledger order")
	}
	return res, nil
}

// ---- CAP: corpus examples (any network) and the dataset's per-CAP set

func byCap(m *dataset.Manifest, corpus string, q Query) (*Result, error) {
	var hits []Hit
	if vs, err := issues.Corpus(corpus); err == nil {
		for _, v := range issues.ByCap(vs, q.Cap) {
			if !v.History {
				continue // a local-core twin's sequence names an unrelated network ledger
			}
			tx := -1
			if v.FocusTx != nil {
				tx = *v.FocusTx
			}
			hits = append(hits, hit(v.Ledger, tx, v.Network+" corpus "+v.Entry, 0, "corpus"))
		}
	}
	if m != nil {
		if refs, err := m.SetRefs(fmt.Sprintf("cap-%d", q.Cap)); err == nil {
			for _, r := range refs {
				hits = append(hits, hit(r.Ledger, r.Tx, "set cap-"+strconv.Itoa(q.Cap), 0, "set"))
			}
		}
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("no corpus ledger captured from network history names CAP %d (replay --cap also runs the local-core ledgers)", q.Cap)
	}
	return finish(hits, q, "corpus"), nil
}
