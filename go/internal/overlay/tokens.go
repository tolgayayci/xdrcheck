package overlay

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Token is one string the overlay holds that a history scan looks for: a record ID, an entry, recipe or
// evidence path, a linter row site, an overlay sink or an overlay-only column. Records names the records it
// belongs to as "<id>:<visibility>/<state>[/url]" (url: the record names an upstream link); never a title or a
// description.
type Token struct {
	Value   string
	Kind    string
	Public  bool // an entry, recipe or column the public tree at root holds too
	Records []string
}

// EmitTokens lists the overlay's tokens, from the same records and files the audit reads. root, when not
// empty, is the public tree whose manifest and sets file decide which entries and columns are public.
func EmitTokens(root, overlayDir string) ([]Token, error) {
	ov, err := loadOverlay(overlayDir)
	if err != nil {
		return nil, err
	}
	manifest, columns := map[string]bool{}, map[string]bool{}
	if root != "" {
		public, err := publicFiles(root)
		if err != nil {
			return nil, err
		}
		a := &auditor{t: &dirTree{root: root, public: public}, public: public, ov: ov, res: &Result{}}
		if err := a.loadTree(); err != nil {
			return nil, err
		}
		manifest, columns = a.manifest, a.pubColumns
	}
	byValue := map[string]*Token{}
	add := func(v, kind string, r *record) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		t := byValue[v]
		if t == nil {
			t = &Token{Value: v, Kind: kind}
			byValue[v] = t
		}
		if r != nil {
			tag := r.ID + ":" + r.Visibility + "/" + r.State
			if hasURL(r.Upstream) {
				tag += "/url"
			}
			for _, x := range t.Records {
				if x == tag {
					return
				}
			}
			t.Records = append(t.Records, tag)
		}
	}
	for _, r := range ov.recs {
		add(r.ID, "record-id", r)
		for _, e := range r.Entries {
			if e.ID != "" && !strings.ContainsAny(e.ID, " \t") && strings.Contains(e.ID, "/") {
				add(e.ID, "entry", r)
			}
		}
		if r.Evidence == nil {
			continue
		}
		for _, t := range r.Evidence.Transcripts {
			add(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "overlay:")), "evidence", r)
		}
		for _, row := range r.Evidence.ReportRows {
			if rest, ok := strings.CutPrefix(row, "lint:"); ok {
				if parts := strings.SplitN(rest, ":", 3); len(parts) == 3 {
					add(parts[2], "lint-row", r)
				}
			}
		}
	}
	for _, base := range []string{"corpus/manifest", "corpus/recipes"} {
		kind := "entry"
		if base == "corpus/recipes" {
			kind = "recipe"
		}
		dir := filepath.Join(overlayDir, filepath.FromSlash(base))
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			id := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
			if byValue[id] == nil {
				add(id, kind, nil)
			}
			return nil
		})
	}
	for _, s := range ov.sinks {
		add(s, "lint-sink", nil)
	}
	for id := range ov.columns {
		add(id, "column", nil)
	}
	out := make([]Token, 0, len(byValue))
	for _, t := range byValue {
		switch t.Kind {
		case "entry", "recipe":
			t.Public = manifest[t.Value]
		case "column":
			t.Public = columns[t.Value]
		}
		sort.Strings(t.Records)
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

func hasURL(raw json.RawMessage) bool {
	var u struct {
		URL string `json:"url"`
	}
	return len(raw) > 0 && json.Unmarshal(raw, &u) == nil && u.URL != ""
}
