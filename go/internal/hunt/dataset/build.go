package dataset

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
)

// Layout v1: where the derived data lives under its roots. `data manifest` turns it into a manifest by
// globbing each pattern and hashing each file; a pattern that matches nothing gives a table marked missing.
//
//	derived  census/, cover/, tokens/, leads/, and the kept-ledger index arch/pilot/index/, lists arch/pilot/lists/
//	kept     a lake-layout directory of kept ledgers (index.tsv)
//	scan     the full scan's per-block Parquet files (<block>/*.parquet, MANIFEST.json)
//	hunt     outputs of the hunt tools: locate/ (locate index), tags/ (value tags)
type layoutTable struct {
	name, root, glob, format, desc, missing string
	fileCols                                map[string]string
	checksums                               string
}

var layout = []layoutTable{
	{name: "shapes", root: "derived", glob: "census/shapes-G*-*.tsv.zst", format: "tsv", desc: "every distinct shape per level (G0..G3) and kind (A, E, F, L, M, O, R, tx): id, occurrences, first_ledger, last_ledger, units",
		fileCols: map[string]string{"level": `shapes-(G\d)-`, "kind": `shapes-G\d-([A-Za-z]+)\.tsv`}},
	{name: "census_summary", root: "derived", glob: "census/summary.tsv", format: "tsv", desc: "distinct shapes and occurrence quantiles per level and kind"},
	{name: "census_facts", root: "derived", glob: "census/facts.tsv", format: "tsv", desc: "ledgers and transactions per protocol and LedgerCloseMeta arm"},
	{name: "tokens", root: "derived", glob: "tokens/tokens.tsv.zst", format: "tsv", desc: "every token: token_id, kind, class, token text, components, occurrences, first_ledger, last_ledger"},
	{name: "covers", root: "derived", glob: "cover/cover-*-*.tsv.zst", format: "tsv", desc: "greedy covers: the ledgers (or ledger, tx_index) that first show each shape or token, per level; order asc or rare",
		fileCols: map[string]string{"level": `cover-([A-Z0-9]+)-`, "unit": `-(ledgers|tx)(?:-rare)?\.tsv`, "order": `-(?:ledgers|tx)-?(rare)?\.tsv`}},
	{name: "cover_summary", root: "derived", glob: "cover/cover-summary.tsv", format: "tsv", desc: "cover sizes per level and order"},
	{name: "rare_tokens", root: "derived", glob: "leads/rare-tokens.tsv", format: "tsv", desc: "tokens seen in few transactions: occ, comps, first_ledger, last_ledger, kind, class, token"},
	{name: "value_extremes", root: "derived", glob: "leads/value-extremes.tsv", format: "tsv", desc: "value-band tokens at the extremes"},
	{name: "event_signatures", root: "derived", glob: "leads/event-signatures.tsv", format: "tsv", desc: "contract event topic signatures"},
	{name: "rare_results", root: "derived", glob: "leads/rare-results.tsv", format: "tsv", desc: "rare result codes"},
	{name: "rare_change_cells", root: "derived", glob: "leads/rare-change-cells.tsv", format: "tsv", desc: "rare ledger-entry change cells"},
	{name: "kept_ledgers", root: "derived", glob: "arch/pilot/index/ledgers.tsv.zst", format: "tsv", desc: "kept-ledger index: seq, partition, protocol, tx_count, op_count, soroban_tx_count, ledger_component, strata"},
	{name: "kept_tx_shapes", root: "derived", glob: "arch/pilot/index/tx_shapes.tsv.zst", format: "tsv", desc: "kept-ledger index: seq, tx_index, tx_shape_id, component_ids (kind:id[*count]), g0_shape_id, op_types"},
	{name: "kept_components", root: "derived", glob: "arch/pilot/index/components.tsv.zst", format: "tsv", desc: "kept-ledger index: component_id, kind, tokens (space-separated), op_type"},
	{name: "scan_occurrences", root: "scan", glob: "*/occurrences.parquet", format: "parquet", checksums: "*/MANIFEST.json", desc: "full scan: seq, tx_shape, n, tx_index per block (Parquet; checksums in each block's MANIFEST.json)"},
	{name: "scan_tx_shapes", root: "scan", glob: "*/tx_shapes.parquet", format: "parquet", checksums: "*/MANIFEST.json", desc: "full scan: transaction shapes per block"},
	{name: "scan_components", root: "scan", glob: "*/components.parquet", format: "parquet", checksums: "*/MANIFEST.json", desc: "full scan: components per block"},
	{name: "locate", root: "hunt", glob: "locate/keys.idx", format: "locate-index", desc: "locate index (scan locate): every (ledger, tx_index) of a token, component or shape in all history; read through xdrcheck-corpus scan locate",
		missing: "the locate index has not been built (xdrcheck-corpus scan locate-build)"},
	{name: "tags", root: "hunt", glob: "tags/*/tags.tsv.zst", format: "tsv", desc: "value tags (xdrcheck-tagger): seq, tx, tx_hash, tag, path, value per tagged value",
		missing: "the value tagger has not run"},
	{name: "tag_summary", root: "hunt", glob: "tags/*/tag-summary.tsv", format: "tsv", desc: "value tags: hits, transactions, ledgers, first and last ledger per tag and path",
		missing: "the value tagger has not run"},
}

type layoutSet struct {
	name, root, glob, unit, desc, missing string
}

var layoutSets = []layoutSet{
	{name: "controls", root: "derived", glob: "arch/pilot/lists/S0.txt", unit: "ledger", desc: "control ledgers: each holds a property a check must flag"},
	{name: "kept", root: "derived", glob: "arch/pilot/lists/all.txt", unit: "ledger", desc: "every kept ledger (the local lake)"},
	{name: "token-cover", root: "derived", glob: "cover/cover-TOK-tx.tsv.zst", unit: "tx", desc: "the fewest transactions that show every token at least once"},
	{name: "g0-cover", root: "derived", glob: "cover/cover-G0-ledgers.tsv.zst", unit: "ledger", desc: "the fewest ledgers that show every G0 shape at least once"},
	{name: "never-seen-generated", root: "hunt", glob: "generated/ledgers.txt", unit: "ledger", desc: "ledgers a local stellar-core closed for arms mainnet has not shown",
		missing: "the core generator has not produced ledgers"},
}

// BuildOptions configure Build.
type BuildOptions struct {
	Version string
	Network string
	Roots   map[string]string
	Corpus  string // corpus root: per-CAP sets and the corpus_entries table
	Find    string // findings directory (public records): the findings table
	Out     string // dataset directory
	Hash    bool   // compute sha256 of every file (slow for the large ones)
	Log     func(string)
}

// Build writes a dataset manifest for the data under opts.Roots.
func Build(o BuildOptions) (*Manifest, error) {
	m := &Manifest{Version: o.Version, Network: o.Network, Roots: o.Roots, Tables: map[string]*Table{}, Sets: map[string]*Set{},
		Created: time.Now().UTC().Format(time.RFC3339)}
	m.SetDir(o.Out)
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	logf := func(f string, a ...any) {
		if o.Log != nil {
			o.Log(fmt.Sprintf(f, a...))
		}
	}
	file := func(path, root string) (File, error) {
		rel := "${" + root + "}" + strings.TrimPrefix(path, m.Root(root))
		st, err := os.Stat(path)
		if err != nil {
			return File{}, err
		}
		f := File{Path: rel, Bytes: st.Size()}
		if o.Hash {
			g, err := FileOf(path)
			if err != nil {
				return File{}, err
			}
			f.SHA256 = g.SHA256
		}
		return f, nil
	}
	for _, lt := range layout {
		t := &Table{Description: lt.desc, Format: lt.format, FilenameColumns: lt.fileCols}
		m.Tables[lt.name] = t
		base := m.Root(lt.root)
		if base == "" {
			t.Missing = "root " + lt.root + " not given"
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(base, lt.glob))
		sort.Strings(matches)
		if len(matches) == 0 {
			t.Missing = lt.missing
			if t.Missing == "" {
				t.Missing = "no file matches " + filepath.Join(base, lt.glob)
			}
			continue
		}
		if lt.format == "parquet" {
			t.Glob = "${" + lt.root + "}/" + lt.glob
			t.ChecksumGlob = "${" + lt.root + "}/" + lt.checksums
			logf("table %s: %d files (checksums in the scan's own manifests)", lt.name, len(matches))
			continue
		}
		for _, p := range matches {
			f, err := file(p, lt.root)
			if err != nil {
				return nil, err
			}
			t.Files = append(t.Files, f)
		}
		logf("table %s: %d files", lt.name, len(t.Files))
	}
	for _, ls := range layoutSets {
		s := &Set{Description: ls.desc, Unit: ls.unit}
		m.Sets[ls.name] = s
		base := m.Root(ls.root)
		p := filepath.Join(base, ls.glob)
		if base == "" {
			s.Missing = "root " + ls.root + " not given"
			continue
		}
		if _, err := os.Stat(p); err != nil {
			s.Missing = ls.missing
			if s.Missing == "" {
				s.Missing = "no file " + p
			}
			continue
		}
		f, err := file(p, ls.root)
		if err != nil {
			return nil, err
		}
		s.File = &f
		if refs, err := ReadRefs(p); err == nil {
			s.Count = len(refs)
		}
	}
	if k := m.Root("kept"); k != "" {
		m.Lakes = []string{"${kept}"}
	}
	// tip: the newest ledger the census counted
	if t := m.Tables["census_facts"]; t != nil && t.Missing == "" {
		m.ScanTable("census_facts", func(c map[string]int, row []string) bool {
			if n, err := strconv.ParseUint(Col(c, row, "last_ledger"), 10, 32); err == nil && uint32(n) > m.TipLedger {
				m.TipLedger = uint32(n)
			}
			return true
		})
	}
	if o.Corpus != "" {
		if err := corpusTables(m, o); err != nil {
			return nil, err
		}
	}
	if o.Find != "" {
		if err := findingsTable(m, o); err != nil {
			return nil, err
		}
	}
	return m, m.Save(o.Out)
}

// corpusEntry is the part of a corpus manifest entry the dataset reads.
type corpusEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Caps     []int  `json:"caps"`
	Protocol struct {
		Introduced int `json:"introduced"`
	} `json:"protocol"`
	Variants []struct {
		Network   string `json:"network"`
		LedgerSeq uint32 `json:"ledger_seq"`
		Source    struct {
			Kind string `json:"kind"`
		} `json:"source"`
		Focus *struct {
			TxIndex *int `json:"tx_index"`
		} `json:"focus"`
	} `json:"variants"`
}

// corpusTables writes corpus_entries.tsv and one set per CAP (pubnet ledgers of the corpus entries naming it).
func corpusTables(m *Manifest, o BuildOptions) error {
	var rows []string
	byCap := map[int]map[string]bool{}
	err := filepath.Walk(filepath.Join(o.Corpus, "manifest"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var e corpusEntry
		if json.Unmarshal(b, &e) != nil || e.ID == "" {
			return nil
		}
		caps := make([]string, len(e.Caps))
		for i, c := range e.Caps {
			caps[i] = strconv.Itoa(c)
		}
		for _, v := range e.Variants {
			tx := ""
			if v.Focus != nil && v.Focus.TxIndex != nil {
				tx = strconv.Itoa(*v.Focus.TxIndex)
			}
			rows = append(rows, fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s", e.ID, e.Kind, strings.Join(caps, ","), e.Protocol.Introduced, v.Network, v.Source.Kind, v.LedgerSeq, tx))
			// only ledgers of the network's own history: a local-core twin's sequence names an unrelated ledger
			if v.Network == m.Network && v.Source.Kind == "history" && v.LedgerSeq > 0 && e.Kind == "ledger" {
				for _, c := range e.Caps {
					if byCap[c] == nil {
						byCap[c] = map[string]bool{}
					}
					line := strconv.FormatUint(uint64(v.LedgerSeq), 10)
					if tx != "" {
						line += "\t" + tx
					}
					byCap[c][line] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(rows)
	p := filepath.Join(o.Out, "corpus_entries.tsv")
	if err := os.WriteFile(p, []byte("entry\tkind\tcaps\tprotocol\tnetwork\tsource\tledger\ttx_index\n"+strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	f, _ := FileOf(p)
	f.Path = "corpus_entries.tsv"
	m.Tables["corpus_entries"] = &Table{Description: "corpus entries: entry, kind, caps, protocol, network, source (history, local-core, …), ledger, tx_index (focus)", Format: "tsv", Files: []File{f}}
	os.MkdirAll(filepath.Join(o.Out, "sets"), 0o755)
	for c, lines := range byCap {
		var ls []string
		for l := range lines {
			ls = append(ls, l)
		}
		sort.Strings(ls)
		name := fmt.Sprintf("cap-%d", c)
		sp := filepath.Join(o.Out, "sets", name+".tsv")
		if err := os.WriteFile(sp, []byte(strings.Join(ls, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		f, _ := FileOf(sp)
		f.Path = "sets/" + name + ".tsv"
		m.Sets[name] = &Set{Description: fmt.Sprintf("corpus examples of CAP %d from %s history", c, m.Network), Unit: "tx", File: &f, Count: len(ls)}
	}
	return nil
}

var findingID = regexp.MustCompile(`^F-\d{4}$`)

// findingsTable writes findings.tsv from the public finding records (<dir>/F-NNNN/finding.json).
func findingsTable(m *Manifest, o BuildOptions) error {
	dirs, _ := filepath.Glob(filepath.Join(o.Find, "F-*", "finding.json"))
	var rows []string
	for _, p := range dirs {
		if !findingID.MatchString(filepath.Base(filepath.Dir(p))) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var f map[string]any
		if json.Unmarshal(b, &f) != nil {
			continue
		}
		str := func(k string) string {
			if v, ok := f[k].(string); ok {
				return strings.NewReplacer("\t", " ", "\n", " ").Replace(v)
			}
			if v, ok := f[k].(map[string]any); ok {
				if n, ok := v["name"].(string); ok {
					return n
				}
				if n, ok := v["project"].(string); ok {
					return n
				}
			}
			return ""
		}
		rows = append(rows, strings.Join([]string{str("id"), str("title"), str("target"), str("status"), str("severity")}, "\t"))
	}
	sort.Strings(rows)
	p := filepath.Join(o.Out, "findings.tsv")
	if err := os.WriteFile(p, []byte("id\ttitle\ttarget\tstatus\tseverity\n"+strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	f, _ := FileOf(p)
	f.Path = "findings.tsv"
	m.Tables["findings"] = &Table{Description: "public finding records: id, title, target, status, severity", Format: "tsv", Files: []File{f}}
	return nil
}

var _ = hunt.Tool
