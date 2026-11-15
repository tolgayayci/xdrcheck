// Package issues maps known public issues to the ledgers that show them and to the target versions before and
// after their fix (issues.json, embedded), and reads the corpus entries those ledgers come from.
package issues

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed issues.json
var publicIssues []byte

// Issue is one known issue.
type Issue struct {
	ID          string  `json:"id"`
	URL         string  `json:"url"`
	Title       string  `json:"title"`
	Target      string  `json:"target"`
	Prefix      string  `json:"prefix"`
	Fixed       string  `json:"fixed"`
	CorpusEntry string  `json:"corpus_entry,omitempty"`
	Network     string  `json:"network,omitempty"`
	Ledger      uint32  `json:"ledger,omitempty"`
	Tx          *int    `json:"tx,omitempty"`
	TxHash      string  `json:"tx_hash,omitempty"`
	Expect      *Expect `json:"expect,omitempty"`
}

// Expect is the verdict the prefix version gives and the fixed version does not.
type Expect struct {
	Check string `json:"check"`
	Class string `json:"class"`
}

type file struct {
	Schema      string  `json:"schema"`
	Description string  `json:"description,omitempty"`
	Issues      []Issue `json:"issues"`
}

// Raw returns the embedded issues.json.
func Raw() []byte { return publicIssues }

// Load returns the public issues and, when overlay is not empty, those of a private overlay file in the same
// format (overlay entries replace public ones with the same id).
func Load(overlay string) (map[string]Issue, error) {
	out := map[string]Issue{}
	add := func(b []byte, name string) error {
		var f file
		if err := json.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("%s: %v", name, err)
		}
		for _, i := range f.Issues {
			out[strings.ToLower(i.ID)] = i
		}
		return nil
	}
	if err := add(publicIssues, "issues.json"); err != nil {
		return nil, err
	}
	if overlay != "" {
		b, err := os.ReadFile(overlay)
		if err != nil {
			return nil, err
		}
		if err := add(b, overlay); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Find returns one issue by id ("repo#n", case-insensitive; an "owner/" prefix is ignored).
func Find(all map[string]Issue, id string) (Issue, error) {
	k := strings.ToLower(id)
	if i := strings.LastIndex(k, "/"); i >= 0 && strings.Contains(k[i:], "#") {
		k = k[i+1:]
	}
	if is, ok := all[k]; ok {
		return is, nil
	}
	var ids []string
	for _, i := range all {
		ids = append(ids, i.ID)
	}
	sort.Strings(ids)
	return Issue{}, fmt.Errorf("unknown issue %q (known: %s)", id, strings.Join(ids, ", "))
}

// ---- corpus entries

// Variant is one ledger of a corpus entry.
type Variant struct {
	Entry    string
	Caps     []int
	Network  string
	Ledger   uint32
	BlobPath string // absolute path of the raw LedgerCloseMeta
	BlobSHA  string
	FocusTx  *int
	FocusTxH string
	Object   string // the public-lake key the blob was captured from, when it was
	// History is true when the blob was captured from the network's own history (the public lake); a
	// local-core twin carries the network's passphrase but is a ledger of a local chain with the same
	// sequence number as an unrelated real one, so it must never be fetched or replayed by sequence.
	History bool
}

type manifestEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Caps     []int  `json:"caps"`
	Variants []struct {
		Network   string `json:"network"`
		LedgerSeq uint32 `json:"ledger_seq"`
		XDRType   string `json:"xdr_type"`
		Blob      struct {
			SHA256 string `json:"sha256"`
			Path   string `json:"path"`
		} `json:"blob"`
		Source struct {
			Kind string `json:"kind"`
			Key  string `json:"key"`
		} `json:"source"`
		Focus *struct {
			TxIndex *int   `json:"tx_index"`
			TxHash  string `json:"tx_hash"`
		} `json:"focus"`
	} `json:"variants"`
}

// Corpus reads every ledger variant of the corpus at root (corpus/manifest/**.json).
func Corpus(root string) ([]Variant, error) {
	var out []Variant
	dir := filepath.Join(root, "manifest")
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("no corpus at %s (pass --corpus DIR)", root)
	}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var e manifestEntry
		if json.Unmarshal(b, &e) != nil || e.Kind != "ledger" {
			return nil
		}
		for _, v := range e.Variants {
			if v.XDRType != "LedgerCloseMeta" || v.Blob.Path == "" || (v.Network != "pubnet" && v.Network != "testnet") {
				continue
			}
			vv := Variant{Entry: e.ID, Caps: e.Caps, Network: v.Network, Ledger: v.LedgerSeq, BlobPath: filepath.Join(root, v.Blob.Path), BlobSHA: v.Blob.SHA256, Object: v.Source.Key, History: v.Source.Kind == "history"}
			if v.Focus != nil {
				vv.FocusTx, vv.FocusTxH = v.Focus.TxIndex, v.Focus.TxHash
			}
			out = append(out, vv)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Entry != out[j].Entry {
			return out[i].Entry < out[j].Entry
		}
		return out[i].Network < out[j].Network
	})
	return out, err
}

// ByCap returns the variants of entries that name a CAP.
func ByCap(vs []Variant, cap int) []Variant {
	var out []Variant
	for _, v := range vs {
		for _, c := range v.Caps {
			if c == cap {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

// ByEntry returns the variants of one entry.
func ByEntry(vs []Variant, id string) []Variant {
	var out []Variant
	for _, v := range vs {
		if v.Entry == id {
			out = append(out, v)
		}
	}
	return out
}
