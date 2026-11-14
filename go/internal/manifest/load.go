package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Corpus is a loaded corpus root.
type Corpus struct {
	Root    string
	Overlay string        // a private overlay's corpus directory merged in (Options.Overlay), or ""
	Index   *CorpusIndex  // nil when the root has no corpus.json
	Entries []*Entry      // sorted by ID
	Chains  []*ChainIndex // sorted by ID

	byID        map[string]*Entry
	chainByID   map[string]*ChainIndex
	chainByBlob map[string][]chainRef // a deterministic setup ledger can occur in several scenarios' chains
}

type chainRef struct {
	chain *ChainIndex
	index int
}

// Options tune Load.
type Options struct {
	// SkipBlobCheck skips hashing blob files. Sizes, names and hashes are checked by default.
	SkipBlobCheck bool
	// Overlay names a private overlay's corpus directory (<overlay>/corpus) to merge in: its manifest/**.json
	// entries are loaded with the public ones, their blobs and sidecars read from the overlay
	// (docs/conformance-protocol.md, private overlay). An entry ID in both is an error.
	Overlay string
}

// Load reads corpus.json (if present), every manifest/**.json and every chains/**.json under root. All problems
// found are returned together; on error the Corpus is nil.
func Load(root string, opts Options) (*Corpus, error) {
	c := &Corpus{
		Root:        root,
		byID:        map[string]*Entry{},
		chainByID:   map[string]*ChainIndex{},
		chainByBlob: map[string][]chainRef{},
	}
	var errs []error

	if data, err := os.ReadFile(filepath.Join(root, "corpus.json")); err == nil {
		idx, err := ParseCorpusIndex(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("corpus.json: %w", err))
		}
		c.Index = idx
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}

	loadManifests := func(base, label string) {
		err := walkJSON(filepath.Join(base, "manifest"), func(rel string, data []byte) {
			e, err := ParseEntry(data)
			if err != nil {
				errs = append(errs, fmt.Errorf("%smanifest/%s: %w", label, rel, err))
				return
			}
			if want := strings.TrimSuffix(rel, ".json"); e.ID != want {
				errs = append(errs, fmt.Errorf("%smanifest/%s: id %q does not match the file path", label, rel, e.ID))
				return
			}
			if c.byID[e.ID] != nil {
				errs = append(errs, fmt.Errorf("%smanifest/%s: entry %s is in both the public and the overlay corpus", label, rel, e.ID))
				return
			}
			if !opts.SkipBlobCheck {
				for i, v := range e.Variants {
					if err := VerifyBlob(base, v.Blob); err != nil {
						errs = append(errs, fmt.Errorf("%smanifest/%s: variants[%d]: %w", label, rel, i, err))
					}
				}
			}
			// Key-selected pinpoints become plain pointers per variant (pinpoint.go).
			for i, v := range e.Variants {
				if err := ResolvePinpoints(base, v); err != nil {
					errs = append(errs, fmt.Errorf("%smanifest/%s: variants[%d]: %w", label, rel, i, err))
				}
			}
			c.byID[e.ID] = e
			c.Entries = append(c.Entries, e)
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	loadManifests(root, "")
	if opts.Overlay != "" {
		if st, err := os.Stat(filepath.Join(opts.Overlay, "manifest")); err != nil || !st.IsDir() {
			errs = append(errs, fmt.Errorf("overlay corpus %s has no manifest/ directory", opts.Overlay))
		} else {
			c.Overlay = opts.Overlay
			loadManifests(opts.Overlay, "overlay ")
		}
	}

	err := walkJSON(filepath.Join(root, "chains"), func(rel string, data []byte) {
		ch, err := ParseChainIndex(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("chains/%s: %w", rel, err))
			return
		}
		if want := strings.TrimSuffix(rel, ".json"); ch.ID != want {
			errs = append(errs, fmt.Errorf("chains/%s: id %q does not match the file path", rel, ch.ID))
			return
		}
		seen := map[string]bool{}
		for i, l := range ch.Ledgers {
			if seen[l.BlobSHA256] {
				errs = append(errs, fmt.Errorf("chains/%s: ledger %d: blob %s occurs twice in the chain", rel, l.Seq, l.BlobSHA256))
				continue
			}
			seen[l.BlobSHA256] = true
			c.chainByBlob[l.BlobSHA256] = append(c.chainByBlob[l.BlobSHA256], chainRef{chain: ch, index: i})
		}
		c.chainByID[ch.ID] = ch
		c.Chains = append(c.Chains, ch)
	})
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	sort.Slice(c.Entries, func(i, j int) bool { return c.Entries[i].ID < c.Entries[j].ID })
	sort.Slice(c.Chains, func(i, j int) bool { return c.Chains[i].ID < c.Chains[j].ID })
	for _, refs := range c.chainByBlob {
		sort.Slice(refs, func(i, j int) bool { return refs[i].chain.ID < refs[j].chain.ID })
	}
	return c, nil
}

// Entry returns the entry with the given ID, or nil.
func (c *Corpus) Entry(id string) *Entry { return c.byID[id] }

// Chain returns the chain index with the given ID, or nil.
func (c *Corpus) Chain(id string) *ChainIndex { return c.chainByID[id] }

// ChainForBlob finds a chain a ledger blob belongs to (replay block, manifest.md §8): the first by chain ID
// when the same ledger occurs in several chains (deterministic setup ledgers shared by scenarios).
func (c *Corpus) ChainForBlob(sha string) (*ChainIndex, *ChainLedger, bool) {
	refs := c.chainByBlob[sha]
	if len(refs) == 0 {
		return nil, nil, false
	}
	return refs[0].chain, &refs[0].chain.Ledgers[refs[0].index], true
}

// InChain reports whether a ledger blob is part of the chain with the given ID.
func (c *Corpus) InChain(sha, chainID string) bool {
	for _, r := range c.chainByBlob[sha] {
		if r.chain.ID == chainID {
			return true
		}
	}
	return false
}

// BlobPath returns the file path of a variant's blob, or "" for a blob with no path (bulk tier). Blobs are
// named by their hash, so a blob the public corpus does not hold is read from the overlay corpus when one is
// merged in and has it.
func (c *Corpus) BlobPath(v *Variant) string {
	if v.Blob.Path == "" {
		return ""
	}
	return c.File(v.Blob.Path)
}

// File returns the path of a corpus-relative file (slash-separated): under Root when it is there, else under
// the overlay corpus when one is merged in and holds it, else under Root.
func (c *Corpus) File(rel string) string {
	p := filepath.Join(c.Root, filepath.FromSlash(rel))
	if c.Overlay != "" {
		if _, err := os.Stat(p); err != nil {
			o := filepath.Join(c.Overlay, filepath.FromSlash(rel))
			if _, err := os.Stat(o); err == nil {
				return o
			}
		}
	}
	return p
}

// ParseEntry decodes one manifest entry strictly and checks it: schema ID, unique variant keys, state-change
// kinds and detail keys, and that every ${derived.…} token resolves in every variant (filling
// Variant.Resolved). An entry without variants must not use tokens.
func ParseEntry(data []byte) (*Entry, error) {
	var e Entry
	if err := decodeStrict(data, &e); err != nil {
		return nil, err
	}
	if e.Schema != EntrySchema {
		return nil, fmt.Errorf("schema is %q, want %q", e.Schema, EntrySchema)
	}
	if err := e.Expect.checkStateChanges(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, v := range e.Variants {
		key := fmt.Sprintf("%s@%d", v.Network, v.Protocol)
		if seen[key] {
			return nil, fmt.Errorf("variants[%d]: a second variant for %s", i, key)
		}
		seen[key] = true
		r, err := ResolveExpect(&e.Expect, v.Derived)
		if err != nil {
			return nil, fmt.Errorf("variants[%d] (%s): expect: %w", i, key, err)
		}
		v.Resolved = r
		if e.API != nil {
			if _, err := ResolveInput(e.API.Input, v.Derived); err != nil {
				return nil, fmt.Errorf("variants[%d] (%s): api.input: %w", i, key, err)
			}
		}
	}
	if len(e.Variants) == 0 && (containsTokens(e.Expect) || (e.API != nil && containsTokens(e.API.Input))) {
		return nil, errors.New("entry has no variants but uses ${derived.…} tokens")
	}
	return &e, nil
}

// LoadEntry reads and parses one manifest file. It does not check the path against the ID or the blob.
func LoadEntry(file string) (*Entry, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	e, err := ParseEntry(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return e, nil
}

// ParseChainIndex decodes a chain index strictly and checks its schema ID and sequence order.
func ParseChainIndex(data []byte) (*ChainIndex, error) {
	var ch ChainIndex
	if err := decodeStrict(data, &ch); err != nil {
		return nil, err
	}
	if ch.Schema != ChainSchema {
		return nil, fmt.Errorf("schema is %q, want %q", ch.Schema, ChainSchema)
	}
	for i := 1; i < len(ch.Ledgers); i++ {
		if ch.Ledgers[i].Seq != ch.Ledgers[i-1].Seq+1 {
			return nil, fmt.Errorf("ledgers[%d]: sequence %d does not follow %d", i, ch.Ledgers[i].Seq, ch.Ledgers[i-1].Seq)
		}
	}
	return &ch, nil
}

// LoadChainIndex reads and parses one chain index file.
func LoadChainIndex(file string) (*ChainIndex, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	ch, err := ParseChainIndex(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return ch, nil
}

// ParseCorpusIndex decodes corpus.json strictly and checks its schema IDs.
func ParseCorpusIndex(data []byte) (*CorpusIndex, error) {
	var idx CorpusIndex
	if err := decodeStrict(data, &idx); err != nil {
		return nil, err
	}
	if idx.Schema != CorpusIndexSchema {
		return nil, fmt.Errorf("schema is %q, want %q", idx.Schema, CorpusIndexSchema)
	}
	if idx.EntrySchema != EntrySchema {
		return nil, fmt.Errorf("entry_schema is %q; this reader understands %q", idx.EntrySchema, EntrySchema)
	}
	return &idx, nil
}

// VerifyBlob checks that a blob's file is at blobs/<aa>/<sha256>.xdr (.wasm for contract code) under root, has the stated size and
// hashes to its name. A blob without a path (bulk tier) is not checked.
func VerifyBlob(root string, b Blob) error {
	if b.Path == "" {
		return nil
	}
	if len(b.SHA256) != 64 {
		return fmt.Errorf("blob: sha256 %q is not 64 hex characters", b.SHA256)
	}
	if want := path.Join("blobs", b.SHA256[:2], b.SHA256+".xdr"); b.Path != want && b.Path != strings.TrimSuffix(want, ".xdr")+".wasm" {
		return fmt.Errorf("blob: path %q, want %q", b.Path, want)
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(b.Path)))
	if err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("blob %s: %w", b.Path, err)
	}
	if n != b.Bytes {
		return fmt.Errorf("blob %s: %d bytes, manifest says %d", b.Path, n, b.Bytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != b.SHA256 {
		return fmt.Errorf("blob %s: sha256 %s, manifest says %s", b.Path, got, b.SHA256)
	}
	return nil
}

// walkJSON calls fn for every *.json file under dir, in lexical order, with its slash-separated path relative
// to dir. A missing dir is not an error.
func walkJSON(dir string, fn func(rel string, data []byte)) error {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(rel), data)
		return nil
	})
}

// decodeStrict decodes one JSON value into v: unknown fields and trailing data are errors, and numbers in open
// values are kept as json.Number.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
