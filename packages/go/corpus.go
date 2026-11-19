// Package xdrcheckcorpus reads the xdrcheck corpus, so an SDK's own tests can put every entry through the
// SDK under test (docs/use-in-sdk-ci.md). It opens a release archive (xdrcheck-<version>.tar.gz, read in
// memory, never extracted), an extracted release directory, or a corpus directory holding index.json, and walks
// the flat entry index corpus/index.json (docs/manifest.md §3.1). Every blob is checked against its sha256 and
// length before it is returned, every decoded sidecar against the sha256 of its uncompressed JSON, and every
// manifest against the root's manifest.sha256 when the root has one.
//
// The package has one dependency (zstd, for the decoded sidecars), uses no network and writes nothing. It is
// one file plus expected.go (expected-failure lists), so it can be vendored.
//
//	c, err := xdrcheckcorpus.Open(os.Getenv("XDRCHECK_CORPUS"))
//	for _, e := range c.Entries {
//		for _, v := range e.Variants {
//			if !v.Decodable() { continue }
//			b, err := v.Blob()            // verified bytes
//			want, err := v.ExpectedJSON() // the SEP-51 JSON the oracle decoded them to (nil when they must not decode)
//			...
//		}
//	}
package xdrcheckcorpus

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
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
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// IndexSchema is the schema ID of corpus/index.json this package reads.
const IndexSchema = "xcc.index/v1"

// Error is every error the package returns about the corpus itself (a missing file, a checksum mismatch, an
// index it cannot read).
type Error struct{ Msg string }

func (e *Error) Error() string { return "xdrcheckcorpus: " + e.Msg }

func errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// Corpus is one opened corpus: its version, where it was read from, and its entries in index order.
type Corpus struct {
	Version string
	Source  string
	Entries []*Entry

	files   fileSource
	release bool // a release layout: corpus/ and stress/ roots
	sums    map[string]map[string]string
	sumsMu  sync.Mutex
	byID    map[string]*Entry
}

// Entry is one row of the entry index.
type Entry struct {
	ID                 string     `json:"id"`
	Title              string     `json:"title"`
	Kind               string     `json:"kind"` // ledger, xdr, api, strkey, spec
	Caps               []int      `json:"caps"`
	Rows               []string   `json:"rows"`
	Protocol           Protocol   `json:"protocol"`
	Synthetic          bool       `json:"synthetic"`
	Validity           string     `json:"validity"` // valid, malformed, invalid, acceptable (docs/manifest.md §9.5)
	Flags              []string   `json:"flags"`
	Sources            []string   `json:"sources"`
	Tier               string     `json:"tier"` // curated, or stress (in a release, under the stress/ root)
	ManifestPath       string     `json:"manifest"`
	Variants           []*Variant `json:"variants"`
	c                  *Corpus
	manifestOnce       sync.Once
	manifest           map[string]any
	manifestErr        error
	ProtocolIntroduced int `json:"-"`
}

// Protocol is the entry's protocol range.
type Protocol struct {
	Introduced int  `json:"introduced"`
	Removed    *int `json:"removed,omitempty"`
}

// Variant is one variant row of an entry: the bytes on one network at one protocol.
type Variant struct {
	Network       string          `json:"network"`
	Protocol      int             `json:"protocol"`
	LedgerSeq     *int64          `json:"ledger_seq"`
	XDRType       string          `json:"xdr_type"`
	Validity      string          `json:"validity"` // the variant's own, else the entry's
	Source        string          `json:"source"`
	BlobPath      string          `json:"blob"`
	SHA256        string          `json:"sha256"`
	Bytes         int64           `json:"bytes"`
	DecodedPath   *string         `json:"decoded"` // nil when the bytes do not decode
	DecodedSHA256 *string         `json:"decoded_sha256"`
	Focus         json.RawMessage `json:"focus,omitempty"`

	// Key is the variant key reports use: the network, or network@protocol when the entry's variants do not all
	// share one protocol.
	Key   string `json:"-"`
	Entry *Entry `json:"-"`
}

type index struct {
	Schema  string   `json:"schema"`
	Entries []*Entry `json:"entries"`
}

// Open opens a corpus: a release archive (*.tar.gz), an extracted release directory (holding corpus/), or a
// corpus directory holding index.json.
func Open(p string) (*Corpus, error) { return OpenSHA256(p, "") }

// OpenSHA256 is Open with the archive's expected sha256 (hex); a mismatch is an error. It must be empty for a
// directory.
func OpenSHA256(p, archiveSHA256 string) (*Corpus, error) {
	if p == "" {
		return nil, errorf("no corpus given: set it to a release archive (.tar.gz), an extracted release or a corpus directory")
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, errorf("%v", err)
	}
	c := &Corpus{Source: p}
	switch {
	case st.IsDir():
		if archiveSHA256 != "" {
			return nil, errorf("%s is a directory: an archive sha256 applies only to an archive", p)
		}
		if _, err := os.Stat(filepath.Join(p, "corpus", "index.json")); err == nil {
			c.files, c.release = dirFiles(p), true
		} else if _, err := os.Stat(filepath.Join(p, "index.json")); err == nil {
			c.files = dirFiles(p)
		} else {
			return nil, errorf("%s holds neither corpus/index.json (a release) nor index.json (a corpus directory)", p)
		}
	default:
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, errorf("%v", err)
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		if archiveSHA256 != "" && !strings.EqualFold(got, archiveSHA256) {
			return nil, errorf("%s: sha256 %s, expected %s", p, got, archiveSHA256)
		}
		files, err := untarGz(raw)
		if err != nil {
			return nil, errorf("%s: %v", p, err)
		}
		c.files, c.release = files, true
		c.Source = fmt.Sprintf("%s (sha256 %s)", p, got)
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Corpus) load() error {
	idxRoot := ""
	if c.release {
		idxRoot = "corpus"
	}
	raw, err := c.files.read(join(idxRoot, "index.json"))
	if err != nil {
		return err
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return errorf("index.json: %v", err)
	}
	if idx.Schema != IndexSchema {
		return errorf("index.json: schema %q, this package reads %q", idx.Schema, IndexSchema)
	}
	c.Entries = idx.Entries
	c.byID = make(map[string]*Entry, len(c.Entries))
	for _, e := range c.Entries {
		e.c = c
		e.ProtocolIntroduced = e.Protocol.Introduced
		c.byID[e.ID] = e
		protocols := map[int]bool{}
		for _, v := range e.Variants {
			protocols[v.Protocol] = true
		}
		for _, v := range e.Variants {
			v.Entry = e
			v.Key = v.Network
			if len(protocols) > 1 {
				v.Key = fmt.Sprintf("%s@%d", v.Network, v.Protocol)
			}
		}
	}
	c.Version = c.version(idxRoot)
	return nil
}

func (c *Corpus) version(idxRoot string) string {
	var v struct {
		Version       string `json:"version"`
		CorpusVersion string `json:"corpus_version"`
	}
	if c.release {
		if raw, err := c.files.read("PROVENANCE.json"); err == nil && json.Unmarshal(raw, &v) == nil && v.Version != "" {
			return v.Version
		}
	}
	if raw, err := c.files.read(join(idxRoot, "corpus.json")); err == nil && json.Unmarshal(raw, &v) == nil && v.CorpusVersion != "" {
		return v.CorpusVersion
	}
	return "unknown"
}

// Entry returns the entry with this ID, or nil.
func (c *Corpus) Entry(id string) *Entry { return c.byID[id] }

// root is the corpus root an entry's files live under: in a release, stress/ for a stress entry and corpus/
// for every other; in a corpus directory, the directory itself.
func (e *Entry) root() string {
	switch {
	case !e.c.release:
		return ""
	case e.Tier == "stress":
		return "stress"
	}
	return "corpus"
}

// Manifest returns the entry's manifest file, parsed (numbers as json.Number), checked against the root's
// manifest.sha256 when the root has one.
func (e *Entry) Manifest() (map[string]any, error) {
	e.manifestOnce.Do(func() {
		raw, err := e.c.files.read(join(e.root(), e.ManifestPath))
		if err != nil {
			e.manifestErr = err
			return
		}
		sums, err := e.c.manifestSums(e.root())
		if err != nil {
			e.manifestErr = err
			return
		}
		if sums != nil {
			want, ok := sums[e.ManifestPath]
			if !ok {
				e.manifestErr = errorf("%s is not listed in %s", e.ManifestPath, join(e.root(), "manifest.sha256"))
				return
			}
			if got := sha256Hex(raw); got != want {
				e.manifestErr = errorf("%s: sha256 %s, manifest.sha256 says %s", join(e.root(), e.ManifestPath), got, want)
				return
			}
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		e.manifestErr = d.Decode(&e.manifest)
		if e.manifestErr != nil {
			e.manifestErr = errorf("%s: %v", e.ManifestPath, e.manifestErr)
		}
	})
	return e.manifest, e.manifestErr
}

// ExpectRejectReason is the manifest's expect.reject.reason (the reason class a refusal should have), or "".
func (e *Entry) ExpectRejectReason() (string, error) {
	m, err := e.Manifest()
	if err != nil {
		return "", err
	}
	exp, _ := m["expect"].(map[string]any)
	rej, _ := exp["reject"].(map[string]any)
	r, _ := rej["reason"].(string)
	return r, nil
}

func (c *Corpus) manifestSums(root string) (map[string]string, error) {
	c.sumsMu.Lock()
	defer c.sumsMu.Unlock()
	if c.sums == nil {
		c.sums = map[string]map[string]string{}
	}
	if s, ok := c.sums[root]; ok {
		return s, nil
	}
	raw, err := c.files.read(join(root, "manifest.sha256"))
	if err != nil {
		c.sums[root] = nil // a corpus directory without the list: nothing to check against
		return nil, nil
	}
	s := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			s[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	c.sums[root] = s
	return s, nil
}

// manifestVariant is the manifest's variant with this variant's network and protocol.
func (v *Variant) manifestVariant() (map[string]any, error) {
	m, err := v.Entry.Manifest()
	if err != nil {
		return nil, err
	}
	vs, _ := m["variants"].([]any)
	for _, x := range vs {
		mv, _ := x.(map[string]any)
		p, _ := mv["protocol"].(json.Number)
		if mv["network"] == v.Network && p.String() == fmt.Sprint(v.Protocol) {
			return mv, nil
		}
	}
	return nil, errorf("%s: the manifest has no variant %s at protocol %d", v.Entry.ID, v.Network, v.Protocol)
}

// Framing is how the blob holds the value: "none" (the blob is one value of XDRType) or "record-marked" (an
// RFC 5531 record-marked stream; FrameIndex is the record that holds the value). Read from the manifest.
func (v *Variant) Framing() (framing string, frameIndex int, err error) {
	mv, err := v.manifestVariant()
	if err != nil {
		return "", 0, err
	}
	framing, _ = mv["framing"].(string)
	if framing == "" {
		framing = "none"
	}
	if n, ok := mv["frame_index"].(json.Number); ok {
		i, _ := n.Int64()
		frameIndex = int(i)
	}
	return framing, frameIndex, nil
}

// MustRefuse reports whether a byte decoder must refuse the variant: its validity is malformed or invalid.
func (v *Variant) MustRefuse() bool { return v.Validity == "malformed" || v.Validity == "invalid" }

// Decodable reports whether the variant is one value of XDRType to decode: the entry is a ledger or xdr entry
// and the blob is not record-marked. The SDK CI recipes judge exactly these variants.
func (v *Variant) Decodable() bool {
	if v.Entry.Kind != "ledger" && v.Entry.Kind != "xdr" {
		return false
	}
	f, _, err := v.Framing()
	return err == nil && f == "none"
}

// Blob returns the variant's bytes, after checking their sha256 and length against the index.
func (v *Variant) Blob() ([]byte, error) {
	p := join(v.Entry.root(), v.BlobPath)
	b, err := v.Entry.c.files.read(p)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(b); got != v.SHA256 || int64(len(b)) != v.Bytes {
		return nil, errorf("%s: sha256 %s and %d bytes, the index says %s and %d bytes", p, got, len(b), v.SHA256, v.Bytes)
	}
	return b, nil
}

var zstdDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))

// ExpectedJSONBytes returns the uncompressed SEP-51 JSON of the variant's decoded sidecar, after checking its
// sha256 against the index; nil when the bytes do not decode (no sidecar).
func (v *Variant) ExpectedJSONBytes() ([]byte, error) {
	if v.DecodedPath == nil {
		return nil, nil
	}
	p := join(v.Entry.root(), *v.DecodedPath)
	z, err := v.Entry.c.files.read(p)
	if err != nil {
		return nil, err
	}
	raw, err := zstdDec.DecodeAll(z, nil)
	if err != nil {
		return nil, errorf("%s: %v", p, err)
	}
	if v.DecodedSHA256 == nil || sha256Hex(raw) != *v.DecodedSHA256 {
		return nil, errorf("%s: the uncompressed sidecar does not match the index's decoded_sha256", p)
	}
	return raw, nil
}

// ExpectedJSON returns the decoded sidecar parsed (numbers as json.Number, so 64-bit values keep their
// digits); nil when the bytes do not decode.
func (v *Variant) ExpectedJSON() (any, error) {
	raw, err := v.ExpectedJSONBytes()
	if raw == nil || err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out any
	if err := d.Decode(&out); err != nil {
		return nil, errorf("%s: %v", *v.DecodedPath, err)
	}
	return out, nil
}

// ---- file sources ----

type fileSource interface {
	read(p string) ([]byte, error)
}

type dirFiles string

func (d dirFiles) read(p string) ([]byte, error) {
	if !fs.ValidPath(p) {
		return nil, errorf("%s: not a path inside the corpus", p)
	}
	b, err := os.ReadFile(filepath.Join(string(d), filepath.FromSlash(p)))
	if err != nil {
		return nil, errorf("%s: %v", p, err)
	}
	return b, nil
}

// archiveFiles maps a path below the archive's single top-level directory to the file's bytes.
type archiveFiles map[string][]byte

func (a archiveFiles) read(p string) ([]byte, error) {
	b, ok := a[p]
	if !ok {
		return nil, errorf("%s is not in the archive", p)
	}
	return b, nil
}

func untarGz(raw []byte) (archiveFiles, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := archiveFiles{}
	top := ""
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		first, rest, _ := strings.Cut(name, "/")
		if top == "" {
			top = first
		} else if first != top {
			return nil, fmt.Errorf("member %s is outside the single top-level directory %s/", h.Name, top)
		}
		switch h.Typeflag {
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out[rest] = b
		case tar.TypeDir:
		default:
			return nil, fmt.Errorf("member %s: unsupported tar entry type %q", h.Name, h.Typeflag)
		}
	}
	if top == "" {
		return nil, fmt.Errorf("the archive is empty")
	}
	return out, nil
}

func join(root, p string) string {
	if root == "" {
		return p
	}
	return root + "/" + p
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
