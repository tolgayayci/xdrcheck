package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Ledger is one served ledger of a unit. Its bytes are read on demand by Load, which checks them against the
// blob hash before anything is served; nothing is held in memory by the plan.
type Ledger struct {
	Seq         uint32 // as served
	OriginalSeq uint32 // in the corpus; differs only in stream units
	BlobSHA256  string
	Bytes       int64
	// Original is the vendored public-lake object of a history entry, served verbatim on SEP-54 inputs of a
	// single unit. Nil otherwise.
	Original *lake.Original

	src blobRef
}

// Transformed reports whether the served bytes differ from the corpus bytes.
func (l Ledger) Transformed() bool { return l.Seq != l.OriginalSeq }

// Load reads the ledger's LedgerCloseMeta, checks its size and sha256, and renumbers it when the unit is a
// stream.
func (l Ledger) Load() ([]byte, error) {
	raw, err := l.src.read()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != l.BlobSHA256 || (l.Bytes > 0 && int64(len(raw)) != l.Bytes) {
		return nil, fmt.Errorf("ledger %d: bytes do not match blob %s (%d bytes, sha256 %s); refusing to serve them",
			l.OriginalSeq, l.BlobSHA256, len(raw), got)
	}
	if l.Transformed() {
		return lake.Renumber(raw, l.Seq)
	}
	return raw, nil
}

// maxStreamBytes bounds what a zstd-compressed chain stream may decompress to.
const maxStreamBytes = 1 << 30

// blobRef locates ledger bytes: a whole blob file, or one record of a chain's meta stream. In a
// zstd-compressed stream (`.zst`, as the generator vendors them under corpus/chains/) the offset is
// in the uncompressed stream, and a read decompresses up to the record.
type blobRef struct {
	path   string
	offset int64 // -1: the whole file
	length int64
	zst    bool
}

func (r blobRef) read() ([]byte, error) {
	if r.offset < 0 {
		return os.ReadFile(r.path)
	}
	f, err := os.Open(r.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, r.length)
	if r.zst {
		dec, err := openZstd(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.path, err)
		}
		defer dec.Close()
		if _, err := io.CopyN(io.Discard, dec, r.offset); err != nil {
			return nil, fmt.Errorf("%s at %d: %w", r.path, r.offset, err)
		}
		if _, err := io.ReadFull(dec, buf); err != nil {
			return nil, fmt.Errorf("%s at %d: %w", r.path, r.offset, err)
		}
		return buf, nil
	}
	if _, err := f.ReadAt(buf, r.offset); err != nil {
		return nil, fmt.Errorf("%s at %d: %w", r.path, r.offset, err)
	}
	return buf, nil
}

func openZstd(r io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(r, zstd.WithDecoderMaxMemory(maxStreamBytes), zstd.WithDecoderConcurrency(1))
}

// isZstd reports whether a stream path names a zstd-compressed stream.
func isZstd(p string) bool { return strings.HasSuffix(p, ".zst") }

// sources finds ledger bytes in a corpus: corpus/blobs first, then chain meta streams (only a chain's entry
// ledgers are vendored as blobs; the rest of the chain is read from its stream, checked against the index).
type sources struct {
	c       *manifest.Corpus
	streams map[string]map[string]blobRef // chain ID -> blob sha256 -> record
}

func newSources(c *manifest.Corpus) *sources {
	return &sources{c: c, streams: map[string]map[string]blobRef{}}
}

func (s *sources) blobFile(sha string) (string, bool) {
	p := s.c.File(path.Join("blobs", sha[:2], sha+".xdr"))
	_, err := os.Stat(p)
	return p, err == nil
}

func (s *sources) variantLedger(v *manifest.Variant) (Ledger, error) {
	led := Ledger{Seq: uint32(v.LedgerSeq), OriginalSeq: uint32(v.LedgerSeq), BlobSHA256: v.Blob.SHA256, Bytes: v.Blob.Bytes}
	p, ok := s.blobFile(v.Blob.SHA256)
	if !ok {
		return Ledger{}, fmt.Errorf("blob %s is not in the corpus (bulk-tier ledgers must be fetched first)", v.Blob.SHA256)
	}
	led.src = blobRef{path: p, offset: -1}
	if h := v.Source.History; h != nil {
		obj := h.ObjectPath
		if obj == "" {
			obj = path.Join("objects", v.Network, strconv.FormatInt(v.LedgerSeq, 10), path.Base(h.Key))
		}
		full := s.c.File(obj)
		if _, err := os.Stat(full); err == nil {
			led.Original = &lake.Original{Key: h.Key, Path: full, SHA256: h.ObjectSHA256, Metadata: h.ObjectMetadata}
		} else if h.ObjectPath != "" {
			return Ledger{}, fmt.Errorf("history object %s: %w", h.ObjectPath, err)
		}
	}
	return led, nil
}

func (s *sources) chainLedger(ch *manifest.ChainIndex, l manifest.ChainLedger) (Ledger, error) {
	led := Ledger{Seq: uint32(l.Seq), OriginalSeq: uint32(l.Seq), BlobSHA256: l.BlobSHA256, Bytes: l.Bytes}
	if p, ok := s.blobFile(l.BlobSHA256); ok {
		led.src = blobRef{path: p, offset: -1}
		return led, nil
	}
	idx, err := s.streamIndex(ch)
	if err != nil {
		return Ledger{}, err
	}
	ref, ok := idx[l.BlobSHA256]
	if !ok {
		return Ledger{}, fmt.Errorf("blob %s is neither in corpus/blobs nor in the chain's stream", l.BlobSHA256)
	}
	led.src = ref
	return led, nil
}

// streamIndex scans a chain's meta stream once: it checks the stream's sha256 and record count against the
// index and maps every record's sha256 to its position.
func (s *sources) streamIndex(ch *manifest.ChainIndex) (map[string]blobRef, error) {
	if idx, ok := s.streams[ch.ID]; ok {
		return idx, nil
	}
	if ch.Stream == nil || ch.Stream.Path == "" {
		return nil, fmt.Errorf("chain %s keeps no meta stream and its ledgers are not all in corpus/blobs", ch.ID)
	}
	p, err := s.streamPath(ch.Stream.Path)
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", ch.ID, err)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	zst := isZstd(p)
	if zst {
		dec, err := openZstd(f)
		if err != nil {
			return nil, fmt.Errorf("chain %s stream %s: %w", ch.ID, p, err)
		}
		defer dec.Close()
		// A stream larger than the bound is cut short, which fails the sha256 check below.
		r = io.LimitReader(dec, maxStreamBytes)
	}
	// The index's sha256 is of the uncompressed stream.
	whole := sha256.New()
	idx := map[string]blobRef{}
	n := 0
	err = lake.ScanFrames(io.TeeReader(r, whole), func(i int, fr lake.Frame, payload []byte) error {
		sum := sha256.Sum256(payload)
		idx[hex.EncodeToString(sum[:])] = blobRef{path: p, offset: fr.Offset, length: fr.Length, zst: zst}
		n++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chain %s stream %s: %w", ch.ID, p, err)
	}
	if ch.Stream.SHA256 != "" {
		if got := hex.EncodeToString(whole.Sum(nil)); got != ch.Stream.SHA256 {
			return nil, fmt.Errorf("chain %s stream %s: sha256 %s, index says %s", ch.ID, p, got, ch.Stream.SHA256)
		}
	}
	if ch.Stream.Records > 0 && n != ch.Stream.Records {
		return nil, fmt.Errorf("chain %s stream %s: %d records, index says %d", ch.ID, p, n, ch.Stream.Records)
	}
	s.streams[ch.ID] = idx
	return idx, nil
}

// streamPath resolves a chain's stream path. Generated chains name their zstd-compressed stream relative to
// the corpus root (chains/<id>.meta.xdr.zst); the first vendored chains name a raw stream relative to the
// repository root (evidence/…), the parent of the corpus root.
func (s *sources) streamPath(p string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}
	for _, base := range []string{s.c.Root, filepath.Dir(filepath.Clean(s.c.Root))} {
		full := filepath.Join(base, filepath.FromSlash(p))
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("meta stream %s: %w", p, fs.ErrNotExist)
}
