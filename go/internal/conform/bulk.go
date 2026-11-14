package conform

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// BulkPrefix starts the ID of every bulk-tier cell entry: bulk/<tier>/<test>/<file>.xdr#<frame>.
const BulkPrefix = "bulk/"

// GoldensRoot is the golden cache root: flag, else $XDRCHECK_GOLDENS, else ~/.cache/xdrcheck/goldens. A golden file
// <file> (a path inside the stellar-core repository) at tag <T> is <root>/<T>/<file>.
func GoldensRoot(flag string) string {
	if flag != "" {
		return flag
	}
	if p := os.Getenv("XDRCHECK_GOLDENS"); p != "" {
		return p
	}
	d, _ := userdir.HomeCache()
	return filepath.Join(d, "goldens")
}

// BulkCorpus builds the bulk tier as a corpus of synthetic ledger entries, one per LedgerCloseMeta frame of
// every golden file the tier's hash index lists (corpus.json tiers.bulk). Each file is checked against its
// indexed sha256 first; a missing or altered file is an error, so nothing is run on unverified bytes. The
// entries carry only what the bytes give: the frame's hash and size (the L0 reference), the tier's protocol
// and level L0. Only files whose ID (bulk/<tier>/<test>/<file>.xdr) matches files are read.
func BulkCorpus(c *manifest.Corpus, goldens string, files Globs) (*manifest.Corpus, error) {
	if c.Index == nil || c.Index.Tiers.Bulk == nil {
		return nil, errors.New("corpus.json has no tiers.bulk")
	}
	b := c.Index.Tiers.Bulk
	tier := strings.TrimPrefix(b.Path, "test-lcm-")
	protocol := c.Index.MaxProtocol
	if tier == "next" {
		protocol++
	}
	root := filepath.Join(goldens, b.Ref)
	idx, err := os.Open(filepath.Join(c.Root, filepath.FromSlash(b.FileIndex)))
	if err != nil {
		return nil, fmt.Errorf("bulk index: %w", err)
	}
	defer idx.Close()
	out := &manifest.Corpus{Root: root, Index: c.Index}
	sc := bufio.NewScanner(idx)
	n := 0
	for sc.Scan() {
		sum, file, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s: line %q is not sha256sum output", b.FileIndex, sc.Text())
		}
		id := BulkPrefix + tier + "/" + strings.TrimPrefix(file, b.Path+"/")
		if !files.Match(id) {
			continue
		}
		n++
		frames, err := readFrames(filepath.Join(root, filepath.FromSlash(file)), sum)
		if err != nil {
			return nil, fmt.Errorf("golden %s (fetch it with xdrcheck-corpus fetch-goldens %s): %w", file, b.Ref, err)
		}
		for i, f := range frames {
			fi := i
			e := &manifest.Entry{
				Schema: manifest.EntrySchema, ID: fmt.Sprintf("%s#%d", id, i), Title: file, Kind: "ledger",
				Protocol: manifest.ProtocolRange{Introduced: protocol}, Reference: "network",
				Conformance: &manifest.Conformance{Levels: []string{"L0"}},
			}
			v := &manifest.Variant{
				Network: "core-test", Protocol: protocol, XDRType: "LedgerCloseMeta",
				Blob:   manifest.Blob{SHA256: f.sha, Bytes: f.size, Path: filepath.ToSlash(file)},
				Source: manifest.Source{Kind: manifest.SourceCoreGolden, CoreGolden: &manifest.CoreGoldenSource{Kind: manifest.SourceCoreGolden, CoreTag: b.Ref, Tier: tier, File: file, FileSHA256: sum, FrameIndex: fi}},
			}
			e.Variants = []*manifest.Variant{v}
			out.Entries = append(out.Entries, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("no bulk file matches --entries")
	}
	return out, nil
}

type frame struct {
	sha  string
	size int64
}

// readFrames checks a golden file's sha256 and splits it into RFC 5531 record-marked frames.
func readFrames(path, wantSHA string) ([]frame, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if s := sha256.Sum256(data); hex.EncodeToString(s[:]) != wantSHA {
		return nil, fmt.Errorf("sha256 %x, the index says %s", s, wantSHA)
	}
	var frames []frame
	h := sha256.New()
	var size int64
	for off := 0; off < len(data); {
		if len(data)-off < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		mark := binary.BigEndian.Uint32(data[off:])
		n := int(mark & 0x7fffffff)
		off += 4
		if len(data)-off < n {
			return nil, fmt.Errorf("frame %d: record mark says %d bytes, %d left", len(frames), n, len(data)-off)
		}
		h.Write(data[off : off+n])
		size += int64(n)
		off += n
		if mark&0x80000000 != 0 {
			frames = append(frames, frame{sha: hex.EncodeToString(h.Sum(nil)), size: size})
			h.Reset()
			size = 0
		}
	}
	if size != 0 {
		return nil, errors.New("the last record has no last-fragment mark")
	}
	return frames, nil
}

// bulkFrame returns the frame index of a bulk-tier variant, or false.
func bulkFrame(e *manifest.Entry, v *manifest.Variant) (int, bool) {
	if !strings.HasPrefix(e.ID, BulkPrefix) || v == nil || v.Source.CoreGolden == nil {
		return 0, false
	}
	return v.Source.CoreGolden.FrameIndex, true
}
