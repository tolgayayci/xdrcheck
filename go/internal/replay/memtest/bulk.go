package memtest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Sample is a sampled bulk tier written out as corpora `xdrcheck replay --corpus` loads.
type Sample struct {
	Root     string `json:"root"`     // the sample's corpus directory
	Tier     string `json:"tier"`     // the bulk tier's path in the golden tree, for example test-lcm-current
	Ref      string `json:"ref"`      // the stellar-core tag
	Files    int    `json:"files"`    // golden files in the tier
	Ledgers  int    `json:"ledgers"`  // ledgers (frames) in the tier
	Distinct int    `json:"distinct"` // distinct ledgers (by sha256) among them
	Stride   int    `json:"stride"`   // every Stride-th distinct ledger under the size bound was taken
	Sampled  int    `json:"sampled"`  // ledgers written to Root
	Bytes    int64  `json:"bytes"`    // their bytes

	LargeRoot  string `json:"large_root,omitempty"` // the corpus of every distinct ledger at or over the size bound
	Large      int    `json:"large"`
	LargeBytes int64  `json:"large_bytes"`
}

// SampleBulk samples the corpus's bulk tier — the LedgerCloseMeta frames of the golden files its hash index
// lists, in index order, each byte-identical frame counted once (golden tests repeat their setup ledgers) — into
// two corpora: under dir about target of the distinct ledgers smaller than large (every Stride-th; target 0
// takes all), and under dir-large every distinct ledger of large bytes or more. A ledger of megabytes takes
// the harness a hundred and more MiB for the moment it is decoded, and how high that moment reaches depends on
// the collector's timing; it would drown the growth a stream's length causes, so large ledgers are run on
// their own. Each corpus holds corpus.json copied from c, one blob per ledger under blobs/, and one manifest
// entry per ledger under manifest/bulk/<tier>/<test>/<file>.xdr#<frame>.json on network core-test with the
// corpus's own core-test passphrase. Every golden file is checked against its indexed sha256 before a byte of it
// is used, and the tier's frame count against corpus.json.
//
// An entry's only expectation is the ledger's transaction count, read from the bytes by the harness's own
// ledger inspector, so the matcher has a fact to check and a correct reader passes.
func SampleBulk(c *manifest.Corpus, goldens string, target int, large int64, dir string) (*Sample, error) {
	if c.Index == nil || c.Index.Tiers.Bulk == nil {
		return nil, errors.New("corpus.json has no tiers.bulk")
	}
	b := c.Index.Tiers.Bulk
	passphrase := ""
	for _, e := range c.Entries {
		for _, v := range e.Variants {
			if v.Network == "core-test" && v.Passphrase != "" && passphrase == "" {
				passphrase = v.Passphrase
			}
		}
	}
	if passphrase == "" {
		return nil, errors.New("no core-test variant in the corpus names the golden files' passphrase")
	}
	files, err := readIndex(filepath.Join(c.Root, filepath.FromSlash(b.FileIndex)))
	if err != nil {
		return nil, err
	}
	root := filepath.Join(goldens, b.Ref)
	read := func(f indexedFile) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			return nil, fmt.Errorf("golden %s (fetch the goldens first: xdrcheck-corpus fetch-goldens %s): %w", f.path, b.Ref, err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f.sha {
			return nil, fmt.Errorf("golden %s: sha256 %x, the index says %s", f.path, sum, f.sha)
		}
		return data, nil
	}

	// Pass 1: the distinct frames, in order, split by size.
	type at struct{ file, frame int }
	var small []at
	big := map[at]bool{}
	seen := map[[32]byte]bool{}
	total, distinct := 0, 0
	for fi, f := range files {
		data, err := read(f)
		if err != nil {
			return nil, err
		}
		err = lake.ScanFrames(bytes.NewReader(data), func(i int, _ lake.Frame, payload []byte) error {
			total++
			if sum := sha256.Sum256(payload); !seen[sum] {
				seen[sum] = true
				distinct++
				if large > 0 && int64(len(payload)) >= large {
					big[at{fi, i}] = true
				} else {
					small = append(small, at{fi, i})
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("golden %s: %w", f.path, err)
		}
	}
	if total != b.Ledgers {
		return nil, fmt.Errorf("the bulk tier holds %d ledgers, corpus.json says %d", total, b.Ledgers)
	}
	s := &Sample{Root: dir, Tier: b.Path, Ref: b.Ref, Files: len(files), Ledgers: total, Distinct: distinct, Stride: 1}
	if target > 0 && len(small) > target {
		s.Stride = (len(small) + target - 1) / target
	}
	take := map[at]bool{}
	for i, a := range small {
		if i%s.Stride == 0 {
			take[a] = true
		}
	}
	if len(big) > 0 {
		s.LargeRoot = dir + "-large"
	}

	// Pass 2: write the chosen frames.
	idx, err := os.ReadFile(filepath.Join(c.Root, "corpus.json"))
	if err != nil {
		return nil, err
	}
	for _, d := range []string{s.Root, s.LargeRoot} {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Join(d, "manifest"), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(d, "corpus.json"), idx, 0o644); err != nil {
			return nil, err
		}
	}
	tierName := strings.TrimPrefix(b.Path, "test-lcm-")
	for fi, f := range files {
		data, err := read(f)
		if err != nil {
			return nil, err
		}
		rel := strings.TrimPrefix(f.path, b.Path+"/")
		err = lake.ScanFrames(bytes.NewReader(data), func(i int, _ lake.Frame, payload []byte) error {
			into := ""
			switch a := (at{fi, i}); {
			case take[a]:
				into = s.Root
				s.Sampled++
				s.Bytes += int64(len(payload))
			case big[a]:
				into = s.LargeRoot
				s.Large++
				s.LargeBytes += int64(len(payload))
			default:
				return nil
			}
			if err := bulkEntry(into, tierName, rel, i, payload, passphrase, b.Ref, f); err != nil {
				return fmt.Errorf("golden %s frame %d: %w", f.path, i, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

type indexedFile struct{ sha, path string }

func readIndex(file string) ([]indexedFile, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("bulk index: %w", err)
	}
	defer f.Close()
	var out []indexedFile
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, p, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s: line %q is not sha256sum output", file, sc.Text())
		}
		out = append(out, indexedFile{sha: sum, path: p})
	}
	return out, sc.Err()
}

// bulkEntry writes one sampled ledger's blob and manifest entry.
func bulkEntry(dir, tier, rel string, frame int, payload []byte, passphrase, ref string, f indexedFile) error {
	h, err := lake.Inspect(payload)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	blob := path.Join("blobs", sha[:2], sha+".xdr")
	if err := os.MkdirAll(filepath.Join(dir, "blobs", sha[:2]), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(blob)), payload, 0o644); err != nil {
		return err
	}
	test, _, _ := strings.Cut(rel, "/")
	txs := h.Transactions
	id := fmt.Sprintf("bulk/%s/%s#%d", tier, rel, frame)
	e := &manifest.Entry{
		Schema: manifest.EntrySchema, ID: id, Title: rel, Kind: "ledger", Caps: []int{},
		Protocol: manifest.ProtocolRange{Introduced: int(h.ProtocolVersion)}, Reference: "network",
		Why:    "a ledger of the sampled bulk tier, for the replay harness's memory test",
		Expect: manifest.Expect{Ledger: &manifest.LedgerCounts{Transactions: &txs}},
		Variants: []*manifest.Variant{{
			Network: "core-test", Passphrase: passphrase, Protocol: int(h.ProtocolVersion), LedgerSeq: int64(h.Seq),
			XDRType: "LedgerCloseMeta", Blob: manifest.Blob{SHA256: sha, Bytes: int64(len(payload)), Path: blob},
			Source: manifest.Source{Kind: manifest.SourceCoreGolden, CoreGolden: &manifest.CoreGoldenSource{
				Kind: manifest.SourceCoreGolden, CoreTag: ref, Tier: tier, File: f.path, FileSHA256: f.sha, FrameIndex: frame, TestName: test}},
		}},
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	file := filepath.Join(dir, "manifest", filepath.FromSlash(id)+".json")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, data, 0o644)
}
