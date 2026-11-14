package memtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// The bulk sample counts byte-identical ledgers once, takes every Stride-th distinct one, checks every golden
// file against its index, and writes a corpus `xdrcheck replay` loads, with the transaction count from the bytes.
func TestSampleBulk(t *testing.T) {
	src, err := manifest.Load(testcorpus.Vendored(), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	var blobs [][]byte
	for _, e := range src.Entries {
		for _, v := range e.Variants {
			if v.Network == "core-test" && v.Blob.Path != "" && len(blobs) < 3 {
				b, err := os.ReadFile(src.BlobPath(v))
				if err != nil {
					t.Fatal(err)
				}
				blobs = append(blobs, b)
			}
		}
	}
	if len(blobs) < 2 {
		t.Skip("the fixture corpus holds fewer than two core-test ledgers")
	}
	a, b := blobs[0], blobs[1]
	root, goldens := t.TempDir(), t.TempDir()
	files := map[string][][]byte{"test-lcm-current/One/f1.xdr": {a, b, a}, "test-lcm-current/Two/f2.xdr": {b, a}}
	var index strings.Builder
	for _, name := range []string{"test-lcm-current/One/f1.xdr", "test-lcm-current/Two/f2.xdr"} {
		var buf bytes.Buffer
		for _, fr := range files[name] {
			binary.Write(&buf, binary.BigEndian, uint32(len(fr))|0x80000000)
			buf.Write(fr)
		}
		p := filepath.Join(goldens, "vT", filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(buf.Bytes())
		index.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	os.MkdirAll(filepath.Join(root, "bulk"), 0o755)
	os.WriteFile(filepath.Join(root, "bulk", "idx.sha256"), []byte(index.String()), 0o644)
	idx, _ := os.ReadFile(filepath.Join(src.Root, "corpus.json"))
	os.WriteFile(filepath.Join(root, "corpus.json"), idx, 0o644)
	c := &manifest.Corpus{Root: root, Index: &manifest.CorpusIndex{}, Entries: src.Entries}
	c.Index.Tiers.Bulk = &manifest.BulkTier{Ref: "vT", Path: "test-lcm-current", Ledgers: 5, FileIndex: "bulk/idx.sha256"}

	out := filepath.Join(t.TempDir(), "sample")
	s, err := SampleBulk(c, goldens, 0, 0, out)
	if err != nil {
		t.Fatal(err)
	}
	if s.Ledgers != 5 || s.Distinct != 2 || s.Sampled != 2 || s.Stride != 1 {
		t.Errorf("sample %+v", s)
	}
	got, err := manifest.Load(out, manifest.Options{})
	if err != nil {
		t.Fatalf("the sample does not load as a corpus: %v", err)
	}
	if len(got.Entries) != 2 || got.Entries[0].Variants[0].Resolved.Ledger.Transactions == nil {
		t.Errorf("entries %d", len(got.Entries))
	}
	if s, err := SampleBulk(c, goldens, 1, 0, filepath.Join(t.TempDir(), "one")); err != nil || s.Sampled != 1 || s.Stride != 2 {
		t.Errorf("target 1: %+v %v", s, err)
	}
	// Ledgers at or over the size bound go to a corpus of their own.
	bound := int64(max(len(a), len(b)))
	s, err = SampleBulk(c, goldens, 0, bound, filepath.Join(t.TempDir(), "split"))
	if err != nil || s.Sampled != 1 || s.Large != 1 || s.LargeBytes != bound || s.LargeRoot == "" {
		t.Fatalf("split at %d: %+v %v", bound, s, err)
	}
	if lc, err := manifest.Load(s.LargeRoot, manifest.Options{}); err != nil || len(lc.Entries) != 1 {
		t.Errorf("large corpus: %v", err)
	}

	// A golden file that does not match its index is refused.
	p := filepath.Join(goldens, "vT", "test-lcm-current", "Two", "f2.xdr")
	os.WriteFile(p, append(blobsFrame(b), 0), 0o644)
	if _, err := SampleBulk(c, goldens, 0, 0, filepath.Join(t.TempDir(), "bad")); err == nil || !strings.Contains(err.Error(), "the index says") {
		t.Errorf("altered golden: %v", err)
	}
}

func blobsFrame(b []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b))|0x80000000)
	buf.Write(b)
	return buf.Bytes()
}

func TestDepth(t *testing.T) {
	type leaf struct{ N int }
	type mid struct {
		L   []leaf
		Raw []byte
		P   *leaf
	}
	type top struct{ M [2]mid }
	v := top{M: [2]mid{{L: []leaf{{1}}, Raw: []byte{1, 2}}, {P: &leaf{2}}}}
	// top → array → mid → slice → leaf
	if d := Depth(reflect.ValueOf(v)); d != 5 {
		t.Errorf("depth %d, want 5", d)
	}
}

func TestWriteOversize(t *testing.T) {
	var buf bytes.Buffer
	if err := writeOversize(&buf, 7, 3<<20); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 3<<20 || !bytes.HasPrefix(buf.Bytes(), []byte(`{"xcc":"xcc.adapter/1","id":7,"method":"observe"`)) || !bytes.HasSuffix(buf.Bytes(), []byte("\"}}\n")) {
		t.Errorf("%d bytes", buf.Len())
	}
}

func TestVmHWM(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if v := vmHWM(os.Getpid(), commName(self)); v <= 0 {
		t.Errorf("VmHWM of this process: %d", v)
	}
	// A process that does not (yet) run the measured program is not measured.
	if v := vmHWM(os.Getpid(), "xdrcheck"); v != 0 {
		t.Errorf("VmHWM of a process running another program: %d", v)
	}
	if v := vmHWM(-1, "xdrcheck"); v != 0 {
		t.Errorf("no process: %d", v)
	}
	if n := commName("/x/a-program-name-of-twenty"); n != "a-program-name-" {
		t.Errorf("commName: %q", n)
	}
}
