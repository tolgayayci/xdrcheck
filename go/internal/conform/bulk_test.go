package conform

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// recordMarked frames values with RFC 5531 record marks; a value given as two parts is written as two fragments.
func recordMarked(values ...[][]byte) []byte {
	var out []byte
	for _, parts := range values {
		for i, p := range parts {
			mark := uint32(len(p))
			if i == len(parts)-1 {
				mark |= 0x80000000
			}
			out = binary.BigEndian.AppendUint32(out, mark)
			out = append(out, p...)
		}
	}
	return out
}

func TestBulkTier(t *testing.T) {
	tmp := t.TempDir()
	vals := [][][]byte{{[]byte("first ledger")}, {[]byte("second "), []byte("in two fragments")}, {[]byte("third")}}
	file := "test-lcm-current/SomeTests/0123456789abcdef.xdr"
	data := recordMarked(vals...)
	golden := filepath.Join(tmp, "goldens", "v1.0.0", filepath.FromSlash(file))
	os.MkdirAll(filepath.Dir(golden), 0o755)
	os.WriteFile(golden, data, 0o644)
	sum := sha256.Sum256(data)
	os.MkdirAll(filepath.Join(tmp, "corpus", "bulk"), 0o755)
	writeIndex := func(sha string) {
		os.WriteFile(filepath.Join(tmp, "corpus", "bulk", "idx.sha256"), []byte(sha+"  "+file+"\n"), 0o644)
	}
	writeIndex(hex.EncodeToString(sum[:]))
	c := &manifest.Corpus{Root: filepath.Join(tmp, "corpus"), Index: &manifest.CorpusIndex{MaxProtocol: 30}}
	c.Index.Tiers.Bulk = &manifest.BulkTier{Ref: "v1.0.0", Path: "test-lcm-current", FileIndex: "bulk/idx.sha256"}

	bulk, err := BulkCorpus(c, filepath.Join(tmp, "goldens"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bulk.Entries) != 3 || bulk.Entries[1].ID != "bulk/current/SomeTests/0123456789abcdef.xdr#1" {
		t.Fatalf("entries %d, first %+v", len(bulk.Entries), bulk.Entries[0])
	}
	res, err := Run(context.Background(), Options{Sets: &Sets{}, Columns: []*Column{stubColumn(t, "stub@0.1.0", nil)}, Corpus: bulk,
		Jobs: 1, Validator: validator(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Observations) != 3 {
		t.Fatalf("%d cells", len(res.Observations))
	}
	for i, o := range res.Observations {
		want := sha256.Sum256([]byte(strings.Join(func() []string {
			var s []string
			for _, p := range vals[i] {
				s = append(s, string(p))
			}
			return s
		}(), "")))
		in := o.Request.Input
		if o.Cell.Level != "L0" || in.Framing != "record-marked" || in.FrameIndex == nil || *in.FrameIndex != i || in.Path != golden {
			t.Errorf("cell %d request %+v", i, in)
		}
		if o.Outcome != "ok" || *o.Response.Actual.ReencodedSHA256 != hex.EncodeToString(want[:]) || o.Cell.Variant.Blob.SHA256 != hex.EncodeToString(want[:]) {
			t.Errorf("cell %d: %+v %+v", i, o, o.Response)
		}
	}
	if _, err := BulkCorpus(c, filepath.Join(tmp, "goldens"), mustGlobs(t, "bulk/next/*")); err == nil {
		t.Error("a filter matching nothing was accepted")
	}
	// A golden file that does not match the index is never run.
	writeIndex(strings.Repeat("0", 64))
	if _, err := BulkCorpus(c, filepath.Join(tmp, "goldens"), nil); err == nil || !strings.Contains(err.Error(), "the index says") {
		t.Errorf("altered golden accepted: %v", err)
	}
}

func mustGlobs(t *testing.T, s string) Globs {
	g, err := CompileGlobs(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
