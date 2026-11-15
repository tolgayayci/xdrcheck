package ledger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestEmptyCutFrame: an empty ledger's cut file must still be a valid zstd frame (zstd -d refuses 0 bytes).
func TestEmptyCutFrame(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.zst")
	f, _ := os.Create(p)
	z, _ := zstd.NewWriter(f, zstd.WithZeroFrames(true))
	z.Close()
	f.Close()
	b, _ := os.ReadFile(p)
	if len(b) == 0 {
		t.Fatal("empty file")
	}
	d, _ := zstd.NewReader(nil)
	if out, err := d.DecodeAll(b, nil); err != nil || len(out) != 0 {
		t.Fatalf("decode: %v %d", err, len(out))
	}
}
