package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// A chain whose stream is vendored zstd-compressed under corpus/chains/ (as the generator writes it) serves
// every ledger from that stream, checked against the index; the raw evidence stream of the same chain serves
// the same bytes.
func TestCompressedChainStream(t *testing.T) {
	// The research-probe chain, whose raw stream is vendored under evidence/ (frozen copy of its index).
	ch, err := manifest.LoadChainIndex(filepath.Join(testcorpus.Frozen(), "chains", "sac-trust", "p28-testnet.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(corpusRoot, "..", filepath.FromSlash(ch.Stream.Path)))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir() // no blobs/: every ledger comes from the stream
	rel := "chains/sac-trust/p28-testnet.meta.xdr.zst"
	if err := os.MkdirAll(filepath.Join(root, "chains", "sac-trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), enc.EncodeAll(raw, nil), 0o644); err != nil {
		t.Fatal(err)
	}

	zch := *ch
	stream := *ch.Stream
	stream.Path = rel
	zch.Stream = &stream
	s := newSources(&manifest.Corpus{Root: root})
	for _, l := range zch.Ledgers {
		led, err := s.chainLedger(&zch, l)
		if err != nil {
			t.Fatal(err)
		}
		if !led.src.zst {
			t.Fatalf("ledger %d not read from the compressed stream", l.Seq)
		}
		b, err := led.Load()
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != l.BlobSHA256 {
			t.Fatalf("ledger %d: wrong bytes", l.Seq)
		}
	}

	// The index's sha256 is of the uncompressed stream; a different one is refused.
	bad := zch
	badStream := stream
	badStream.SHA256 = strings.Repeat("0", 64)
	bad.ID = "sac-trust/p28-testnet-bad"
	bad.Stream = &badStream
	if _, err := s.chainLedger(&bad, bad.Ledgers[0]); err == nil || !strings.Contains(err.Error(), "index says") {
		t.Fatalf("a stream with the wrong sha256 was accepted: %v", err)
	}
}
