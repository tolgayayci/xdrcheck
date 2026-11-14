package lake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/ingest/loadtest"
	"github.com/stellar/go-stellar-sdk/support/datastore"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const (
	repo       = "../../.."
	testnet    = "Test SDF Network ; September 2015"
	chainP28   = repo + "/evidence/wallet-backend-731/out/p28-testnet/run-1/meta.xdr"
	historyObj = repo + "/corpus/objects/testnet/4437357/FFBC4A92--4437357.xdr.zst"
	historyCap = repo + "/corpus/objects/testnet/4437357/capture.json"
)

// chainLedgers reads the vendored Protocol 28 testnet chain run (ledgers 2..24).
func chainLedgers(t *testing.T) [][]byte {
	t.Helper()
	f, err := os.Open(chainP28)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	if err := ScanFrames(f, func(i int, fr Frame, p []byte) error {
		out = append(out, bytes.Clone(p))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 23 {
		t.Fatalf("%d records", len(out))
	}
	return out
}

func TestConfigAndKeysMatchSDK(t *testing.T) {
	cfg := NewConfig(testnet)
	// The public testnet lake's .config.json, 142 bytes.
	want := `{"networkPassphrase":"Test SDF Network ; September 2015","version":"1.0","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}`
	if string(cfg.Bytes()) != want {
		t.Errorf("config %s", cfg.Bytes())
	}
	worked := map[uint32]string{
		2:       "FFFFFFFF--0-63999/FFFFFFFD--2.xdr.zst",
		63999:   "FFFFFFFF--0-63999/FFFF0600--63999.xdr.zst",
		64000:   "FFFF05FF--64000-127999/FFFF05FF--64000.xdr.zst",
		4437357: "FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst",
	}
	for seq, key := range worked {
		if got := cfg.ObjectKey(seq); got != key {
			t.Errorf("%d: %s, want %s", seq, got, key)
		}
	}
	for _, c := range []Config{cfg, {LedgersPerBatch: 8, BatchesPerPartition: 64000}, {LedgersPerBatch: 1, BatchesPerPartition: 1}, {LedgersPerBatch: 64, BatchesPerPartition: 10}} {
		schema := datastore.DataStoreSchema{LedgersPerFile: c.LedgersPerBatch, FilesPerPartition: c.BatchesPerPartition}
		for _, seq := range []uint32{0, 1, 2, 7, 8, 63999, 64000, 4437357, 65437981, 4294967295} {
			if got, want := c.ObjectKey(seq), schema.GetObjectKeyFromSequenceNumber(seq); got != want {
				t.Errorf("%+v seq %d: %s, SDK %s", c, seq, got, want)
			}
		}
	}
}

// openBSB opens dir through go-stellar-sdk's filesystem datastore and BufferedStorageBackend.
func openBSB(t *testing.T, dir string, from, to uint32) *ledgerbackend.BufferedStorageBackend {
	t.Helper()
	ctx := context.Background()
	ds, err := datastore.NewDataStore(ctx, datastore.DataStoreConfig{Type: "Filesystem", Params: map[string]string{"destination_path": dir}})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := datastore.LoadSchema(ctx, ds, datastore.DataStoreConfig{NetworkPassphrase: testnet, Compression: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	if schema.LedgersPerFile != 1 || schema.FilesPerPartition != 64000 || schema.FileExtension != "zst" {
		t.Fatalf("schema %+v", schema)
	}
	bsb, err := ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{BufferSize: 4, NumWorkers: 2, RetryLimit: 0, RetryWait: time.Millisecond}, ds, schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := bsb.PrepareRange(ctx, ledgerbackend.BoundedRange(from, to)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bsb.Close() })
	return bsb
}

func TestChainReadBackThroughSDK(t *testing.T) {
	lcms := chainLedgers(t)
	var ledgers []Ledger
	for i, b := range lcms {
		ledgers = append(ledgers, Ledger{Seq: uint32(2 + i), Load: func() ([]byte, error) { return b, nil }})
	}
	dir := t.TempDir()
	l, err := Write(dir, NewConfig(testnet), ledgers)
	if err != nil {
		t.Fatal(err)
	}
	if l.First != 2 || l.Last != 24 || len(l.Objects) != 23 {
		t.Fatalf("layout %d-%d, %d objects", l.First, l.Last, len(l.Objects))
	}
	bsb := openBSB(t, dir, 2, 24)
	for i, want := range lcms {
		got, err := bsb.GetLedger(context.Background(), uint32(2+i))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := got.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, want) {
			t.Fatalf("ledger %d differs after the round trip", 2+i)
		}
	}
	// The ledger the CAP-0073 entry names is ledger 15 of this chain.
	if sum := sha256.Sum256(lcms[13]); hex.EncodeToString(sum[:]) != "fe7ebd94df50cff714681207f98699c4e5d86a0eeca9175f96a38358b28dfb75" {
		t.Error("ledger 15 is not the corpus blob")
	}
}

func TestHistoryObjectServedVerbatim(t *testing.T) {
	var capture struct {
		LakeKey string `json:"key"`
		SHA     string `json:"object_sha256"`
	}
	data, err := os.ReadFile(historyCap)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	key := capture.LakeKey
	if i := strings.Index(key, "2025-12-18/"); i >= 0 {
		key = key[i+len("2025-12-18/"):]
	}
	dir := t.TempDir()
	_, err = Write(dir, NewConfig(testnet), []Ledger{{Seq: 4437357, Original: &Original{Key: key, Path: historyObj, SHA256: capture.SHA}}})
	if err != nil {
		t.Fatal(err)
	}
	served, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(served); hex.EncodeToString(sum[:]) != capture.SHA {
		t.Fatalf("served object sha256 %x, captured %s", sum, capture.SHA)
	}
	bsb := openBSB(t, dir, 4437357, 4437357)
	got, err := bsb.GetLedger(context.Background(), 4437357)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := got.MarshalBinary()
	blob, err := os.ReadFile(repo + "/corpus/blobs/58/582e694b96bf69f894763909a1b058c1a2523d5634f2e0947393cee9765f4e0e.xdr")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, blob) {
		t.Error("ledger read from the lake object is not the corpus blob")
	}
	// Our own wrapping of the same blob decompresses to the lake's batch bytes.
	lakeBatch, _ := Decompress(served)
	if !bytes.Equal(lakeBatch, BatchXDR(4437357, blob)) {
		t.Error("BatchXDR differs from the public lake's decompressed object")
	}

	bad := Original{Key: key, Path: historyObj, SHA256: strings.Repeat("0", 64)}
	if _, err := Write(t.TempDir(), NewConfig(testnet), []Ledger{{Seq: 4437357, Original: &bad}}); err == nil {
		t.Error("an object with the wrong sha256 was served")
	}
}

func TestRefusals(t *testing.T) {
	lcms := chainLedgers(t)
	load := func(b []byte) func() ([]byte, error) { return func() ([]byte, error) { return b, nil } }
	if _, err := Write(t.TempDir(), NewConfig(testnet), []Ledger{{Seq: 2, Load: load(lcms[0])}, {Seq: 4, Load: load(lcms[2])}}); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Errorf("gap: %v", err)
	}
	if _, err := Write(t.TempDir(), NewConfig(testnet), []Ledger{{Seq: 3, Load: load(lcms[0])}}); err == nil || !strings.Contains(err.Error(), "header says sequence 2") {
		t.Errorf("wrong sequence: %v", err)
	}
}

func TestInspectAndRenumber(t *testing.T) {
	lcms := chainLedgers(t)
	src := lcms[13] // ledger 15
	h, err := Inspect(src)
	if err != nil {
		t.Fatal(err)
	}
	if h.Seq != 15 || h.Hash != "c0f754e7c9a7a47a0969dbf88f861c89bf79ae0e97ffe464e90aaa8c292145b3" || h.ProtocolVersion != 28 || h.Transactions != 1 || h.Version != 2 {
		t.Errorf("header %+v", h)
	}
	var entry xdr.LedgerHeaderHistoryEntry
	if err := entry.UnmarshalBinary(h.HeaderXDR); err != nil || entry.Hash.HexString() != h.Hash {
		t.Errorf("header xdr: %v", err)
	}

	out, err := Renumber(src, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var before, after xdr.LedgerCloseMeta
	before.UnmarshalBinary(src)
	if err := after.UnmarshalBinary(out); err != nil {
		t.Fatal(err)
	}
	if after.LedgerSequence() != 1000 || after.LedgerHash() != before.LedgerHash() || after.TransactionHash(0) != before.TransactionHash(0) {
		t.Errorf("renumbered: seq %d", after.LedgerSequence())
	}
	// Same result as the SDK's loadtest update restricted to the ledger's own sequence.
	ref := before
	if err := loadtest.UpdateLedgerSeqInLedgerEntries(&ref, func(s uint32) uint32 {
		if s == 15 {
			return 1000
		}
		return s
	}); err != nil {
		t.Fatal(err)
	}
	ref.V2.LedgerHeader.Header.LedgerSeq = 1000
	refRaw, _ := ref.MarshalBinary()
	// loadtest would also map a liveUntilLedgerSeq equal to 15; this ledger has none, so the two must agree
	// byte for byte (including the source account's seqLedger, which is 15).
	if !bytes.Equal(refRaw, out) {
		t.Error("renumbered bytes differ from the SDK loadtest transformation")
	}
	if bytes.Equal(out, src) {
		t.Error("renumber changed nothing")
	}
}
