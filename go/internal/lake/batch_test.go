package lake

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/support/datastore"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// batchCase is one batch-shaped layout and the range a reader is asked for.
type batchCase struct {
	name     string
	perBatch uint32
	batches  []Batch
	at       []uint32 // the key sequence of each object
	from, to uint32
	// disagree: an object's header names other ledgers than the ones it holds.
	disagree bool
}

// batchCases builds the layouts from the vendored chain (ledger 2+i is lcms[i]).
func batchCases(t *testing.T) []batchCase {
	lcms := chainLedgers(t)
	l := func(seq uint32) []byte { return lcms[seq-2] }
	return []batchCase{
		{name: "multi-ledger batch", perBatch: 4, batches: []Batch{{4, 7, [][]byte{l(4), l(5), l(6), l(7)}}, {8, 11, [][]byte{l(8), l(9), l(10), l(11)}}},
			at: []uint32{4, 8}, from: 4, to: 11},
		{name: "multi-ledger batch read from its middle", perBatch: 4, batches: []Batch{{4, 7, [][]byte{l(4), l(5), l(6), l(7)}}},
			at: []uint32{4}, from: 6, to: 7},
		{name: "empty batch", perBatch: 1, batches: []Batch{{10, 10, nil}}, at: []uint32{10}, from: 10, to: 10},
		{name: "header below the object's key", perBatch: 1, batches: []Batch{{9, 9, [][]byte{l(10)}}}, at: []uint32{10}, from: 10, to: 10},
		{name: "header above its contents", perBatch: 1, batches: []Batch{{10, 10, [][]byte{l(11)}}}, at: []uint32{10}, from: 10, to: 10, disagree: true},
		{name: "multi-ledger header shifted against its contents", perBatch: 4, batches: []Batch{{4, 7, [][]byte{l(5), l(6), l(7), l(8)}}},
			at: []uint32{4}, from: 4, to: 7, disagree: true},
		{name: "end beyond the ledgers held", perBatch: 4, batches: []Batch{{4, 7, [][]byte{l(4), l(5)}}}, at: []uint32{4}, from: 4, to: 7},
		{name: "a stale object repeats the previous ledger", perBatch: 1, batches: []Batch{{10, 10, [][]byte{l(10)}}, {10, 10, [][]byte{l(10)}}},
			at: []uint32{10, 11}, from: 10, to: 11},
	}
}

// getLedgerFunc is what a reader under test does when asked for one ledger.
type getLedgerFunc func(seq uint32) (xdr.LedgerCloseMeta, error)

// checkBatchReplay asks for every ledger of the range in order and returns the first answer that is neither the
// requested ledger nor a refusal: a reader must return the ledger it was asked for or refuse, never a different
// ledger. Asking stops at the first refusal (a halted reader asks no further).
func checkBatchReplay(from, to uint32, get getLedgerFunc) (wrong string, refused bool) {
	for seq := from; seq <= to; seq++ {
		lcm, err := get(seq)
		if err != nil {
			return "", true
		}
		if got := lcm.LedgerSequence(); got != seq {
			return fmt.Sprintf("asked for ledger %d, got ledger %d", seq, got), false
		}
	}
	return "", false
}

// sdkReader opens a layout through go-stellar-sdk's filesystem datastore and BufferedStorageBackend, the reader
// stellar-etl, wallet-backend, stellar-rpc and Horizon ingest lake objects with. A refusal in PrepareRange
// counts as a refusal.
func sdkReader(t *testing.T, dir string, from, to uint32) getLedgerFunc {
	ctx := context.Background()
	ds, err := datastore.NewDataStore(ctx, datastore.DataStoreConfig{Type: "Filesystem", Params: map[string]string{"destination_path": dir}})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := datastore.LoadSchema(ctx, ds, datastore.DataStoreConfig{NetworkPassphrase: testnet, Compression: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	bsb, err := ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{BufferSize: 4, NumWorkers: 2, RetryLimit: 0, RetryWait: time.Millisecond}, ds, schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bsb.Close() })
	prepErr := bsb.PrepareRange(ctx, ledgerbackend.BoundedRange(from, to))
	return func(seq uint32) (xdr.LedgerCloseMeta, error) {
		if prepErr != nil {
			return xdr.LedgerCloseMeta{}, prepErr
		}
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return bsb.GetLedger(c, seq)
	}
}

// indexReader is a reader that trusts the object header: it takes ledger seq-start of the object whose key
// covers seq. It returns a different ledger whenever a header disagrees with its contents; the check must say so.
func indexReader(c batchCase) getLedgerFunc {
	return func(seq uint32) (xdr.LedgerCloseMeta, error) {
		for i, b := range c.batches {
			first := (c.at[i] / c.perBatch) * c.perBatch
			if seq < first || seq >= first+c.perBatch {
				continue
			}
			k := int(seq) - int(b.Start)
			if k < 0 || k >= len(b.Ledgers) {
				return xdr.LedgerCloseMeta{}, fmt.Errorf("ledger %d is not in the object", seq)
			}
			var lcm xdr.LedgerCloseMeta
			return lcm, xdr.SafeUnmarshal(b.Ledgers[k], &lcm)
		}
		return xdr.LedgerCloseMeta{}, fmt.Errorf("no object holds ledger %d", seq)
	}
}

// checkingReader is indexReader plus the check a careful reader makes: the ledger it returns has the sequence
// it was asked for.
func checkingReader(c batchCase) getLedgerFunc {
	inner := indexReader(c)
	return func(seq uint32) (xdr.LedgerCloseMeta, error) {
		lcm, err := inner(seq)
		if err == nil && lcm.LedgerSequence() != seq {
			return xdr.LedgerCloseMeta{}, fmt.Errorf("the object holds ledger %d where %d belongs", lcm.LedgerSequence(), seq)
		}
		return lcm, err
	}
}

// The check itself: a reader that verifies sequences passes every layout; one that trusts headers is caught on
// every layout whose header disagrees with its contents, and passes the honest ones.
func TestBatchReplayCheck(t *testing.T) {
	for _, c := range batchCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if wrong, _ := checkBatchReplay(c.from, c.to, checkingReader(c)); wrong != "" {
				t.Errorf("a checking reader: %s", wrong)
			}
			wrong, _ := checkBatchReplay(c.from, c.to, indexReader(c))
			if (wrong != "") != c.disagree {
				t.Errorf("a header-trusting reader: %q", wrong)
			}
		})
	}
}

// The SDK's BufferedStorageBackend on the batch shapes whose headers agree with their contents: multi-ledger
// objects come back ledger by ledger, and empty, short and mis-keyed objects are refused.
func TestBatchReplayThroughSDK(t *testing.T) {
	refuse := map[string]bool{"empty batch": true, "header below the object's key": true, "end beyond the ledgers held": true,
		"a stale object repeats the previous ledger": true}
	for _, c := range batchCases(t) {
		if c.disagree {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := NewConfig(testnet)
			cfg.LedgersPerBatch = c.perBatch
			if err := WriteBatches(dir, cfg, c.batches, c.at); err != nil {
				t.Fatal(err)
			}
			wrong, refused := checkBatchReplay(c.from, c.to, sdkReader(t, dir, c.from, c.to))
			if wrong != "" {
				t.Fatalf("the SDK reader: %s", wrong)
			}
			if refused != refuse[c.name] {
				t.Errorf("refused %v, want %v", refused, refuse[c.name])
			}
		})
	}
}
