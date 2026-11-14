package lake

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Batch-shaped layouts: the lake objects a replay serves are normally one ledger each, with a header that
// agrees with the ledger inside. Production lakes can be configured with several ledgers per object
// (ledgersPerBatch > 1), and a reader must also cope with an object that is empty or whose header disagrees with
// its contents. WriteBatches publishes such objects so a reader built on the SDK's BufferedStorageBackend can be
// checked: asked for a ledger, it must return that ledger or refuse, never a different one.

// Batch is one object of a batch-shaped layout: the header it carries and the LedgerCloseMeta bytes inside.
// Start and End are written as given, whatever the ledgers say.
type Batch struct {
	Start, End uint32
	Ledgers    [][]byte
}

// BatchBytes encodes LedgerCloseMetaBatch{start, end, ledgers} by concatenation (the ledgers are not re-encoded).
func BatchBytes(b Batch) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint32(out[0:], b.Start)
	binary.BigEndian.PutUint32(out[4:], b.End)
	binary.BigEndian.PutUint32(out[8:], uint32(len(b.Ledgers)))
	for _, l := range b.Ledgers {
		out = append(out, l...)
	}
	return out
}

// WriteBatches writes a layout of the given objects with cfg (cfg.LedgersPerBatch sets the object keys): each
// object is stored at the key of the sequence `at` names for it (at[i] for batches[i]), so an object's key and
// its header can disagree too.
func WriteBatches(dir string, cfg Config, batches []Batch, at []uint32) error {
	if len(batches) != len(at) {
		return errors.New("lake: one key sequence per batch")
	}
	if cfg.LedgersPerBatch == 0 {
		return errors.New("lake: ledgersPerBatch must be at least 1")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), cfg.Bytes(), 0o644); err != nil {
		return err
	}
	for i, b := range batches {
		p := filepath.Join(dir, filepath.FromSlash(cfg.ObjectKey(at[i])))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, Compress(BatchBytes(b)), 0o644); err != nil {
			return fmt.Errorf("lake: object %d: %w", i, err)
		}
	}
	return nil
}
