// Package ledger reads lake objects (zstd LedgerCloseMetaBatch) and cuts them into per-transaction rows in
// apply order, the reference cut the SDK sweeps read: seq, idx (0-based apply order), hash, and the envelope,
// result pair and meta as base64. The cut uses go-stellar-sdk's ingest reader, which pairs each result with its
// envelope by hash, so the SDK under test never decides what a transaction is.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
)

// ReadObject returns the decompressed bytes of a lake object (or the bytes of an uncompressed file).
func ReadObject(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd {
		d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(1<<31))
		if err != nil {
			return nil, err
		}
		defer d.Close()
		return d.DecodeAll(b, nil)
	}
	return b, nil
}

// Batch decodes a lake object.
func Batch(path string) (xdr.LedgerCloseMetaBatch, error) {
	var b xdr.LedgerCloseMetaBatch
	raw, err := ReadObject(path)
	if err != nil {
		return b, err
	}
	err = xdr.SafeUnmarshal(raw, &b)
	return b, err
}

// Row is one transaction of the cut.
type Row struct {
	Seq  uint32 `json:"seq"`
	Idx  int    `json:"idx"`
	Hash string `json:"hash"`
	Env  string `json:"env"`
	Pair string `json:"pair"`
	Meta string `json:"meta"`
	// Truth: what the result and meta state, for judging computed helpers (fee, ids).
	Truth *Truth `json:"truth,omitempty"`
}

// Rows cuts a lake object into transactions in apply order.
func Rows(path, passphrase string) ([]Row, error) {
	b, err := Batch(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	var out []Row
	for _, lcm := range b.LedgerCloseMetas {
		rd, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(passphrase, lcm)
		if err != nil {
			return nil, err
		}
		for {
			tx, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			env, err1 := xdr.MarshalBase64(tx.Envelope)
			pair, err2 := xdr.MarshalBase64(tx.Result)
			meta, err3 := xdr.MarshalBase64(tx.UnsafeMeta)
			if err1 != nil || err2 != nil || err3 != nil {
				return nil, fmt.Errorf("ledger %d tx %d: re-encode failed", lcm.LedgerSequence(), tx.Index)
			}
			out = append(out, Row{Seq: lcm.LedgerSequence(), Idx: int(tx.Index) - 1, Hash: hex.EncodeToString(tx.Hash[:]), Env: env, Pair: pair, Meta: meta, Truth: truthOf(tx)})
		}
	}
	return out, nil
}

// WriteCut writes the cut of one object to <dir>/<seq>.jsonl.zst.
func WriteCut(path, passphrase, dir string, seq uint32) error {
	rows, err := Rows(path, passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dir, fmt.Sprintf("%d.jsonl.zst", seq))
	f, err := os.Create(dst + ".tmp")
	if err != nil {
		return err
	}
	// a ledger without transactions still gets a valid (empty) zstd frame: zstd -d refuses a 0-byte file
	z, _ := zstd.NewWriter(f, zstd.WithZeroFrames(true))
	w := bufio.NewWriter(z)
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	z.Close()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(dst+".tmp", dst)
}

// Envelope returns the base64 envelope and hash of one transaction of a lake object.
func Envelope(path, passphrase string, tx int) (Row, error) {
	rows, err := Rows(path, passphrase)
	if err != nil {
		return Row{}, err
	}
	for _, r := range rows {
		if r.Idx == tx {
			return r, nil
		}
	}
	return Row{}, fmt.Errorf("%s: no transaction %d (the ledger has %d)", path, tx, len(rows))
}

// FindHash returns the apply-order index of a transaction hash in a lake object, or -1.
func FindHash(path, passphrase, hash string) (int, error) {
	rows, err := Rows(path, passphrase)
	if err != nil {
		return -1, err
	}
	for _, r := range rows {
		if r.Hash == hash {
			return r.Idx, nil
		}
	}
	return -1, nil
}

// WriteBlobObject writes a raw LedgerCloseMeta (a corpus blob) as a lake object: the one-ledger batch,
// zstd-compressed. It returns the sha256 of the written file.
func WriteBlobObject(blob []byte, seq uint32, dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	z, _ := zstd.NewWriter(nil)
	out := z.EncodeAll(lake.BatchXDR(seq, blob), nil)
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return "", err
	}
	s := sha256.Sum256(out)
	return hex.EncodeToString(s[:]), nil
}

// Base64 is a helper for bundles.
func Base64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
