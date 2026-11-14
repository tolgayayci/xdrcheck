// Package lake writes corpus ledgers as a SEP-54 data-lake layout on disk, exactly as go-stellar-sdk v0.9.0
// `support/datastore` reads it and Galexie v30.0.1 writes it, and inspects and renumbers LedgerCloseMeta bytes.
//
// A layout is a root directory holding `.config.json` (the compact JSON the SDK's manifest struct marshals to)
// and one zstd-compressed `LedgerCloseMetaBatch` object per ledger at the key the SDK derives from the
// sequence. The batch is written by concatenation, `uint32 S ‖ uint32 S ‖ uint32 1 ‖ <LedgerCloseMeta bytes>`,
// so corpus bytes are never re-encoded. A history entry is served as the original public-lake object, byte for
// byte, at its original key; its sha256 is checked before it is written.
//
// The layout must be gap-free: every SDK backend demands strictly consecutive sequences, so Write refuses a
// ledger list with a gap.
package lake

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/klauspost/compress/zstd"
)

// ConfigFile is the name of the layout's manifest at the store root.
const ConfigFile = ".config.json"

// Config is the layout manifest. Field order and names are those of go-stellar-sdk's DatastoreManifest, so
// json.Marshal gives the same bytes the public lake holds.
type Config struct {
	NetworkPassphrase   string `json:"networkPassphrase"`
	Version             string `json:"version"`
	Compression         string `json:"compression"`
	LedgersPerBatch     uint32 `json:"ledgersPerBatch"`
	BatchesPerPartition uint32 `json:"batchesPerPartition"`
}

// NewConfig returns the public lake's configuration for a passphrase: version "1.0", zstd, one ledger per
// batch, 64000 batches per partition.
func NewConfig(passphrase string) Config {
	return Config{NetworkPassphrase: passphrase, Version: "1.0", Compression: "zstd", LedgersPerBatch: 1, BatchesPerPartition: 64000}
}

// Bytes returns the manifest file's content.
func (c Config) Bytes() []byte {
	b, _ := json.Marshal(c)
	return b
}

// ObjectKey returns the object key of the batch holding seq, as the SDK's DataStoreSchema derives it with the
// default "zst" extension.
func (c Config) ObjectKey(seq uint32) string {
	var key string
	if c.BatchesPerPartition > 1 {
		size := c.LedgersPerBatch * c.BatchesPerPartition
		start := (seq / size) * size
		end := uint32(math.MaxUint32)
		if uint64(start)+uint64(size)-1 < math.MaxUint32 {
			end = start + size - 1
		}
		key = fmt.Sprintf("%08X--%d-%d/", math.MaxUint32-start, start, end)
	}
	fileStart := (seq / c.LedgersPerBatch) * c.LedgersPerBatch
	fileEnd := uint32(min(uint64(fileStart)+uint64(c.LedgersPerBatch)-1, math.MaxUint32))
	key += fmt.Sprintf("%08X--%d", math.MaxUint32-fileStart, fileStart)
	if fileStart != fileEnd {
		key += fmt.Sprintf("-%d", fileEnd)
	}
	return key + ".xdr.zst"
}

// BatchXDR wraps one LedgerCloseMeta as the XDR of LedgerCloseMetaBatch{seq, seq, [lcm]}.
func BatchXDR(seq uint32, lcm []byte) []byte {
	out := make([]byte, 12, 12+len(lcm))
	binary.BigEndian.PutUint32(out[0:], seq)
	binary.BigEndian.PutUint32(out[4:], seq)
	binary.BigEndian.PutUint32(out[8:], 1)
	return append(out, lcm...)
}

// UnwrapBatch returns the LedgerCloseMeta bytes of a one-ledger batch and its sequence.
func UnwrapBatch(batch []byte) (uint32, []byte, error) {
	if len(batch) < 12 {
		return 0, nil, errors.New("batch shorter than its 12-byte head")
	}
	start, end, n := binary.BigEndian.Uint32(batch), binary.BigEndian.Uint32(batch[4:]), binary.BigEndian.Uint32(batch[8:])
	if start != end || n != 1 {
		return 0, nil, fmt.Errorf("batch %d-%d with %d ledgers; only one-ledger batches are unwrapped", start, end, n)
	}
	return start, batch[12:], nil
}

// One encoder and one decoder. By default each keeps a pool of GOMAXPROCS coders, and EncodeAll and DecodeAll
// take them in turn, so even one caller at a time ends up with every coder holding its own history buffers
// (about 16 MiB per encoder): 128 MiB live on an 8-CPU machine, and a peak that depends on the CPU count.
// The replay harness compresses one ledger at a time under its memory bound (make verify-memory). Concurrency
// does not change the bytes written.
var (
	encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	decoder, _ = zstd.NewReader(nil, zstd.WithDecoderMaxMemory(1<<30), zstd.WithDecoderConcurrency(1))
)

// Compress returns one zstd frame of raw.
func Compress(raw []byte) []byte { return encoder.EncodeAll(raw, nil) }

// Decompress decodes a zstd object.
func Decompress(obj []byte) ([]byte, error) { return decoder.DecodeAll(obj, nil) }

// Ledger is one ledger to publish. Either Load returns its LedgerCloseMeta bytes, or Original names a
// public-lake object to copy verbatim.
type Ledger struct {
	Seq      uint32
	Load     func() ([]byte, error)
	Original *Original
}

// Original is a vendored public-lake object, served byte-identical at its original key.
type Original struct {
	Key      string            // key under the store root, for example FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst
	Path     string            // the vendored file
	SHA256   string            // of the compressed object, as captured
	Metadata map[string]string // the object's user metadata as the lake returned it, if known
}

// Object is one written object.
type Object struct {
	Key      string
	Seq      uint32
	SHA256   string // of the object as written (compressed)
	Bytes    int64
	Metadata map[string]string // SEP-54 object metadata, for stores that keep it
	Original bool              // copied from the public lake verbatim
}

// Layout is a written layout.
type Layout struct {
	Dir         string
	Config      Config
	First, Last uint32
	Objects     []Object
}

// Write publishes ledgers, which must be consecutive, as a layout under dir. Ledger bytes are loaded one at a
// time.
func Write(dir string, cfg Config, ledgers []Ledger) (*Layout, error) {
	if len(ledgers) == 0 {
		return nil, errors.New("lake: no ledgers")
	}
	for i := 1; i < len(ledgers); i++ {
		if ledgers[i].Seq != ledgers[i-1].Seq+1 {
			return nil, fmt.Errorf("lake: gap between ledgers %d and %d; a layout must be consecutive", ledgers[i-1].Seq, ledgers[i].Seq)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), cfg.Bytes(), 0o644); err != nil {
		return nil, err
	}
	l := &Layout{Dir: dir, Config: cfg, First: ledgers[0].Seq, Last: ledgers[len(ledgers)-1].Seq}
	for _, led := range ledgers {
		obj, data, err := build(cfg, led)
		if err != nil {
			return nil, fmt.Errorf("lake: ledger %d: %w", led.Seq, err)
		}
		p := filepath.Join(dir, filepath.FromSlash(obj.Key))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return nil, err
		}
		l.Objects = append(l.Objects, obj)
	}
	return l, nil
}

func build(cfg Config, led Ledger) (Object, []byte, error) {
	key := cfg.ObjectKey(led.Seq)
	if o := led.Original; o != nil {
		if o.Key != key {
			return Object{}, nil, fmt.Errorf("original object key %s, but this layout puts ledger %d at %s", o.Key, led.Seq, key)
		}
		data, err := os.ReadFile(o.Path)
		if err != nil {
			return Object{}, nil, err
		}
		if got := sha(data); got != o.SHA256 {
			return Object{}, nil, fmt.Errorf("original object %s has sha256 %s, captured as %s", o.Path, got, o.SHA256)
		}
		return Object{Key: key, Seq: led.Seq, SHA256: o.SHA256, Bytes: int64(len(data)), Metadata: o.Metadata, Original: true}, data, nil
	}
	lcm, err := led.Load()
	if err != nil {
		return Object{}, nil, err
	}
	h, err := Inspect(lcm)
	if err != nil {
		return Object{}, nil, err
	}
	if h.Seq != led.Seq {
		return Object{}, nil, fmt.Errorf("ledger header says sequence %d", h.Seq)
	}
	data := Compress(BatchXDR(led.Seq, lcm))
	s := strconv.FormatUint(uint64(led.Seq), 10)
	ct := strconv.FormatInt(h.CloseTime, 10)
	md := map[string]string{
		"start-ledger": s, "end-ledger": s, "start-ledger-close-time": ct, "end-ledger-close-time": ct,
		"protocol-version": strconv.FormatUint(uint64(h.ProtocolVersion), 10), "network-passphrase": cfg.NetworkPassphrase,
		"compression-type": "zst", "version": "xcc",
	}
	return Object{Key: key, Seq: led.Seq, SHA256: sha(data), Bytes: int64(len(data)), Metadata: md}, data, nil
}

// ReadObject reads a one-ledger object of a layout back: its sequence and LedgerCloseMeta bytes.
func ReadObject(path string) (uint32, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, nil, err
	}
	raw, err := Decompress(data)
	if err != nil {
		return 0, nil, err
	}
	return UnwrapBatch(raw)
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
