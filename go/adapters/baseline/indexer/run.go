package indexer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/support/datastore"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Exit codes of `baseline index`. A Go runtime panic exits 2 by itself.
const (
	ExitOK      = 0
	ExitError   = 1 // a decode or processing error: nothing written for the failing ledger
	ExitRefused = 3 // a declared gate refused the ledger before anything was written for it
)

// Gates are the indexer's own envelope (enforcement indexer_gate). Defaults: protocol ≤ 30, LedgerCloseMeta
// versions 0–2, transactions only at Protocol ≥ 10 (older meta has no per-operation changes the SDK can read).
type Gates struct {
	MaxProtocol                 uint32
	MaxLedgerCloseMetaVersion   int32
	MinProtocolWithTransactions uint32
}

// DefaultGates are the baseline's declared limits.
var DefaultGates = Gates{MaxProtocol: 30, MaxLedgerCloseMetaVersion: 2, MinProtocolWithTransactions: 10}

// Input is where to read ledgers.
type Input struct {
	Kind       string // sep54-dir, sep54-s3, rpc
	Path       string // sep54-dir
	Endpoint   string // sep54-s3
	BucketPath string // sep54-s3
	Region     string // sep54-s3
	URL        string // rpc
}

// Config is one ingest run.
type Config struct {
	Input      Input
	Start, End uint32
	Passphrase string
	Out        string // the session's store: ledgers/<seq>.json, cursor, exit.json
	Gates      Gates
	Seed       Seed // nil for the baseline; one deliberate defect for the harness's self-test
}

// Seed is one deliberate defect switched on for the harness's self-test (the seeded-bug indexers in
// ../bugs). The baseline runs with none. Ledger is called for every ledger that passed the gates, after its
// facts are derived and before anything is written for it; it may change doc, and its Outcome says what the run
// does with the ledger.
type Seed interface {
	Ledger(lcm xdr.LedgerCloseMeta, doc *Doc, passphrase string) Outcome
}

// Outcome is what the run does with a ledger a seed has seen. The zero value is the baseline's behaviour: write
// the document, then move the cursor past the ledger.
type Outcome struct {
	Skip bool        // do not write the document
	Stop *ExitRecord // stop on this ledger (after writing the document unless Skip); the cursor stays below it
}

// ExitRecord is written to <out>/exit.json when the run stops on a ledger: the adapter reads it instead of log
// text.
type ExitRecord struct {
	Status   string `json:"status"` // refused, error
	Ledger   uint32 `json:"ledger"`
	Phase    string `json:"phase"` // fetch, decode (gates), process, persist
	Gate     string `json:"gate,omitempty"`
	Observed int64  `json:"observed,omitempty"`
	Message  string `json:"message"`
}

// Cursor reads the last ledger fully stored in out, or false when none is.
func Cursor(out string) (uint32, bool) {
	b, err := os.ReadFile(filepath.Join(out, "cursor"))
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	return uint32(n), err == nil
}

// DocPath is where a ledger's document is stored.
func DocPath(out string, seq uint32) string {
	return filepath.Join(out, "ledgers", strconv.FormatUint(uint64(seq), 10)+".json")
}

// ReadExit reads the exit record, if any.
func ReadExit(out string) (*ExitRecord, bool) {
	b, err := os.ReadFile(filepath.Join(out, "exit.json"))
	if err != nil {
		return nil, false
	}
	var r ExitRecord
	if json.Unmarshal(b, &r) != nil {
		return nil, false
	}
	return &r, true
}

// stop is a run that ended on a ledger.
type stop struct {
	code int
	rec  ExitRecord
}

func (s *stop) Error() string { return s.rec.Message }

// Run ingests [Start, End] and returns the process exit code. Every stored ledger is written whole (a temporary
// file renamed into place) before the cursor moves past it, so a stop never leaves a partial ledger.
func Run(ctx context.Context, cfg Config) int {
	err := run(ctx, cfg)
	if err == nil {
		return ExitOK
	}
	var s *stop
	if !errors.As(err, &s) {
		s = &stop{code: ExitError, rec: ExitRecord{Status: "error", Phase: "startup", Message: err.Error()}}
	}
	if b, merr := json.Marshal(s.rec); merr == nil {
		writeFile(filepath.Join(cfg.Out, "exit.json"), b)
	}
	fmt.Fprintln(os.Stderr, "baseline index:", s.rec.Message)
	return s.code
}

func run(ctx context.Context, cfg Config) error {
	if err := os.MkdirAll(filepath.Join(cfg.Out, "ledgers"), 0o755); err != nil {
		return err
	}
	os.Remove(filepath.Join(cfg.Out, "exit.json"))
	backend, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	defer backend.Close()
	if err := backend.PrepareRange(ctx, ledgerbackend.BoundedRange(cfg.Start, cfg.End)); err != nil {
		return fmt.Errorf("prepare range %d-%d: %w", cfg.Start, cfg.End, err)
	}
	for seq := cfg.Start; seq <= cfg.End; seq++ {
		lcm, err := backend.GetLedger(ctx, seq)
		if err != nil {
			return &stop{ExitError, ExitRecord{Status: "error", Ledger: seq, Phase: "fetch", Message: fmt.Sprintf("ledger %d: %v", seq, err)}}
		}
		if g := cfg.Gates.refuse(lcm); g != nil {
			g.Ledger = seq
			return &stop{ExitRefused, *g}
		}
		doc, err := Derive(lcm, cfg.Passphrase)
		if err != nil {
			return &stop{ExitError, ExitRecord{Status: "error", Ledger: seq, Phase: "process", Message: fmt.Sprintf("ledger %d: %v", seq, err)}}
		}
		var o Outcome
		if cfg.Seed != nil {
			o = cfg.Seed.Ledger(lcm, doc, cfg.Passphrase)
		}
		var b []byte
		if !o.Skip {
			b, err = json.Marshal(doc)
			if err == nil {
				err = writeFile(DocPath(cfg.Out, seq), b)
			}
		}
		if err == nil && o.Stop != nil {
			rec, code := *o.Stop, ExitError
			rec.Ledger = seq
			if rec.Status == "refused" {
				code = ExitRefused
			}
			return &stop{code, rec}
		}
		if err == nil {
			err = writeFile(filepath.Join(cfg.Out, "cursor"), []byte(strconv.FormatUint(uint64(seq), 10)))
		}
		if err != nil {
			return &stop{ExitError, ExitRecord{Status: "error", Ledger: seq, Phase: "persist", Message: fmt.Sprintf("ledger %d: %v", seq, err)}}
		}
		if seq == ^uint32(0) {
			break
		}
	}
	return nil
}

// refuse applies the gates before anything is written for the ledger.
func (g Gates) refuse(lcm xdr.LedgerCloseMeta) *ExitRecord {
	p := lcm.ProtocolVersion()
	switch {
	case g.MaxProtocol > 0 && p > g.MaxProtocol:
		return &ExitRecord{Status: "refused", Phase: "decode", Gate: "max_protocol", Observed: int64(p),
			Message: fmt.Sprintf("refusing ledger %d: protocol %d is newer than the maximum supported protocol %d", lcm.LedgerSequence(), p, g.MaxProtocol)}
	case lcm.V > g.MaxLedgerCloseMetaVersion:
		return &ExitRecord{Status: "refused", Phase: "decode", Gate: "ledger_close_meta_version", Observed: int64(lcm.V),
			Message: fmt.Sprintf("refusing ledger %d: LedgerCloseMeta v%d is newer than v%d", lcm.LedgerSequence(), lcm.V, g.MaxLedgerCloseMetaVersion)}
	case p < g.MinProtocolWithTransactions && lcm.CountTransactions() > 0:
		return &ExitRecord{Status: "refused", Phase: "decode", Gate: "min_protocol_with_transactions", Observed: int64(p),
			Message: fmt.Sprintf("refusing ledger %d: transactions at protocol %d, below %d", lcm.LedgerSequence(), p, g.MinProtocolWithTransactions)}
	}
	return nil
}

func openBackend(ctx context.Context, cfg Config) (ledgerbackend.LedgerBackend, error) {
	in := cfg.Input
	var dsc datastore.DataStoreConfig
	switch in.Kind {
	case "rpc":
		return ledgerbackend.NewRPCLedgerBackend(ledgerbackend.RPCLedgerBackendOptions{RPCServerURL: in.URL, BufferSize: 10}), nil
	case "sep54-dir":
		dsc = datastore.DataStoreConfig{Type: "Filesystem", Params: map[string]string{"destination_path": in.Path}}
	case "sep54-s3":
		dsc = datastore.DataStoreConfig{Type: "S3", Params: map[string]string{
			"destination_bucket_path": in.BucketPath, "region": in.Region, "endpoint_url": in.Endpoint}}
	default:
		return nil, fmt.Errorf("input kind %q is not supported", in.Kind)
	}
	ds, err := datastore.NewDataStore(ctx, dsc)
	if err != nil {
		return nil, fmt.Errorf("open datastore: %w", err)
	}
	schema, err := datastore.LoadSchema(ctx, ds, datastore.DataStoreConfig{NetworkPassphrase: cfg.Passphrase})
	if err != nil {
		return nil, fmt.Errorf("load datastore schema: %w", err)
	}
	return ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{
		BufferSize: 10, NumWorkers: 2, RetryLimit: 3, RetryWait: 200 * time.Millisecond}, ds, schema)
}

// writeFile writes a file whole: a temporary file renamed into place.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
