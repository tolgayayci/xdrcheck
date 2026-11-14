package rig

import (
	"bufio"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Statuses of a requested ledger.
const (
	StatusIngested     = "ingested"
	StatusHalted       = "halted"
	StatusSkipped      = "skipped"
	StatusHarnessFault = "harness_fault"
)

// Status is one requested ledger's outcome.
type Status struct {
	Ledger  uint32 `json:"ledger"`
	Status  string `json:"status"`
	Segment string `json:"segment"`
	Shard   int    `json:"shard"`
	// Halt: the error text, the ledger the error names, and the last durable ledger (the service's cursor) when the
	// process stopped.
	Error         string  `json:"error,omitempty"`
	ErrorLedger   *uint32 `json:"error_ledger,omitempty"`
	DurableCursor *int64  `json:"durable_cursor,omitempty"`
	StoppedAt     *uint32 `json:"stopped_at,omitempty"`
	// Why a ledger was skipped (an earlier ledger of its segment halted, or the rig moved past a halt).
	Reason string `json:"reason,omitempty"`
	// Per-export outcomes (stellar-etl).
	Exports map[string]string `json:"exports,omitempty"`
}

// Row is one common row (ROW_SCHEMA): fixed fields plus the kind's own fields.
type Row map[string]any

// JSONL appends JSON lines to a file, safe for concurrent use.
type JSONL struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
	n  int
}

// CreateJSONL creates (truncates) a JSON Lines file.
func CreateJSONL(path string) (*JSONL, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &JSONL{f: f, w: bufio.NewWriterSize(f, 1<<20)}, nil
}

// Write appends one value.
func (j *JSONL) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.n++
	j.w.Write(b)
	return j.w.WriteByte('\n')
}

// Count is the number of lines written.
func (j *JSONL) Count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.n
}

// Close flushes and closes the file.
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.w.Flush(); err != nil {
		j.f.Close()
		return err
	}
	return j.f.Close()
}

// WriteJSON writes one indented JSON document.
func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Raw turns a decimal string with up to `places` fractional digits ("12.3456789") into the integer string of raw
// units ("123456789"), by moving the point; ok is false when the text is not such a decimal. No float is used.
func Raw(dec string, places int) (string, bool) {
	s := strings.TrimSpace(dec)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > places || whole == "" && frac == "" {
		return "", false
	}
	digits := whole + frac + strings.Repeat("0", places-len(frac))
	n, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return "", false
	}
	if neg {
		n.Neg(n)
	}
	return n.String(), true
}
