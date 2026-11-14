package report

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultMaxEvidence is the default cap on one row's evidence object, in bytes of JSON.
const DefaultMaxEvidence = 32 << 10

// EvidenceDir is the directory, next to a report written by Create, that holds the full evidence of rows whose
// evidence is over the cap.
const EvidenceDir = "evidence"

// keepListed is how many elements of a long list the inline copy of oversized evidence keeps.
const keepListed = 10

// Writer streams a report. It is safe for concurrent use.
type Writer struct {
	// MaxEvidence caps one row's inline evidence. A larger evidence object is kept whole in a side file
	// (EvidenceDir/<hash of the row ID>.json next to the report, when Create opened it) and the row carries a
	// shortened copy: long lists cut to their first elements except the diffs and the missing_or_wrong facts,
	// with "truncated": true, "original_bytes" and "full_evidence" (the side file's path relative to the
	// report). When even that copy is over the cap, only those three keys remain. A note is added to the row.
	// Zero means DefaultMaxEvidence.
	MaxEvidence int

	dir string // the report's directory; "" when the writer has no file

	mu      sync.Mutex
	bw      *bufio.Writer
	closer  io.Closer
	header  Header
	summary Summary
	buf     bytes.Buffer
	enc     *json.Encoder
	closed  bool
	err     error
}

// Create creates the report file at path and writes its opening. The header can still be changed with SetHeader
// or SetRun until Close.
func Create(path string, h Header) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w, err := NewWriter(f, h)
	if err != nil {
		f.Close()
		return nil, err
	}
	w.closer = f
	w.dir = filepath.Dir(path)
	return w, nil
}

// NewWriter writes the opening of a report to out. Close writes the rest; it does not close out.
func NewWriter(out io.Writer, h Header) (*Writer, error) {
	w := &Writer{bw: bufio.NewWriterSize(out, 64<<10), header: h}
	w.enc = json.NewEncoder(&w.buf)
	w.enc.SetEscapeHTML(false)
	if _, err := w.bw.WriteString(`{"schema":"` + Schema + `","rows":[`); err != nil {
		return nil, err
	}
	return w, w.bw.Flush()
}

// SetHeader replaces the header written at Close.
func (w *Writer) SetHeader(h Header) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.header = h
}

// SetRun sets the header's run block (for example once the wall time is known).
func (w *Writer) SetRun(r *Run) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.header.Run = r
}

// Summary returns the counts so far.
func (w *Writer) Summary() Summary {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.summary
	s.ByResult = make(map[string]int, len(w.summary.ByResult))
	for k, v := range w.summary.ByResult {
		s.ByResult[k] = v
	}
	return s
}

// Write checks a row, caps its evidence, appends it to the report and flushes it to the underlying writer.
func (w *Writer) Write(r Row) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("report: write after close")
	}
	if w.err != nil {
		return w.err
	}
	if err := checkRow(&r); err != nil {
		return err
	}
	limit := w.MaxEvidence
	if limit <= 0 {
		limit = DefaultMaxEvidence
	}
	if len(r.Evidence) > limit {
		if err := w.capEvidence(&r, limit); err != nil {
			w.err = err
			return err
		}
	}
	w.buf.Reset()
	if w.summary.Rows > 0 {
		w.buf.WriteByte(',')
	}
	w.buf.WriteByte('\n')
	if err := w.enc.Encode(&r); err != nil {
		return fmt.Errorf("report: row %s: %w", r.RowID, err)
	}
	w.buf.Truncate(w.buf.Len() - 1) // the encoder's newline; the separator carries it
	if _, err := w.bw.Write(w.buf.Bytes()); err != nil {
		w.err = err
		return err
	}
	if err := w.bw.Flush(); err != nil {
		w.err = err
		return err
	}
	w.summary.Add(&r)
	return nil
}

// capEvidence keeps an oversized evidence object whole in a side file and puts a shortened copy in the row.
func (w *Writer) capEvidence(r *Row, limit int) error {
	n := len(r.Evidence)
	side := ""
	if w.dir != "" {
		sum := sha256.Sum256([]byte(r.RowID))
		side = EvidenceDir + "/" + hex.EncodeToString(sum[:8]) + ".json"
		if err := os.MkdirAll(filepath.Join(w.dir, EvidenceDir), 0o755); err != nil {
			return fmt.Errorf("report: row %s: %w", r.RowID, err)
		}
		if err := os.WriteFile(filepath.Join(w.dir, filepath.FromSlash(side)), r.Evidence, 0o644); err != nil {
			return fmt.Errorf("report: row %s: %w", r.RowID, err)
		}
	}
	stub := map[string]any{"truncated": true, "original_bytes": n}
	if side != "" {
		stub["full_evidence"] = side
	}
	var short map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.Evidence))
	dec.UseNumber()
	if dec.Decode(&short) == nil {
		shorten(short)
		for k, v := range stub {
			short[k] = v
		}
		if b, err := marshalCompact(short); err == nil && len(b) <= limit {
			r.Evidence = b
			stub = nil
		}
	}
	if stub != nil {
		b, err := marshalCompact(stub)
		if err != nil {
			return err
		}
		r.Evidence = b
	}
	note := fmt.Sprintf("evidence shortened by the report writer: %d bytes, cap %d", n, limit)
	if side != "" {
		note += "; in full in " + side
	}
	r.Notes = append(r.Notes[:len(r.Notes):len(r.Notes)], note)
	return nil
}

// shorten cuts every list longer than keepListed to its first elements, recording the full length under
// "<key>_total", except the lists triage reads in full: "diffs" and "missing_or_wrong".
func shorten(o map[string]any) {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := o[k].(type) {
		case map[string]any:
			shorten(v)
		case []any:
			for _, x := range v {
				if m, ok := x.(map[string]any); ok {
					shorten(m)
				}
			}
			if len(v) > keepListed && k != "diffs" && k != "missing_or_wrong" {
				o[k], o[k+"_total"] = v[:keepListed], len(v)
			}
		}
	}
}

func marshalCompact(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// Close writes the header and the summary, completing the document, and closes the file if Create opened it.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	err := w.err
	if err == nil {
		err = w.finish()
	}
	if w.closer != nil {
		if cerr := w.closer.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

func (w *Writer) finish() error {
	h, err := json.Marshal(w.header)
	if err != nil {
		return err
	}
	s, err := json.Marshal(w.summary)
	if err != nil {
		return err
	}
	w.bw.WriteString("\n],\n\"header\":")
	w.bw.Write(h)
	w.bw.WriteString(",\n\"summary\":")
	w.bw.Write(s)
	w.bw.WriteString("}\n")
	return w.bw.Flush()
}

// ReadFile streams the report at path, calling fn for each row in file order. fn may keep the row. It returns
// the header and the summary; the summary's counts are checked against the rows.
func ReadFile(path string, fn func(*Row) error) (*Header, *Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	h, s, err := Read(bufio.NewReaderSize(f, 64<<10), fn)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return h, s, nil
}

// ReadAll reads a whole report into memory. Use it for small reports only.
func ReadAll(path string) (*Report, error) {
	rep := &Report{Schema: Schema}
	h, s, err := ReadFile(path, func(r *Row) error {
		rep.Rows = append(rep.Rows, *r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep.Header, rep.Summary = *h, *s
	return rep, nil
}

// Read streams a report from r; see ReadFile.
func Read(r io.Reader, fn func(*Row) error) (*Header, *Summary, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := expectDelim(dec, '{'); err != nil {
		return nil, nil, err
	}
	var (
		header  *Header
		summary *Summary
		schema  string
		counted Summary
		seen    = map[string]bool{}
	)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := tok.(string)
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		switch key {
		case "schema":
			if err := dec.Decode(&schema); err != nil {
				return nil, nil, err
			}
			if schema != Schema {
				return nil, nil, fmt.Errorf("schema is %q, want %q", schema, Schema)
			}
		case "header":
			header = &Header{}
			if err := dec.Decode(header); err != nil {
				return nil, nil, fmt.Errorf("header: %w", err)
			}
		case "summary":
			summary = &Summary{}
			if err := dec.Decode(summary); err != nil {
				return nil, nil, fmt.Errorf("summary: %w", err)
			}
		case "rows":
			if err := expectDelim(dec, '['); err != nil {
				return nil, nil, err
			}
			for i := 0; dec.More(); i++ {
				row := new(Row)
				if err := dec.Decode(row); err != nil {
					return nil, nil, fmt.Errorf("rows[%d]: %w", i, err)
				}
				if err := checkRow(row); err != nil {
					return nil, nil, fmt.Errorf("rows[%d]: %w", i, err)
				}
				counted.Add(row)
				if err := fn(row); err != nil {
					return nil, nil, err
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unknown top-level key %q", key)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("trailing data after the report")
	}
	for _, k := range []string{"schema", "header", "rows", "summary"} {
		if !seen[k] {
			return nil, nil, fmt.Errorf("missing %q", k)
		}
	}
	if summary.Rows != counted.Rows || summary.Failures != counted.Failures || summary.Unexpected != counted.Unexpected ||
		summary.FailuresWithoutFinding != counted.FailuresWithoutFinding {
		return nil, nil, fmt.Errorf("summary %+v does not match the rows (%d rows, %d failures, %d unexpected, %d failures without finding)",
			*summary, counted.Rows, counted.Failures, counted.Unexpected, counted.FailuresWithoutFinding)
	}
	return header, summary, nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("expected %q, found %v", d, tok)
	}
	return nil
}

var (
	tools       = map[string]bool{"replay": true, "conform": true, "lint": true, "corpus": true}
	targetKinds = map[string]bool{"sdk": true, "pipeline": true, "core": true, "oracle": true, "selftest": true, "fixture": true}
	mishandledQ = map[string]bool{"wrong_value": true, "crash": true, "hang": true, "halt": true}
	droppedQ    = map[string]bool{"silent": true, "partial": true, "refused": true}
)

// checkRow enforces the parts of the row contract that tools must agree on: the tool's block is present and
// alone, required strings are set, the class and qualifier fit, failure agrees with the result, and evidence is
// a JSON object. It is not a schema validator.
func checkRow(r *Row) error {
	if r.RowID == "" {
		return errors.New("row_id is empty")
	}
	if !tools[r.Tool] {
		return fmt.Errorf("row %s: unknown tool %q", r.RowID, r.Tool)
	}
	if r.Target.Name == "" || r.Target.Version == "" || !targetKinds[r.Target.Kind] {
		return fmt.Errorf("row %s: target needs name, version and a known kind: %+v", r.RowID, r.Target)
	}
	if r.Expectation != "expected" && r.Expectation != "unexpected" && r.Expectation != ExpectationPending {
		return fmt.Errorf("row %s: expectation %q", r.RowID, r.Expectation)
	}
	if r.Finding != nil && !findingRe.MatchString(*r.Finding) {
		return fmt.Errorf("row %s: finding %q is not F-NNNN", r.RowID, *r.Finding)
	}
	blocks := map[string]bool{"replay": r.Replay != nil, "conform": r.Conform != nil, "lint": r.Lint != nil, "corpus": r.Corpus != nil}
	for name, set := range blocks {
		if set != (name == r.Tool) {
			return fmt.Errorf("row %s: tool %s must carry exactly its own block (%s present: %v)", r.RowID, r.Tool, name, set)
		}
	}
	if r.Tool != "lint" && r.Entry == "" {
		return fmt.Errorf("row %s: entry is required for tool %s", r.RowID, r.Tool)
	}
	switch {
	case r.Replay != nil:
		c, q := r.Replay.Class, r.Replay.Qualifier
		if (c == "mishandled" && !mishandledQ[q]) || (c == "dropped" && !droppedQ[q]) {
			return fmt.Errorf("row %s: class %s with qualifier %q", r.RowID, c, q)
		}
		if r.Failure != ReplayFailure(c, q) {
			return fmt.Errorf("row %s: failure=%v disagrees with %s·%s", r.RowID, r.Failure, c, q)
		}
	case r.Conform != nil:
		if r.Failure != ConformFailure(r.Conform.Verdict) {
			return fmt.Errorf("row %s: failure=%v disagrees with verdict %s", r.RowID, r.Failure, r.Conform.Verdict)
		}
	case r.Corpus != nil:
		if r.Failure == r.Corpus.OK {
			return fmt.Errorf("row %s: failure=%v disagrees with ok=%v", r.RowID, r.Failure, r.Corpus.OK)
		}
	}
	if len(r.Evidence) > 0 {
		if b := bytes.TrimLeft(r.Evidence, " \t\r\n"); len(b) == 0 || b[0] != '{' || !json.Valid(r.Evidence) {
			return fmt.Errorf("row %s: evidence is not a JSON object", r.RowID)
		}
	}
	return nil
}
