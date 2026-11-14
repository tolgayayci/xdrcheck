package conform

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// Output files in the --report directory.
const (
	ReportFile   = "report.json"   // xcc.report/v1: one row per judged cell
	CellsFile    = "cells.ndjson"  // raw: every cell, its request, the driver's line verbatim, crashes, protocol errors
	DescribeFile = "describe.json" // raw: each column's describe
)

// ToolVersion is the orchestrator's version in report headers.
const ToolVersion = "0.1.0"

// Header builds the report header's comparable part. The run block is added by WriteOutputs.
func Header(c *manifest.Corpus, p *pins.Pins, columns []*Column, suite, tier string) (report.Header, error) {
	sum, err := ManifestSHA256(c)
	if err != nil {
		return report.Header{}, err
	}
	version := "unversioned"
	if c.Index != nil && c.Index.CorpusVersion != "" {
		version = c.Index.CorpusVersion
	}
	values := map[string]string{}
	for _, col := range columns {
		values["column "+col.ID] = col.Version
	}
	return report.Header{
		Tool:   report.Tool{Name: "xcc conform", Version: ToolVersion},
		Corpus: report.CorpusRef{Version: version, ManifestSHA256: sum, Schema: manifest.EntrySchema, Tier: tier},
		Pins:   report.PinsRef{FileSHA256: p.FileSHA256, Values: values},
		Mode:   report.Mode{Suite: suite, Overlay: false, Offline: OfflineMode()},
	}, nil
}

// ManifestSHA256 is the sha256 of the corpus's manifest checksum file (corpus.json checksums.manifest) when it
// has one, else of the same listing computed here: one "<sha256>  manifest/<path>" line per manifest file,
// sorted by path, as sha256sum writes it. With an overlay corpus merged in, the listing is computed over the
// public and the overlay manifest files together.
func ManifestSHA256(c *manifest.Corpus) (string, error) {
	if c.Overlay == "" && c.Index != nil && c.Index.Checksums.Manifest != "" {
		if data, err := os.ReadFile(filepath.Join(c.Root, c.Index.Checksums.Manifest)); err == nil {
			s := sha256.Sum256(data)
			return hex.EncodeToString(s[:]), nil
		}
	}
	var lines []string
	for _, root := range []string{c.Root, c.Overlay} {
		if root == "" {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, "manifest"), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			s := sha256.Sum256(data)
			lines = append(lines, hex.EncodeToString(s[:])+"  "+filepath.ToSlash(rel)+"\n")
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	s := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(s[:]), nil
}

// OfflineMode says how networking was disabled for this process: "network namespace, loopback only" when lo is
// the only interface of its network namespace (/proc/self/net/dev; /sys/class/net shows the namespace sysfs
// was mounted in), else "not-enforced".
func OfflineMode() string {
	data, err := os.ReadFile("/proc/self/net/dev")
	if err != nil {
		return "not-enforced"
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok || strings.Contains(name, "|") {
			continue
		}
		n++
		if strings.TrimSpace(name) != "lo" {
			return "not-enforced"
		}
	}
	if n == 0 {
		return "not-enforced"
	}
	return "network namespace, loopback only"
}

// Summary counts a run's cells.
type Summary struct {
	Cells, Judged, ProtocolErrors, NotRun int
	Report                                report.Summary
}

// WriteOutputs writes the report, the raw cells and the describes into dir; Result.Apply must have run. run, if
// not nil, is the header's non-comparable run block.
func WriteOutputs(dir string, res *Result, h report.Header, run *report.Run) (Summary, error) {
	var sum Summary
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return sum, err
	}
	if err := writeDescribes(filepath.Join(dir, DescribeFile), res); err != nil {
		return sum, err
	}
	cf, err := os.Create(filepath.Join(dir, CellsFile))
	if err != nil {
		return sum, err
	}
	defer cf.Close()
	cw := bufio.NewWriter(cf)
	h.Run = run
	w, err := report.Create(filepath.Join(dir, ReportFile), h)
	if err != nil {
		return sum, err
	}
	for _, ob := range res.Observations {
		sum.Cells++
		j := ob.Judgement
		switch {
		case ob.ProtocolError != "":
			sum.ProtocolErrors++
		case ob.NotRun != "":
			sum.NotRun++
		case ob.Judged():
			if j == nil {
				w.Close()
				return sum, fmt.Errorf("%s: not judged (Result.Apply was not called)", ob.Cell.RowID())
			}
			sum.Judged++
			if err := w.Write(Row(ob, j)); err != nil {
				w.Close()
				return sum, err
			}
		}
		line, err := json.Marshal(rawCell(ob, j))
		if err != nil {
			w.Close()
			return sum, err
		}
		cw.Write(append(line, '\n'))
	}
	sum.Report = w.Summary()
	if err := w.Close(); err != nil {
		return sum, err
	}
	if err := cw.Flush(); err != nil {
		return sum, err
	}
	return sum, cf.Close()
}

// Row is the report row of a judged cell.
func Row(ob *Observation, j *Judgement) report.Row {
	c := ob.Cell
	ev := map[string]any{"source": ob.Source}
	if r := ob.Response; r != nil {
		if r.Reason != nil {
			for k, v := range map[string]string{"message": r.Reason.Message, "error_class": r.Reason.ErrorClass, "entry_point": r.Reason.EntryPoint} {
				if v != "" {
					ev[k] = v
				}
			}
		}
		if r.Actual != nil {
			if b, err := json.Marshal(r.Actual); err == nil {
				if len(b) <= 8<<10 {
					ev["actual"] = json.RawMessage(b)
				} else {
					ev["actual_bytes"] = len(b)
				}
			}
		}
	}
	if cr := ob.Crash; cr != nil {
		m := map[string]any{"reason": cr.Reason, "exit_code": cr.ExitCode}
		if cr.Signal != "" {
			m["signal"] = cr.Signal
		}
		if cr.TimedOut {
			m["timed_out"] = true
		}
		if cr.MemoryCapHit {
			m["memory_cap_hit"] = true
		}
		ev["crash"] = m
	}
	evidence, _ := json.Marshal(ev)
	return report.Row{
		RowID:   c.RowID(),
		Tool:    "conform",
		Entry:   c.Entry.ID,
		Variant: c.VariantKey,
		Target: report.Target{Name: c.Column.Package, Version: c.Column.Version, Kind: c.Column.Kind,
			Column: c.Column.ID, Profile: c.Column.Profile},
		Failure:         report.ConformFailure(j.Verdict),
		Expectation:     j.Expectation,
		Expected:        j.Expected,
		KnownDivergence: j.KnownDivergence,
		Finding:         j.Finding,
		Caps:            c.Entry.Caps,
		Conform: &report.ConformResult{Level: c.Level, Reference: c.Entry.Reference, Outcome: ob.Outcome,
			Reason: ob.Reason, Verdict: j.Verdict, Check: j.Check},
		Evidence: evidence,
		Notes:    j.Notes,
	}
}

type cellLine struct {
	Entry         string          `json:"entry"`
	Variant       string          `json:"variant,omitempty"`
	Column        string          `json:"column"`
	Level         string          `json:"level"`
	Status        string          `json:"status"` // observed, protocol_error, not_run
	Process       int             `json:"process,omitempty"`
	Isolated      bool            `json:"isolated,omitempty"`
	Sandbox       string          `json:"sandbox,omitempty"`
	Outcome       string          `json:"outcome,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	Source        string          `json:"source,omitempty"`
	Verdict       string          `json:"verdict,omitempty"`
	Check         string          `json:"check,omitempty"`
	WallMS        float64         `json:"wall_ms,omitempty"`
	Request       *RunRequest     `json:"request,omitempty"`
	Response      json.RawMessage `json:"response,omitempty"`
	Crash         *Crash          `json:"crash,omitempty"`
	ProtocolError string          `json:"protocol_error,omitempty"`
	BadLine       string          `json:"bad_line,omitempty"`
	NotRun        string          `json:"not_run,omitempty"`
}

func rawCell(ob *Observation, j *Judgement) cellLine {
	c := ob.Cell
	l := cellLine{Entry: c.Entry.ID, Variant: c.VariantKey, Column: c.Column.ID, Level: c.Level, Process: ob.Process,
		Isolated: c.Isolate, Sandbox: c.Sandbox, Outcome: ob.Outcome, Reason: ob.Reason, Source: ob.Source, WallMS: ob.WallMS,
		Request: ob.Request, Response: ob.ResponseRaw, Crash: ob.Crash, ProtocolError: ob.ProtocolError,
		BadLine: ob.BadLine, NotRun: ob.NotRun}
	switch {
	case ob.ProtocolError != "":
		l.Status = "protocol_error"
	case ob.NotRun != "":
		l.Status = "not_run"
	default:
		l.Status = "observed"
	}
	if j != nil {
		l.Verdict, l.Check = j.Verdict, j.Check
	}
	return l
}

func writeDescribes(path string, res *Result) error {
	type col struct {
		Column    string          `json:"column"`
		Processes int             `json:"processes"`
		Describe  json.RawMessage `json:"describe,omitempty"`
		Errors    []string        `json:"errors,omitempty"`
	}
	out := struct {
		Columns []col `json:"columns"`
	}{}
	for _, c := range res.Columns {
		out.Columns = append(out.Columns, col{Column: c.Column.ID, Processes: c.Processes, Describe: c.DescribeRaw, Errors: c.Errors})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("describe.json: %w", err)
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
