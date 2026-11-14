package stellaretl

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// HaltOracleRow is one line of the halt-oracle file (--halt-oracle): how one export command ended on one ledger
// of an ingest. It is judged on facts only — exit status, signal, a Go runtime panic on stderr, the deadline and
// the memory cap — never on log text beyond the panic marker, and it does not depend on any fact mapping, so it
// covers the exports the adapter maps nothing from.
//
// Status per ledger: `ok` when the command exited 0; otherwise the ledgers before the failing ledger are `ok`,
// the failing ledger carries the command's ending (`halted`, `crashed`, `timeout`) and the ledgers after it are
// `not_reached`. A command the deadline left no time to start is `not_run` on every ledger.
//
// The failing ledger (failingLedger) is where the command fails when run alone on one ledger, tried from the
// highest ledger it wrote rows for (else the range start) upward (`failing_ledger_by: probe`). Rows alone cannot
// place it for an export that writes nothing on most ledgers: a halt on the last ledger of a range and one on the
// first look the same. When no probe fails there (a timeout, no time left, a failure that needs the whole range),
// it is the ledger after the command's last rows, else the range start: the earliest it can be
// (`failing_ledger_by: rows`).
type HaltOracleRow struct {
	Session      string `json:"session"`
	Binary       string `json:"binary"`
	RangeStart   int64  `json:"range_start"`
	RangeEnd     int64  `json:"range_end"`
	Ledger       int64  `json:"ledger"`
	Export       string `json:"export"`
	Status       string `json:"status"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	Signal       string `json:"signal,omitempty"`
	RuntimePanic bool   `json:"runtime_panic,omitempty"`
	TimedOut     bool   `json:"timed_out,omitempty"`
	MemoryCapHit bool   `json:"memory_cap_hit,omitempty"`
	WallMS       int64  `json:"wall_ms"`
	PeakRSSBytes int64  `json:"peak_rss_bytes,omitempty"`
	FailingBy    string `json:"failing_ledger_by,omitempty"`
	Rows         int    `json:"rows"`
	StderrTail   string `json:"stderr_tail,omitempty"`
}

// probeFunc reruns one export alone on one ledger: failed is whether it failed there, ran whether it could be run
// to an end at all.
type probeFunc func(cmd string, ledger int64) (failed, ran bool)

// failingLedger is the ledger a failed command stopped at, and how it was placed (see HaltOracleRow). probe may be
// nil. A timeout is never probed: the range as a whole ran out of time.
func failingLedger(cmd string, r adapterkit.Range, ex *exports, probe probeFunc, timedOut bool) (int64, string) {
	from, lower := r.Start, r.Start
	if hi := ex.highestLedgerOf(cmd, r); hi != nil {
		from, lower = *hi, min(*hi+1, r.End)
	}
	if probe != nil && !timedOut {
		for l := from; l <= r.End; l++ {
			failed, ran := probe(cmd, l)
			if !ran {
				break
			}
			if failed {
				return l, "probe"
			}
		}
	}
	return lower, "rows"
}

// haltOracleRows lays the command runs of one ingest out per export and ledger.
func haltOracleRows(p adapterkit.IngestParams, binary string, runs []commandRun, ex *exports, probe probeFunc) []HaltOracleRow {
	byName := map[string]*commandRun{}
	for i := range runs {
		byName[runs[i].name] = &runs[i]
	}
	var out []HaltOracleRow
	for _, cmd := range exportCommands {
		rows := map[int64]int{}
		for _, l := range ex.rowLedger[cmd] {
			rows[l]++
		}
		r := byName[cmd]
		ending, failing, by := "ok", int64(0), ""
		if r != nil && (r.res.ExitCode != 0 || r.res.Signal != 0 || r.res.TimedOut) {
			stderr := string(r.res.Stderr.Data)
			panicked := r.res.ExitCode == 2 && strings.Contains(stderr, "panic:") && strings.Contains(stderr, "goroutine ")
			switch {
			case r.res.TimedOut:
				ending = "timeout"
			case r.res.Signal != 0 || panicked || r.res.MemoryCapHit:
				ending = "crashed"
			default:
				ending = "halted"
			}
			failing, by = failingLedger(cmd, p.Range, ex, probe, r.res.TimedOut)
		}
		for l := p.Range.Start; l <= p.Range.End; l++ {
			row := HaltOracleRow{Session: p.Session, Binary: binary, RangeStart: p.Range.Start, RangeEnd: p.Range.End,
				Ledger: l, Export: cmd, Rows: rows[l]}
			switch {
			case r == nil:
				row.Status = "not_run"
			case ending == "ok" || l < failing:
				row.Status = "ok"
			case l > failing:
				row.Status = "not_reached"
			default:
				row.Status = ending
			}
			if r != nil {
				code := r.res.ExitCode
				row.ExitCode = &code
				if r.res.Signal != 0 && !r.res.TimedOut {
					row.ExitCode, row.Signal = nil, signalName(r.res.Signal)
				}
				row.RuntimePanic = ending == "crashed" && r.res.Signal == 0 && !r.res.MemoryCapHit
				row.TimedOut, row.MemoryCapHit = r.res.TimedOut, r.res.MemoryCapHit
				row.WallMS, row.PeakRSSBytes = r.res.Wall.Milliseconds(), max(r.res.PeakRSSBytes, r.res.GroupPeakBytes)
				if row.Status != "ok" && row.Status != "not_reached" {
					row.StderrTail = stderrTail(string(r.res.Stderr.Data))
					row.FailingBy = by
				}
			}
			out = append(out, row)
		}
	}
	return out
}

// appendHaltOracle appends the ingest's rows to path, one write per row (O_APPEND), so parallel sessions can
// share the file.
func appendHaltOracle(path string, p adapterkit.IngestParams, binary string, runs []commandRun, ex *exports, probe probeFunc) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, row := range haltOracleRows(p, binary, runs, ex, probe) {
		b, err := json.Marshal(row)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}
