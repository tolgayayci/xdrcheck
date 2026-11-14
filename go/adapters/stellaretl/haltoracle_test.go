package stellaretl

import (
	"fmt"
	"slices"
	"syscall"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
)

// One row per export per ledger: a command that exited 0 is ok everywhere; a panicking one is ok up to the
// ledger after its last rows, crashed there and not_reached after; a signal is a crash; an export the deadline
// left no time for is not_run.
func TestHaltOracleRows(t *testing.T) {
	p := adapter.IngestParams{Session: "s", Range: adapter.Range{Start: 10, End: 13}}
	ex := &exports{rowLedger: map[string][]int64{"export_trades": {10, 11, 11}}}
	var runs []commandRun
	for _, cmd := range exportCommands {
		switch cmd {
		case "export_trades":
			runs = append(runs, commandRun{cmd, proc.Result{ExitCode: 2, Stderr: proc.Tail{Data: []byte("panic: boom\n\ngoroutine 1 [running]:")}}})
		case "export_assets":
			runs = append(runs, commandRun{cmd, proc.Result{ExitCode: 128 + 11, Signal: syscall.SIGSEGV}})
		case "export_ledger_transaction":
		default:
			runs = append(runs, commandRun{cmd, proc.Result{}})
		}
	}
	rows := haltOracleRows(p, "stellar-etl-x", runs, ex, nil)
	if want := len(exportCommands) * 4; len(rows) != want {
		t.Fatalf("%d rows, want %d", len(rows), want)
	}
	got := map[string][]string{}
	for _, r := range rows {
		got[r.Export] = append(got[r.Export], r.Status)
	}
	check := func(cmd string, want ...string) {
		t.Helper()
		if len(got[cmd]) != len(want) {
			t.Fatalf("%s: %v", cmd, got[cmd])
		}
		for i := range want {
			if got[cmd][i] != want[i] {
				t.Errorf("%s: %v, want %v", cmd, got[cmd], want)
				return
			}
		}
	}
	check("export_ledgers", "ok", "ok", "ok", "ok")
	check("export_trades", "ok", "ok", "crashed", "not_reached")
	check("export_assets", "crashed", "not_reached", "not_reached", "not_reached")
	check("export_ledger_transaction", "not_run", "not_run", "not_run", "not_run")
	for _, r := range rows {
		if r.Export == "export_trades" && r.Ledger == 12 && (!r.RuntimePanic || r.StderrTail == "") {
			t.Errorf("the panic row: %+v", r)
		}
		if r.Export == "export_assets" && r.Ledger == 10 && (r.Signal != "SIGSEGV" || r.ExitCode != nil) {
			t.Errorf("the signal row: %+v", r)
		}
	}
}

// A sparse export that halts on a later ledger of the range, having written no rows before it: rows place the halt
// at the range start, the single-ledger probe at the ledger it fails on. Probing starts at the ledger of the last
// rows and stops when it cannot run.
func TestHaltOracleSparseExportProbe(t *testing.T) {
	p := adapter.IngestParams{Session: "s", Range: adapter.Range{Start: 10, End: 13}}
	ex := &exports{rowLedger: map[string][]int64{"export_trades": {11}}}
	halt := proc.Result{ExitCode: 1, Stderr: proc.Tail{Data: []byte("unified events stream expects v4")}}
	var runs []commandRun
	for _, cmd := range exportCommands {
		res := proc.Result{}
		if cmd == "export_token_transfer" || cmd == "export_trades" {
			res = halt
		}
		runs = append(runs, commandRun{cmd, res})
	}
	var probed []string
	probe := func(cmd string, l int64) (bool, bool) {
		probed = append(probed, fmt.Sprintf("%s@%d", cmd, l))
		return l == 12, true
	}
	statuses := func(rows []HaltOracleRow, cmd string) (got []string, by string) {
		for _, r := range rows {
			if r.Export == cmd {
				got = append(got, r.Status)
				if r.FailingBy != "" {
					by = r.FailingBy
				}
			}
		}
		return got, by
	}
	cases := []struct {
		name  string
		probe probeFunc
		cmd   string
		want  []string
		by    string
	}{
		{"no probe", nil, "export_token_transfer", []string{"halted", "not_reached", "not_reached", "not_reached"}, "rows"},
		{"probe", probe, "export_token_transfer", []string{"ok", "ok", "halted", "not_reached"}, "probe"},
		{"probe after rows", probe, "export_trades", []string{"ok", "ok", "halted", "not_reached"}, "probe"},
		{"no rows after rows", nil, "export_trades", []string{"ok", "ok", "halted", "not_reached"}, "rows"},
		{"probe cannot run", func(string, int64) (bool, bool) { return false, false }, "export_token_transfer",
			[]string{"halted", "not_reached", "not_reached", "not_reached"}, "rows"},
		{"probe never fails", func(string, int64) (bool, bool) { return false, true }, "export_trades",
			[]string{"ok", "ok", "halted", "not_reached"}, "rows"},
	}
	for _, c := range cases {
		got, by := statuses(haltOracleRows(p, "stellar-etl-x", runs, ex, c.probe), c.cmd)
		if fmt.Sprint(got) != fmt.Sprint(c.want) || by != c.by {
			t.Errorf("%s: %s %v by %q, want %v by %q", c.name, c.cmd, got, by, c.want, c.by)
		}
	}
	want := "[export_token_transfer@10 export_token_transfer@11 export_token_transfer@12 export_trades@11 export_trades@12]"
	probed = nil
	haltOracleRows(p, "stellar-etl-x", runs, ex, probe)
	slices.Sort(probed)
	if fmt.Sprint(probed) != want {
		t.Errorf("probed %v, want %s", probed, want)
	}
	// A timeout is not probed.
	runs = []commandRun{{"export_trades", proc.Result{TimedOut: true}}}
	probed = nil
	haltOracleRows(p, "stellar-etl-x", runs, ex, probe)
	if len(probed) != 0 {
		t.Errorf("a timeout was probed: %v", probed)
	}
}
