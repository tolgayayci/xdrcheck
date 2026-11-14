package run

import (
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/classify"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/plan"
)

// A unit is observed in windows bounded by served bytes and by ledger count, each at least one ledger, covering
// the unit once in order; a negative budget observes it whole.
func TestWindows(t *testing.T) {
	var ls []plan.Ledger
	for i, b := range []int64{400, 400, 400, 2000, 100, 0, 300} {
		ls = append(ls, plan.Ledger{Seq: uint32(10 + i), Bytes: b})
	}
	u := &plan.Unit{Ledgers: ls}
	got := windows(u, 1000)
	want := [][2]uint32{{10, 11}, {12, 12}, {13, 13}, {14, 16}}
	if len(got) != len(want) {
		t.Fatalf("windows %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("windows %v, want %v", got, want)
		}
	}
	if w := windows(u, -1); len(w) != 1 || w[0] != [2]uint32{10, 16} {
		t.Errorf("whole unit: %v", w)
	}
	var many []plan.Ledger
	for i := 0; i < 3*maxWindowLedgers+1; i++ {
		many = append(many, plan.Ledger{Seq: uint32(100 + i), Bytes: 1})
	}
	w := windows(&plan.Unit{Ledgers: many}, 1<<40)
	if len(w) != 4 || w[0] != [2]uint32{100, 100 + maxWindowLedgers - 1} || w[3][0] != w[3][1] {
		t.Errorf("count-bounded windows: %v", w)
	}
}

// A stop the harness observed itself is located at the last ledger of the unit the delivery log shows served.
func TestLastServed(t *testing.T) {
	u := &plan.Unit{Kind: plan.Chain, Ledgers: []plan.Ledger{{Seq: 2}, {Seq: 3}, {Seq: 4}, {Seq: 5}}}
	log := lake.NewDeliveryLog(nil)
	v := &view{delivery: classify.DeliveryExact, served: log.Served}
	if got := lastServed(u, v); got != 0 {
		t.Errorf("nothing served: %d", got)
	}
	log.Add(lake.Delivery{View: "rpc", Method: "getLedgers", Ledgers: []uint32{2, 3}, Status: "ok"})
	log.Add(lake.Delivery{View: "rpc", Method: "getLedgers", Ledgers: []uint32{4}, Status: "error -32600"})
	log.Add(lake.Delivery{View: "rpc", Method: "getLedgers", Ledgers: []uint32{9}, Status: "ok"}) // not in the unit
	if got := lastServed(u, v); got != 3 {
		t.Errorf("served 2 and 3, 4 failed: %d, want 3", got)
	}
	// A filesystem layout observes no reads.
	if got := lastServed(u, &view{delivery: classify.DeliveryNone, served: func(uint32) bool { return true }}); got != 0 {
		t.Errorf("no delivery evidence: %d", got)
	}
}

// An adapter that resolves the requested target version to another one leaves one note naming both, and the
// report's target keeps the requested version, so the note and the report agree.
func TestResolvedTargetVersionNote(t *testing.T) {
	r := &runner{o: Options{TargetVersion: "0.0.1"}, res: &Result{}, ranges: map[string]bool{}}
	r.target.Version = r.o.TargetVersion
	r.applyPrepare(&adapter.PrepareResult{TargetVersion: "0.0.1"})
	if len(r.res.Notes) != 0 {
		t.Fatalf("same version: %v", r.res.Notes)
	}
	r.applyPrepare(&adapter.PrepareResult{TargetVersion: "0.1.0"})
	r.applyPrepare(&adapter.PrepareResult{TargetVersion: "0.1.0"})
	want := "adapter resolved the requested target version 0.0.1 to 0.1.0; the report and its row IDs keep 0.0.1 (--target-version)"
	if len(r.res.Notes) != 1 || r.res.Notes[0] != want {
		t.Errorf("notes %q, want [%q]", r.res.Notes, want)
	}
	if r.target.Version != "0.0.1" || !strings.Contains(r.rowID("e", "v", "single"), "@0.0.1:") {
		t.Errorf("report target %q, row ID %s", r.target.Version, r.rowID("e", "v", "single"))
	}
}
