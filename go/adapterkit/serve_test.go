package adapterkit_test

import (
	"bytes"
	"context"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapterkit/kittest"
)

// fake holds nothing and ingests nothing: the smallest Handler that passes the protocol checks.
type fake struct{ observeErr error }

func (fake) Describe(adapterkit.DescribeParams) (adapterkit.DescribeResult, error) {
	no := adapterkit.Capability{Supported: false, Reason: "fake"}
	return adapterkit.DescribeResult{
		Adapter: adapterkit.NameVersion{Name: "fake", Version: "1"}, Target: adapterkit.Target{Name: "fake"},
		Inputs: []string{"sep54-dir"}, Units: []string{"single"}, Envelope: adapterkit.Envelope{Enforcement: "none"},
		Observations: adapterkit.Observations{Receipts: adapterkit.Capability{Supported: true}, Transactions: no,
			Participants: no, StateChanges: no, Movements: no, Addresses: no},
	}, nil
}

func (fake) Prepare(adapterkit.PrepareParams) (adapterkit.PrepareResult, error) {
	return adapterkit.PrepareResult{Ready: true, TargetVersion: "1"}, nil
}

func (fake) Ingest(p adapterkit.IngestParams) (adapterkit.IngestResult, error) {
	return adapterkit.IngestResult{Status: adapterkit.StatusCompleted, LastLedger: &p.Range.End,
		Signals: adapterkit.Signals{CursorAfter: &p.Range.End}}, nil
}

func (f fake) Observe(p adapterkit.ObserveParams) (adapterkit.Observation, error) {
	d, _ := f.Describe(adapterkit.DescribeParams{})
	return adapterkit.Observation{Schema: adapterkit.ObservationSchema, Range: p.Range,
		Kinds: adapterkit.ProvidedKinds(d.Observations, p.Kinds), Ledgers: []adapterkit.Ledger{}}, f.observeErr
}

func (fake) Teardown(adapterkit.TeardownParams) (adapterkit.TeardownResult, error) {
	return adapterkit.TeardownResult{OK: true}, nil
}

func TestKittestPassesAConformingHandler(t *testing.T) {
	kittest.Check(t, func() adapterkit.Handler { return fake{} }, nil)
}

// Serve answers undeclared inputs and units, unknown methods and handler errors with the documented codes,
// and stops after a describe that offers no version it speaks.
func TestServeErrors(t *testing.T) {
	in := strings.Join([]string{
		`{"xcc":"xcc.adapter/1","id":1,"method":"describe","params":{"harness_version":"t","protocol_versions":["xcc.adapter/1"]}}`,
		`{"xcc":"xcc.adapter/1","id":2,"method":"ingest","params":{"session":"s","input":{"kind":"rpc","url":"http://127.0.0.1:1"},"range":{"start":2,"end":2},"network":{"name":"testnet","passphrase":"p"},"unit":"single","deadline_ms":1}}`,
		`{"xcc":"xcc.adapter/1","id":3,"method":"ingest","params":{"session":"s","input":{"kind":"sep54-dir","path":"/x"},"range":{"start":2,"end":2},"network":{"name":"testnet","passphrase":"p"},"unit":"chain","deadline_ms":1}}`,
		`{"xcc":"xcc.adapter/1","id":4,"method":"frobnicate","params":{}}`,
		`{"xcc":"xcc.adapter/1","id":5,"method":"observe","params":{"session":"s","range":{"start":2,"end":2},"kinds":["receipts"]}}`,
		`{"xcc":"xcc.adapter/1","id":6,"method":"describe","params":{"harness_version":"t","protocol_versions":["xcc.adapter/9"]}}`,
		`{"xcc":"xcc.adapter/1","id":7,"method":"teardown","params":{"session":"s"}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := adapterkit.Serve(strings.NewReader(in), &out, fake{observeErr: adapterkit.Errorf(adapterkit.CodeUnknownSession, "no")}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{"", adapterkit.CodeUnsupportedInput, adapterkit.CodeUnsupportedUnit, adapterkit.CodeUnknownMethod,
		adapterkit.CodeUnknownSession, adapterkit.CodeUnsupportedProtocolVersion}
	if len(lines) != len(want) {
		t.Fatalf("%d response lines, want %d (Serve must stop after the unsupported version):\n%s", len(lines), len(want), out.String())
	}
	for i, code := range want {
		if code == "" {
			continue
		}
		if !strings.Contains(lines[i], `"code":"`+code+`"`) {
			t.Errorf("response %d: want error %s, got %s", i+1, code, lines[i])
		}
		if errs := adapterkit.ValidateMessage([]byte(lines[i])); len(errs) > 0 && code != adapterkit.CodeUnknownMethod {
			t.Errorf("response %d does not validate: %v", i+1, errs)
		}
	}
}

func TestRunChild(t *testing.T) {
	ctx := context.Background()
	res, err := adapterkit.RunChild(ctx, adapterkit.ChildSpec{Path: "sh", Args: []string{"-c", "echo boom >&2; exit 3"}})
	if err != nil || res.ExitCode != 3 || res.Signal != 0 || strings.TrimSpace(res.Stderr) != "boom" {
		t.Errorf("exit: %+v %v", res, err)
	}
	res, err = adapterkit.RunChild(ctx, adapterkit.ChildSpec{Path: "sh", Args: []string{"-c", "kill -SEGV $$"}})
	if err != nil || res.Signal != syscall.SIGSEGV || res.TermSignal() != "SIGSEGV" {
		t.Errorf("signal: %+v %v", res, err)
	}
	start := time.Now()
	res, err = adapterkit.RunChild(ctx, adapterkit.ChildSpec{Path: "sh", Args: []string{"-c", "sleep 30 & sleep 30"}, Deadline: 200 * time.Millisecond})
	if err != nil || !res.TimedOut || time.Since(start) > 5*time.Second {
		t.Errorf("deadline: %+v %v after %v", res, err, time.Since(start))
	}
	res, _ = adapterkit.RunChild(ctx, adapterkit.ChildSpec{Path: "sh", Args: []string{"-c", "head -c 10000 /dev/zero | tr '\\0' x >&2"}, TailBytes: 100})
	if len(res.Stderr) != 100 {
		t.Errorf("tail: kept %d bytes, want 100", len(res.Stderr))
	}
}
