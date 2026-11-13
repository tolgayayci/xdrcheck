// Package kittest checks a Go adapter from its own `go test`, in process: the same protocol checks as
// `xdrcheck replay --selftest` (docs/adapter-protocol.md §9), on a Handler served through adapterkit.Serve.
//
//	func TestProtocol(t *testing.T) {
//		kittest.Check(t, func() adapterkit.Handler { return newAdapter() }, nil)
//	}
//
// Check runs two "processes" (two handlers from newHandler), as the selftest does:
//
//   - A: describe; prepare; an ingest with an input kind the adapter did not declare (must be the error
//     unsupported_input) and one with an undeclared unit (unsupported_unit); with a probe, a real ingest that
//     must complete; observe; teardown; then the input closes and Serve must return.
//   - B: describe again, which must equal A's; with a probe, a second session over the same unit, whose
//     observation set must equal A's.
//
// Every response line is checked with adapterkit.CheckResponse, exactly as the harness checks it. Without a
// probe nothing is ingested; give one (a SEP-54 directory of a few ledgers and its range) to check ingest and
// determinism too. The harness's selftest stays the final word: it runs your real binary.
package kittest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// Probe is a unit to ingest: an input the indexer can read and the range it holds.
type Probe struct {
	Input      adapterkit.Input
	Range      adapterkit.Range
	Network    adapterkit.Network
	Unit       string // "" takes the first unit the adapter declares
	DeadlineMS int64  // 0 means 60000
	TxHashes   []string
}

// Check runs the protocol checks; every failure is reported through t.
func Check(t testing.TB, newHandler func() adapterkit.Handler, probe *Probe) {
	t.Helper()
	descA, obsA := run(t, newHandler(), "a", probe, true)
	if descA == nil {
		return
	}
	descB, obsB := run(t, newHandler(), "b", probe, false)
	if descB == nil {
		return
	}
	if !same(t, descA, descB) {
		t.Errorf("describe_stable: two describe calls in two handlers gave different results")
	}
	if probe != nil && obsA != nil && obsB != nil && !same(t, obsA, obsB) {
		t.Errorf("deterministic: two sessions over the same unit gave different observation sets\nA: %s\nB: %s", obsA, obsB)
	}
}

var (
	allInputs = []string{"sep54-dir", "sep54-s3", "sep54-gcs", "rpc"}
	allUnits  = []string{"single", "chain", "stream"}
)

// conn is a served handler: requests go in on one pipe, responses come back on the other.
type conn struct {
	t    testing.TB
	tag  string
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan error
	id   int64
}

func serve(t testing.TB, h adapterkit.Handler, tag string) *conn {
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	c := &conn{t: t, tag: tag, in: reqW, out: bufio.NewReaderSize(respR, 1<<20), done: make(chan error, 1)}
	go func() {
		err := adapterkit.Serve(reqR, respW, h)
		respW.Close()
		c.done <- err
	}()
	return c
}

// call sends one request and checks the response line as the harness does. It returns the result, or the
// error body when the adapter answered with an error response; ok is false when the line broke the protocol
// (already reported).
func (c *conn) call(method string, params any) (result json.RawMessage, errBody *adapterkit.ErrorBody, ok bool) {
	c.t.Helper()
	c.id++
	line, err := json.Marshal(map[string]any{"xcc": adapterkit.Protocol, "id": c.id, "method": method, "params": params})
	if err != nil {
		c.t.Fatalf("%s_%s: %v", method, c.tag, err)
	}
	if errs := adapterkit.ValidateRequest(method, line); len(errs) > 0 {
		c.t.Fatalf("%s_%s: the test built an invalid request: %s", method, c.tag, adapterkit.JoinSchemaErrors(errs))
	}
	go c.in.Write(append(line, '\n'))
	resp, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Errorf("%s_%s: no response line: %v", method, c.tag, err)
		return nil, nil, false
	}
	msg, perr := adapterkit.CheckResponse(resp[:len(resp)-1], c.id, method)
	if perr != nil {
		c.t.Errorf("%s_%s: %s: %s", method, c.tag, perr.Reason, perr.Detail)
		return nil, nil, false
	}
	if e, isErr := msg["error"]; isErr {
		var body adapterkit.ErrorBody
		b, _ := json.Marshal(e)
		json.Unmarshal(b, &body)
		return nil, &body, true
	}
	b, _ := json.Marshal(msg["result"])
	return b, nil, true
}

func (c *conn) close() {
	c.t.Helper()
	c.in.Close()
	if err := <-c.done; err != nil {
		c.t.Errorf("exit_%s: Serve returned %v after the input closed, want nil", c.tag, err)
	}
}

// run is one "process". It returns describe's result and the observation set as JSON.
func run(t testing.TB, h adapterkit.Handler, tag string, probe *Probe, first bool) (json.RawMessage, json.RawMessage) {
	t.Helper()
	c := serve(t, h, tag)
	defer c.close()
	descRaw, eb, ok := c.call(adapterkit.MethodDescribe, adapterkit.DescribeParams{HarnessVersion: "kittest", ProtocolVersions: []string{adapterkit.Protocol}})
	if !ok || !answered(t, "describe_"+tag, eb) {
		return nil, nil
	}
	var desc adapterkit.DescribeResult
	if err := json.Unmarshal(descRaw, &desc); err != nil {
		t.Errorf("describe_%s: %v", tag, err)
		return nil, nil
	}
	if !first && probe == nil {
		return descRaw, nil
	}

	network := adapterkit.Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"}
	rng := adapterkit.Range{Start: 2, End: 2}
	unit := desc.Units[0]
	if probe != nil {
		network, rng = probe.Network, probe.Range
		if probe.Unit != "" {
			unit = probe.Unit
		}
	}
	session := "kittest-" + tag
	workdir := filepath.Join(t.TempDir(), session)
	if _, eb, ok := c.call(adapterkit.MethodPrepare, adapterkit.PrepareParams{Session: session, TargetVersion: desc.Target.Version,
		Network: network, Workdir: workdir}); !ok || !answered(t, "prepare_"+tag, eb) {
		return descRaw, nil
	}

	if first {
		// An undeclared input kind must be refused with unsupported_input, an undeclared unit with
		// unsupported_unit, before the indexer is touched.
		if k := missing(allInputs, desc.Inputs); k != "" {
			wantError(t, c, adapterkit.CodeUnsupportedInput, adapterkit.IngestParams{Session: session, Input: dummyInput(k, workdir),
				Range: rng, Network: network, Unit: unit, DeadlineMS: 5000})
		}
		if u := missing(allUnits, desc.Units); u != "" {
			in := dummyInput(desc.Inputs[0], workdir)
			if probe != nil {
				in = probe.Input
			}
			wantError(t, c, adapterkit.CodeUnsupportedUnit, adapterkit.IngestParams{Session: session, Input: in,
				Range: rng, Network: network, Unit: u, DeadlineMS: 5000})
		}
	}

	if probe != nil {
		dl := probe.DeadlineMS
		if dl <= 0 {
			dl = 60000
		}
		raw, eb, ok := c.call(adapterkit.MethodIngest, adapterkit.IngestParams{Session: session, Input: probe.Input, Range: rng, Network: network, Unit: unit, DeadlineMS: dl})
		if !ok || !answered(t, "ingest_"+tag, eb) {
			return descRaw, nil
		}
		var res adapterkit.IngestResult
		json.Unmarshal(raw, &res)
		if res.Status != adapterkit.StatusCompleted || res.LastLedger == nil || *res.LastLedger < rng.End {
			t.Errorf("ingest_%s: the probe unit did not complete: %s", tag, raw)
		}
	}

	var kinds []string
	for _, k := range adapterkit.AllKinds {
		if desc.Observations.Kind(k).Supported {
			kinds = append(kinds, k)
		}
	}
	var txs []string
	if probe != nil {
		txs = probe.TxHashes
	}
	obs, eb, ok := c.call(adapterkit.MethodObserve, adapterkit.ObserveParams{Session: session, Range: rng, Kinds: kinds, TxHashes: txs})
	if !ok || !answered(t, "observe_"+tag, eb) {
		return descRaw, nil
	}
	if _, eb, ok := c.call(adapterkit.MethodTeardown, adapterkit.TeardownParams{Session: session}); ok {
		answered(t, "teardown_"+tag, eb)
	}
	return descRaw, obs
}

func wantError(t testing.TB, c *conn, code string, p adapterkit.IngestParams) {
	t.Helper()
	_, eb, ok := c.call(adapterkit.MethodIngest, p)
	switch {
	case !ok:
	case eb == nil:
		t.Errorf("%s: got an ingest result, want the error %s", code, code)
	case eb.Code != code:
		t.Errorf("%s: got the error %s (%s), want %s", code, eb.Code, eb.Message, code)
	}
}

// answered reports whether the call got a result; an error response is a failed check.
func answered(t testing.TB, check string, eb *adapterkit.ErrorBody) bool {
	t.Helper()
	if eb != nil {
		t.Errorf("%s: adapter error %s: %s", check, eb.Code, eb.Message)
		return false
	}
	return true
}

// dummyInput is a well-formed input of the kind that points nowhere (loopback port 1, an absent directory).
func dummyInput(kind, workdir string) adapterkit.Input {
	sch := &adapterkit.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}
	switch kind {
	case "sep54-dir":
		return adapterkit.Input{Kind: kind, Path: filepath.Join(workdir, "no-such-lake"), Schema: sch}
	case "sep54-s3":
		return adapterkit.Input{Kind: kind, EndpointURL: "http://127.0.0.1:1", BucketPath: "kittest/none", Region: "us-east-1",
			AccessKeyID: "test", SecretAccessKey: "test", Schema: sch}
	case "sep54-gcs":
		return adapterkit.Input{Kind: kind, EmulatorHost: "127.0.0.1:1", BucketPath: "kittest/none", Schema: sch}
	}
	return adapterkit.Input{Kind: "rpc", URL: "http://127.0.0.1:1"}
}

func missing(all, declared []string) string {
	for _, x := range all {
		if !slices.Contains(declared, x) {
			return x
		}
	}
	return ""
}

func same(t testing.TB, a, b json.RawMessage) bool {
	t.Helper()
	ok, err := adapterkit.SameJSON(a, b)
	if err != nil {
		t.Errorf("%v", fmt.Errorf("compare: %w", err))
	}
	return ok
}
