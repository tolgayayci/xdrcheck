package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Selftest checks an adapter's protocol conformance without scoring its indexer (`xdrcheck replay --selftest`,
// adapter-protocol.md §9). It runs the adapter twice:
//
//   - process A: describe; prepare; an ingest with an input kind the adapter did not declare (must be the error
//     unsupported_input) and one with an undeclared unit (unsupported_unit); with a probe unit, a real ingest;
//     observe; teardown; then stdin is closed and the adapter must exit 0 within the grace period;
//   - process B: describe again, which must equal A's; with a probe unit, a second session over the same unit,
//     whose observation set must equal A's.
//
// Every response is validated as in normal runs, so a broken message ends the selftest with the protocol
// error's reason (missing_field, wrong_protocol_tag, malformed_message, wall_clock_field, …). The checks that
// need the ledger server or a network namespace — the withheld-ledger deadline and loopback-only traffic — are
// reported as skipped; the harness's own selftest target runs them.

// SelftestConfig is what the selftest needs to drive an adapter.
type SelftestConfig struct {
	Adapter        Config
	HarnessVersion string
	TargetVersion  string
	Network        Network
	Workdir        string // sessions get subdirectories
	Cachedir       string
	PortRange      *PortRange
	Limits         *Limits
	Probe          *SelftestProbe // optional: a unit the harness serves, for the ingest and determinism checks
}

// SelftestProbe is a served unit to ingest twice.
type SelftestProbe struct {
	Input      Input
	Range      Range
	Unit       string
	DeadlineMS int64
	TxHashes   []string
}

// Check statuses.
const (
	CheckPass = "pass"
	CheckFail = "fail"
	CheckSkip = "skip"
)

// Check is one selftest check.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitzero"` // a ProtocolError reason, or a selftest reason
	Detail string `json:"detail,omitzero"`
}

// Selftest-specific reasons.
const (
	ReasonWrongErrorCode = "wrong_error_code" // a probe got another error, or a result, instead of the documented error
	ReasonUnstable       = "describe_unstable"
	ReasonNondeterminism = "nondeterministic_observation"
	ReasonBadExit        = "bad_exit"
	ReasonAdapterError   = "adapter_error"
	ReasonTimeout        = "timeout"
	ReasonExited         = "adapter_exited"
	ReasonStart          = "start_failed"
)

// SelftestReport is the outcome.
type SelftestReport struct {
	Describe *DescribeResult `json:"describe,omitzero"`
	Checks   []Check         `json:"checks"`
}

// OK reports whether no check failed.
func (r *SelftestReport) OK() bool { return r.FirstFailure() == nil }

// FirstFailure returns the first failed check, or nil.
func (r *SelftestReport) FirstFailure() *Check {
	for i := range r.Checks {
		if r.Checks[i].Status == CheckFail {
			return &r.Checks[i]
		}
	}
	return nil
}

func (r *SelftestReport) add(name, status, reason, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Reason: reason, Detail: detail})
}

// failErr records a failed check from a call error and reports whether the client can go on.
func (r *SelftestReport) failErr(name string, err error) bool {
	var pe *ProtocolError
	var ae *AdapterError
	var te *TimeoutError
	var xe *ExitError
	switch {
	case errors.As(err, &pe):
		r.add(name, CheckFail, pe.Reason, pe.Detail)
		return false
	case errors.As(err, &ae):
		r.add(name, CheckFail, ReasonAdapterError, ae.Code+": "+ae.Message)
		return true
	case errors.As(err, &te):
		r.add(name, CheckFail, ReasonTimeout, te.Error())
	case errors.As(err, &xe):
		r.add(name, CheckFail, ReasonExited, xe.Error())
	default:
		r.add(name, CheckFail, ReasonStart, err.Error())
	}
	return false
}

var allInputs = []string{"sep54-dir", "sep54-s3", "sep54-gcs", "rpc"}
var allUnits = []string{"single", "chain", "stream"}

// dummyInput is a well-formed input of the kind that points nowhere (loopback port 1, an absent directory).
func dummyInput(kind, workdir string) Input {
	sch := &SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}
	switch kind {
	case "sep54-dir":
		return Input{Kind: kind, Path: filepath.Join(workdir, "no-such-lake"), Schema: sch}
	case "sep54-s3":
		return Input{Kind: kind, EndpointURL: "http://127.0.0.1:1", BucketPath: "selftest/none", Region: "us-east-1", AccessKeyID: "test", SecretAccessKey: "test", Schema: sch}
	case "sep54-gcs":
		return Input{Kind: kind, EmulatorHost: "127.0.0.1:1", BucketPath: "selftest/none", Schema: sch}
	default:
		return Input{Kind: "rpc", URL: "http://127.0.0.1:1"}
	}
}

// Selftest runs the checks. It never returns an error: everything, including a failure to start the adapter,
// is a check in the report.
func Selftest(ctx context.Context, cfg SelftestConfig) *SelftestReport {
	r := &SelftestReport{}
	descA, obsA, ok := selftestProcess(ctx, cfg, r, "a", nil)
	if !ok {
		return r
	}
	r.Describe = descA
	selftestProcess(ctx, cfg, r, "b", &firstRun{describe: descA, observation: obsA})
	r.add("deadline", CheckSkip, "", "needs a ledger the server withholds; run by the harness selftest target")
	r.add("loopback_only", CheckSkip, "", "needs a network namespace; run by the harness selftest target")
	return r
}

// probe is an ingest that must be answered with the error named like the check.
type probe struct {
	name  string
	input Input
	unit  string
}

type firstRun struct {
	describe    *DescribeResult
	observation *Observation
}

func selftestProcess(ctx context.Context, cfg SelftestConfig, r *SelftestReport, tag string, first *firstRun) (*DescribeResult, *Observation, bool) {
	c, err := Start(ctx, cfg.Adapter)
	if err != nil {
		r.failErr("start_"+tag, err)
		return nil, nil, false
	}
	defer c.Kill("selftest done")

	desc, err := c.Describe(ctx, DescribeParams{HarnessVersion: cfg.HarnessVersion, ProtocolVersions: []string{Protocol}, TargetVersion: cfg.TargetVersion})
	if err != nil {
		r.failErr("describe_"+tag, err)
		return nil, nil, false
	}
	r.add("describe_"+tag, CheckPass, "", "")
	if first != nil {
		a, b := mustJSON(first.describe), mustJSON(desc)
		if string(a) != string(b) {
			r.add("describe_stable", CheckFail, ReasonUnstable, "two describe calls in two processes gave different results")
		} else {
			r.add("describe_stable", CheckPass, "", "")
		}
		if cfg.Probe == nil {
			return desc, nil, true
		}
	}

	session := "selftest-" + tag
	workdir := filepath.Join(cfg.Workdir, session)
	_, err = c.Prepare(ctx, PrepareParams{Session: session, TargetVersion: cfg.TargetVersion, Network: cfg.Network,
		Workdir: workdir, Cachedir: cfg.Cachedir, PortRange: cfg.PortRange, Limits: cfg.Limits})
	if err != nil {
		r.failErr("prepare_"+tag, err)
		return desc, nil, false
	}
	r.add("prepare_"+tag, CheckPass, "", "")

	unit := ""
	if len(desc.Units) > 0 {
		unit = desc.Units[0]
	}
	if cfg.Probe != nil && cfg.Probe.Unit != "" {
		unit = cfg.Probe.Unit
	}
	rng := Range{Start: 1, End: 1}
	if cfg.Probe != nil {
		rng = cfg.Probe.Range
	}

	if first == nil {
		// Undeclared input kind → unsupported_input; undeclared unit → unsupported_unit.
		var probes []probe
		if k := firstMissing(allInputs, desc.Inputs); k != "" {
			probes = append(probes, probe{"unsupported_input", dummyInput(k, workdir), unit})
		} else {
			r.add("unsupported_input", CheckSkip, "", "the adapter declares every input kind")
		}
		if u := firstMissing(allUnits, desc.Units); u != "" {
			in := dummyInput(desc.Inputs[0], workdir)
			if cfg.Probe != nil {
				in = cfg.Probe.Input
			}
			probes = append(probes, probe{"unsupported_unit", in, u})
		} else {
			r.add("unsupported_unit", CheckSkip, "", "the adapter declares every unit")
		}
		for _, p := range probes {
			_, err := c.Ingest(ctx, IngestParams{Session: session, Input: p.input, Range: rng, Network: cfg.Network, Unit: p.unit, DeadlineMS: 5000})
			var ae *AdapterError
			switch {
			case err == nil:
				r.add(p.name, CheckFail, ReasonWrongErrorCode, "got an ingest result, want error "+p.name)
			case errors.As(err, &ae) && ae.Code == p.name:
				r.add(p.name, CheckPass, "", "")
			case errors.As(err, &ae):
				r.add(p.name, CheckFail, ReasonWrongErrorCode, fmt.Sprintf("got error %s, want %s", ae.Code, p.name))
			default:
				r.failErr(p.name, err)
				return desc, nil, false
			}
		}
	}

	if cfg.Probe != nil {
		dl := cfg.Probe.DeadlineMS
		if dl <= 0 {
			dl = 30000
		}
		if _, err := c.Ingest(ctx, IngestParams{Session: session, Input: cfg.Probe.Input, Range: rng, Network: cfg.Network, Unit: unit, DeadlineMS: dl}); err != nil {
			if !r.failErr("ingest_"+tag, err) {
				return desc, nil, false
			}
		} else {
			r.add("ingest_"+tag, CheckPass, "", "")
		}
	}

	var kinds []string
	for _, k := range AllKinds {
		if desc.Observations.Kind(k).Supported {
			kinds = append(kinds, k)
		}
	}
	if len(kinds) == 0 {
		kinds = AllKinds
	}
	var txs []string
	if cfg.Probe != nil {
		txs = cfg.Probe.TxHashes
	}
	obs, err := c.Observe(ctx, ObserveParams{Session: session, Range: rng, Kinds: kinds, TxHashes: txs})
	if err != nil {
		if !r.failErr("observe_"+tag, err) {
			return desc, nil, false
		}
	} else {
		r.add("observe_"+tag, CheckPass, "", "")
	}
	if first != nil && obs != nil && first.observation != nil {
		if a, b := mustJSON(first.observation), mustJSON(obs); string(a) != string(b) {
			r.add("deterministic", CheckFail, ReasonNondeterminism, "two sessions over the same unit gave different observation sets")
		} else {
			r.add("deterministic", CheckPass, "", "")
		}
	}

	if _, err := c.Teardown(ctx, TeardownParams{Session: session}); err != nil {
		if !r.failErr("teardown_"+tag, err) {
			return desc, obs, false
		}
	} else {
		r.add("teardown_"+tag, CheckPass, "", "")
	}

	res := c.Close()
	switch {
	case res.ExitCode == 0 && res.Signal == 0 && !hasKillNote(res.Notes):
		r.add("exit_"+tag, CheckPass, "", "")
	default:
		detail, _ := json.Marshal(struct {
			Exit  int      `json:"exit_code"`
			Notes []string `json:"notes,omitzero"`
		}{res.ExitCode, res.Notes})
		r.add("exit_"+tag, CheckFail, ReasonBadExit, "after stdin closed, want exit 0 within the grace period: "+string(detail))
	}
	return desc, obs, true
}

func hasKillNote(notes []string) bool {
	for _, n := range notes {
		if strings.Contains(n, "killed by the supervisor") {
			return true
		}
	}
	return false
}

func firstMissing(all, declared []string) string {
	for _, x := range all {
		if !slices.Contains(declared, x) {
			return x
		}
	}
	return ""
}
