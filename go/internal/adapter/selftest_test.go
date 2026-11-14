package adapter

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func selftestConfig(t *testing.T, mode string) SelftestConfig {
	cfg := fakeConfig(mode)
	cfg.Stderr = &bytes.Buffer{}
	cfg.Deadlines.Exit = 2 * time.Second
	cfg.Deadlines.Observe = 2 * time.Second
	return SelftestConfig{
		Adapter:        cfg,
		HarnessVersion: "0.1.0-test",
		TargetVersion:  "2c873353c1f0f3c9b145e25a7d009023ad104a1c",
		Network:        Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"},
		Workdir:        t.TempDir(),
		Probe: &SelftestProbe{
			Input: Input{Kind: "sep54-s3", EndpointURL: "http://127.0.0.1:1", BucketPath: "ledgers/testnet", Region: "us-east-1",
				AccessKeyID: "test", SecretAccessKey: "test", Schema: &SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000}},
			Range:      Range{Start: 4437357, End: 4437357},
			Unit:       "single",
			DeadlineMS: 2000,
		},
	}
}

func TestSelftestPassesAConformingAdapter(t *testing.T) {
	r := Selftest(context.Background(), selftestConfig(t, "good"))
	if !r.OK() {
		t.Fatalf("selftest failed: %+v", r.Checks)
	}
	want := []string{"describe_a", "prepare_a", "unsupported_input", "unsupported_unit", "ingest_a", "observe_a", "teardown_a", "exit_a",
		"describe_b", "describe_stable", "prepare_b", "ingest_b", "observe_b", "deterministic", "teardown_b", "exit_b", "deadline", "loopback_only"}
	var got []string
	for _, c := range r.Checks {
		got = append(got, c.Name)
	}
	if len(got) != len(want) {
		t.Fatalf("checks %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("checks %v, want %v", got, want)
		}
	}
	if r.Describe == nil || r.Describe.Adapter.Name != "wallet-backend" {
		t.Errorf("describe result not kept: %+v", r.Describe)
	}
}

// Deliberately broken fake adapters, each rejected with the reason that names its flaw.
func TestSelftestRejectsBrokenAdapters(t *testing.T) {
	cases := []struct {
		flaw, check, reason string
	}{
		{"no-envelope", "describe_a", ReasonMissingField},
		{"wrong-tag", "describe_a", ReasonWrongProtocol},
		{"malformed", "describe_a", ReasonMalformed},
		{"wall-clock", "observe_a", ReasonWallClock},
		{"wall-clock-value", "observe_a", ReasonWallClock},
		{"bad-id", "prepare_a", ReasonIDMismatch},
		{"unknown-field", "prepare_a", ReasonUnknownField},
		{"old-version", "describe_a", ReasonVersionNotOffered},
		{"wrong-code", "unsupported_unit", ReasonWrongErrorCode},
		{"unstable", "describe_stable", ReasonUnstable},
		{"hang-observe", "observe_a", ReasonTimeout},
		{"no-exit", "exit_a", ReasonBadExit},
	}
	for _, tc := range cases {
		t.Run(tc.flaw, func(t *testing.T) {
			r := Selftest(context.Background(), selftestConfig(t, "good,"+tc.flaw))
			f := r.FirstFailure()
			if f == nil {
				t.Fatalf("selftest passed a %s adapter: %+v", tc.flaw, r.Checks)
			}
			if f.Name != tc.check || f.Reason != tc.reason {
				t.Fatalf("first failure %s/%s (%s), want %s/%s", f.Name, f.Reason, f.Detail, tc.check, tc.reason)
			}
		})
	}
}

// Without a served unit the selftest still checks every message and the documented probe errors.
func TestSelftestWithoutAProbeUnit(t *testing.T) {
	cfg := selftestConfig(t, "good")
	cfg.Probe = nil
	r := Selftest(context.Background(), cfg)
	if !r.OK() {
		t.Fatalf("selftest failed: %+v", r.Checks)
	}
	for _, c := range r.Checks {
		if c.Name == "ingest_a" || c.Name == "deterministic" {
			t.Errorf("check %s ran without a probe unit", c.Name)
		}
	}
	cfg = selftestConfig(t, "good,no-envelope")
	cfg.Probe = nil
	if f := Selftest(context.Background(), cfg).FirstFailure(); f == nil || f.Reason != ReasonMissingField {
		t.Fatalf("missing describe field not rejected: %+v", f)
	}
}
