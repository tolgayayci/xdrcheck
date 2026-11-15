package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The engine must find what is already known. With suppression off, a fixed-seed run of three mutators over a
// small named entry set re-discovers three public findings of different verdict classes: stellar-xdr reading a
// bool of 2 against stellar-core and the other SDKs (a split, F-0037), stellar-xdr under Limits::none()
// allocating a length prefix's claim before reading the body (a halt under an address-space cap, F-0043), and
// js-xdr 4.x in js-stellar-sdk 16.x refusing a valid deeply nested value (refuses-valid, F-0022). Each
// candidate's replay command then gives its verdict line byte for byte.
//
// Needs the release engine and the Rust, Python, Go, JS 16 and stellar-core drivers built; without them the
// test is skipped, unless XDRCHECK_MUTATE_REQUIRE=1 makes that a failure (make mutate-sensitivity).
func TestMutateSensitivity(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"target/release/xdrcheck-mutate", "drivers/rust/30.0.0/bin/xdrcheck-driver", "drivers/rust/28.0.0/bin/xdrcheck-driver",
		"drivers/python/17.0.1/bin/xdrcheck-driver", "drivers/go/v0.9.0/bin/xdrcheck-driver", "drivers/js16/16.3.0/bin/xdrcheck-driver",
		"drivers/core/bin/xdrcheck-driver"} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			if os.Getenv("XDRCHECK_MUTATE_REQUIRE") == "1" {
				t.Fatalf("%s is not built", p)
			}
			t.Skipf("%s is not built (cargo build --release -p xdrcheck-mutate; xdrcheck conform build --set all)", p)
		}
	}
	cache := os.Getenv("XDRCHECK_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "xdrcheck")
	}
	work := filepath.Join(cache, "mutate", "test-sensitivity")
	overlay := filepath.Join(work, "overlay")
	os.RemoveAll(work)
	t.Cleanup(func() { os.RemoveAll(work) })
	if err := os.MkdirAll(overlay, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var out, errb bytes.Buffer
	// The address-space cap is for the Rust columns only: node cannot start under it.
	const asLimit = "rust@*=1G"
	args := []string{"run", "--seed", "1", "--budget", "120", "--columns", "rust@*,python@*,go@v0.9.0,js@16.3.0,core@*",
		"--as-limit", asLimit, "--adapters", "none", "--no-suppress", "--classes", "valid,wire-invalid",
		"--mutators", "bool-2,len-over-remaining,deepen",
		"--entries", "cap-0046/scval-map-keys-collide-*,classic/muxed-id-max-and-offer-id-max-roundtrip,cap-0038/pool-share-limit-only-change," +
			"cap-0046/event-topic-count-extremes.four-topics",
		"--work", work, "--overlay", overlay}
	if code := mutateMain(ctx, args, &out, &errb); code != 0 {
		t.Fatalf("xdrcheck mutate run exited %d:\n%s\n%s", code, out.String(), errb.String())
	}
	var rep mutRunReport
	data, err := os.ReadFile(filepath.Join(work, "report", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.OwnFaults) > 0 || len(rep.Unclassified) > 0 {
		t.Fatalf("own faults %v, unclassified %v", rep.OwnFaults, rep.Unclassified)
	}
	known := []struct {
		name                     string
		reader, verdict, mutator func(string) bool
	}{
		{"stellar-xdr bool 2 (split)", prefix("rust@"), is("cross-reader-split"), is("bool-2")},
		{"stellar-xdr Limits::none() length allocation (halt)", contains(":limits-none"), is("halt"), is("len-over-remaining")},
		{"js-xdr 4.x decode depth (refuses-valid)", prefix("js@16."), is("refuses-valid"), is("deepen")},
	}
	for _, k := range known {
		var hit *mutRunCandidate
		for i := range rep.Candidates {
			f := strings.Split(rep.Candidates[i].Signature, "|")
			if len(f) == 4 && k.reader(f[0]) && k.verdict(f[1]) && k.mutator(f[2]) {
				hit = &rep.Candidates[i]
				break
			}
		}
		if hit == nil {
			t.Errorf("not re-discovered: %s", k.name)
			continue
		}
		// The candidate's own replay command reproduces its verdict line.
		cmd, err := splitCommand(hit.Replay)
		if err != nil || len(cmd) < 3 || cmd[0] != "xdrcheck" || cmd[1] != "mutate" {
			t.Fatalf("replay command %q: %v", hit.Replay, err)
		}
		var rout, rerr bytes.Buffer
		rargs := append(cmd[2:], "--overlay", overlay, "--as-limit", asLimit, "--work", filepath.Join(work, "replay"))
		if code := mutateMain(ctx, rargs, &rout, &rerr); code != 0 {
			t.Errorf("%s: replay exited %d: %s", k.name, code, rerr.String())
			continue
		}
		if got := strings.TrimSpace(rout.String()); got != hit.Line {
			t.Errorf("%s: replay gave\n%s\nthe run recorded\n%s", k.name, got, hit.Line)
		}
	}
}

func prefix(p string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, p) }
}
func contains(p string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, p) }
}
func is(p string) func(string) bool { return func(s string) bool { return s == p } }

func TestAsLimitFlag(t *testing.T) {
	var a asLimitFlag
	if err := a.Set("2G"); err != nil || a.all != 2<<30 || len(a.per) != 0 {
		t.Fatalf("2G: %+v %v", a, err)
	}
	if err := a.Set("rust@*:limits-none=1G,go@*=512M"); err != nil || a.all != 0 {
		t.Fatalf("per column: %+v %v", a, err)
	}
	for id, want := range map[string]int64{"rust@30.0.0:limits-none": 1 << 30, "go@v0.7.1": 512 << 20} {
		if got, ok := a.forColumn(id); !ok || got != want {
			t.Errorf("%s: %d %v, want %d", id, got, ok, want)
		}
	}
	for _, id := range []string{"rust@30.0.0:limits-default", "js@16.3.0"} {
		if _, ok := a.forColumn(id); ok {
			t.Errorf("%s: capped", id)
		}
	}
	if err := a.Set("rust@*=1G,js@*"); err == nil {
		t.Error("a glob without a size was accepted")
	}
}
