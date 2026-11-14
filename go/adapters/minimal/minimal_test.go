package main

// Tests that need this repository (its corpus and the harness's own packages). They are not part of the
// template: copy main.go and protocol_test.go only.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapterkit/kittest"
	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/plan"
)

// The test binary doubles as the adapter: with XDRCHECK_MINIMAL_MAIN set it runs main.
func TestMain(m *testing.M) {
	if os.Getenv("XDRCHECK_MINIMAL_MAIN") == "1" {
		main()
	}
	os.Exit(m.Run())
}

const repo = "../../.."

// probeUnit writes one planned unit of the corpus as a SEP-54 directory and returns it as a probe.
func probeUnit(t *testing.T, entry string) *kittest.Probe {
	t.Helper()
	d, _ := (&minimal{}).Describe(adapterkit.DescribeParams{})
	c, err := manifest.Load(repo+"/corpus", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	maxP, minTx := *d.Envelope.MaxProtocol, *d.Envelope.MinProtocolWithTransactions
	p, err := plan.Build(c, plan.Options{Units: d.Units, Envelope: &plan.Envelope{Enforcement: d.Envelope.Enforcement,
		MaxProtocol: &maxP, MinProtocolWithTransactions: &minTx, LedgerCloseMetaVersions: d.Envelope.LedgerCloseMetaVersions}})
	if err != nil {
		t.Fatal(err)
	}
	for _, pass := range p.Passes {
		for _, u := range pass.Units {
			if len(u.Entries) == 0 || u.Entries[0].Entry != entry {
				continue
			}
			dir := filepath.Join(t.TempDir(), "lake")
			if _, err := u.WriteLayout(dir); err != nil {
				t.Fatal(err)
			}
			return &kittest.Probe{
				Input:   adapterkit.Input{Kind: "sep54-dir", Path: dir, Schema: &adapterkit.SEP54Schema{LedgersPerBatch: 1, BatchesPerPartition: 64000, Compression: "zstd"}},
				Range:   adapterkit.Range{Start: int64(u.First()), End: int64(u.Last())},
				Network: adapterkit.Network{Name: u.Network, Passphrase: u.Passphrase}, Unit: u.Kind,
			}
		}
	}
	t.Fatalf("%s is not planned", entry)
	return nil
}

// The in-process checks with a real unit: ingest completes and two sessions observe the same facts.
func TestProtocolWithProbe(t *testing.T) {
	probe := probeUnit(t, "cap-0040/signed-payload-signer-added")
	kittest.Check(t, func() adapterkit.Handler { return &minimal{sessions: map[string]*session{}} }, probe)
}

// The harness's selftest on the real process, as `xdrcheck replay --selftest` runs it.
func TestSelftest(t *testing.T) {
	probe := probeUnit(t, "cap-0040/signed-payload-signer-added")
	rep := adapter.Selftest(context.Background(), adapter.SelftestConfig{
		Adapter:        adapter.Config{Argv: []string{os.Args[0]}, Env: append(os.Environ(), "XDRCHECK_MINIMAL_MAIN=1"), Name: "minimal-test"},
		HarnessVersion: "test", TargetVersion: version, Network: probe.Network, Workdir: t.TempDir(),
		Probe: &adapter.SelftestProbe{Input: probe.Input, Range: probe.Range, Unit: probe.Unit, DeadlineMS: 60000},
	})
	for _, c := range rep.Checks {
		t.Logf("%-18s %s %s %s", c.Name, c.Status, c.Reason, c.Detail)
	}
	if f := rep.FirstFailure(); f != nil {
		t.Fatalf("selftest failed: %+v", *f)
	}
}

// The template is copyable: main.go and protocol_test.go, alone in a module of their own that requires this
// repository's Go module (here through a replace to the local checkout), build, vet and pass their test. This
// is what an indexer team does on day one, so nothing in them may import a package under internal/.
func TestTemplateBuildsInItsOwnModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a separate module")
	}
	kit, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, f := range []string{"main.go", "protocol_test.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "/internal/") {
			t.Errorf("%s imports a package under internal/", f)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gomod := "module example.com/my-indexer-adapter\n\ngo 1.26.11\n\n" +
		"require github.com/tolgayayci/xdrcheck/go v0.0.0\n\n" +
		"replace github.com/tolgayayci/xdrcheck/go => " + kit + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	// The kit's go.sum already holds every checksum the template needs; nothing is downloaded.
	sum, err := os.ReadFile(filepath.Join(kit, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local", "GONOSUMDB=*", "GOSUMDB=off")
	// tidy -e: with GOPROXY=off, tidy also asks for the test-only dependencies of the SDK's own packages, which a
	// clean module cache does not hold; build, vet and test below still prove the template compiles and passes.
	for _, args := range [][]string{{"mod", "tidy", "-e"}, {"build", "./..."}, {"vet", "./..."}, {"test", "./..."}} {
		cmd := exec.Command("go", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s in the copied template: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}
