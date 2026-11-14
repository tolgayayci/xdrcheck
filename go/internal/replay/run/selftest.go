package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
)

// Selftest runs adapter.Selftest (`xdrcheck replay --selftest`). The probe unit is the first unit the plan would
// run, served on the chosen input, so the ingest and determinism checks run on real corpus ledgers. With no
// plannable unit the selftest runs without a probe.
func Selftest(ctx context.Context, o Options) (*adapter.SelftestReport, error) {
	if o.Corpus == nil || len(o.Adapter.Argv) == 0 || o.WorkDir == "" {
		return nil, errors.New("selftest: corpus, adapter command and work directory are required")
	}
	if o.LogDir == "" {
		o.LogDir = filepath.Join(o.WorkDir, "logs")
	}
	if err := os.MkdirAll(o.LogDir, 0o755); err != nil {
		return nil, err
	}
	if o.TargetVersion == "" {
		o.TargetVersion = "unknown"
	}
	r := &runner{o: o, res: &Result{ByResult: map[string]int{}}, ranges: map[string]bool{}}
	defer r.closeStore()
	o.Adapter.Limits.MemoryMax, o.Adapter.Limits.TasksMax = o.MemoryMax, o.PidsMax
	r.o = o
	cfg := o.Adapter
	cfg.Name = "adapter"

	// Describe once to plan the probe unit; the selftest then starts its own processes.
	a, err := r.startAdapter(ctx)
	if err != nil {
		return &adapter.SelftestReport{Checks: []adapter.Check{{Name: "describe_a", Status: adapter.CheckFail, Reason: adapter.ReasonStart, Detail: err.Error()}}}, nil
	}
	r.desc = a.desc
	r.target.Name = a.desc.Target.Name
	a.close()

	sc := adapter.SelftestConfig{Adapter: cfg, HarnessVersion: o.HarnessVersion, TargetVersion: o.TargetVersion,
		Workdir: filepath.Join(o.WorkDir, "selftest"), Cachedir: o.CacheDir, Limits: r.limits(), PortRange: freePortRange(4)}
	if lf, err := os.Create(filepath.Join(o.LogDir, "selftest-adapter.log")); err == nil {
		defer lf.Close()
		sc.Adapter.Stderr = lf
	}
	sc.Network = adapter.Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"}
	if err := r.chooseInput(); err == nil {
		if p, err := r.buildPlan(); err == nil {
			r.plan = p
			for _, pass := range p.Passes {
				if len(pass.Units) == 0 {
					continue
				}
				u := pass.Units[0]
				w := &worker{r: r}
				v, err := w.serve(ctx, u, filepath.Join(o.WorkDir, "probe"))
				if err != nil {
					return nil, err
				}
				defer v.close()
				sc.Network = adapter.Network{Name: u.Network, Passphrase: u.Passphrase}
				sc.Probe = &adapter.SelftestProbe{Input: v.input, Range: adapter.Range{Start: int64(u.First()), End: int64(u.Last())},
					Unit: u.Kind, DeadlineMS: r.deadline(u).Milliseconds()}
				break
			}
		}
	}
	return adapter.Selftest(ctx, sc), nil
}
