// Package memtest is the replay harness's memory-bound test (`make verify-memory`): every `xdrcheck replay` it starts
// runs in a memory-limited group of its own (256 MiB by default, swap off), with its adapters in groups of
// theirs, and its peak is the high-water mark of the xdrcheck process's resident set.
//
//   - T-mem-1, harness memory is flat in corpus size: the baseline indexer over the sampled bulk tier as one
//     stream unit, repeated once and ten times (each five times, interleaved, as a collected heap's peak
//     varies with the collector's timing); every run finishes without a harness fault and under the limit, the
//     lowest peak at ten repeats minus the lowest at one is under 16 MiB, and the ten-repeat report has ten
//     times the run rows. The sample leaves out the bulk tier's ledgers of a megabyte or more (decoding one
//     alone takes the harness 100 MiB and more for a moment, which would drown the growth being measured);
//     they run as a stream of their own, repeated ten times, under the limit. Then the corpus's largest ledger
//     as a stream repeated a hundred times.
//   - T-mem-2, an observation set cannot blow the harness up: a seeded adapter answers one observe with a
//     512 MiB line; the harness stops reading at its response cap, records harness_fault for that unit with the
//     reason, and goes on to pass the other units.
//   - T-mem-3, the harness catches an indexer that grows without bound: the seeded memory-hog indexer over the
//     ten-repeat stream with its adapter's group at 128 MiB gives exactly one mishandled·crash noted as memory,
//     scored entries before it and not_reached after it, while xdrcheck stays under its own limit.
//   - T-mem-4, deep and large single values: the corpus's maximum-length and maximum-depth ledgers run through
//     the server and matcher as single units under the limit.
//
// The negative control (Config.NegativeControl) runs T-mem-1's two stream runs with streaming switched off —
// the harness observes, matches and holds each unit whole (XDRCHECK_REPLAY_OBSERVE_WINDOW=unit) — and is expected
// to fail, which shows the test can.
//
// Sizes come from the corpus: the sample's stride from the bulk tier's distinct ledgers (checked against the
// ledger count in corpus.json), the largest and deepest ledgers from the manifest and the bytes.
package memtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Config sets up the test. Zero sizes take the specification's starting values.
type Config struct {
	XDRCHECK string // the xdrcheck binary
	Baseline string // the baseline adapter binary
	Self     string // this test's own binary, which serves as T-mem-2's oversize adapter (OversizeAdapter)
	Corpus   string
	Goldens  string // the golden cache root
	Pins     string
	Out      string

	Sample       int   // bulk-tier ledgers to sample (about); 0 takes the whole tier
	Repeat       int   // the larger stream's repeat count (default 10)
	Trials       int   // runs of each T-mem-1 stream size (default 5)
	BigRepeat    int   // the largest ledger's repeat count (default 100)
	HarnessLimit int64 // xdrcheck's memory group (default 256 MiB)
	Growth       int64 // allowed peak growth from one repeat to Repeat (default 16 MiB)
	AdapterLimit int64 // the baseline adapter's group in T-mem-1, 2 and 4 (default 2 GiB)
	HogLimit     int64 // memory-hog's adapter group (default 128 MiB)
	Oversize     int64 // T-mem-2's response line (default 512 MiB)
	LargeLedger  int64 // bulk ledgers of this size or more are run apart from the sample (default 1 MiB)
	Deadline     time.Duration

	Only            []string // test names to run (T-mem-1 …); nil runs all
	NegativeControl bool

	Log io.Writer
}

// Report is the test's result, written as memory.json and memory.md under Out.
type Report struct {
	Schema          string  `json:"schema"`
	NegativeControl bool    `json:"negative_control"`
	Sample          *Sample `json:"sample,omitempty"`
	Tests           []*Test `json:"tests"`
	OK              bool    `json:"ok"`
}

// Test is one of the four tests.
type Test struct {
	Name    string   `json:"name"`
	What    string   `json:"what"`
	OK      bool     `json:"ok"`
	Asserts []Assert `json:"asserts"`
	Runs    []*Run   `json:"runs"`
	Picks   []Pick   `json:"picks,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Assert is one checked statement.
type Assert struct {
	What   string `json:"what"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func (t *Test) check(ok bool, what, format string, a ...any) {
	t.Asserts = append(t.Asserts, Assert{What: what, OK: ok, Detail: fmt.Sprintf(format, a...)})
}

type tester struct {
	cfg    Config
	corpus *manifest.Corpus
	sample *Sample
}

func (t *tester) logf(format string, a ...any) {
	if t.cfg.Log != nil {
		fmt.Fprintf(t.cfg.Log, "memtest: "+format+"\n", a...)
	}
}

// Main runs the tests and writes the report. The error is for a test that could not be set up at all.
func Main(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.XDRCHECK == "" || cfg.Baseline == "" || cfg.Corpus == "" || cfg.Out == "" {
		return nil, errors.New("memtest: xdrcheck, baseline, corpus and out are required")
	}
	def := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&cfg.HarnessLimit, 256*mib)
	def(&cfg.Growth, 16*mib)
	def(&cfg.AdapterLimit, 2048*mib)
	def(&cfg.HogLimit, 128*mib)
	def(&cfg.Oversize, 512*mib)
	def(&cfg.LargeLedger, mib)
	if cfg.Repeat <= 0 {
		cfg.Repeat = 10
	}
	if cfg.Trials <= 0 {
		cfg.Trials = 5
	}
	if cfg.NegativeControl {
		cfg.Trials = 1
	}
	if cfg.BigRepeat <= 0 {
		cfg.BigRepeat = 100
	}
	if cfg.Deadline <= 0 {
		cfg.Deadline = 30 * time.Minute
	}
	for _, p := range []*string{&cfg.XDRCHECK, &cfg.Baseline, &cfg.Self, &cfg.Corpus, &cfg.Out, &cfg.Pins} {
		if *p != "" {
			abs, err := filepath.Abs(*p)
			if err != nil {
				return nil, err
			}
			*p = abs
		}
	}
	if cfg.Pins == "" {
		cfg.Pins = filepath.Join(filepath.Dir(cfg.Corpus), "pins.toml")
	}
	if err := os.MkdirAll(cfg.Out, 0o755); err != nil {
		return nil, err
	}
	c, err := manifest.Load(cfg.Corpus, manifest.Options{})
	if err != nil {
		return nil, err
	}
	t := &tester{cfg: cfg, corpus: c}
	rep := &Report{Schema: "xcc.memtest/v1", NegativeControl: cfg.NegativeControl, OK: true}
	tests := []struct {
		name, what string
		run        func(context.Context, *Test) error
	}{
		{"T-mem-1", "harness memory is flat in corpus size", t.flat},
		{"T-mem-2", "an oversized observation cannot blow the harness up", t.oversize},
		{"T-mem-3", "the harness catches an indexer that grows without bound", t.hog},
		{"T-mem-4", "the deepest and the largest ledgers run under the limit", t.extremes},
	}
	for _, x := range tests {
		if cfg.NegativeControl && x.name != "T-mem-1" || len(cfg.Only) > 0 && !slices.Contains(cfg.Only, x.name) {
			continue
		}
		tt := &Test{Name: x.name, What: x.what}
		if err := x.run(ctx, tt); err != nil {
			tt.Error = err.Error()
		}
		tt.OK = tt.Error == "" && len(tt.Asserts) > 0
		for _, a := range tt.Asserts {
			tt.OK = tt.OK && a.OK
		}
		rep.OK = rep.OK && tt.OK
		rep.Tests = append(rep.Tests, tt)
		t.logf("%s: ok=%v", x.name, tt.OK)
	}
	rep.Sample = t.sample
	return rep, rep.write(cfg.Out)
}

// bulk samples the bulk tier once.
func (t *tester) bulk() (*Sample, error) {
	if t.sample != nil {
		return t.sample, nil
	}
	dir := filepath.Join(t.cfg.Out, "bulk-sample")
	os.RemoveAll(dir)
	os.RemoveAll(dir + "-large")
	s, err := SampleBulk(t.corpus, t.cfg.Goldens, t.cfg.Sample, t.cfg.LargeLedger, dir)
	if err != nil {
		return nil, err
	}
	t.logf("bulk sample: %d ledgers (%.1f MiB) of the %d distinct, every %d-th under %.0f MiB, and the %d (%.1f MiB) at or over it; %d ledgers in the tier",
		s.Sampled, toMiB(s.Bytes), s.Distinct, s.Stride, toMiB(t.cfg.LargeLedger), s.Large, toMiB(s.LargeBytes), s.Ledgers)
	t.sample = s
	return s, nil
}

func (t *tester) common(corpus, adapter string, adapterLimit int64) []string {
	args := []string{"--corpus", corpus, "--adapter", adapter, "--target-version", "memtest", "--input", "sep54-dir",
		"--keep-going", "--memory-max", strconv.FormatInt(adapterLimit, 10)}
	if t.cfg.Pins != "" {
		args = append(args, "--pins", t.cfg.Pins)
	}
	return args
}

// underLimit checks a run against the harness limit.
func (t *tester) underLimit(tt *Test, x *Run) {
	tt.check(x.Completed() && x.peak < t.cfg.HarnessLimit, x.Name+": xdrcheck stays under its limit",
		"peak %.1f MiB of %.0f MiB (%s), exit %d, memory-killed %v", x.PeakMiB, x.LimitMiB, x.Mechanism, x.ExitCode, x.MemoryKilled)
}

func (t *tester) noFaults(tt *Test, x *Run) {
	tt.check(x.Completed() && x.ByResult["harness_fault"] == 0 && len(x.Rows) > 0, x.Name+": completes without a harness fault",
		"%d rows %v; %s", len(x.Rows), x.ByResult, strings.Join(x.Faults, " | "))
}

// T-mem-1.
func (t *tester) flat(ctx context.Context, tt *Test) error {
	s, err := t.bulk()
	if err != nil {
		return err
	}
	var env []string
	if t.cfg.NegativeControl {
		env = []string{"XDRCHECK_REPLAY_OBSERVE_WINDOW=unit"}
	}
	stream := func(name string, k int) (*Run, error) {
		args := append(t.common(s.Root, t.cfg.Baseline, t.cfg.AdapterLimit), "--network", "core-test", "--unit", "stream", "--out-of-envelope", "skip", "--repeat", strconv.Itoa(k))
		x, err := t.xdrcheck(ctx, name, env, args...)
		if x != nil {
			tt.Runs = append(tt.Runs, x)
		}
		return x, err
	}
	// A garbage-collected process's peak varies from run to run with the collector's timing, never below what
	// the run needs: each size runs Trials times, interleaved, and the lowest peaks are compared.
	var one, many *Run
	completed := true
	for i := 1; i <= t.cfg.Trials; i++ {
		a, err := stream(fmt.Sprintf("t-mem-1-repeat-1-trial-%d", i), 1)
		if err != nil {
			return err
		}
		b, err := stream(fmt.Sprintf("t-mem-1-repeat-%d-trial-%d", t.cfg.Repeat, i), t.cfg.Repeat)
		if err != nil {
			return err
		}
		for _, x := range []*Run{a, b} {
			t.noFaults(tt, x)
			t.underLimit(tt, x)
			completed = completed && x.Completed()
		}
		if one == nil || a.peak < one.peak {
			one = a
		}
		if many == nil || b.peak < many.peak {
			many = b
		}
	}
	growth := many.peak - one.peak
	tt.check(completed && growth < t.cfg.Growth, fmt.Sprintf("peak growth from 1 to %d repeats is under %.0f MiB", t.cfg.Repeat, toMiB(t.cfg.Growth)),
		"lowest peak of %d trial(s): %.1f MiB → %.1f MiB: %+.1f MiB", t.cfg.Trials, one.PeakMiB, many.PeakMiB, toMiB(growth))
	// Planned not_applicable rows (ledgers outside the indexer's envelope, left out of the stream) are written once.
	na := len(one.Rows) - one.RunRows
	tt.check(one.RunRows > 0 && one.RunRows+na == s.Sampled && many.RunRows == t.cfg.Repeat*one.RunRows && len(many.Rows)-many.RunRows == na,
		fmt.Sprintf("the %d-repeat report has %d times the rows", t.cfg.Repeat, t.cfg.Repeat),
		"%d sampled ledgers, %d outside the envelope; %d stream rows at 1 repeat, %d at %d", s.Sampled, na, one.RunRows, many.RunRows, t.cfg.Repeat)
	if t.cfg.NegativeControl {
		return nil
	}

	if s.LargeRoot != "" {
		args := append(t.common(s.LargeRoot, t.cfg.Baseline, t.cfg.AdapterLimit), "--network", "core-test", "--unit", "stream", "--out-of-envelope", "skip",
			"--repeat", strconv.Itoa(t.cfg.Repeat))
		x, err := t.xdrcheck(ctx, fmt.Sprintf("t-mem-1-large-bulk-ledgers-repeat-%d", t.cfg.Repeat), nil, args...)
		if err != nil {
			return err
		}
		tt.Runs = append(tt.Runs, x)
		t.noFaults(tt, x)
		t.underLimit(tt, x)
		tt.check(x.RunRows == t.cfg.Repeat*(s.Large-(len(x.Rows)-x.RunRows)), fmt.Sprintf("the bulk tier's %d large ledgers are served %d times", s.Large, t.cfg.Repeat),
			"%.1f MiB of ledgers of %.0f MiB or more: %d stream rows", toMiB(s.LargeBytes), toMiB(t.cfg.LargeLedger), x.RunRows)
	}

	longest, _, err := Extremes(t.corpus)
	if err != nil {
		return err
	}
	tt.Picks = append(tt.Picks, longest)
	args := append(t.common(t.cfg.Corpus, t.cfg.Baseline, t.cfg.AdapterLimit), "--entries", longest.Entry, "--network", longest.Network,
		"--unit", "stream", "--repeat", strconv.Itoa(t.cfg.BigRepeat))
	big, err := t.xdrcheck(ctx, fmt.Sprintf("t-mem-1-largest-ledger-repeat-%d", t.cfg.BigRepeat), nil, args...)
	if err != nil {
		return err
	}
	tt.Runs = append(tt.Runs, big)
	t.noFaults(tt, big)
	t.underLimit(tt, big)
	tt.check(big.RunRows > 0 && big.RunRows%t.cfg.BigRepeat == 0, fmt.Sprintf("the largest ledger is served %d times", t.cfg.BigRepeat),
		"%s on %s (%.2f MiB): %d rows", longest.Entry, longest.Network, toMiB(longest.Bytes), big.RunRows)
	return nil
}

// T-mem-2.
func (t *tester) oversize(ctx context.Context, tt *Test) error {
	if t.cfg.Self == "" {
		return errors.New("the oversize adapter needs this test's own binary (Config.Self)")
	}
	// The first few entries a single unit can replay, on one network.
	network, ids := "", []string{}
	for _, e := range t.corpus.Entries {
		if e.Kind != "ledger" || e.IndexerScope() == "sdk-only" || e.RequiresPriorState() || len(ids) == 3 {
			continue
		}
		for _, v := range e.Variants {
			if network == "" && v.Network != "none" {
				network = v.Network
			}
			if v.Network == network && !slices.Contains(ids, e.ID) {
				ids = append(ids, e.ID)
			}
		}
	}
	if len(ids) < 2 {
		return fmt.Errorf("the corpus has fewer than two single-unit entries on one network")
	}
	dir := filepath.Join(t.cfg.Out, "t-mem-2-oversized-observe")
	marker := filepath.Join(dir, "oversized.marker")
	os.MkdirAll(dir, 0o755)
	os.Remove(marker)
	adapter := fmt.Sprintf("%s oversize-adapter --marker %s --bytes %d -- %s", t.cfg.Self, marker, t.cfg.Oversize, t.cfg.Baseline)
	args := append(t.common(t.cfg.Corpus, adapter, t.cfg.AdapterLimit), "--entries", strings.Join(ids, ","), "--network", network, "--unit", "single")
	x, err := t.xdrcheck(ctx, "t-mem-2-oversized-observe", nil, args...)
	if err != nil {
		return err
	}
	tt.Runs = append(tt.Runs, x)
	_, mErr := os.Stat(marker)
	tt.check(mErr == nil, "the seeded adapter answered an observe with an oversized line", "%d bytes (marker %v)", t.cfg.Oversize, mErr)
	faults, capped, passes := 0, 0, 0
	for _, r := range x.Rows {
		switch r.Replay.Class {
		case "harness_fault":
			faults++
			if r.HasNote("longer than") {
				capped++
			}
		case "pass":
			passes++
		}
	}
	units := map[int64]bool{}
	for _, r := range x.Rows {
		if r.Replay.Class == "harness_fault" && r.Replay.Range != nil {
			units[r.Replay.Range.Start] = true
		}
	}
	tt.check(faults > 0 && capped == faults && len(units) == 1, "one unit is a harness_fault at the response cap",
		"%d harness_fault row(s) in %d unit(s), %d naming the cap", faults, len(units), capped)
	tt.check(passes > 0 && passes+faults == len(x.Rows), "the run goes on: every other unit passes", "%d rows %v", len(x.Rows), x.ByResult)
	t.underLimit(tt, x)
	return nil
}

// T-mem-3.
func (t *tester) hog(ctx context.Context, tt *Test) error {
	s, err := t.bulk()
	if err != nil {
		return err
	}
	adapter := t.cfg.Baseline + " --bug memory-hog"
	args := append(t.common(s.Root, adapter, t.cfg.HogLimit), "--network", "core-test", "--unit", "stream", "--out-of-envelope", "skip", "--repeat", strconv.Itoa(t.cfg.Repeat))
	x, err := t.xdrcheck(ctx, "t-mem-3-memory-hog", nil, args...)
	if err != nil {
		return err
	}
	tt.Runs = append(tt.Runs, x)
	crash, memory, before, after, other := -1, false, 0, 0, []string{}
	for i, r := range x.Rows {
		if r.Replay.Range == nil {
			continue
		}
		switch {
		case r.Result() == "mishandled·crash" && crash < 0:
			crash, memory = i, r.HasNote("memory")
		case crash < 0 && r.Replay.Class == "pass":
			before++
		case crash >= 0 && r.Replay.Class == "not_reached":
			after++
		default:
			other = append(other, fmt.Sprintf("row %d %s", i, r.Result()))
		}
	}
	// The sample holds each ledger once, so one entry sits at the ledger where memory ran out.
	tt.check(crash >= 0 && memory && x.ByResult["mishandled·crash"] == 1, "exactly one mishandled·crash, noted as memory",
		"crash at row %d, memory note %v; %v", crash, memory, x.ByResult)
	tt.check(before > 0 && after > 0 && len(other) == 0, "scored before the crash, not_reached after it",
		"%d pass before, %d not_reached after, unexpected: %v", before, after, head(other, 5))
	t.underLimit(tt, x)
	return nil
}

// T-mem-4.
func (t *tester) extremes(ctx context.Context, tt *Test) error {
	longest, deepest, err := Extremes(t.corpus)
	if err != nil {
		return err
	}
	tt.Picks = []Pick{longest, deepest}
	ids := []string{longest.Entry}
	if deepest.Entry != longest.Entry {
		ids = append(ids, deepest.Entry)
	}
	args := append(t.common(t.cfg.Corpus, t.cfg.Baseline, t.cfg.AdapterLimit), "--entries", strings.Join(ids, ","), "--unit", "single")
	x, err := t.xdrcheck(ctx, "t-mem-4-deepest-and-largest", nil, args...)
	if err != nil {
		return err
	}
	tt.Runs = append(tt.Runs, x)
	seen := map[string]bool{}
	for _, r := range x.Rows {
		if r.Replay.Range != nil {
			seen[r.Entry] = true
		}
	}
	tt.check(seen[longest.Entry] && seen[deepest.Entry], "both ledgers were served and matched",
		"largest %s (%.2f MiB), deepest %s (%d levels)", longest.Entry, toMiB(longest.Bytes), deepest.Entry, deepest.Depth)
	t.noFaults(tt, x)
	t.underLimit(tt, x)
	return nil
}

func head(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("… %d more", len(xs)-n))
	}
	return xs
}

func (r *Report) write(dir string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	name := "memory"
	if r.NegativeControl {
		name = "memory-negative-control"
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".md"), []byte(r.Markdown()), 0o644)
}

// Markdown is the report as a table per test.
func (r *Report) Markdown() string {
	var b strings.Builder
	title := "Memory-bound test"
	if r.NegativeControl {
		title += " — negative control (streaming off; expected to fail)"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	if s := r.Sample; s != nil {
		fmt.Fprintf(&b, "Bulk sample: %d of the %d distinct ledgers (every %d-th; %d ledgers in all) of %s at %s, %.1f MiB.\n\n", s.Sampled, s.Distinct, s.Stride, s.Ledgers, s.Tier, s.Ref, toMiB(s.Bytes))
	}
	for _, t := range r.Tests {
		status := "ok"
		if !t.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "## %s — %s: %s\n\n", t.Name, t.What, status)
		if t.Error != "" {
			fmt.Fprintf(&b, "Error: %s\n\n", t.Error)
		}
		b.WriteString("| run | exit | xdrcheck peak MiB | group peak MiB | rows | wall s |\n|---|---|---|---|---|---|\n")
		for _, x := range t.Runs {
			fmt.Fprintf(&b, "| %s | %d | %.1f | %.1f | %d | %.1f |\n", x.Name, x.ExitCode, x.PeakMiB, x.GroupPeakMiB, len(x.Rows), x.WallS)
		}
		b.WriteString("\n| assertion | ok | detail |\n|---|---|---|\n")
		for _, a := range t.Asserts {
			fmt.Fprintf(&b, "| %s | %v | %s |\n", a.What, a.OK, strings.ReplaceAll(a.Detail, "|", "\\|"))
		}
		b.WriteString("\n")
	}
	return b.String()
}
