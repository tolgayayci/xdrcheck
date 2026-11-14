package memtest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/proc"
)

// Run is one measured `xdrcheck replay`: the process ran in a memory-limited group of its own, and its peak is the
// high-water mark of its resident set (VmHWM), sampled every few milliseconds until it exits — the harness's
// own memory, not its adapters' (they run in groups of their own) and not the page cache its files leave
// behind, which the group's memory.peak also counts.
type Run struct {
	Name      string   `json:"name"`
	Args      []string `json:"args"`
	Env       []string `json:"env,omitempty"`
	Mechanism string   `json:"mechanism"`
	LimitMiB  float64  `json:"limit_mib"`

	ExitCode     int     `json:"exit_code"`
	MemoryKilled bool    `json:"memory_killed"`
	TimedOut     bool    `json:"timed_out"`
	PeakMiB      float64 `json:"peak_mib"`       // VmHWM of the xdrcheck process
	GroupPeakMiB float64 `json:"group_peak_mib"` // the group's memory.peak (page cache included), when known
	WallS        float64 `json:"wall_s"`
	StderrTail   string  `json:"stderr_tail,omitempty"`

	Rows     []Row          `json:"-"`
	RunRows  int            `json:"run_rows"` // rows of entries that were run (a unit range), not planned not_applicable
	ByResult map[string]int `json:"by_result"`
	Faults   []string       `json:"faults,omitempty"` // the first harness_fault notes
	peak     int64
}

// Row is what the test reads of a report row.
type Row struct {
	Entry   string   `json:"entry"`
	Variant string   `json:"variant"`
	Notes   []string `json:"notes"`
	Replay  struct {
		Unit      string `json:"unit"`
		Class     string `json:"class"`
		Qualifier string `json:"qualifier"`
		Range     *struct {
			Start int64 `json:"start"`
		} `json:"range"`
	} `json:"replay"`
}

// Result is the row's class·qualifier.
func (r Row) Result() string {
	if r.Replay.Qualifier == "" {
		return r.Replay.Class
	}
	return r.Replay.Class + "·" + r.Replay.Qualifier
}

// HasNote reports whether a note contains s.
func (r Row) HasNote(s string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// Completed reports whether the run ran to its end: not killed, its report written.
func (x *Run) Completed() bool {
	return !x.MemoryKilled && !x.TimedOut && x.ExitCode >= 0 && x.ExitCode <= 2 && x.ByResult != nil
}

const mib = 1 << 20

func toMiB(b int64) float64 { return float64(b*100/mib) / 100 }

// xdrcheck runs `xdrcheck replay ARGS --report DIR` under a memory limit and reads its report.
func (t *tester) xdrcheck(ctx context.Context, name string, env []string, args ...string) (*Run, error) {
	dir := filepath.Join(t.cfg.Out, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp := filepath.Join(t.cfg.Out, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, err
	}
	argv := append([]string{"replay"}, args...)
	argv = append(argv, "--report", dir)
	x := &Run{Name: name, Args: argv, Env: env, LimitMiB: toMiB(t.cfg.HarnessLimit)}
	fullEnv := append(os.Environ(), "TMPDIR="+tmp)
	fullEnv = append(fullEnv, env...)
	t.logf("%s: xdrcheck %s", name, strings.Join(argv, " "))
	start := time.Now()
	c, err := proc.Start(ctx, proc.Spec{Path: t.cfg.XDRCHECK, Args: argv, Env: fullEnv, Name: "xdrcheck-memtest",
		Limits: proc.Limits{MemoryMax: t.cfg.HarnessLimit, Deadline: t.cfg.Deadline}, TailBytes: 8 << 10})
	if err != nil {
		return nil, err
	}
	tick := time.NewTicker(5 * time.Millisecond)
	comm := commName(t.cfg.XDRCHECK)
	for done := false; !done; {
		if v := vmHWM(c.Pid(), comm); v > x.peak {
			x.peak = v
		}
		select {
		case <-c.Done():
			done = true
		case <-tick.C:
		}
	}
	tick.Stop()
	res := c.Wait()
	x.WallS = time.Since(start).Seconds()
	x.Mechanism = string(res.Mechanism)
	x.ExitCode, x.MemoryKilled, x.TimedOut = res.ExitCode, res.MemoryCapHit, res.TimedOut
	x.PeakMiB, x.GroupPeakMiB = toMiB(x.peak), toMiB(res.GroupPeakBytes)
	x.StderrTail = lastLines(string(res.Stderr.Data), 6)
	if err := x.readReport(filepath.Join(dir, "report.json")); err != nil {
		x.Faults = append(x.Faults, "report: "+err.Error())
	}
	t.logf("%s: exit %d, peak %.1f MiB (group %.1f MiB, %s), %d rows %v, %.1f s", name, x.ExitCode, x.PeakMiB, x.GroupPeakMiB, x.Mechanism, len(x.Rows), x.ByResult, x.WallS)
	return x, nil
}

func (x *Run) readReport(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var rep struct {
		Rows []Row `json:"rows"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return err
	}
	x.Rows, x.ByResult = rep.Rows, map[string]int{}
	for _, r := range rep.Rows {
		x.ByResult[r.Result()]++
		if r.Replay.Range != nil {
			x.RunRows++
		}
		if r.Replay.Class == "harness_fault" && len(x.Faults) < 5 {
			x.Faults = append(x.Faults, r.Entry+": "+strings.Join(r.Notes, "; "))
		}
	}
	return nil
}

// vmHWM is the peak resident set of a live process in bytes, counted only once the process runs the program
// named name (its comm, as /proc shows it): 0 when it cannot be read (the process is gone) or runs something else.
//
// The program is started through systemd-run (or prlimit), which execs it under the same process ID; before
// those execs complete, the new process can still show the test's own memory (os/exec starts it with vfork, the
// child sharing this process's address space until its exec), and the test's own peak — it reads golden files
// and large reports whole — was recorded as xdrcheck's: a run whose memory group peaked at 53 MiB reported
// 209 MiB. The kernel sets the name after the exec has replaced the address space, so a Name line that names
// the program comes with that program's own VmHWM.
func vmHWM(pid int, name string) int64 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "Name:"); ok && strings.TrimSpace(v) != name {
			return 0
		}
		if v, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}

// commName is the name /proc shows for a process running the program at path: its base name, cut to the
// kernel's 15 bytes.
func commName(path string) string {
	n := filepath.Base(path)
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
