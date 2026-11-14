// Package proc runs a child process (an adapter, a conformance driver, an indexer) under a deadline, a memory
// cap and a process cap, and reports how it ended.
//
// Mechanisms, in order of preference (the one used is reported in Result.Mechanism):
//
//   - cgroup: the child runs in its own transient cgroup v2 scope, created with
//     `systemd-run --user --scope -p MemoryMax=… -p MemorySwapMax=0 -p TasksMax=…`. When the scope exceeds its
//     memory the kernel's out-of-memory killer kills the process of the scope using the most memory — the child
//     itself (SIGKILL, exit 137) or one of its descendants (an indexer an adapter started), in which case the
//     child lives on and sees its own child die (the scope gets OOMPolicy=continue, so systemd does not stop it
//     either). The supervisor does not add a kill of its own: it counts the kernel's kills from the scope's
//     memory.events and reads memory.peak while the scope runs.
//   - rlimit: `prlimit --as=… --nproc=…` (an address-space limit: allocation fails inside the child), plus
//     polling of the resident memory of the child's process group and its descendants. Over MemoryMax the
//     supervisor does what the kernel would: it kills the process using the most memory, which ends the run
//     only when that process is the child itself. RLIMIT_NPROC counts every process of the user, not just the
//     child's.
//   - none: no limits were asked for, or no mechanism is available; the deadline still applies.
//
// `scripts/limit-run.sh` uses the same two mechanisms; `XDRCHECK_LIMIT_MECHANISM=cgroup|rlimit|none` forces one.
//
// The child is the leader of a new process group. On timeout, cancellation or a memory kill the whole group is
// killed (and, under a cgroup, the whole scope through cgroup.kill); after the child exits, whatever is left of
// its group is killed too, so no process outlives the run. Output is captured as bounded tails.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Mechanism is how limits are enforced.
type Mechanism string

const (
	Auto   Mechanism = ""
	Cgroup Mechanism = "cgroup"
	Rlimit Mechanism = "rlimit"
	None   Mechanism = "none"
)

// Limits for one child. Zero values mean "no limit".
type Limits struct {
	Deadline        time.Duration
	MemoryMax       int64 // bytes
	TasksMax        int   // processes and threads (cgroup) or user processes (rlimit)
	AddressSpaceMax int64 // bytes; under rlimit it defaults to MemoryMax plus AddressSpaceReserve

	// Not applied yet: carried so callers can state them now; a later change sets them as rlimits.
	CPUSeconds  int   // RLIMIT_CPU
	NoFile      int   // RLIMIT_NOFILE
	FileSizeMax int64 // RLIMIT_FSIZE, bytes
}

// AddressSpaceReserve is the address space the rlimit mechanism allows beyond MemoryMax by default: runtimes
// reserve address space they never touch (a Go program does not start under about 1 GiB), so a limit equal to
// the memory cap would stop them before they run. The resident cap itself is enforced by polling.
const AddressSpaceReserve = 4 << 30

func (l Limits) any() bool { return l.MemoryMax > 0 || l.TasksMax > 0 || l.AddressSpaceMax > 0 }

// Spec describes the child to run.
type Spec struct {
	Path string // looked up in PATH when it has no slash
	Args []string
	Dir  string
	// Env is the child's whole environment. nil means the supervisor's environment; callers should pass an
	// explicit one, since a later change refuses nil.
	Env []string

	Stdin  io.Reader // nil means /dev/null
	Stdout io.Writer // optional; receives the full output beside the tail
	Stderr io.Writer

	Limits    Limits
	Mechanism Mechanism     // Auto picks the best available
	Grace     time.Duration // on deadline or cancellation, SIGTERM first and SIGKILL after Grace; 0 kills at once
	TailBytes int           // bytes kept of each stream; default 64 KiB
	Name      string        // label for the cgroup scope unit
	Poll      time.Duration // memory sampling interval; default 25 ms

	// Sandbox is the isolation the child should run in; nil: none. Not acted on yet: Start runs the child as
	// it would without it, and a later change wraps the child in it.
	Sandbox *Sandbox
}

// Sandbox describes a child's isolation: a named profile, whether it may reach the network, and the paths it
// sees. Inert for now (see Spec.Sandbox).
type Sandbox struct {
	Profile  string   // the profile name, for example driver, adapter or core
	Network  bool     // false: loopback only
	ReadOnly []string // paths bound read-only
	Writable []string // paths bound read-write
}

// Result is how the child ended.
type Result struct {
	Mechanism Mechanism
	Unit      string // the systemd scope unit, under the cgroup mechanism

	ExitCode int            // exit status, or 128+signal when the child died of a signal
	Signal   syscall.Signal // 0 unless the child died of a signal

	TimedOut     bool // the deadline expired and the supervisor killed the group
	Canceled     bool // the context was canceled and the supervisor killed the group
	MemoryCapHit bool // the child itself was killed for its group exceeding MemoryMax
	OOMKills     int  // processes of the group killed for MemoryMax: the scope's memory.events oom_kill, or the poller's kills

	Wall           time.Duration
	PeakRSSBytes   int64 // the child's own peak resident set (getrusage), when available
	GroupPeakBytes int64 // the scope's memory.peak, or the polled peak RSS of the process group; 0 if unknown

	Stdout, Stderr Tail
	Notes          []string
}

// Tail is the end of an output stream.
type Tail struct {
	Data  []byte // the last TailBytes bytes
	Total int64  // bytes written in all
}

// Truncated reports whether bytes were dropped from the front.
func (t Tail) Truncated() bool { return t.Total > int64(len(t.Data)) }

// Child is a running child.
type Child struct {
	cmd     *exec.Cmd
	spec    Spec
	mech    Mechanism
	unit    string
	pgid    int
	start   time.Time
	outs    []*os.File // read ends of stdout and stderr pipes
	stdinW  *os.File
	copies  sync.WaitGroup
	stdout  *tail
	stderr  *tail
	mon     *monitor
	killReq chan string
	done    chan struct{}
	result  Result
}

// Run starts the child and waits for it.
func Run(ctx context.Context, spec Spec) (Result, error) {
	c, err := Start(ctx, spec)
	if err != nil {
		return Result{}, err
	}
	return c.Wait(), nil
}

var unitSeq struct {
	sync.Mutex
	n int
}

// live maps the process ID of every running child to its supervisor, for OOMKills.
var live sync.Map

// OOMKills returns how many processes of the group of the running child with process ID pid have been killed
// for its memory cap so far — by the kernel under the cgroup mechanism, by the supervisor under polling — and
// false when pid is not a child this package supervises (or it has ended). A caller that drives a long-lived
// child (an adapter) compares the count before and after one request to learn whether memory ran out during it.
func OOMKills(pid int) (int, bool) {
	v, ok := live.Load(pid)
	if !ok {
		return 0, false
	}
	return v.(*Child).OOMKills(), true
}

// OOMKills is the child's group's memory kills so far (see the package function), sampled now.
func (c *Child) OOMKills() int {
	c.mon.sample()
	c.mon.mu.Lock()
	defer c.mon.mu.Unlock()
	return c.mon.oomKills
}

// Start starts the child under its limits and returns at once. The deadline and ctx are enforced from now.
func Start(ctx context.Context, spec Spec) (*Child, error) {
	path, err := exec.LookPath(spec.Path)
	if err != nil {
		return nil, err
	}
	mech := spec.Mechanism
	if mech == Auto {
		mech = None
		if spec.Limits.any() {
			mech = Available()
		}
	}
	if spec.TailBytes <= 0 {
		spec.TailBytes = 64 << 10
	}
	if spec.Poll <= 0 {
		spec.Poll = 25 * time.Millisecond
	}

	c := &Child{spec: spec, mech: mech, killReq: make(chan string, 1), done: make(chan struct{})}
	argv := append([]string{path}, spec.Args...)
	switch mech {
	case Cgroup:
		unitSeq.Lock()
		unitSeq.n++
		c.unit = fmt.Sprintf("xdrcheck-%s-%d-%d", unitLabel(spec.Name), os.Getpid(), unitSeq.n)
		unitSeq.Unlock()
		pre := []string{"systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit=" + c.unit}
		if l := spec.Limits.MemoryMax; l > 0 {
			// OOMPolicy=continue: systemd's default for a scope is to stop it (SIGTERM to every process) once the
			// kernel has killed any one of them, which would end the child for a descendant's overflow.
			pre = append(pre, "-p", "MemoryMax="+strconv.FormatInt(l, 10), "-p", "MemorySwapMax=0", "-p", "OOMPolicy=continue")
		}
		if l := spec.Limits.TasksMax; l > 0 {
			pre = append(pre, "-p", "TasksMax="+strconv.Itoa(l))
		}
		pre = append(pre, "--")
		if l := spec.Limits.AddressSpaceMax; l > 0 {
			pre = append(pre, "prlimit", "--as="+strconv.FormatInt(l, 10), "--")
		}
		argv = append(pre, argv...)
		spec.Env = withBusEnv(spec.Env)
	case Rlimit:
		var pre []string
		as := spec.Limits.AddressSpaceMax
		if as == 0 {
			if m := spec.Limits.MemoryMax; m > 0 {
				as = m + AddressSpaceReserve
			}
		}
		if as > 0 {
			pre = append(pre, "--as="+strconv.FormatInt(as, 10))
		}
		if spec.Limits.TasksMax > 0 {
			pre = append(pre, "--nproc="+strconv.Itoa(spec.Limits.TasksMax))
		}
		if len(pre) > 0 {
			argv = append(append(append([]string{"prlimit"}, pre...), "--"), argv...)
		}
	case None:
	default:
		return nil, fmt.Errorf("proc: unknown mechanism %q", mech)
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}

	cmd := &exec.Cmd{Path: bin, Args: argv, Dir: spec.Dir, Env: spec.Env}
	cmd.SysProcAttr = childAttr()
	c.cmd = cmd
	c.stdout = newTail(spec.TailBytes)
	c.stderr = newTail(spec.TailBytes)

	var childEnds []*os.File
	closeAll := func() {
		for _, f := range append(childEnds, c.outs...) {
			f.Close()
		}
		if c.stdinW != nil {
			c.stdinW.Close()
		}
	}
	if f, ok := spec.Stdin.(*os.File); ok {
		cmd.Stdin = f
	} else if spec.Stdin != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		cmd.Stdin, c.stdinW = r, w
		childEnds = append(childEnds, r)
	}
	for _, s := range []struct {
		set  func(*os.File)
		tail *tail
		tee  io.Writer
	}{
		{func(f *os.File) { cmd.Stdout = f }, c.stdout, spec.Stdout},
		{func(f *os.File) { cmd.Stderr = f }, c.stderr, spec.Stderr},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll()
			return nil, err
		}
		s.set(w)
		childEnds = append(childEnds, w)
		c.outs = append(c.outs, r)
		c.copies.Add(1)
		go func(r *os.File, t *tail, tee io.Writer) {
			defer c.copies.Done()
			copyTail(r, t, tee)
		}(r, s.tail, s.tee)
	}

	c.start = time.Now()
	if err := cmd.Start(); err != nil {
		closeAll()
		return nil, err
	}
	for _, f := range childEnds {
		f.Close()
	}
	c.pgid = cmd.Process.Pid
	if c.stdinW != nil {
		go func() {
			io.Copy(c.stdinW, spec.Stdin)
			c.stdinW.Close()
		}()
	}
	c.mon = startMonitor(c)
	live.Store(c.pgid, c)
	go c.supervise(ctx)
	return c, nil
}

// Pid returns the child's process ID (also its process group ID).
func (c *Child) Pid() int { return c.pgid }

// Kill kills the child's whole group now. The reason is added to the result's notes.
func (c *Child) Kill(reason string) {
	select {
	case c.killReq <- reason:
	default:
	}
}

// Wait waits for the child and returns how it ended. It may be called more than once.
func (c *Child) Wait() Result {
	<-c.done
	return c.result
}

// Done is closed when the child has ended and its result is ready.
func (c *Child) Done() <-chan struct{} { return c.done }

func (c *Child) supervise(ctx context.Context) {
	exited := make(chan error, 1)
	go func() { exited <- c.cmd.Wait() }()

	var deadline <-chan time.Time
	if d := c.spec.Limits.Deadline; d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		deadline = t.C
	}
	res := &c.result
	var waitErr error
	killed := false // the supervisor killed the group on request
	select {
	case waitErr = <-exited:
	case <-deadline:
		res.TimedOut = true
		waitErr = c.terminate(exited, c.spec.Grace)
	case <-ctx.Done():
		res.Canceled = true
		waitErr = c.terminate(exited, c.spec.Grace)
	case reason := <-c.mon.overLimit:
		res.MemoryCapHit = true
		res.Notes = append(res.Notes, reason)
		waitErr = c.terminate(exited, 0)
	case reason := <-c.killReq:
		res.Notes = append(res.Notes, "killed by the supervisor: "+reason)
		killed = true
		waitErr = c.terminate(exited, 0)
	}
	res.Wall = time.Since(c.start)

	// Read the scope's counters before it disappears, then remove what is left of the group.
	c.mon.stop()
	c.killGroup(syscall.SIGKILL)
	if c.stdinW != nil {
		c.stdinW.Close()
	}
	outsDone := make(chan struct{})
	go func() { c.copies.Wait(); close(outsDone) }()
	select {
	case <-outsDone:
	case <-time.After(2 * time.Second):
		res.Notes = append(res.Notes, "output still open 2 s after the group was killed; tails cut")
		for _, f := range c.outs {
			f.Close()
		}
		<-outsDone
	}

	res.Mechanism, res.Unit = c.mech, c.unit
	res.Stdout, res.Stderr = c.stdout.snapshot(), c.stderr.snapshot()
	c.mon.fill(res)
	ps := c.cmd.ProcessState
	if ps == nil {
		res.ExitCode = -1
		res.Notes = append(res.Notes, fmt.Sprintf("wait failed: %v", waitErr))
	} else {
		ws, _ := ps.Sys().(syscall.WaitStatus)
		switch {
		case ws.Signaled():
			res.Signal = ws.Signal()
			res.ExitCode = 128 + int(res.Signal)
		default:
			res.ExitCode = ws.ExitStatus()
		}
		if ru, ok := ps.SysUsage().(*syscall.Rusage); ok && ru != nil {
			res.PeakRSSBytes = ru.Maxrss * 1024
		}
	}
	// The child ended for memory when it died of a SIGKILL nobody here sent — or exited 137, as a wrapper script
	// does when the program it runs is killed — and its group recorded a memory kill; under a cgroup also when
	// systemd removed the scope before its final memory.events could be read (it stops a scope at once after an
	// OOM kill of its main process). A descendant killed while the child lives on is only counted in OOMKills.
	sigkilled := res.Signal == syscall.SIGKILL || res.ExitCode == 128+int(syscall.SIGKILL)
	if c.spec.Limits.MemoryMax > 0 && !res.MemoryCapHit && sigkilled && !res.TimedOut && !res.Canceled && !killed {
		switch {
		case res.OOMKills > 0:
			res.MemoryCapHit = true
		case c.mech == Cgroup && res.Signal == syscall.SIGKILL && !c.mon.lastEventsRead:
			res.MemoryCapHit = true
			res.Notes = append(res.Notes, "memory cap inferred from SIGKILL; memory.events was not readable")
		}
	}
	live.Delete(c.pgid)
	close(c.done)
}

// terminate stops the group (SIGTERM, then SIGKILL after grace) and waits for the child.
func (c *Child) terminate(exited <-chan error, grace time.Duration) error {
	if grace > 0 {
		c.killGroup(syscall.SIGTERM)
		select {
		case err := <-exited:
			return err
		case <-time.After(grace):
		}
	}
	c.killGroup(syscall.SIGKILL)
	return <-exited
}

// killGroup signals the process group and, under a cgroup, kills every process in the scope.
func (c *Child) killGroup(sig syscall.Signal) {
	syscall.Kill(-c.pgid, sig)
	if sig == syscall.SIGKILL {
		if dir := c.mon.cgroupDir(); dir != "" {
			os.WriteFile(dir+"/cgroup.kill", []byte("1"), 0)
		}
	}
}

var (
	probeOnce sync.Once
	probed    Mechanism
)

// Available returns the mechanism Auto picks on this host: XDRCHECK_LIMIT_MECHANISM if set, else cgroup when a
// transient user scope with a memory limit (and OOMPolicy) can be created, else rlimit when prlimit exists, else none.
func Available() Mechanism {
	probeOnce.Do(func() {
		switch m := Mechanism(os.Getenv("XDRCHECK_LIMIT_MECHANISM")); m {
		case Cgroup, Rlimit, None:
			probed = m
			return
		}
		if _, err := exec.LookPath("systemd-run"); err == nil {
			probe := exec.Command("systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", "MemoryMax=64M", "-p", "OOMPolicy=continue", "true")
			if probe.Run() == nil {
				probed = Cgroup
				return
			}
		}
		if _, err := exec.LookPath("prlimit"); err == nil {
			probed = Rlimit
			return
		}
		probed = None
	})
	return probed
}

// withBusEnv adds the variables systemd-run needs to reach the user manager to an explicit environment that
// lacks them. A scope runs its command in-process, so the child sees them too.
func withBusEnv(env []string) []string {
	if env == nil {
		return nil
	}
	for _, k := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		v, ok := os.LookupEnv(k)
		if !ok {
			continue
		}
		present := false
		for _, e := range env {
			if strings.HasPrefix(e, k+"=") {
				present = true
				break
			}
		}
		if !present {
			env = append(env[:len(env):len(env)], k+"="+v)
		}
	}
	return env
}

func unitLabel(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "child"
	}
	return b.String()
}

// tail keeps the last n bytes written to it.
type tail struct {
	mu    sync.Mutex
	n     int
	buf   []byte
	total int64
}

func newTail(n int) *tail { return &tail{n: n} }

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total += int64(len(p))
	if len(p) >= t.n {
		t.buf = append(t.buf[:0], p[len(p)-t.n:]...)
		return len(p), nil
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.n {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.n:]...)
	}
	return len(p), nil
}

func (t *tail) snapshot() Tail {
	t.mu.Lock()
	defer t.mu.Unlock()
	data := t.buf
	if len(data) > t.n {
		data = data[len(data)-t.n:]
	}
	return Tail{Data: bytes.Clone(data), Total: t.total}
}

// copyTail drains r into the tail and, if given, the tee. A failing tee is dropped; the tail keeps draining.
func copyTail(r io.Reader, t *tail, tee io.Writer) {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			t.Write(buf[:n])
			if tee != nil {
				if _, werr := tee.Write(buf[:n]); werr != nil {
					tee = nil
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				t.Write([]byte(fmt.Sprintf("\n[proc: read error: %v]\n", err)))
			}
			return
		}
	}
}
