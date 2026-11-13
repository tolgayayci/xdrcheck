//go:build unix

package adapterkit

// RunChild runs an indexer as a child process for one ingest, the way an adapter whose indexer is a separate
// program needs it: in its own process group, killed whole at a deadline, with the end of its stderr kept for
// the report. It never reads the child's output for meaning; the adapter decides the status from the indexer's
// own progress marker and exit record (docs/adapter-protocol.md §4.3).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ChildSpec is one run of an indexer process.
type ChildSpec struct {
	Path     string   // looked up in PATH when it has no slash
	Args     []string // arguments after the program name
	Env      []string // nil inherits the adapter's environment; pass a scrubbed list
	Dir      string
	Deadline time.Duration // 0: none. At the deadline the whole process group is killed with SIGKILL
	// TailBytes is how much of the end of stderr to keep; default 3000, under the protocol's 4000-character cap
	// on signals.stderr_tail.
	TailBytes int
	Stdout    io.Writer // optional: receives stdout in full; nil discards it
}

// ChildResult is how the child ended.
type ChildResult struct {
	ExitCode int            // exit status, or 128+signal when the child died of a signal
	Signal   syscall.Signal // 0 unless the child died of a signal
	TimedOut bool           // the deadline passed and the group was killed
	Wall     time.Duration
	Stderr   string // the last TailBytes bytes of stderr
}

// TermSignal is the signal's protocol name (SIGKILL, SIGSEGV, …), or "" when the child exited on its own.
func (r ChildResult) TermSignal() string {
	if r.Signal == 0 {
		return ""
	}
	return SignalName(r.Signal)
}

// SignalName names a signal as the protocol's term_signal does.
func SignalName(s syscall.Signal) string {
	switch s {
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGBUS:
		return "SIGBUS"
	}
	return fmt.Sprintf("SIG%d", int(s))
}

// RunChild starts the child and waits for it to end, for the deadline, or for ctx. An error means it could not
// be started.
func RunChild(ctx context.Context, spec ChildSpec) (ChildResult, error) {
	if spec.TailBytes <= 0 {
		spec.TailBytes = 3000
	}
	cmd := exec.Command(spec.Path, spec.Args...)
	cmd.Env, cmd.Dir, cmd.Stdout = spec.Env, spec.Dir, spec.Stdout
	tail := &tailWriter{n: spec.TailBytes}
	cmd.Stderr = tail
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second // a grandchild holding stderr open does not hold up the result
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return ChildResult{}, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var deadline <-chan time.Time
	if spec.Deadline > 0 {
		t := time.NewTimer(spec.Deadline)
		defer t.Stop()
		deadline = t.C
	}
	var res ChildResult
	var werr error
	select {
	case werr = <-exited:
	case <-deadline:
		res.TimedOut = true
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		werr = <-exited
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		werr = <-exited
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // anything the child left running in its group
	res.Wall = time.Since(start)
	res.Stderr = tail.String()
	var ee *exec.ExitError
	if werr != nil && !errors.As(werr, &ee) && !errors.Is(werr, exec.ErrWaitDelay) {
		return res, werr
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		res.Signal = ws.Signal()
		res.ExitCode = 128 + int(res.Signal)
	} else {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	return res, nil
}

// tailWriter keeps the last n bytes written to it.
type tailWriter struct {
	mu  sync.Mutex
	n   int
	buf []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.n {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.n:]...)
	}
	return len(p), nil
}

func (t *tailWriter) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
