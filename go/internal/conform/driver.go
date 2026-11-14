package conform

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// Limits apply to every driver process. A long-lived driver process serves many cells, so Timeout is enforced
// per request by the orchestrator, while the memory caps hold for the process as a whole: a cell that breaks
// one kills the process, and that cell is recorded as crash.
type Limits struct {
	Timeout         time.Duration // per request (describe, run); default 20 s
	MemoryMax       int64         // bytes; cgroup memory.max, or polled process-group RSS (proc package)
	AddressSpaceMax int64         // bytes; RLIMIT_AS
	Mechanism       proc.Mechanism
}

// DefaultTimeout is the per-request timeout when Limits.Timeout is zero; BulkTimeout the default for the
// bulk tier's larger ledgers.
const (
	DefaultTimeout = 20 * time.Second
	BulkTimeout    = 120 * time.Second
)

func (l Limits) timeout() time.Duration {
	if l.Timeout <= 0 {
		return DefaultTimeout
	}
	return l.Timeout
}

// RequestTimeout is the timeout of one run request whose input is the given number of bytes: the base timeout,
// plus the base timeout again for every MiB of input. Decoding, parsing every envelope and projecting a ledger
// all grow with its size, and some SDKs need seconds per MiB, so a fixed timeout would turn a large valid
// ledger into a crash on a loaded machine; a small input keeps the base timeout, so a hang is still caught
// quickly.
func (l Limits) RequestTimeout(inputBytes int64) time.Duration {
	base := l.timeout()
	if inputBytes <= 0 {
		return base
	}
	return base + time.Duration(float64(base)*float64(inputBytes)/float64(1<<20))
}

// MaxLine is the longest response line accepted (an L2 projection of a large ledger is large).
const MaxLine = 256 << 20

const stderrKeep = 4 << 10

// Crash is how the orchestrator saw a driver process fail on a request: it died, or it was killed for its
// timeout or memory cap.
type Crash struct {
	Reason         string   `json:"reason"` // timeout, out_of_memory, process_died
	ExitCode       int      `json:"exit_code"`
	Signal         string   `json:"signal,omitempty"`
	TimedOut       bool     `json:"timed_out,omitempty"`
	MemoryCapHit   bool     `json:"memory_cap_hit,omitempty"`
	Mechanism      string   `json:"mechanism"`
	StderrTail     string   `json:"stderr_tail,omitempty"` // the last 4 KiB written since the request was sent
	WallMS         float64  `json:"wall_ms"`               // the process's whole life
	PeakRSSBytes   int64    `json:"peak_rss_bytes,omitempty"`
	GroupPeakBytes int64    `json:"group_peak_bytes,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

type lineMsg struct {
	line []byte
	err  error
}

// driverProc is one running driver process.
type driverProc struct {
	col    *Column
	seq    int // process number within the column, from 1
	child  *proc.Child
	stdin  *os.File
	lines  chan lineMsg
	stderr *stderrLog
	limits Limits
	nextID int
	v      *Validator

	Describe    *Describe
	DescribeRaw json.RawMessage
}

// startDriver starts the column's driver and asks for its describe. A failure to start, a crash during
// describe or an invalid describe is returned as an error; the process is gone afterwards.
func startDriver(ctx context.Context, sets *Sets, col *Column, limits Limits, v *Validator, seq int) (*driverProc, error) {
	dir := sets.AbsDir(col)
	cmd := col.Run[0]
	if strings.Contains(cmd, "/") && !filepath.IsAbs(cmd) {
		cmd = filepath.Join(dir, cmd)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW := io.Pipe()
	d := &driverProc{col: col, seq: seq, stdin: stdinW, lines: make(chan lineMsg, 16), stderr: &stderrLog{}, limits: limits, nextID: 1, v: v}
	env := append(os.Environ(), "XDRCHECK_COLUMN="+col.ID, "XDRCHECK_CACHE_DIR="+CacheDir(col))
	child, err := proc.Start(ctx, proc.Spec{
		Path:      cmd,
		Args:      col.Run[1:],
		Dir:       dir,
		Env:       env,
		Stdin:     stdinR,
		Stdout:    outW,
		Stderr:    d.stderr,
		Limits:    proc.Limits{MemoryMax: limits.MemoryMax, AddressSpaceMax: limits.AddressSpaceMax},
		Mechanism: limits.Mechanism,
		TailBytes: stderrKeep,
		Name:      "conform-" + col.ID,
	})
	stdinR.Close()
	if err != nil {
		stdinW.Close()
		outW.Close()
		return nil, fmt.Errorf("column %s: cannot start the driver %q in %s: %w", col.ID, cmd, dir, err)
	}
	d.child = child
	go func() {
		<-child.Done()
		outW.Close()
	}()
	go d.readLines(outR)

	id := d.newID()
	line, crash, err := d.roundTrip(ctx, simpleRequest{XDRCHECK: ProtocolTag, ID: id, Op: "describe"}, d.limits.timeout())
	if err == nil && crash != nil {
		err = fmt.Errorf("the driver failed during describe: %s (exit %d%s)%s", crash.Reason, crash.ExitCode, sigSuffix(crash.Signal), stderrSuffix(crash.StderrTail))
	}
	if err == nil {
		d.Describe, err = v.ParseDescribe(line, id)
	}
	if err == nil {
		err = checkDescribe(col, d.Describe)
	}
	if err != nil {
		d.kill("describe failed")
		return nil, fmt.Errorf("column %s: %w", col.ID, err)
	}
	d.DescribeRaw = json.RawMessage(bytes.Clone(line))
	return d, nil
}

// checkDescribe holds a driver to its column: the SDK it reports, read from the installed package, must be the
// pinned one, and the column's profile must be one the driver offers.
func checkDescribe(col *Column, d *Describe) error {
	var errs []string
	if got := *d.SDK.Ecosystem; got != col.Ecosystem {
		errs = append(errs, fmt.Sprintf("sdk.ecosystem %q, column says %q", got, col.Ecosystem))
	}
	if got := *d.SDK.Package; got != col.Package {
		errs = append(errs, fmt.Sprintf("sdk.package %q, column says %q", got, col.Package))
	}
	// A column built from a checkout (--sdk) reports the checkout's own version, whatever it is.
	if got := *d.SDK.Version; got != col.Version && col.Source == "" {
		errs = append(errs, fmt.Sprintf("sdk.version %q, pinned %q", got, col.Version))
	}
	if col.Profile != "" {
		found := false
		for _, p := range d.Decode.Profiles {
			found = found || p == col.Profile
		}
		if !found {
			errs = append(errs, fmt.Sprintf("profile %q is not among the driver's decode.profiles %v", col.Profile, d.Decode.Profiles))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("describe does not match the column (integrity): %s", strings.Join(errs, "; "))
	}
	return nil
}

func (d *driverProc) newID() int {
	id := d.nextID
	d.nextID++
	return id
}

// readLines splits the driver's stdout into lines. It never blocks the supervisor's copy: a driver that
// writes more unanswered lines than the buffer holds is a protocol error.
func (d *driverProc) readLines(r io.Reader) {
	defer close(d.lines)
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxLine {
			tooLong = true
		} else {
			buf = append(buf, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(buf) > 0 || tooLong {
			msg := lineMsg{line: bytes.TrimRight(buf, "\r\n")}
			if tooLong {
				msg = lineMsg{err: protoErr(nil, "a response line is longer than %d bytes", MaxLine)}
			} else if err != nil {
				msg.err = protoErr(msg.line, "the last output line has no newline")
			}
			select {
			case d.lines <- msg:
			default:
				// The buffer is full of lines nobody asked for; the next request already reports the first.
			}
		}
		buf, tooLong = nil, false
		if err != nil {
			return
		}
	}
}

// roundTrip sends one request and waits for one line. It returns the line; or a crash when the process died or
// was killed (timeout, memory) before answering; or an error when the context ended or the output broke the
// protocol.
func (d *driverProc) roundTrip(ctx context.Context, req any, timeout time.Duration) ([]byte, *Crash, error) {
	// A line that arrived before the request is one the driver should not have written.
	select {
	case msg, ok := <-d.lines:
		if ok {
			return nil, nil, protoErr(msg.line, "the driver wrote a line nobody asked for")
		}
		return nil, d.crash(false), nil
	default:
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	d.stderr.mark()
	d.stdin.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := d.stdin.Write(append(b, '\n')); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			d.child.Kill(fmt.Sprintf("did not read its request within the %s timeout", timeout))
			return nil, d.crash(true), nil
		}
		// The process closed its stdin, so it is gone or going: give it the timeout to exit.
		select {
		case <-d.child.Done():
		case <-time.After(timeout):
			d.child.Kill("closed its stdin and did not exit")
		}
		return nil, d.crash(false), nil
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case msg, ok := <-d.lines:
		if !ok {
			return nil, d.crash(false), nil
		}
		if msg.err != nil {
			return nil, nil, msg.err
		}
		return msg.line, nil, nil
	case <-t.C:
		d.child.Kill(fmt.Sprintf("no answer within the %s timeout", timeout))
		<-d.child.Done()
		return nil, d.crash(true), nil
	case <-ctx.Done():
		d.kill("canceled")
		return nil, nil, ctx.Err()
	}
}

func (d *driverProc) crash(timedOut bool) *Crash {
	<-d.child.Done()
	r := d.child.Wait()
	c := &Crash{
		ExitCode:       r.ExitCode,
		TimedOut:       timedOut || r.TimedOut,
		MemoryCapHit:   r.MemoryCapHit,
		Mechanism:      string(r.Mechanism),
		StderrTail:     d.stderr.since(),
		WallMS:         float64(r.Wall.Microseconds()) / 1000,
		PeakRSSBytes:   r.PeakRSSBytes,
		GroupPeakBytes: r.GroupPeakBytes,
		Notes:          r.Notes,
	}
	c.Signal = sigName(r.Signal)
	switch {
	case c.TimedOut:
		c.Reason = "timeout"
	case c.MemoryCapHit:
		c.Reason = "out_of_memory"
	default:
		c.Reason = "process_died"
	}
	return c
}

// run sends one run request with the given timeout and returns the validated response, or the crash.
func (d *driverProc) run(ctx context.Context, req *RunRequest, timeout time.Duration) (*RunResponse, []byte, *Crash, error) {
	req.XDRCHECK, req.Op, req.ID = ProtocolTag, "run", d.newID()
	line, crash, err := d.roundTrip(ctx, req, timeout)
	if err != nil || crash != nil {
		return nil, nil, crash, err
	}
	resp, err := d.v.ParseRun(line, req)
	if err != nil {
		return nil, line, nil, err
	}
	return resp, bytes.Clone(line), nil, nil
}

// shutdown asks the driver to exit and waits for it; a driver that does not comply is killed.
func (d *driverProc) shutdown(ctx context.Context) error {
	select {
	case <-d.child.Done():
		return nil
	default:
	}
	id := d.newID()
	line, crash, err := d.roundTrip(ctx, simpleRequest{XDRCHECK: ProtocolTag, ID: id, Op: "shutdown"}, d.limits.timeout())
	switch {
	case err != nil:
	case crash != nil:
		err = fmt.Errorf("the driver died during shutdown: %s (exit %d%s)", crash.Reason, crash.ExitCode, sigSuffix(crash.Signal))
	default:
		err = d.v.ParseShutdown(line, id)
	}
	d.stdin.Close()
	select {
	case <-d.child.Done():
	case <-time.After(5 * time.Second):
		d.child.Kill("did not exit after shutdown")
		<-d.child.Done()
	}
	return err
}

func (d *driverProc) kill(reason string) {
	d.child.Kill(reason)
	<-d.child.Done()
	d.stdin.Close()
}

func sigName(s syscall.Signal) string {
	if s == 0 {
		return ""
	}
	return s.String()
}

// alive reports whether the process is still running.
func (d *driverProc) alive() bool {
	select {
	case <-d.child.Done():
		return false
	default:
		return true
	}
}

func sigSuffix(s string) string {
	if s == "" {
		return ""
	}
	return ", " + s
}

func stderrSuffix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 500 {
		s = "…" + s[len(s)-500:]
	}
	return "; stderr: " + s
}

// stderrLog keeps what a driver wrote to stderr since the last mark, at most 4 KiB: the first 1 KiB (where a
// runtime's fatal error line is) and the last 3 KiB (where a panic's own frame is).
type stderrLog struct {
	mu    sync.Mutex
	head  []byte
	tail  []byte
	total int64
}

const stderrHead = 1 << 10

func (s *stderrLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += int64(len(p))
	q := p
	if n := stderrHead - len(s.head); n > 0 {
		if n > len(q) {
			n = len(q)
		}
		s.head = append(s.head, q[:n]...)
		q = q[n:]
	}
	s.tail = append(s.tail, q...)
	if keep := stderrKeep - stderrHead; len(s.tail) > 2*keep {
		s.tail = append(s.tail[:0], s.tail[len(s.tail)-keep:]...)
	}
	return len(p), nil
}

func (s *stderrLog) mark() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.head, s.tail, s.total = s.head[:0], s.tail[:0], 0
}

func (s *stderrLog) since() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tail := s.tail
	if keep := stderrKeep - stderrHead; len(tail) > keep {
		tail = tail[len(tail)-keep:]
	}
	if cut := s.total - int64(len(s.head)) - int64(len(tail)); cut > 0 {
		return fmt.Sprintf("%s\n[… %d bytes cut …]\n%s", s.head, cut, tail)
	}
	return string(s.head) + string(tail)
}

// CacheDir is the per-driver-directory package cache: $XDRCHECK_CACHE (default ~/.cache/xdrcheck) /conform/<dir with
// slashes as dashes>. Columns that share a driver directory share its cache. A column built from an SDK
// checkout (Source) has a cache of its own, <dir>@source-<key>, so the pinned build is never disturbed.
func CacheDir(col *Column) string {
	name := strings.ReplaceAll(filepath.ToSlash(filepath.Clean(col.Dir)), "/", "-")
	if col.Source != "" {
		name += "@source-" + sourceKey(col.Source, col.Dir)
	}
	return filepath.Join(cacheBase(), "conform", name)
}

// cacheBase is $XDRCHECK_CACHE, default ~/.cache/xdrcheck.
func cacheBase() string {
	if base := os.Getenv("XDRCHECK_CACHE"); base != "" {
		return base
	}
	if d, ok := userdir.HomeCache(); ok {
		return d
	}
	return filepath.Join(os.TempDir(), "xdrcheck-cache")
}

// DescribeColumn starts a column's driver, returns its validated describe line and shuts it down.
func DescribeColumn(ctx context.Context, sets *Sets, col *Column, limits Limits, v *Validator) (json.RawMessage, error) {
	d, err := startDriver(ctx, sets, col, limits, v, 1)
	if err != nil {
		return nil, err
	}
	if err := d.shutdown(ctx); err != nil {
		return nil, fmt.Errorf("column %s: shutdown: %w", col.ID, err)
	}
	return d.DescribeRaw, nil
}
