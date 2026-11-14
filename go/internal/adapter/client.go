// Package adapter is the harness side of the replay adapter protocol `xcc.adapter/1`: a client that runs an
// adapter process under the process supervisor (internal/proc) and talks newline-delimited JSON to it over
// stdio — describe, prepare, ingest, observe, teardown — and a selftest that checks an adapter's protocol
// conformance without scoring its indexer.
//
// Every message in both directions is validated against the frozen schemas (corpus/schema/adapter-protocol and
// observation, embedded byte for byte in adapterkit) with a small JSON Schema validator, then decoded strictly into the
// types of this package. A response that breaks the protocol is a *ProtocolError; an error response is an
// *AdapterError; a call that is not answered within its deadline kills the adapter's whole process group and
// returns a *TimeoutError; an adapter that exits mid-call returns an *ExitError. Only an *AdapterError leaves
// the client usable. stderr is passed through as logs and never parsed.
package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
)

// Deadlines are the per-call limits (adapter-protocol.md §6). Ingest is bounded by its own deadline_ms plus
// IngestGrace: the adapter must answer timeout by deadline_ms and gets IngestGrace more before it is killed.
type Deadlines struct {
	Describe, Prepare, Observe, Teardown time.Duration
	IngestGrace                          time.Duration
	Exit                                 time.Duration // after stdin is closed, before the group is killed
}

// DefaultDeadlines are the protocol's defaults.
var DefaultDeadlines = Deadlines{
	Describe:    10 * time.Second,
	Prepare:     10 * time.Minute,
	Observe:     60 * time.Second,
	Teardown:    60 * time.Second,
	IngestGrace: 10 * time.Second,
	Exit:        10 * time.Second,
}

// Config says how to start an adapter.
type Config struct {
	Argv []string // the user's command line; the harness adds no arguments
	Dir  string
	Env  []string // nil means the harness's environment

	Limits    proc.Limits // memory and process caps for the adapter's group; Deadline is ignored (calls have their own)
	Mechanism proc.Mechanism
	Name      string // label for the supervisor's scope

	Deadlines    Deadlines // zero fields take DefaultDeadlines
	MaxLineBytes int       // longest response line accepted; default 256 MiB

	Stderr     io.Writer // the adapter's logs, stored with the report; never parsed
	Transcript io.Writer // optional: every line sent ("> ") and received ("< ")
}

// TimeoutError is a call the adapter did not answer in time; the client killed its process group.
type TimeoutError struct {
	Method string
	After  time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("adapter did not answer %s within %s; its process group was killed", e.Method, e.After)
}

// ExitError is an adapter process that ended while a call was pending (or before it could be sent).
type ExitError struct {
	Method string
	Result proc.Result
}

func (e *ExitError) Error() string {
	how := fmt.Sprintf("exit code %d", e.Result.ExitCode)
	if e.Result.Signal != 0 {
		how = "signal " + e.Result.Signal.String()
	}
	if e.Result.MemoryCapHit {
		how += " (memory cap)"
	}
	return fmt.Sprintf("adapter process ended during %s: %s", e.Method, how)
}

// ErrClosed is returned by calls on a client that was closed or killed.
var ErrClosed = errors.New("adapter client is closed")

type lineMsg struct {
	data []byte
	err  error
}

// Client is one running adapter process. Calls are strictly sequential (one request, one response); the client
// is not safe for concurrent use.
type Client struct {
	cfg     Config
	child   *proc.Child
	stdin   *os.File
	lines   chan lineMsg
	nextID  int64
	broken  error // set once the protocol cannot continue
	offered []string
	mu      sync.Mutex // guards transcript writes
	closed  bool
}

// Start starts the adapter process.
func Start(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.Argv) == 0 {
		return nil, errors.New("adapter: empty command")
	}
	d := &cfg.Deadlines
	def := DefaultDeadlines
	for _, p := range []struct{ v, def *time.Duration }{{&d.Describe, &def.Describe}, {&d.Prepare, &def.Prepare}, {&d.Observe, &def.Observe}, {&d.Teardown, &def.Teardown}, {&d.IngestGrace, &def.IngestGrace}, {&d.Exit, &def.Exit}} {
		if *p.v <= 0 {
			*p.v = *p.def
		}
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = 256 << 20
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW := io.Pipe()
	limits := cfg.Limits
	limits.Deadline = 0
	name := cfg.Name
	if name == "" {
		name = "adapter"
	}
	child, err := proc.Start(context.WithoutCancel(ctx), proc.Spec{
		Path: cfg.Argv[0], Args: cfg.Argv[1:], Dir: cfg.Dir, Env: cfg.Env,
		Stdin: inR, Stdout: outW, Stderr: cfg.Stderr,
		Limits: limits, Mechanism: cfg.Mechanism, Grace: 0, Name: name,
		TailBytes: 64 << 10,
	})
	inR.Close()
	if err != nil {
		inW.Close()
		return nil, err
	}
	c := &Client{cfg: cfg, child: child, stdin: inW, lines: make(chan lineMsg, 4), nextID: 1}
	go func() {
		<-child.Done()
		outW.Close()
	}()
	go c.readLines(outR)
	return c, nil
}

// readLines splits stdout into lines and hands them to the pending call. A line longer than the reader's buffer
// is kept as copies of its fragments and joined once at its end: growing one slice by appending would hold the
// old and the new array at every growth, about twice the line, and a line cut at MaxLineBytes is dropped as soon
// as it passes the cap, never joined.
func (c *Client) readLines(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	defer close(c.lines)
	for {
		var frags [][]byte
		n := 0
		tooLong := false
		var err error
		for {
			var frag []byte
			frag, err = br.ReadSlice('\n')
			if tooLong || n+len(frag) > c.cfg.MaxLineBytes+1 {
				tooLong, frags = true, nil
			} else if len(frag) > 0 {
				frags = append(frags, bytes.Clone(frag))
				n += len(frag)
			}
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if err != nil {
			if n > 0 && !tooLong {
				// A last line without its newline still counts as a line; the framing check flags it.
				c.lines <- lineMsg{data: joinFrags(frags, n), err: io.ErrUnexpectedEOF}
			}
			io.Copy(io.Discard, br)
			return
		}
		if tooLong {
			c.lines <- lineMsg{err: errLineTooLong}
			io.Copy(io.Discard, br) // keep draining so the supervisor's copier never blocks
			return
		}
		line := joinFrags(frags, n)
		c.lines <- lineMsg{data: bytes.TrimSuffix(line, []byte("\n"))}
	}
}

// joinFrags joins a line's fragments of n bytes in all into one slice.
func joinFrags(frags [][]byte, n int) []byte {
	if len(frags) == 1 {
		return frags[0]
	}
	line := make([]byte, 0, n)
	for _, f := range frags {
		line = append(line, f...)
	}
	return line
}

var errLineTooLong = errors.New("line too long")

// Pid is the adapter's process (group) ID.
func (c *Client) Pid() int { return c.child.Pid() }

// Done is closed when the adapter process has ended.
func (c *Client) Done() <-chan struct{} { return c.child.Done() }

// Describe sends describe. It must be the first call; the offered protocol versions are remembered so a
// response that picks another one is a protocol violation.
func (c *Client) Describe(ctx context.Context, p DescribeParams) (*DescribeResult, error) {
	if len(p.ProtocolVersions) == 0 {
		p.ProtocolVersions = []string{Protocol}
	}
	c.offered = p.ProtocolVersions
	var r DescribeResult
	if err := c.call(ctx, MethodDescribe, p, &r, c.cfg.Deadlines.Describe); err != nil {
		return nil, err
	}
	ok := false
	for _, v := range c.offered {
		ok = ok || v == r.ProtocolVersion
	}
	if !ok {
		return nil, c.fail(&ProtocolError{Method: MethodDescribe, ID: c.nextID - 1, Reason: ReasonVersionNotOffered,
			Detail: fmt.Sprintf("protocol_version %q is not one of %v", r.ProtocolVersion, c.offered)})
	}
	return &r, nil
}

// Prepare sends prepare.
func (c *Client) Prepare(ctx context.Context, p PrepareParams) (*PrepareResult, error) {
	var r PrepareResult
	if err := c.call(ctx, MethodPrepare, p, &r, c.cfg.Deadlines.Prepare); err != nil {
		return nil, err
	}
	return &r, nil
}

// Ingest sends ingest and waits deadline_ms plus the ingest grace.
func (c *Client) Ingest(ctx context.Context, p IngestParams) (*IngestResult, error) {
	var r IngestResult
	limit := time.Duration(p.DeadlineMS)*time.Millisecond + c.cfg.Deadlines.IngestGrace
	if err := c.call(ctx, MethodIngest, p, &r, limit); err != nil {
		return nil, err
	}
	return &r, nil
}

// Observe sends observe and returns the observation set.
func (c *Client) Observe(ctx context.Context, p ObserveParams) (*Observation, error) {
	var r Observation
	if err := c.call(ctx, MethodObserve, p, &r, c.cfg.Deadlines.Observe); err != nil {
		return nil, err
	}
	return &r, nil
}

// Teardown sends teardown.
func (c *Client) Teardown(ctx context.Context, p TeardownParams) (*TeardownResult, error) {
	var r TeardownResult
	if err := c.call(ctx, MethodTeardown, p, &r, c.cfg.Deadlines.Teardown); err != nil {
		return nil, err
	}
	return &r, nil
}

// Close asks the adapter to exit by closing stdin, waits the exit grace, then kills its process group. It
// returns how the process ended. It may be called more than once.
func (c *Client) Close() proc.Result {
	if !c.closed {
		c.closed = true
		c.stdin.Close()
		select {
		case <-c.child.Done():
		case <-time.After(c.cfg.Deadlines.Exit):
			c.child.Kill(fmt.Sprintf("adapter did not exit within %s of stdin closing", c.cfg.Deadlines.Exit))
		}
	}
	if c.broken == nil {
		c.broken = ErrClosed
	}
	return c.child.Wait()
}

// Kill kills the adapter's process group now.
func (c *Client) Kill(reason string) proc.Result {
	c.child.Kill(reason)
	if !c.closed {
		c.closed = true
		c.stdin.Close()
	}
	if c.broken == nil {
		c.broken = ErrClosed
	}
	return c.child.Wait()
}

func (c *Client) fail(err error) error {
	c.broken = err
	c.Kill(err.Error())
	return err
}

// Err returns the error that made the client unusable, or nil.
func (c *Client) Err() error { return c.broken }

func (c *Client) logLine(dir string, b []byte) {
	if c.cfg.Transcript == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.Transcript.Write(append(append([]byte(dir), b...), '\n'))
}

// call sends one request and waits for its response.
func (c *Client) call(ctx context.Context, method string, params any, out any, limit time.Duration) error {
	if c.broken != nil {
		return c.broken
	}
	if method != MethodDescribe && c.nextID == 1 {
		return fmt.Errorf("adapter: %s before describe", method)
	}
	id := c.nextID
	c.nextID++

	// A line waiting before anything was asked is output the protocol does not allow.
	select {
	case m, ok := <-c.lines:
		if ok {
			return c.fail(&ProtocolError{Method: method, ID: id, Reason: ReasonUnsolicited, Detail: fmt.Sprintf("line with no request pending: %q", head(m.data))})
		}
		return c.fail(&ExitError{Method: method, Result: c.child.Wait()})
	default:
	}

	line, err := json.Marshal(request{XDRCHECK: Protocol, ID: id, Method: method, Params: params})
	if err != nil {
		return err
	}
	if errs := adapterkit.ValidateRequest(method, line); len(errs) > 0 {
		// The harness built an invalid request: a bug here, not in the adapter.
		return fmt.Errorf("adapter: invalid %s request: %s", method, adapterkit.JoinSchemaErrors(errs))
	}
	c.logLine("> ", line)
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		select {
		case <-c.child.Done():
			return c.fail(&ExitError{Method: method, Result: c.child.Wait()})
		case <-time.After(time.Second):
		}
		return c.fail(fmt.Errorf("adapter: writing %s request: %w", method, err))
	}

	timer := time.NewTimer(limit)
	defer timer.Stop()
	var m lineMsg
	var ok bool
	select {
	case m, ok = <-c.lines:
	case <-timer.C:
		return c.fail(&TimeoutError{Method: method, After: limit})
	case <-ctx.Done():
		return c.fail(ctx.Err())
	}
	if !ok {
		return c.fail(&ExitError{Method: method, Result: c.child.Wait()})
	}
	if m.err == errLineTooLong {
		return c.fail(&ProtocolError{Method: method, ID: id, Reason: ReasonLineTooLong, Detail: fmt.Sprintf("response longer than %d bytes", c.cfg.MaxLineBytes)})
	}
	c.logLine("< ", m.data)
	if m.err != nil {
		return c.fail(&ProtocolError{Method: method, ID: id, Reason: ReasonMalformed, Detail: "response line not terminated by a newline before the adapter closed stdout"})
	}
	msg, perr := adapterkit.CheckResponse(m.data, id, method)
	if perr != nil {
		return c.fail(perr)
	}
	if e, isErr := msg["error"]; isErr {
		var body ErrorBody
		if err := decodeStrict(mustJSON(e), &body); err != nil {
			return c.fail(&ProtocolError{Method: method, ID: id, Reason: ReasonSchema, Detail: err.Error()})
		}
		return &AdapterError{Method: method, ErrorBody: body}
	}
	if err := decodeStrict(mustJSON(msg["result"]), out); err != nil {
		return c.fail(&ProtocolError{Method: method, ID: id, Reason: ReasonSchema, Detail: "result does not decode: " + err.Error()})
	}
	return nil
}

func mustAny(b []byte) any {
	v, err := decodeAny(b)
	if err != nil {
		panic(err)
	}
	return v
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
