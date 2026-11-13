package adapterkit

// The adapter side of the transport (docs/adapter-protocol.md §2): one JSON request per line on stdin, one
// response per line on stdout, logs on stderr. Serve does the framing, the protocol-version check, error
// responses and the input and unit checks; a Handler only does what is specific to its indexer.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// Handler is an adapter: one method per protocol call. Return an *Error (Errorf) to answer with a specific
// error code; any other error is answered as "internal".
type Handler interface {
	// Describe declares the adapter, the indexer and what it handles. It must return the same value every time.
	Describe(DescribeParams) (DescribeResult, error)
	// Prepare creates an empty store for a new session.
	Prepare(PrepareParams) (PrepareResult, error)
	// Ingest makes the indexer ingest the range and reports what happened as facts (status and signals).
	Ingest(IngestParams) (IngestResult, error)
	// Observe returns what the indexer holds for the range, mapped onto the neutral observation kinds.
	Observe(ObserveParams) (Observation, error)
	// Teardown removes the session's store.
	Teardown(TeardownParams) (TeardownResult, error)
}

// ResultWriter is an observe result written while the response is sent, for an indexer whose observation set
// is too large to hold in memory. WriteResult writes one JSON object (the observation set); an error after the
// first byte leaves the line unfinished, which the harness reports as a protocol violation of the unit.
type ResultWriter interface {
	WriteResult(w io.Writer) error
}

// StreamingObserver is an optional Handler extension: when a Handler has it, Serve calls ObserveStream instead
// of Observe.
type StreamingObserver interface {
	ObserveStream(ObserveParams) (ResultWriter, error)
}

// Error codes of an error response (adapter-protocol.schema.json, errorResponse).
const (
	CodeUnsupportedProtocolVersion = "unsupported_protocol_version"
	CodeUnknownMethod              = "unknown_method"
	CodeInvalidParams              = "invalid_params"
	CodeUnknownSession             = "unknown_session"
	CodeUnsupportedInput           = "unsupported_input"
	CodeUnsupportedUnit            = "unsupported_unit"
	CodeUnsupportedTargetVersion   = "unsupported_target_version"
	CodePrepareFailed              = "prepare_failed"
	CodeEnvironment                = "environment"
	CodeInternal                   = "internal"
)

// Error is an error response. It says the adapter or its environment failed, never anything about how the
// indexer handled a ledger: a ledger the indexer cannot handle is an ingest result (halted, crashed, …).
type Error struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf returns an *Error with the code and a formatted message.
func Errorf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// maxMessage is the schema's cap on an error message.
const maxMessage = 4000

// Main serves the protocol on stdin and stdout until stdin closes and returns the process exit code (0).
func Main(h Handler) int {
	if err := Serve(os.Stdin, os.Stdout, h); err != nil {
		fmt.Fprintln(os.Stderr, "adapter:", err)
		return 1
	}
	return 0
}

// Serve answers one request per line from in on out until in closes (it then returns nil) or a describe
// offers no protocol version this package speaks (answered with unsupported_protocol_version, then it
// returns). It checks an ingest's input kind and unit against the inputs and units Describe declared, so a
// Handler sees only those.
func Serve(in io.Reader, out io.Writer, h Handler) error {
	s := &server{h: h, out: bufio.NewWriter(out)}
	r := bufio.NewReaderSize(in, 1<<20)
	for !s.quit {
		line, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			if werr := s.handle(line); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type server struct {
	h    Handler
	out  *bufio.Writer
	desc *DescribeResult
	quit bool
}

type inRequest struct {
	XDRCHECK string          `json:"xcc"`
	ID       int64           `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params"`
}

type outResponse struct {
	XDRCHECK string     `json:"xcc"`
	ID       int64      `json:"id"`
	Method   string     `json:"method"`
	Result   any        `json:"result,omitempty"`
	Error    *ErrorBody `json:"error,omitempty"`
}

func (s *server) handle(line []byte) error {
	var req inRequest
	if err := json.Unmarshal(line, &req); err != nil {
		fmt.Fprintln(os.Stderr, "adapter: unreadable request:", err)
		return nil
	}
	res, err := s.dispatch(req)
	if rw, ok := res.(ResultWriter); ok && err == nil {
		return s.stream(req, rw)
	}
	resp := outResponse{XDRCHECK: Protocol, ID: req.ID, Method: req.Method}
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: CodeInternal, Message: err.Error()}
		}
		msg := e.Message
		if len(msg) > maxMessage {
			msg = msg[:maxMessage-3] + "..."
		}
		retry := e.Retryable
		resp.Error = &ErrorBody{Code: e.Code, Message: msg, Retryable: &retry}
	} else {
		resp.Result = res
	}
	b, merr := json.Marshal(resp)
	if merr != nil {
		no := false
		b, _ = json.Marshal(outResponse{XDRCHECK: Protocol, ID: req.ID, Method: req.Method,
			Error: &ErrorBody{Code: CodeInternal, Message: merr.Error(), Retryable: &no}})
	}
	s.out.Write(b)
	s.out.WriteByte('\n')
	return s.out.Flush()
}

// stream writes an observe response whose result a ResultWriter writes.
func (s *server) stream(req inRequest, rw ResultWriter) error {
	head, _ := json.Marshal(outResponse{XDRCHECK: Protocol, ID: req.ID, Method: req.Method})
	// head is {"xcc":…,"id":…,"method":…}: reopen it for the result member.
	s.out.Write(head[:len(head)-1])
	s.out.WriteString(`,"result":`)
	if err := rw.WriteResult(s.out); err != nil {
		fmt.Fprintln(os.Stderr, "adapter: observe: response cut short:", err)
	} else {
		s.out.WriteByte('}')
	}
	s.out.WriteByte('\n')
	return s.out.Flush()
}

func params(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return Errorf(CodeInvalidParams, "params are required")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return Errorf(CodeInvalidParams, "%v", err)
	}
	return nil
}

func (s *server) dispatch(req inRequest) (any, error) {
	switch req.Method {
	case MethodDescribe:
		var p DescribeParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		if !slices.Contains(p.ProtocolVersions, Protocol) {
			s.quit = true
			return nil, Errorf(CodeUnsupportedProtocolVersion, "this adapter speaks %s only", Protocol)
		}
		d, err := s.h.Describe(p)
		if err != nil {
			return nil, err
		}
		if d.ProtocolVersion == "" {
			d.ProtocolVersion = Protocol
		}
		s.desc = &d
		return d, nil
	case MethodPrepare:
		var p PrepareParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		if p.Session == "" {
			return nil, Errorf(CodeInvalidParams, "session is required")
		}
		return s.h.Prepare(p)
	case MethodIngest:
		var p IngestParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		if d := s.desc; d != nil {
			if !slices.Contains(d.Inputs, p.Input.Kind) {
				return nil, Errorf(CodeUnsupportedInput, "this indexer cannot read input kind %s; supported: %s", p.Input.Kind, strings.Join(d.Inputs, ", "))
			}
			if p.Unit != "" && !slices.Contains(d.Units, p.Unit) {
				return nil, Errorf(CodeUnsupportedUnit, "unit %s is not supported; supported: %s", p.Unit, strings.Join(d.Units, ", "))
			}
		}
		return s.h.Ingest(p)
	case MethodObserve:
		var p ObserveParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		if so, ok := s.h.(StreamingObserver); ok {
			return so.ObserveStream(p)
		}
		return s.h.Observe(p)
	case MethodTeardown:
		var p TeardownParams
		if err := params(req.Params, &p); err != nil {
			return nil, err
		}
		return s.h.Teardown(p)
	}
	return nil, Errorf(CodeUnknownMethod, "unknown method %q", req.Method)
}

// ProvidedKinds is an observation set's kinds block: each kind that was requested and that the indexer models
// (declared supported in describe) is provided; every other kind is not_applicable with a reason.
func ProvidedKinds(declared Observations, requested []string) KindsSet {
	var k KindsSet
	for _, name := range AllKinds {
		st := k.Kind(name)
		switch {
		case !slices.Contains(requested, name):
			*st = KindStatus{Status: "not_applicable", Reason: "not requested"}
		case !declared.Kind(name).Supported:
			reason := declared.Kind(name).Reason
			if reason == "" {
				reason = "not modelled by this indexer"
			}
			*st = KindStatus{Status: "not_applicable", Reason: reason}
		default:
			*st = KindStatus{Status: "provided"}
		}
	}
	return k
}

// Provided reports whether the kinds block provides the kind.
func (k *KindsSet) Provided(name string) bool {
	st := k.Kind(name)
	return st != nil && st.Status == "provided"
}
