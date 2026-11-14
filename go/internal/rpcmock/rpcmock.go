// Package rpcmock is a JSON-RPC 2.0 server over HTTP that answers `getLedgers` and `getHealth` for a consecutive
// range of corpus ledgers with stellar-rpc v30.0.1's wire types (the go-stellar-sdk v0.9.0 `protocols/rpc`
// structs that stellar-rpc v30.0.1 itself uses), so Go, JS and other clients decode it unchanged.
//
// Rules copied from the real server: params by name only; getLedgers limit default 50, maximum 200; cursor and
// a non-zero startLedger together, a start outside the served range, a limit over 200 or a bad xdrFormat are
// -32600 with the real message text; a bad cursor is -32602. `metadataXdr` is the corpus LedgerCloseMeta
// verbatim and `headerXdr` the embedded LedgerHeaderHistoryEntry re-encoded with the pinned XDR library.
//
// Not copied: real RPC turns unhealthy when its latest ledger closed more than 30 s ago; the mock is always
// healthy, or every client replaying old ledgers would stop. `xdrFormat: "json"` is not served (-32602).
// `getLatestLedger`, `getNetwork` and `getVersionInfo` are answered too; every other method gets a well-formed
// -32601 error (never a dropped connection) and is logged, because clients such as wallet-backend call
// `getLedgerEntries` and carry on after the error.
package rpcmock

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
)

// JSON-RPC error codes (jrpc2).
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

const (
	defaultLimit    = 50
	maxLimit        = 200
	retentionWindow = 120960 // stellar-rpc's default history-retention-window (seven days of ledgers)
	maxBody         = 1 << 20
)

// Ledger is one ledger to serve.
type Ledger struct {
	Seq  uint32
	Load func() ([]byte, error) // the LedgerCloseMeta bytes; called per request, so bytes need not stay in memory
}

// Config describes the pass the mock serves.
type Config struct {
	Passphrase      string
	ProtocolVersion int    // for getNetwork and getVersionInfo; 0 means the newest ledger's protocol
	Nonce           string // per-run nonce, returned in the X-Xdrcheck-Nonce header and in getVersionInfo.commitHash
	Log             *lake.DeliveryLog
	// Entries, when set, answers getLedgerEntries: base64 LedgerKey → the entry as an RPC would return it. Keys it
	// does not hold are absent from the answer, as an RPC answers for an entry that does not exist. Nil keeps the
	// method unanswered (-32601).
	Entries map[string]protocol.LedgerEntryResult
	// Simulate, when set, answers simulateTransaction for a one-operation InvokeContract envelope: given the
	// contract strkey, function name and argument count it returns the base64 ScVal result, or false for a
	// failed simulation. It is a stand-in (the mock has no host): the caller decides where results come from.
	Simulate func(contract, function string, args int) (string, bool)
}

// Server is the mock. It is an http.Handler.
type Server struct {
	cfg     Config
	first   uint32
	last    uint32
	headers []lake.Header
	loads   []func() ([]byte, error)
}

// New checks that ledgers are consecutive and reads each one's header once.
func New(cfg Config, ledgers []Ledger) (*Server, error) {
	if len(ledgers) == 0 {
		return nil, errors.New("rpcmock: no ledgers")
	}
	s := &Server{cfg: cfg, first: ledgers[0].Seq, last: ledgers[len(ledgers)-1].Seq}
	for i, l := range ledgers {
		if i > 0 && l.Seq != ledgers[i-1].Seq+1 {
			return nil, fmt.Errorf("rpcmock: gap between ledgers %d and %d", ledgers[i-1].Seq, l.Seq)
		}
		raw, err := l.Load()
		if err != nil {
			return nil, fmt.Errorf("rpcmock: ledger %d: %w", l.Seq, err)
		}
		h, err := lake.Inspect(raw)
		if err != nil {
			return nil, fmt.Errorf("rpcmock: ledger %d: %w", l.Seq, err)
		}
		if h.Seq != l.Seq {
			return nil, fmt.Errorf("rpcmock: ledger %d: header says sequence %d", l.Seq, h.Seq)
		}
		s.headers = append(s.headers, h)
		s.loads = append(s.loads, l.Load)
	}
	if s.cfg.ProtocolVersion == 0 {
		s.cfg.ProtocolVersion = int(s.headers[len(s.headers)-1].ProtocolVersion)
	}
	return s, nil
}

// Range returns the served ledger range.
func (s *Server) Range() (uint32, uint32) { return s.first, s.last }

// Listen serves on addr (for example 127.0.0.1:0) until the returned server is shut down. It binds first, so a
// port in use fails here.
func (s *Server) Listen(addr string) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	return srv, "http://" + ln.Addr().String(), nil
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// ServeHTTP answers one JSON-RPC request or a batch.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Nonce != "" {
		w.Header().Set("X-Xdrcheck-Nonce", s.cfg.Nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		s.write(w, response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{CodeInvalidRequest, "JSON-RPC requests must be POSTed"}})
		s.log(lake.Delivery{Method: r.Method + " " + r.URL.Path, Status: "error -32600"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		var reqs []request
		if err := json.Unmarshal(body, &reqs); err != nil || len(reqs) == 0 {
			s.write(w, parseError())
			return
		}
		out := make([]response, 0, len(reqs))
		for _, q := range reqs {
			out = append(out, s.handle(q))
		}
		s.write(w, out)
		return
	}
	var q request
	if err := json.Unmarshal(body, &q); err != nil {
		s.write(w, parseError())
		s.log(lake.Delivery{Status: "error -32700"})
		return
	}
	s.write(w, s.handle(q))
}

func parseError() response {
	return response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{CodeParse, "parse error"}}
}

func (s *Server) write(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	w.Write(b)
}

func (s *Server) log(d lake.Delivery) {
	d.View = "rpc"
	s.cfg.Log.Add(d)
}

func (s *Server) handle(q request) response {
	id := q.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	res, ledgers, nbytes, rerr := s.call(q)
	d := lake.Delivery{Method: q.Method, Ledgers: ledgers, Bytes: nbytes, Status: "ok"}
	if rerr != nil {
		d.Status = "error " + strconv.Itoa(rerr.Code)
		s.log(d)
		return response{JSONRPC: "2.0", ID: id, Error: rerr}
	}
	s.log(d)
	return response{JSONRPC: "2.0", ID: id, Result: res}
}

// params decodes by-name params. Absent params decode as the zero value.
func params(raw json.RawMessage, v any) *rpcError {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return &rpcError{CodeInvalidParams, "invalid parameters: parameters must be passed by name (an object)"}
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return &rpcError{CodeInvalidParams, "invalid parameters: " + err.Error()}
	}
	return nil
}

func (s *Server) call(q request) (any, []uint32, int64, *rpcError) {
	newest := s.headers[len(s.headers)-1]
	oldest := s.headers[0]
	switch q.Method {
	case protocol.GetHealthMethodName:
		return protocol.GetHealthResponse{
			Status: "healthy", LatestLedger: s.last, LatestLedgerCloseTime: newest.CloseTime,
			OldestLedger: s.first, OldestLedgerCloseTime: oldest.CloseTime, LedgerRetentionWindow: retentionWindow,
		}, nil, 0, nil
	case protocol.GetLedgersMethodName:
		return s.getLedgers(q.Params)
	case protocol.GetLatestLedgerMethodName:
		raw, err := s.loads[len(s.loads)-1]()
		if err != nil {
			return nil, nil, 0, &rpcError{CodeInternal, err.Error()}
		}
		return protocol.GetLatestLedgerResponse{
			Hash: newest.Hash, ProtocolVersion: newest.ProtocolVersion, Sequence: newest.Seq, LedgerCloseTime: newest.CloseTime,
			LedgerHeader: base64.StdEncoding.EncodeToString(newest.HeaderXDR), LedgerMetadata: base64.StdEncoding.EncodeToString(raw),
		}, []uint32{newest.Seq}, int64(len(raw)), nil
	case protocol.GetLedgerEntriesMethodName:
		if s.cfg.Entries == nil {
			break
		}
		var req protocol.GetLedgerEntriesRequest
		if e := params(q.Params, &req); e != nil {
			return nil, nil, 0, e
		}
		if req.Format != "" && req.Format != "base64" {
			return nil, nil, 0, &rpcError{CodeInvalidParams, "invalid parameters: xdrFormat json is not served"}
		}
		out := protocol.GetLedgerEntriesResponse{Entries: []protocol.LedgerEntryResult{}, LatestLedger: s.last}
		for _, k := range req.Keys {
			if e, ok := s.cfg.Entries[k]; ok {
				e.KeyXDR = k
				out.Entries = append(out.Entries, e)
			}
		}
		return out, nil, 0, nil
	case "simulateTransaction":
		if s.cfg.Simulate == nil {
			break
		}
		var req struct {
			Transaction string `json:"transaction"`
		}
		if e := params(q.Params, &req); e != nil {
			return nil, nil, 0, e
		}
		var env xdr.TransactionEnvelope
		if err := xdr.SafeUnmarshalBase64(req.Transaction, &env); err != nil {
			return nil, nil, 0, &rpcError{CodeInvalidParams, "invalid parameters: transaction: " + err.Error()}
		}
		ops := env.Operations()
		if len(ops) == 1 && ops[0].Body.Type == xdr.OperationTypeInvokeHostFunction {
			if ic := ops[0].Body.InvokeHostFunctionOp.HostFunction.InvokeContract; ic != nil && ic.ContractAddress.ContractId != nil {
				id := *ic.ContractAddress.ContractId
				c, _ := strkey.Encode(strkey.VersionByteContract, id[:])
				if v, ok := s.cfg.Simulate(c, string(ic.FunctionName), len(ic.Args)); ok {
					return map[string]any{"results": []map[string]any{{"auth": []string{}, "xdr": v}}, "minResourceFee": "0",
						"latestLedger": s.last}, nil, 0, nil
				}
				return map[string]any{"error": "HostError: the mock has no recorded result for " + c + "." + string(ic.FunctionName),
					"latestLedger": s.last}, nil, 0, nil
			}
		}
		return map[string]any{"error": "HostError: only a one-operation InvokeContract is simulated", "latestLedger": s.last}, nil, 0, nil
	case protocol.GetNetworkMethodName:
		return protocol.GetNetworkResponse{Passphrase: s.cfg.Passphrase, ProtocolVersion: s.cfg.ProtocolVersion}, nil, 0, nil
	case protocol.GetVersionInfoMethodName:
		return protocol.GetVersionInfoResponse{Version: "xdrcheck-rpcmock (stellar-rpc v30.0.1 wire types)", CommitHash: s.cfg.Nonce,
			ProtocolVersion: uint32(s.cfg.ProtocolVersion)}, nil, 0, nil
	}
	return nil, nil, 0, &rpcError{CodeMethodNotFound, "method not found"}
}

func (s *Server) getLedgers(raw json.RawMessage) (any, []uint32, int64, *rpcError) {
	var req protocol.GetLedgersRequest
	if e := params(raw, &req); e != nil {
		return nil, nil, 0, e
	}
	rng := protocol.LedgerSeqRange{FirstLedger: s.first, LastLedger: s.last}
	if err := req.Validate(maxLimit, rng); err != nil {
		return nil, nil, 0, &rpcError{CodeInvalidRequest, err.Error()}
	}
	if req.Format == protocol.FormatJSON {
		return nil, nil, 0, &rpcError{CodeInvalidParams, "xdrFormat \"json\" is not served by this mock; use base64"}
	}
	start, limit := req.StartLedger, uint(defaultLimit)
	cursor := ""
	if p := req.Pagination; p != nil {
		if p.Limit > 0 {
			limit = p.Limit
		}
		if p.Cursor != "" {
			c, err := strconv.ParseUint(p.Cursor, 10, 32)
			if err != nil {
				return nil, nil, 0, &rpcError{CodeInvalidParams, fmt.Sprintf("invalid cursor %q: %v", p.Cursor, err)}
			}
			cursor = p.Cursor
			start = uint32(c) + 1
			if start < s.first {
				return nil, nil, 0, &rpcError{CodeInvalidRequest, fmt.Sprintf(
					"start ledger (%d) must be between the oldest ledger: %d and the latest ledger: %d for this rpc instance", start, s.first, s.last)}
			}
		}
	}
	resp := protocol.GetLedgersResponse{
		Ledgers:      []protocol.LedgerInfo{},
		LatestLedger: s.last, LatestLedgerCloseTime: s.headers[len(s.headers)-1].CloseTime,
		OldestLedger: s.first, OldestLedgerCloseTime: s.headers[0].CloseTime,
	}
	var served []uint32
	var nbytes int64
	for seq := start; seq <= s.last && uint(len(resp.Ledgers)) < limit; seq++ {
		i := seq - s.first
		lcm, err := s.loads[i]()
		if err != nil {
			return nil, nil, 0, &rpcError{CodeInternal, fmt.Sprintf("error processing ledger %d: %v", seq, err)}
		}
		h := s.headers[i]
		resp.Ledgers = append(resp.Ledgers, protocol.LedgerInfo{
			Hash: h.Hash, Sequence: h.Seq, LedgerCloseTime: h.CloseTime,
			LedgerHeader: base64.StdEncoding.EncodeToString(h.HeaderXDR), LedgerMetadata: base64.StdEncoding.EncodeToString(lcm),
		})
		served = append(served, seq)
		nbytes += int64(len(lcm))
		if seq == ^uint32(0) {
			break
		}
	}
	switch {
	case len(resp.Ledgers) > 0:
		resp.Cursor = strconv.FormatUint(uint64(resp.Ledgers[len(resp.Ledgers)-1].Sequence), 10)
	case cursor != "":
		resp.Cursor = cursor
	default:
		resp.Cursor = strconv.FormatUint(uint64(start-1), 10)
	}
	return resp, served, nbytes, nil
}
