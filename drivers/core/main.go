// Command xdrcheck-driver is the conformance driver of the core column: stellar-core's own XDR decoder, run offline
// through the pinned release binary.
//
// It speaks the driver protocol xcc.driver/1 (one JSON object per line on stdin and stdout; see
// drivers/README.md and corpus/schema/driver-protocol.schema.json). The column shows how stellar-core
// *decodes* bytes, not what stellar-core admits to the network or emits: transaction admission and the Soroban
// host apply bounds of their own that an offline decode never reaches.
//
// Levels:
//
//   - L0: decode by type name. The types `stellar-core print-xdr --filetype <t>` knows are decoded with it
//     (`meta` with --raw, so core's change-order normalisation is not applied); LedgerCloseMeta and the history
//     stream types are written as a one-record stream and decoded with `stellar-core dump-xdr`, the only
//     offline command that reads them (see core.go). The column answers accept or reject with a typed
//     reason and, on accept, consumed_bytes. It cannot answer reencoded_sha256: neither command re-encodes,
//     and core's JSON rendering is no substitute for its encoder (a bool decoded from 2 prints as TRUE; the
//     bytes core would write back are not observable offline). describe says so in decode.entry_point.
//   - L1, L3, L4: n_a. Core has no SDK object layer, native-value conversion, builder or strkey API.
//   - L2: n_a. Core's JSON is its own (cereal: camelCase keys, upper-case enum names, 64-bit integers as bare
//     numbers, raw non-UTF-8 bytes), not the neutral projection the L2 pinpoints address.
//
// print-xdr exits 0 on every decode failure and writes `Could not decode with type '<t>' : <message>` to
// standard error, so outcomes are classified by that line, never by the exit code
// (evidence/core-print-xdr/out/misc-invocation.txt). The decoder's nesting limit is xdrpp's
// marshaling_stack_limit of 1500 units, which core sets for every command; it is a per-value decoder bound
// (evidence/core-print-xdr/out/depth.txt), not a limit a reader of ledger data should adopt.
//
// The driver never reads the manifest and never sees expected values.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

const (
	tag           = "xcc.driver/1"
	driverName    = "xdrcheck-driver-core"
	driverVersion = "0.1.0"
)

// Set at build time (Makefile): the pinned stellar-core version, which names the package directory in the
// cache, and the cache directory used when XDRCHECK_CACHE_DIR is not in the environment.
var (
	coreVersion     = ""
	defaultCacheDir = ""
)

// levels the driver answers. Only L0 decodes; the others are declared so that each cell carries the precise
// reason the column cannot answer it (levelNA) rather than a generic one.
var levels = []string{"L0", "L1", "L2", "L3", "L4"}

func main() {
	core, err := locateCore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck-driver-core: %v\n", err)
		os.Exit(1)
	}
	defer core.close()
	serve(core, os.Stdin, os.Stdout)
}

// serve answers requests until shutdown or the end of input.
func serve(core *Core, in io.Reader, out io.Writer) {
	w := bufio.NewWriter(out)
	send := func(v any) {
		line, err := json.Marshal(v)
		if err != nil {
			panic(err) // every response is built from plain values
		}
		w.Write(append(line, '\n'))
		if w.Flush() != nil {
			os.Exit(0) // the orchestrator went away
		}
	}
	r := bufio.NewReaderSize(in, 1<<20)
	var described *describeResponse
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			resp, stop := handle(core, line, &described)
			send(resp)
			if stop {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

type request struct {
	XDRCHECK *string         `json:"xcc"`
	ID       json.RawMessage `json:"id"`
	Op       *string         `json:"op"`
	Entry    *string         `json:"entry"`
	Variant  *string         `json:"variant"`
	Level    *string         `json:"level"`
	Profile  *string         `json:"profile"`
	Input    json.RawMessage `json:"input"`
}

type protocolError struct {
	XDRCHECK string  `json:"xcc"`
	ID       *uint64 `json:"id,omitempty"`
	Op       string  `json:"op"`
	Error    string  `json:"error"`
}

func perr(id *uint64, format string, args ...any) protocolError {
	return protocolError{XDRCHECK: tag, ID: id, Op: "protocol_error", Error: fmt.Sprintf(format, args...)}
}

// handle answers one request line; stop is true after shutdown.
func handle(core *Core, line []byte, described **describeResponse) (resp any, stop bool) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return perr(nil, "not a JSON object: %v", err), false
	}
	var id *uint64
	var n uint64
	if json.Unmarshal(req.ID, &n) == nil && n >= 1 {
		id = &n
	}
	if req.XDRCHECK == nil || *req.XDRCHECK != tag {
		return perr(id, "unsupported protocol tag; this driver speaks %s", tag), false
	}
	if id == nil {
		return perr(nil, "the request has no id"), false
	}
	op := ""
	if req.Op != nil {
		op = *req.Op
	}
	switch op {
	case "describe":
		if *described == nil {
			d := describe(core)
			*described = &d
		}
		d := **described
		d.ID = *id
		return d, false
	case "run":
		return handleRun(core, *id, &req), false
	case "shutdown":
		return shutdownResponse{XDRCHECK: tag, ID: *id, Op: "shutdown", OK: true}, true
	default:
		if op == "" {
			op = "(none)"
		}
		return perr(id, "unknown op %s", op), false
	}
}

type shutdownResponse struct {
	XDRCHECK string `json:"xcc"`
	ID       uint64 `json:"id"`
	Op       string `json:"op"`
	OK       bool   `json:"ok"`
}

type describeResponse struct {
	XDRCHECK  string         `json:"xcc"`
	ID        uint64         `json:"id"`
	Op        string         `json:"op"`
	Driver    map[string]any `json:"driver"`
	SDK       map[string]any `json:"sdk"`
	Runtime   map[string]any `json:"runtime"`
	XDRSchema map[string]any `json:"xdr_schema"`
	Levels    []string       `json:"levels"`
	APIOps    []string       `json:"api_ops"`
	Decode    map[string]any `json:"decode"`
}

// knownProtocol is the newest protocol whose features the probes test.
const knownProtocol = 30 // pin:protocol.max_supported

// schemaProtocol is the xdr_schema.protocol to report: the ledger protocol the binary states as its own (the
// `ledger protocol version` line of `stellar-core version`), held below knownProtocol when a probe of a
// knownProtocol feature fails. A binary that states none gets none: nothing is excused as beyond its reach.
func schemaProtocol(binary int, probesPass bool) (int, bool) {
	switch {
	case binary <= 0:
		return 0, false
	case !probesPass && binary >= knownProtocol:
		return knownProtocol - 1, true
	}
	return binary, true
}

// describe reports the binary as found: the version is what `stellar-core version` prints, the integrity value
// is the sha256 of the binary that runs, and the schema probes are decodes of the probed arms.
func describe(core *Core) describeResponse {
	muxedContract := core.accepts("SCVal", probeMuxedContract())
	signedMS := core.accepts("LedgerHeader", probeLedgerHeader(3))
	schema := map[string]any{
		"probes": map[string]bool{
			"sc_address_type_muxed_contract": muxedContract,
			"stellar_value_signed_ms":        signedMS,
		},
		"types": typeNames(),
	}
	if p, ok := schemaProtocol(core.protocol, muxedContract && signedMS); ok {
		schema["protocol"] = p
	}
	return describeResponse{
		XDRCHECK: tag,
		Op:       "describe",
		Driver:   map[string]any{"name": driverName, "version": driverVersion, "adapter": "stellar-core print-xdr/dump-xdr"},
		SDK: map[string]any{
			"ecosystem": "other",
			"package":   "stellar-core",
			"version":   core.version,
			"integrity": "sha256:" + core.sha256,
		},
		Runtime: map[string]any{
			"name":    "native",
			"version": core.versionLine,
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		},
		XDRSchema: schema,
		Levels:    levels,
		APIOps:    []string{},
		Decode: map[string]any{
			"entry_point": "stellar-core print-xdr --filetype <t> --compact (--raw for meta); dump-xdr on a one-record " +
				"stream for LedgerCloseMeta and the history stream types. Decode only: core never re-encodes " +
				"offline, so an L0 ok carries consumed_bytes and no reencoded_sha256",
			// xdrpp's marshaling_stack_limit, in its units: one per struct, union, optional or container level.
			"default_depth":      1500,
			"depth_configurable": false,
			// print-xdr checks that the value consumed the whole input; dump-xdr does not, so the driver checks
			// for those types and reports dump-xdr under lenient_entry_points when it accepts trailing bytes.
			"checks_consumed_length": false,
		},
	}
}

type reason struct {
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	EntryPoint string `json:"entry_point,omitempty"`
}

type lenientEntryPoint struct {
	EntryPoint string `json:"entry_point"`
	Accepted   bool   `json:"accepted"`
	Note       string `json:"note,omitempty"`
}

type actual struct {
	ConsumedBytes      *int                `json:"consumed_bytes,omitempty"`
	LenientEntryPoints []lenientEntryPoint `json:"lenient_entry_points,omitempty"`
}

// result is a run outcome before the echo fields are added.
type result struct {
	Outcome string
	Reason  *reason
	Actual  *actual
}

type runResponse struct {
	XDRCHECK string  `json:"xcc"`
	ID       uint64  `json:"id"`
	Op       string  `json:"op"`
	Entry    string  `json:"entry"`
	Variant  *string `json:"variant,omitempty"`
	Level    string  `json:"level"`
	Profile  *string `json:"profile,omitempty"`
	Outcome  string  `json:"outcome"`
	Reason   *reason `json:"reason,omitempty"`
	Actual   *actual `json:"actual,omitempty"`
}

type xdrInput struct {
	Kind       string  `json:"kind"`
	XDRType    string  `json:"xdr_type"`
	Path       *string `json:"path"`
	XDRHex     *string `json:"xdr_hex"`
	Framing    string  `json:"framing"`
	FrameIndex *int    `json:"frame_index"`
}

func handleRun(core *Core, id uint64, req *request) any {
	if req.Entry == nil || req.Level == nil {
		return perr(&id, "a run request needs entry and level")
	}
	level := *req.Level
	switch level {
	case "L0", "L1", "L2", "L3", "L4":
	default:
		return perr(&id, "unknown level %s", level)
	}
	if req.Profile != nil {
		return perr(&id, "unknown profile %s: this driver offers no decode profiles", *req.Profile)
	}
	var kind struct {
		Kind string `json:"kind"`
	}
	if len(req.Input) == 0 || json.Unmarshal(req.Input, &kind) != nil {
		return perr(&id, "a run request needs an input object")
	}
	var res result
	if level != "L0" {
		res = levelNA(level, kind.Kind)
	} else {
		if kind.Kind != "xdr" {
			return perr(&id, "level L0 needs an xdr input, not %q", kind.Kind)
		}
		var in xdrInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return perr(&id, "bad xdr input: %v", err)
		}
		r, err := runL0(core, &in)
		if err != nil {
			return perr(&id, "%v", err)
		}
		res = r
	}
	return runResponse{
		XDRCHECK: tag, ID: id, Op: "run", Entry: *req.Entry, Variant: req.Variant, Level: level,
		Outcome: res.Outcome, Reason: res.Reason, Actual: res.Actual,
	}
}

// levelNA is the answer for every level other than L0: the column cannot do it, and the reason says why.
func levelNA(level, kind string) result {
	na := func(code, msg string) result {
		return result{Outcome: "n_a", Reason: &reason{Code: code, Message: msg}}
	}
	switch level {
	case "L1":
		return na("no_object_layer", "stellar-core's offline decoder has no SDK object layer; the column answers L0 only")
	case "L2":
		return na("other", "stellar-core prints its own JSON (cereal: camelCase keys, upper-case enum names, "+
			"64-bit integers as bare numbers, raw non-UTF-8 bytes), not the neutral value projection; the column answers L0 only")
	case "L3":
		return na("no_native_layer", "stellar-core's offline decoder has no native-value conversion; the column answers L0 only")
	default:
		what := "api operation"
		if kind == "strkey" {
			what = "strkey decoder"
		}
		return na("op_not_supported", "stellar-core's offline commands offer no "+what+"; the column declares no api ops")
	}
}

// trim cuts a message to the protocol's 500 characters.
func trim(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 500 {
		return string(r[:497]) + "..."
	}
	return s
}
