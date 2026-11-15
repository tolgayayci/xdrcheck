// Package driver is the conformance driver for github.com/stellar/go-stellar-sdk. It speaks the driver protocol
// xcc.driver/1 (one JSON object per line on stdin and stdout, corpus/schema/driver-protocol.schema.json) and
// reports what the SDK did with each input: ok, diverge, reject, crash or n_a with a typed reason. It never
// sees expected values.
//
// The same source is built once per pinned SDK version: each directory drivers/go/<version> is a Go module
// whose go.mod requires that SDK version (and so the go-xdr version that SDK pins) and points this package at
// ../driver with a replace directive. Nothing here depends on the version number; the SDK version, its
// integrity hash and the go-xdr version are read from the binary's build information at run time, and what
// the generated XDR can represent is probed from its enums.
//
// Levels:
//
//	L0  xdr.SafeUnmarshal (strict, default depth, checks that every byte was consumed) and MarshalBinary;
//	    the generated UnmarshalBinary, which accepts trailing bytes, is reported as a lenient entry point
//	L1  txnbuild.TransactionFromXDR on a TransactionEnvelope, or on every envelope of a ledger's transaction
//	    set, in apply order (object.go), then the facts read back through the object: hashes, operation
//	    counts and types, and derived facts of the focus operation
//	L2  the neutral value projection (project.go), whole or at JSON Pointer pinpoints
//	L4  api operations and strkey vectors (api.go)
//
// Under the decode profile "views" (views.go; SDK v0.8.0 and later) L0 and L1 read the same bytes through the
// SDK's zero-copy XDR views and view-based ingest extractors and compare them with the full decode.
//
// L3 is not offered: the SDK has no native-value conversion layer.
package driver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"
)

const (
	protocolTag   = "xcc.driver/1"
	driverName    = "xdrcheck-driver-go"
	driverVersion = "0.1.0"
	sdkModule     = "github.com/stellar/go-stellar-sdk"
	goXDRModule   = "github.com/stellar/go-xdr"
	maxMessage    = 500
	maxLineBytes  = 64 << 20
)

// request is one line from the orchestrator.
type request struct {
	XDRCHECK string `json:"xcc"`
	ID       *int   `json:"id"`
	Op       string `json:"op"`
	Entry    string `json:"entry"`
	Variant  string `json:"variant"`
	Level    string `json:"level"`
	Profile  string `json:"profile"`
	Input    input  `json:"input"`
}

// input is the union of the three request input forms (xdr, api, strkey).
type input struct {
	Kind         string         `json:"kind"`
	XDRType      string         `json:"xdr_type"`
	Path         string         `json:"path"`
	XDRHex       *string        `json:"xdr_hex"`
	Framing      string         `json:"framing"`
	FrameIndex   int            `json:"frame_index"`
	Passphrase   string         `json:"passphrase"`
	Focus        *focus         `json:"focus"`
	Pinpoints    []string       `json:"pinpoints"`
	APIOp        string         `json:"api_op"`
	Args         map[string]any `json:"args"`
	Text         string         `json:"text"`
	DeclaredType string         `json:"declared_type"`
	Container    string         `json:"container"`
	Sections     []specSection  `json:"sections"`
}

// specSection is where a contractspecv0 section payload lies in a Wasm module (spec inputs).
type specSection struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

type focus struct {
	TxIndex *int   `json:"tx_index"`
	OpIndex *int   `json:"op_index"`
	Path    string `json:"path"`
}

// result is what a level handler reports; run turns it into the response line.
type result struct {
	Outcome string
	Reason  *reason
	Actual  map[string]any
	// Protocol, when set, means the request itself is unusable (an unknown or malformed argument, an input of
	// the wrong kind): the answer is a protocol_error message, not an SDK outcome.
	Protocol string
}

type reason struct {
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
	EntryPoint string `json:"entry_point,omitempty"`
}

func ok(actual map[string]any) result { return result{Outcome: "ok", Actual: actual} }

func outcome(o, code, entryPoint string, err error) result {
	r := &reason{Code: code, EntryPoint: entryPoint}
	if err != nil {
		r.Message = trim(err.Error())
		r.ErrorClass = fmt.Sprintf("%T", err)
	}
	return result{Outcome: o, Reason: r}
}

func reject(code, entryPoint string, err error) result {
	return outcome("reject", code, entryPoint, err)
}

func protocolError(msg string) result { return result{Protocol: msg} }

func notApplicable(code, msg string) result {
	return result{Outcome: "n_a", Reason: &reason{Code: code, Message: trim(msg)}}
}

// trim makes a message valid UTF-8 and at most maxMessage characters long.
func trim(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= maxMessage {
		return s
	}
	r := []rune(s)
	return string(r[:maxMessage-1]) + "…"
}

// Main serves requests from stdin until shutdown or end of input.
func Main() {
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "xdrcheck-driver-go:", err)
		os.Exit(1)
	}
}

func serve(r io.Reader, w io.Writer) error {
	in := bufio.NewReaderSize(r, 1<<16)
	out := bufio.NewWriterSize(w, 1<<16)
	send := func(v any) error {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		if _, err := out.Write(buf.Bytes()); err != nil {
			return err
		}
		return out.Flush()
	}
	for {
		line, err := in.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) == 0 {
			if err != nil {
				return nil
			}
			continue
		}
		var req request
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if derr := dec.Decode(&req); derr != nil || req.XDRCHECK != protocolTag {
			msg := "cannot parse the request"
			if derr != nil {
				msg += ": " + derr.Error()
			} else {
				msg += ": protocol tag is not " + protocolTag
			}
			e := map[string]any{"xcc": protocolTag, "op": "protocol_error", "error": msg}
			if req.ID != nil && *req.ID >= 1 {
				e["id"] = *req.ID
			}
			if serr := send(e); serr != nil {
				return serr
			}
			continue
		}
		if req.ID == nil || *req.ID < 1 {
			if serr := send(map[string]any{"xcc": protocolTag, "op": "protocol_error", "error": "the request has no valid id"}); serr != nil {
				return serr
			}
			continue
		}
		id := *req.ID
		switch req.Op {
		case "describe":
			err = send(describe(id))
		case "shutdown":
			return send(map[string]any{"xcc": protocolTag, "id": id, "op": "shutdown", "ok": true})
		case "run":
			err = send(run(&req))
		default:
			err = send(map[string]any{"xcc": protocolTag, "id": id, "op": "protocol_error", "error": "unknown op " + req.Op})
		}
		if err != nil {
			return err
		}
	}
}

// run answers one run request. A panic inside the SDK is a fault: it is reported as crash/panic, never as a
// reject.
func run(req *request) map[string]any {
	resp := map[string]any{"xcc": protocolTag, "id": *req.ID, "op": "run", "entry": req.Entry, "level": req.Level}
	if req.Variant != "" {
		resp["variant"] = req.Variant
	}
	if req.Profile != "" {
		resp["profile"] = req.Profile
	}
	res := func() (res result) {
		defer func() {
			if p := recover(); p != nil {
				res = result{Outcome: "crash", Reason: &reason{Code: "panic", Message: trim(fmt.Sprintf("panic: %v", p)), ErrorClass: "panic"}}
			}
		}()
		return dispatch(req)
	}()
	if res.Protocol != "" {
		return map[string]any{"xcc": protocolTag, "id": *req.ID, "op": "protocol_error", "error": trim(res.Protocol)}
	}
	resp["outcome"] = res.Outcome
	if res.Reason != nil {
		resp["reason"] = res.Reason
	} else if res.Outcome != "ok" {
		resp["reason"] = &reason{Code: "internal_error"}
	}
	if len(res.Actual) > 0 {
		resp["actual"] = res.Actual
	}
	return resp
}

func dispatch(req *request) result {
	switch {
	case req.Profile == ViewsProfile && viewsOffered():
		return dispatchViews(req)
	case req.Profile != "":
		return protocolError("this Go driver offers no decode profile " + req.Profile)
	}
	return dispatchLevel(req)
}

// dispatchLevel answers a request on the full-decode path.
func dispatchLevel(req *request) result {
	in := &req.Input
	switch req.Level {
	case "L0", "L1", "L2":
		if in.Kind != "xdr" {
			return protocolError(req.Level + " needs an xdr input, got " + in.Kind)
		}
		raw, err := readInput(in)
		if err != nil {
			return protocolError("cannot read the input: " + err.Error())
		}
		switch req.Level {
		case "L0":
			return levelCodec(in.XDRType, raw)
		case "L1":
			return levelObject(in, raw)
		default:
			return levelValues(in, raw)
		}
	case "L3":
		return notApplicable("no_native_layer", "go-stellar-sdk has no native-value conversion layer")
	case "spec":
		if in.Kind != "spec" {
			return protocolError("spec needs a spec input, got " + in.Kind)
		}
		return levelSpec(in)
	case "L4":
		switch in.Kind {
		case "api":
			return levelAPI(in)
		case "strkey":
			return levelStrkey(in.Text, in.DeclaredType)
		}
		return protocolError("L4 needs an api or strkey input, got " + in.Kind)
	}
	return protocolError("unknown level " + req.Level)
}

// describe reports the driver, the SDK as built into this binary, the schema probes and the levels and ops.
func describe(id int) map[string]any {
	sdk := map[string]any{"ecosystem": "go", "package": sdkModule, "version": "unknown"}
	var deps []map[string]any
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			m := d
			if m.Replace != nil {
				m = m.Replace
			}
			switch d.Path {
			case sdkModule:
				sdk["version"] = m.Version
				if m.Version == "" {
					// Replaced by a directory: built from an SDK checkout (xdrcheck conform --sdk), which has no version.
					sdk["version"] = "(devel)"
				}
				if m.Sum != "" {
					sdk["integrity"] = m.Sum
				}
			case goXDRModule:
				dep := map[string]any{"package": d.Path, "version": m.Version}
				if m.Sum != "" {
					dep["integrity"] = m.Sum
				}
				deps = append(deps, dep)
			}
		}
	}
	if deps != nil {
		sdk["dependencies"] = deps
	}
	decode := map[string]any{
		"entry_point":            "xdr.SafeUnmarshal",
		"default_depth":          defaultDepth(),
		"depth_configurable":     false,
		"checks_consumed_length": true,
	}
	if viewsOffered() {
		decode["profiles"] = []string{ViewsProfile}
	}
	probes := schemaProbes()
	schema := map[string]any{"probes": probes, "types": typeNames()}
	if p, ok := schemaProtocol(probes, beyondKnown()); ok {
		schema["protocol"] = p
	}
	return map[string]any{
		"xcc": protocolTag, "id": id, "op": "describe",
		"driver":     map[string]any{"name": driverName, "version": driverVersion, "adapter": "go"},
		"sdk":        sdk,
		"runtime":    map[string]any{"name": "go", "version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH},
		"xdr_schema": schema,
		"levels":     []string{"L0", "L1", "L2", "L4", "spec"},
		"object_parsers": map[string]string{
			"TransactionEnvelope":  "txnbuild.TransactionFromXDR",
			"LedgerCloseMeta":      "xdr.LedgerCloseMeta.TransactionEnvelopes + txnbuild.TransactionFromXDR",
			"LedgerCloseMetaBatch": "xdr.LedgerCloseMeta.TransactionEnvelopes + txnbuild.TransactionFromXDR",
		},
		"object_rebuild": rebuildEntry,
		"api_ops":        apiOps(),
		"decode":         decode,
	}
}
