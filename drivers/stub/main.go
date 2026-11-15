// Command xdrcheck-driver is the conformance orchestrator's test driver. It speaks the driver protocol
// (xcc.driver/1, NDJSON over stdio) without wrapping any SDK, and answers each run request with a canned
// outcome chosen by rules from a JSON configuration file:
//
//	xdrcheck-driver [--config FILE]
//
// Configuration (every key optional):
//
//	{
//	  "sdk_version": "0.1.0",          // describe sdk.version
//	  "levels": ["L0", "L1"],           // describe levels (default L0-L4 and spec)
//	  "describe_malformed": false,      // answer describe with an unknown field
//	  "rules": [                        // the first rule whose entry and level match decides
//	    {"entry": "cap-0040/*", "level": "L1", "do": "reject", "code": "ordering", "message": "…"},
//	    {"entry": "*", "do": "ok", "delay_ms": 5}
//	  ]
//	}
//
// "do" is one of: ok, diverge, reject, crash, n_a (answered as that outcome; diverge, reject, crash and n_a
// carry "code", default decode_error / other); exit (exit with "exit_code" without answering); abort (kill
// itself with SIGABRT); hang (never answer); alloc (allocate and touch "mib" MiB, 0 meaning without bound, then
// answer ok); malformed (answer with a response that breaks the protocol: "malformed" is unknown_field,
// missing_reason, wrong_id, wrong_entry, not_json or bad_sha). "delay_ms" sleeps before acting; "exit_after"
// exits 0 after answering, without being asked to shut down; "actual" replaces the actual block of an ok answer
// (for example a spec reader's {"spec": {"entries": [...]}}). An entry pattern
// is a path.Match glob; "" and "*" match every entry. Without a matching rule the answer is ok.
//
// For an xdr input with a path, ok reports the value's size as consumed_bytes and its sha256 as
// reencoded_sha256 (an identity codec); a record-marked input's value is frame frame_index. The driver never reads the manifest.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

const tag = "xcc.driver/1"

type config struct {
	SDKVersion        string   `json:"sdk_version"`
	Levels            []string `json:"levels"`
	DescribeMalformed bool     `json:"describe_malformed"`
	Rules             []rule   `json:"rules"`
}

type rule struct {
	Entry     string `json:"entry"`
	Level     string `json:"level"`
	Do        string `json:"do"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	ExitCode  int    `json:"exit_code"`
	MiB       int    `json:"mib"`
	Malformed string `json:"malformed"`
	DelayMS   int    `json:"delay_ms"`
	ExitAfter bool   `json:"exit_after"`
	// Actual is the actual block an ok answer carries instead of the identity codec's (a spec reader's entries).
	Actual map[string]any `json:"actual"`
}

type request struct {
	XDRCHECK string `json:"xcc"`
	ID       int    `json:"id"`
	Op       string `json:"op"`
	Entry    string `json:"entry"`
	Variant  string `json:"variant"`
	Level    string `json:"level"`
	Profile  string `json:"profile"`
	Input    struct {
		Kind       string `json:"kind"`
		Path       string `json:"path"`
		Framing    string `json:"framing"`
		FrameIndex int    `json:"frame_index"`
	} `json:"input"`
}

var sink [][]byte

func main() {
	cfgPath := flag.String("config", "", "JSON configuration file")
	flag.Parse()
	cfg := config{SDKVersion: "0.1.0", Levels: []string{"L0", "L1", "L2", "L3", "L4", "spec"}}
	if *cfgPath != "" {
		data, err := os.ReadFile(*cfgPath)
		if err == nil {
			err = json.Unmarshal(data, &cfg)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "xdrcheck-driver-stub: config:", err)
			os.Exit(2)
		}
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<16)
	out := bufio.NewWriter(os.Stdout)
	send := func(v any) {
		b, _ := json.Marshal(v)
		out.Write(append(b, '\n'))
		out.Flush()
	}
	for {
		line, err := in.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return
		}
		var req request
		if json.Unmarshal(line, &req) != nil || req.XDRCHECK != tag {
			send(map[string]any{"xcc": tag, "op": "protocol_error", "error": "cannot parse the request"})
			continue
		}
		switch req.Op {
		case "describe":
			send(describe(&cfg, req.ID))
		case "shutdown":
			send(map[string]any{"xcc": tag, "id": req.ID, "op": "shutdown", "ok": true})
			return
		case "run":
			r := match(&cfg, &req)
			if r.DelayMS > 0 {
				time.Sleep(time.Duration(r.DelayMS) * time.Millisecond)
			}
			if resp := act(&r, &req); resp != nil {
				if raw, ok := resp.([]byte); ok {
					out.Write(append(raw, '\n'))
					out.Flush()
				} else {
					send(resp)
				}
			}
			if r.ExitAfter {
				os.Exit(0)
			}
		default:
			send(map[string]any{"xcc": tag, "id": req.ID, "op": "protocol_error", "error": "unknown op " + req.Op})
		}
	}
}

// knownProtocol is the protocol the stub claims to reach: it wraps no SDK, so it reaches what the kit does.
const knownProtocol = 30 // pin:protocol.max_supported

func describe(cfg *config, id int) map[string]any {
	d := map[string]any{
		"xcc": tag, "id": id, "op": "describe",
		"driver":     map[string]any{"name": "xdrcheck-driver-stub", "version": "0.1.0"},
		"sdk":        map[string]any{"ecosystem": "other", "package": "xdrcheck-driver-stub", "version": cfg.SDKVersion},
		"runtime":    map[string]any{"name": "go", "version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH},
		"xdr_schema": map[string]any{"protocol": knownProtocol, "probes": map[string]bool{"sc_address_type_muxed_contract": true, "stellar_value_signed_ms": true}},
		"levels":     cfg.Levels,
		"api_ops":    []string{},
		"decode": map[string]any{"entry_point": "identity", "default_depth": nil, "checks_consumed_length": true,
			"profiles": []string{"limits-default", "limits-none"}},
	}
	if cfg.DescribeMalformed {
		d["unexpected_field"] = true
	}
	return d
}

func match(cfg *config, req *request) rule {
	for _, r := range cfg.Rules {
		if r.Level != "" && r.Level != req.Level {
			continue
		}
		if r.Entry == "" || r.Entry == "*" {
			return r
		}
		if ok, _ := path.Match(r.Entry, req.Entry); ok {
			return r
		}
	}
	return rule{Do: "ok"}
}

// act carries out a rule. It returns the response to send (a value to marshal, or raw bytes), or nil.
func act(r *rule, req *request) any {
	resp := map[string]any{"xcc": tag, "id": req.ID, "op": "run", "entry": req.Entry, "level": req.Level}
	if req.Variant != "" {
		resp["variant"] = req.Variant
	}
	if req.Profile != "" {
		resp["profile"] = req.Profile
	}
	reason := func(def string) map[string]any {
		code := r.Code
		if code == "" {
			code = def
		}
		m := map[string]any{"code": code, "entry_point": "stub"}
		if r.Message != "" {
			m["message"] = r.Message
		}
		return m
	}
	switch r.Do {
	case "", "ok":
		resp["outcome"] = "ok"
		if r.Actual != nil {
			resp["actual"] = r.Actual
		} else if a := identity(req); a != nil {
			resp["actual"] = a
		}
	case "diverge":
		resp["outcome"], resp["reason"] = "diverge", reason("reencode_mismatch")
	case "reject":
		resp["outcome"], resp["reason"] = "reject", reason("decode_error")
	case "crash":
		resp["outcome"], resp["reason"] = "crash", reason("panic")
	case "n_a":
		resp["outcome"], resp["reason"] = "n_a", reason("op_not_supported")
	case "exit":
		fmt.Fprintf(os.Stderr, "xdrcheck-driver-stub: exiting with %d on %s %s\n", r.ExitCode, req.Entry, req.Level)
		os.Exit(r.ExitCode)
	case "abort":
		fmt.Fprintf(os.Stderr, "xdrcheck-driver-stub: aborting on %s %s\n", req.Entry, req.Level)
		// Die of the signal itself, as a native abort does: by default the Go runtime catches SIGABRT and exits
		// 2; with traceback "crash" it re-raises the signal. No core file is written.
		syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
		debug.SetTraceback("crash")
		syscall.Kill(os.Getpid(), syscall.SIGABRT)
		time.Sleep(time.Hour)
	case "hang":
		fmt.Fprintf(os.Stderr, "xdrcheck-driver-stub: hanging on %s %s\n", req.Entry, req.Level)
		time.Sleep(24 * time.Hour)
	case "alloc":
		for i := 0; r.MiB == 0 || i < r.MiB/16; i++ {
			b := make([]byte, 16<<20)
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			sink = append(sink, b)
		}
		resp["outcome"] = "ok"
	case "malformed":
		switch r.Malformed {
		case "unknown_field":
			resp["outcome"], resp["not_in_the_schema"] = "ok", 1
		case "missing_reason":
			resp["outcome"] = "reject"
		case "wrong_id":
			resp["outcome"], resp["id"] = "ok", req.ID+1
		case "wrong_entry":
			resp["outcome"], resp["entry"] = "ok", req.Entry+"-other"
		case "bad_sha":
			resp["outcome"], resp["actual"] = "ok", map[string]any{"reencoded_sha256": "XYZ"}
		default: // not_json
			return []byte("this is not a JSON object")
		}
	default:
		resp["outcome"], resp["reason"] = "crash", map[string]any{"code": "internal_error", "message": "unknown rule action " + r.Do}
	}
	return resp
}

func identity(req *request) map[string]any {
	if req.Input.Kind != "xdr" || req.Input.Path == "" {
		return nil
	}
	data, err := os.ReadFile(req.Input.Path)
	if err != nil {
		return nil
	}
	if req.Input.Framing == "record-marked" {
		if data = frameAt(data, req.Input.FrameIndex); data == nil {
			return nil
		}
	}
	sum := sha256.Sum256(data)
	return map[string]any{"consumed_bytes": len(data), "reencoded_sha256": hex.EncodeToString(sum[:])}
}

// frameAt returns record-marked frame i (RFC 5531 record marks), or nil.
func frameAt(data []byte, i int) []byte {
	var cur []byte
	for off, n := 0, 0; off+4 <= len(data); n++ {
		mark := binary.BigEndian.Uint32(data[off:])
		size := int(mark & 0x7fffffff)
		off += 4
		if off+size > len(data) {
			return nil
		}
		cur = append(cur, data[off:off+size]...)
		off += size
		if mark&0x80000000 == 0 {
			n--
			continue
		}
		if n == i {
			return cur
		}
		cur = nil
	}
	return nil
}
