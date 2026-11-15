package driver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The executed matrix probe under evidence/sdk-matrix/ runs its hand-encoded vectors through the four Go
// versions. TestReproducesMatrixProbe maps each vector onto the driver's levels and api ops and checks that
// the driver, on the SDK version it was built with, lands in the outcome class the probe recorded for that
// version (accepted, rejected, n/a), and, where the probe accepted and the vector states a value, that the
// value matches the vector (the vectors were encoded without any SDK). The result files are not committed: the
// test reads evidence/sdk-matrix/results/ when a probe run has written it, and $XDRCHECK_OVERLAY/evidence/sdk-matrix/
// results/ when XDRCHECK_OVERLAY is set, and is skipped when neither holds this version's file.

type probeVector struct {
	ID     string         `json:"id"`
	Group  int            `json:"group"`
	Hex    *string        `json:"hex"`
	Params map[string]any `json:"params"`
	Expect map[string]any `json:"expect"`
}

type probeResult struct {
	Vector  string `json:"vector"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// k1 is the 32-byte key every strkey vector of the probe is built from.
const k1 = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"

// notMapped are vectors the driver does not run, with the reason.
var notMapped = map[string]string{
	"10l5540313": "the probe's lake objects are not in the repository; the same ledgers are corpus entries (cap-0088)",
	"10l5540314": "the probe's lake objects are not in the repository; the same ledgers are corpus entries (cap-0088)",
}

// intendedDifferences are vectors where the driver deliberately differs from the throwaway probe.
var intendedDifferences = map[string]string{
	"7c": "the probe converted ScString to a Go string by hand; the SDK has no native ScVal layer, so the driver answers n_a",
	"7d": "the probe converted ScSymbol to a Go string by hand; the SDK has no native ScVal layer, so the driver answers n_a",
}

func probeRequest(v probeVector) (*request, bool) {
	id := 1
	req := &request{XDRCHECK: protocolTag, ID: &id, Op: "run", Entry: "probe/" + v.ID}
	param := func(k string) string { s, _ := v.Params[k].(string); return s }
	native := func() map[string]any {
		kind := param("kind")
		if kind == "" {
			kind = "string"
		}
		return map[string]any{"native": kind, "value": param("value")}
	}
	hexArg := func() map[string]any {
		if v.Hex == nil {
			return map[string]any{"hex": ""}
		}
		return map[string]any{"hex": *v.Hex}
	}
	xdrIn := func(level, typ string) {
		req.Level = level
		req.Input = input{Kind: "xdr", XDRType: typ, XDRHex: v.Hex, Passphrase: param("network")}
	}
	api := func(op string, args map[string]any) {
		req.Level = "L4"
		req.Input = input{Kind: "api", APIOp: op, Args: args, Passphrase: param("network")}
	}
	switch {
	case v.Group == 1 && v.ID == "1c":
		// the vector's value names the pool ID of operation 2, so the request focuses that operation
		xdrIn("L1", "TransactionEnvelope")
		op := 2
		req.Input.Focus = &focus{OpIndex: &op}
	case v.Group == 1:
		code := param("code")
		api("liquidity_pool.id", map[string]any{"asset_a": code + ":" + param("a"), "asset_b": code + ":" + param("b")})
	case v.Group == 2 && strings.HasPrefix(v.ID, "2m"):
		api("muxed_account.encode", map[string]any{"account": param("g"), "id": native()})
	case v.Group == 2:
		api("offer.manage_sell", map[string]any{"offer_id": native(), "buying": "USD:" + param("g")})
	case v.Group == 3:
		xdrIn("L1", "TransactionEnvelope")
	case v.Group == 4:
		api("scval.to_native", map[string]any{"xdr_hex": hexArg()})
	case v.Group == 5:
		api("scval.sort_map", map[string]any{"keys": []any{}})
	case v.ID == "6d2":
		xdrIn("L1", "TransactionEnvelope")
	case v.Group == 6 || v.Group == 8:
		xdrIn("L0", param("type"))
	case v.ID == "7a":
		api("memo.text_roundtrip", map[string]any{"xdr_hex": hexArg()})
	case v.ID == "7b":
		api("operation.object_roundtrip", map[string]any{"xdr_hex": hexArg()})
	case v.Group == 7:
		api("scval.native_roundtrip", map[string]any{"xdr_hex": hexArg()})
	case v.ID == "9E1":
		// a muxed contract's payload is the contract ID followed by the 64-bit ID, big-endian
		id, err := strconv.ParseUint(param("id"), 10, 64)
		if err != nil {
			return nil, false
		}
		api("strkey.encode", map[string]any{"type": "muxed_contract", "payload_hex": param("contract") + fmt.Sprintf("%016x", id)})
	case v.ID == "9E2":
		api("address.from_sc_address", map[string]any{"xdr_hex": hexArg()})
	case v.ID == "9E3":
		// SignerKey ED25519_SIGNED_PAYLOAD (3): the key, then the payload as variable-length opaque
		payload := param("payload")
		pad := strings.Repeat("00", (4-len(payload)/2%4)%4)
		api("signer_key.to_strkey", map[string]any{"xdr_hex": "00000003" + param("key") + fmt.Sprintf("%08x", len(payload)/2) + payload + pad})
	case v.ID == "9E4":
		api("address.to_strkey", map[string]any{"xdr_hex": hexArg(), "xdr_type": "MuxedAccount"})
	case v.Group == 9:
		req.Level = "L4"
		req.Input = input{Kind: "strkey", Text: param("s")}
	default:
		return nil, false
	}
	return req, true
}

func outcomeClass(o string) string {
	switch o {
	case "ok", "wrong", "diverge":
		return "accepted"
	case "reject":
		return "rejected"
	case "n/a", "n_a":
		return "n_a"
	}
	return o
}

// value returns the value of a response the vector's expect.value is comparable with.
func responseValue(v probeVector, resp map[string]any) (string, bool) {
	actual, _ := resp["actual"].(map[string]any)
	if actual == nil {
		return "", false
	}
	if api, isAPI := actual["api"].(map[string]any); isAPI {
		switch v.ID {
		case "7a", "7b":
			s, found := api["xdr_hex"].(string)
			return s, found
		}
		if strings.HasPrefix(v.ID, "2m") {
			// the vector states the id; the driver returns the M address and the XDR, whose last 40 bytes are
			// id || key
			s, _ := api["xdr_hex"].(string)
			if len(s) != 8+16+64 || s[:8] != "00000100" || s[24:] != k1 {
				return "MuxedAccount XDR " + s, true
			}
			id := s[8:24]
			var n uint64
			fmt.Sscanf(id, "%x", &n)
			return fmt.Sprintf("%d", n), true
		}
		s, found := api["value"].(string)
		return s, found
	}
	if obj, isObj := actual["object"].(map[string]any); isObj && v.ID == "1c" {
		h, _ := obj["tx_hash"].(string)
		derived, _ := obj["derived"].(map[string]any)
		pool, _ := derived["pool_id"].(string)
		return "hash=" + h + " pool=" + pool, true
	}
	return "", false
}

func TestReproducesMatrixProbe(t *testing.T) {
	root := repoRoot(t)
	d := startDriver(t)
	ver := d.sdkVersion()
	dir := filepath.Join(root, "evidence", "sdk-matrix")
	raw, err := os.ReadFile(filepath.Join(dir, "vectors", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []probeVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	// A local probe run's file, and with XDRCHECK_OVERLAY set the overlay's file of the same name. A vector with no
	// row is an error only when the overlay's file was read.
	overlay := os.Getenv("XDRCHECK_OVERLAY")
	files := []string{filepath.Join(dir, "results", "go_"+ver+".jsonl")}
	if overlay != "" {
		files = append(files, filepath.Join(overlay, "evidence", "sdk-matrix", "results", "go_"+ver+".jsonl"))
	}
	recorded := map[string]probeResult{}
	read := 0
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		read++
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var r probeResult
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			recorded[r.Vector] = r
		}
		f.Close()
	}
	if read == 0 {
		t.Skipf("no probe results for %s (run evidence/sdk-matrix/run.sh, or set XDRCHECK_OVERLAY)", ver)
	}
	ran, missing := 0, 0
	for _, v := range vectors {
		if why, skip := notMapped[v.ID]; skip {
			t.Logf("%s: not run: %s", v.ID, why)
			continue
		}
		rec, found := recorded[v.ID]
		if !found {
			missing++
			if overlay != "" {
				t.Errorf("%s: no probe result for %s", v.ID, ver)
			}
			continue
		}
		req, mapped := probeRequest(v)
		if !mapped {
			t.Errorf("%s: vector not mapped onto the driver", v.ID)
			continue
		}
		ran++
		resp := d.run(req)
		got := outcomeClass(resp["outcome"].(string))
		want := outcomeClass(rec.Outcome)
		if why, differs := intendedDifferences[v.ID]; differs {
			if got != "n_a" {
				t.Errorf("%s: intended difference (%s) no longer holds: driver %s", v.ID, why, got)
			}
			continue
		}
		if v.ID == "9E1" && got == "n_a" && want == "rejected" && strings.Contains(rec.Detail, "version byte") {
			// Before v0.8.0 the SDK's strkey package has no muxed-contract (W…) type: the probe recorded the
			// encoder's version-byte refusal; the driver protocol calls that n_a/type_not_generated.
			if code, _ := resp["reason"].(map[string]any)["code"].(string); code != "type_not_generated" {
				t.Errorf("9E1: n_a/%s, want type_not_generated", code)
			}
			continue
		}
		if got != want {
			t.Errorf("%s at %s: driver %s (%v), probe %s (%s)", v.ID, req.Level, got, resp["reason"], want, rec.Detail)
			continue
		}
		if rec.Outcome != "ok" {
			continue
		}
		wantVal, hasVal := v.Expect["value"].(string)
		if !hasVal {
			continue
		}
		gotVal, comparable := responseValue(v, resp)
		if !comparable {
			continue
		}
		if gotVal != wantVal {
			t.Errorf("%s: value %q, vector says %q", v.ID, gotVal, wantVal)
		}
	}
	if ran < 100-missing {
		t.Errorf("only %d probe vectors ran", ran)
	}
}

// driverProc is the built driver binary (XDRCHECK_DRIVER_BIN, set by the Makefile's test target), driven over
// stdin and stdout exactly as the orchestrator drives it. The SDK version is only known to the binary: a test
// binary carries no dependency build information.
type driverProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	nextID int
}

func startDriver(t *testing.T, env ...string) *driverProc {
	t.Helper()
	bin := os.Getenv("XDRCHECK_DRIVER_BIN")
	if bin == "" {
		t.Skip("XDRCHECK_DRIVER_BIN is not set")
	}
	cmd := exec.Command(bin)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	d := &driverProc{t: t, cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<20), nextID: 1}
	t.Cleanup(func() {
		resp := d.send(map[string]any{"xcc": protocolTag, "op": "shutdown"})
		if resp["ok"] != true {
			t.Errorf("shutdown answered %v", resp)
		}
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("driver exit: %v", err)
		}
	})
	return d
}

// send writes one request (assigning its id) and reads the one response line.
func (d *driverProc) send(req map[string]any) map[string]any {
	d.t.Helper()
	req["id"] = d.nextID
	d.nextID++
	line, err := json.Marshal(req)
	if err != nil {
		d.t.Fatal(err)
	}
	if _, err := d.stdin.Write(append(line, '\n')); err != nil {
		d.t.Fatal(err)
	}
	out, err := d.stdout.ReadBytes('\n')
	if err != nil {
		d.t.Fatalf("no response to %s: %v", line, err)
	}
	var resp map[string]any
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		d.t.Fatalf("response is not JSON: %v: %s", err, out)
	}
	if resp["id"] != json.Number(strconv.Itoa(req["id"].(int))) {
		d.t.Fatalf("response id %v does not echo %v", resp["id"], req["id"])
	}
	return resp
}

func (d *driverProc) describe() map[string]any {
	return d.send(map[string]any{"xcc": protocolTag, "op": "describe"})
}

func (d *driverProc) sdkVersion() string {
	return d.describe()["sdk"].(map[string]any)["version"].(string)
}

// run sends a run request built from the driver's own request type.
func (d *driverProc) run(req *request) map[string]any {
	d.t.Helper()
	m := map[string]any{"xcc": protocolTag, "op": "run", "entry": req.Entry, "level": req.Level}
	in := map[string]any{"kind": req.Input.Kind}
	put := func(k string, v any, present bool) {
		if present {
			in[k] = v
		}
	}
	put("xdr_type", req.Input.XDRType, req.Input.XDRType != "")
	put("path", req.Input.Path, req.Input.Path != "")
	if req.Input.XDRHex != nil {
		in["xdr_hex"] = *req.Input.XDRHex
	}
	put("passphrase", req.Input.Passphrase, req.Input.Passphrase != "")
	put("api_op", req.Input.APIOp, req.Input.APIOp != "")
	put("args", req.Input.Args, req.Input.Kind == "api")
	put("text", req.Input.Text, req.Input.Kind == "strkey")
	put("pinpoints", req.Input.Pinpoints, req.Input.Pinpoints != nil)
	if f := req.Input.Focus; f != nil {
		fm := map[string]any{}
		if f.TxIndex != nil {
			fm["tx_index"] = *f.TxIndex
		}
		if f.OpIndex != nil {
			fm["op_index"] = *f.OpIndex
		}
		in["focus"] = fm
	}
	m["input"] = in
	if req.Variant != "" {
		m["variant"] = req.Variant
	}
	if req.Profile != "" {
		m["profile"] = req.Profile
	}
	resp := d.send(m)
	if resp["op"] == "protocol_error" {
		d.t.Fatalf("protocol_error for %v: %v", m, resp["error"])
	}
	if resp["entry"] != req.Entry || resp["level"] != req.Level {
		d.t.Fatalf("response does not echo entry and level: %v", resp)
	}
	return resp
}
