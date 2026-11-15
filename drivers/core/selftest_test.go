package main

// The core driver's own checks, run by `make test` after `make build`. They drive the built bin/xdrcheck-driver
// over the protocol, as the orchestrator does, and check:
//
//  1. describe: package, the version read from the binary, the binary's sha256 against pins.toml, the schema
//     probes (and that the probe values are built right: the declared control arm decodes, an undeclared arm
//     does not), every level declared (only L0 decodes; the rest answer a typed n_a), no api ops.
//  2. The executed print-xdr transcripts in evidence/core-print-xdr/out/: every case the driver can express
//     (all but `auto`) is replayed at L0. Accept and reject must match the transcript, a reject must carry
//     core's message verbatim and the reason code listed in wantCode, and an accept must carry
//     consumed_bytes and no reencoded_sha256. The binary is also run exactly as the transcript ran it and must
//     print the same standard output.
//  3. The nesting boundaries in evidence/core-print-xdr/out/depth.txt.
//  4. The golden LedgerCloseMeta stream in evidence/core-print-xdr/in/: every record decodes at L0 as a
//     record-marked frame, as many as the dump-xdr transcript counted; the truncated copy's incomplete record
//     is refused by the frame reader.
//  5. Every vendored ledger variant in corpus/manifest decodes at L0 with all its bytes consumed, unless the
//     manifest declares a known divergence for this version (asserted instead) or the pending list names the
//     cell (expected_test.go); the same
//     bytes with 4 trailing bytes are refused for trailing bytes (dump-xdr listed as the lenient entry point
//     that accepts them), and without their last 4 bytes for length.
//  6. Protocol hygiene: typed n_a for L1-L4, unknown types, type-name spelling, protocol errors, shutdown.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// wantCode is the reason code each refused transcript case must carry, read off core's message by hand.
var wantCode = map[string]string{
	"optional-flag-2":                 "optional_flag_range",
	"string-pad-nonzero":              "nonzero_padding",
	"bytes-pad-nonzero":               "nonzero_padding",
	"symbol-pad-nonzero":              "nonzero_padding",
	"trailing-4":                      "trailing_bytes",
	"trailing-1":                      "decode_error", // "message size not multiple of 4": xdrpp checks it before decoding
	"truncated":                       "decode_error", // the same check; a 6-byte input
	"enum-undeclared-scerrortype":     "union_arm_undeclared",
	"union-undeclared-scvaltype":      "union_arm_undeclared",
	"union-undeclared-scvaltype-bare": "union_arm_undeclared",
	"union-undeclared-scaddresstype":  "union_arm_undeclared",
	"symbol-33":                       "length_exceeds_max",
	"signers-21":                      "length_exceeds_max",
	"map-depth-375":                   "depth",
}

// filetypeType maps the transcripts' print-xdr file types onto the XDR type names a run request carries.
var filetypeType = map[string]string{"scval": "ScVal", "ledgerentry": "LedgerEntry"}

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run these checks with make -C drivers/core test", name)
	}
	return v
}

// pin reads a scalar from pins.toml [stellar_core].
func pin(t *testing.T, key string) string {
	t.Helper()
	b, err := os.ReadFile(env(t, "XDRCHECK_PINS"))
	if err != nil {
		t.Fatal(err)
	}
	section := ""
	re := regexp.MustCompile(`^(\w+)\s*=\s*"([^"]*)"`)
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			section = strings.TrimSpace(strings.SplitN(strings.Trim(l, "[]"), "]", 2)[0])
			continue
		}
		if m := re.FindStringSubmatch(l); m != nil && section == "stellar_core" && m[1] == key {
			return m[2]
		}
	}
	t.Fatalf("pins.toml has no [stellar_core] %s", key)
	return ""
}

type client struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr bytes.Buffer
	next   int
}

func start(t *testing.T) *client {
	t.Helper()
	c := &client{t: t, cmd: exec.Command(env(t, "XDRCHECK_DRIVER_BIN")), next: 1}
	c.cmd.Stderr = &c.stderr
	var err error
	if c.in, err = c.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.out = bufio.NewReaderSize(stdout, 1<<20)
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.in.Close()
		c.cmd.Wait()
	})
	return c
}

func (c *client) raw(line string) map[string]any {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatalf("write: %v (stderr %s)", err, c.stderr.String())
	}
	resp, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read: %v (stderr %s)", err, c.stderr.String())
	}
	var m map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		c.t.Fatalf("driver wrote non-JSON %q: %v", resp, err)
	}
	return m
}

func (c *client) call(req map[string]any) map[string]any {
	c.t.Helper()
	req["xcc"] = tag
	req["id"] = c.next
	c.next++
	b, _ := json.Marshal(req)
	r := c.raw(string(b))
	if r["op"] != "protocol_error" && r["id"] != float64(c.next-1) {
		c.t.Fatalf("response id %v, request id %d", r["id"], c.next-1)
	}
	return r
}

func (c *client) run(level string, input map[string]any) map[string]any {
	c.t.Helper()
	return c.call(map[string]any{"op": "run", "entry": "selftest/x", "variant": "none", "level": level, "input": input})
}

func (c *client) l0(xdrType string, raw []byte) map[string]any {
	c.t.Helper()
	return c.run("L0", map[string]any{"kind": "xdr", "xdr_type": xdrType, "xdr_hex": hex.EncodeToString(raw)})
}

func outcome(r map[string]any) string { s, _ := r["outcome"].(string); return s }

func reasonField(r map[string]any, k string) string {
	m, _ := r["reason"].(map[string]any)
	s, _ := m[k].(string)
	return s
}

func actualField(r map[string]any, k string) any {
	m, _ := r["actual"].(map[string]any)
	return m[k]
}

// wantOK checks an L0 accept: consumed_bytes is the input length and there is no re-encoding.
func wantOK(t *testing.T, what string, r map[string]any, n int) {
	t.Helper()
	if outcome(r) != "ok" || actualField(r, "consumed_bytes") != float64(n) || actualField(r, "reencoded_sha256") != nil {
		t.Errorf("%s: want ok with consumed_bytes %d, got %v", what, n, r)
	}
}

func wantReject(t *testing.T, what string, r map[string]any, code string) {
	t.Helper()
	if outcome(r) != "reject" || reasonField(r, "code") != code {
		t.Errorf("%s: want reject/%s, got %v", what, code, r)
	}
}

func root(t *testing.T) string { return env(t, "XDRCHECK_ROOT") }

func TestDescribe(t *testing.T) {
	c := start(t)
	d := c.call(map[string]any{"op": "describe"})
	sdk, _ := d["sdk"].(map[string]any)
	if sdk["ecosystem"] != "other" || sdk["package"] != "stellar-core" {
		t.Errorf("describe sdk: %v", sdk)
	}
	if v := pin(t, "version"); sdk["version"] != v {
		t.Errorf("describe sdk.version %v, pinned %s", sdk["version"], v)
	}
	if want := "sha256:" + pin(t, "binary_sha256"); sdk["integrity"] != want {
		t.Errorf("describe sdk.integrity %v, pinned %s", sdk["integrity"], want)
	}
	schema, _ := d["xdr_schema"].(map[string]any)
	probes, _ := schema["probes"].(map[string]any)
	if probes["sc_address_type_muxed_contract"] != true || probes["stellar_value_signed_ms"] != true || schema["protocol"] != float64(30) {
		t.Errorf("describe xdr_schema: %v", schema)
	}
	if fmt.Sprint(d["levels"]) != "[L0 L1 L2 L3 L4]" || fmt.Sprint(d["api_ops"]) != "[]" {
		t.Errorf("describe levels %v, api_ops %v", d["levels"], d["api_ops"])
	}
	dec, _ := d["decode"].(map[string]any)
	if dec["default_depth"] != float64(1500) || dec["checks_consumed_length"] != false || !strings.Contains(fmt.Sprint(dec["entry_point"]), "no reencoded_sha256") {
		t.Errorf("describe decode: %v", dec)
	}

	// The probe values: the control arm decodes and an undeclared arm is refused, so a false probe would mean
	// the binary lacks the arm and not that the bytes are wrong.
	for _, p := range []struct {
		what, typ string
		raw       []byte
		want      string
	}{
		{"LedgerHeader with StellarValueType 0", "LedgerHeader", probeLedgerHeader(0), "ok"},
		{"LedgerHeader with StellarValueType 5", "LedgerHeader", probeLedgerHeader(5), "reject"},
		{"SCAddress arm 6", "ScVal", append(u32(u32(nil, 18), 6), make([]byte, 40)...), "reject"},
	} {
		if r := c.l0(p.typ, p.raw); outcome(r) != p.want {
			t.Errorf("%s: want %s, got %v", p.what, p.want, r)
		}
	}
}

// transcript is one case file of evidence/core-print-xdr/out.
type transcript struct {
	name, filetype string
	input          []byte
	stdout         string
	errLine        string // core's message after its prefix; empty when the value was accepted
	accepted       bool
}

var (
	cmdRE   = regexp.MustCompile(`(?m)^\$ \S+ print-xdr --filetype (\w+) \S+$`)
	inputRE = regexp.MustCompile(`(?m)^input hex \((\d+) B\): ([0-9a-f]*)$`)
)

func readTranscripts(t *testing.T) []transcript {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root(t), "evidence/core-print-xdr/out/*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no transcripts: %v", err)
	}
	var out []transcript
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		cm, im := cmdRE.FindStringSubmatch(s), inputRE.FindStringSubmatch(s)
		if cm == nil || im == nil {
			continue // auto file type, depth summary, dump-xdr and invocation notes
		}
		tr := transcript{name: strings.TrimSuffix(filepath.Base(f), ".txt"), filetype: cm[1]}
		if tr.input, err = hex.DecodeString(im[2]); err != nil || strconv.Itoa(len(tr.input)) != im[1] {
			t.Fatalf("%s: input hex does not match its length", f)
		}
		o := strings.Index(s, "--- stdout ---\n")
		e := strings.Index(s, "--- stderr ---\n")
		x := strings.Index(s, "--- exit code: ")
		if o < 0 || e < o || x < e {
			t.Fatalf("%s: not a transcript", f)
		}
		tr.stdout = s[o+len("--- stdout ---\n") : e]
		prefix := "Could not decode with type '" + tr.filetype + "' : "
		for _, l := range strings.Split(s[e:x], "\n") {
			if strings.HasPrefix(l, prefix) {
				tr.errLine = strings.TrimPrefix(l, prefix)
			}
		}
		tr.accepted = tr.errLine == ""
		if strings.TrimSpace(s[x+len("--- exit code: "):]) != "0" {
			t.Fatalf("%s: print-xdr exits 0 on every decode, the transcript says otherwise", f)
		}
		out = append(out, tr)
	}
	return out
}

// backslashReplace renders bytes the way the transcripts were written: UTF-8, with every byte that is not part
// of a valid sequence as \xNN.
func backslashReplace(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 {
			fmt.Fprintf(&sb, `\x%02x`, b[0])
			b = b[1:]
			continue
		}
		sb.Write(b[:n])
		b = b[n:]
	}
	return sb.String()
}

func TestTranscripts(t *testing.T) {
	c := start(t)
	trs := readTranscripts(t)
	binary := filepath.Join(env(t, "XDRCHECK_CACHE_DIR"), "stellar-core", pin(t, "version"), "pkg/usr/bin/stellar-core")
	lib := filepath.Join(filepath.Dir(filepath.Dir(binary)), "lib/x86_64-linux-gnu")
	dir := t.TempDir()
	rejected := 0
	for _, tr := range trs {
		typ, ok := filetypeType[tr.filetype]
		if !ok {
			t.Errorf("%s: file type %s has no type mapping in this test", tr.name, tr.filetype)
			continue
		}
		r := c.l0(typ, tr.input)
		if tr.accepted {
			wantOK(t, tr.name, r, len(tr.input))
		} else {
			rejected++
			code, listed := wantCode[tr.name]
			if !listed {
				t.Errorf("%s: refused case missing from wantCode (core says %q)", tr.name, tr.errLine)
			}
			wantReject(t, tr.name, r, code)
			if got := reasonField(r, "message"); got != tr.errLine {
				t.Errorf("%s: message %q, transcript %q", tr.name, got, tr.errLine)
			}
			if got := reasonField(r, "entry_point"); got != "stellar-core print-xdr --filetype "+tr.filetype {
				t.Errorf("%s: entry_point %q", tr.name, got)
			}
		}

		// The binary itself, run as the transcript ran it, prints the same.
		in := filepath.Join(dir, tr.name+".bin")
		if err := os.WriteFile(in, tr.input, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "print-xdr", "--filetype", tr.filetype, in)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+lib)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			t.Errorf("%s: print-xdr: %v", tr.name, err)
		}
		if got := backslashReplace(out.Bytes()); got != tr.stdout {
			t.Errorf("%s: print-xdr stdout\n%s\ntranscript\n%s", tr.name, got, tr.stdout)
		}
		if !strings.Contains(errOut.String(), tr.errLine) {
			t.Errorf("%s: print-xdr stderr %q, transcript %q", tr.name, errOut.String(), tr.errLine)
		}
	}
	if rejected == 0 || rejected == len(trs) {
		t.Errorf("transcripts: %d of %d refused; expected both outcomes", rejected, len(trs))
	}
	t.Logf("transcripts replayed: %d (%d refused)", len(trs), rejected)
}

func nest(levels int, level []byte) []byte {
	return append(bytes.Repeat(level, levels), u32(nil, 1)...) // around SCV_VOID
}

func TestDepth(t *testing.T) {
	c := start(t)
	b, err := os.ReadFile(filepath.Join(root(t), "evidence/core-print-xdr/out/depth.txt"))
	if err != nil {
		t.Fatal(err)
	}
	levels := map[string][]byte{
		"VEC": hexBytes("000000100000000100000001"),         // SCV_VEC, present, one element
		"MAP": hexBytes("00000011000000010000000100000001"), // SCV_MAP, present, one entry, key SCV_VOID
	}
	re := regexp.MustCompile(`nested SCV_(\w+): largest accepted (\d+), first rejected (\d+)`)
	ms := re.FindAllStringSubmatch(string(b), -1)
	if len(ms) != len(levels) {
		t.Fatalf("depth.txt: %q", b)
	}
	for _, m := range ms {
		ok, _ := strconv.Atoi(m[2])
		bad, _ := strconv.Atoi(m[3])
		wantOK(t, fmt.Sprintf("%d nested SCV_%s", ok, m[1]), c.l0("ScVal", nest(ok, levels[m[1]])), len(nest(ok, levels[m[1]])))
		wantReject(t, fmt.Sprintf("%d nested SCV_%s", bad, m[1]), c.l0("ScVal", nest(bad, levels[m[1]])), "depth")
	}
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// frames splits a record-marked stream; the last element is set when the stream ends inside a record.
func frames(b []byte) (complete [][]byte, cut bool) {
	for pos := 0; pos < len(b); {
		if len(b)-pos < 4 {
			return complete, true
		}
		n := int(binary.BigEndian.Uint32(b[pos:]) & 0x7fffffff)
		if pos+4+n > len(b) {
			return complete, true
		}
		complete = append(complete, b[pos+4:pos+4+n])
		pos += 4 + n
	}
	return complete, false
}

func TestGoldenStream(t *testing.T) {
	c := start(t)
	dir := filepath.Join(root(t), "evidence/core-print-xdr")
	note, err := os.ReadFile(filepath.Join(dir, "out/dump-xdr.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`records: (\d+)`).FindSubmatch(note)
	if m == nil {
		t.Fatal("dump-xdr.txt states no record count")
	}
	for _, name := range []string{"meta-golden-4c437318.xdr", "meta-truncated.xdr"} {
		path := filepath.Join(dir, "in", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fs, cut := frames(b)
		if name == "meta-golden-4c437318.xdr" && (cut || strconv.Itoa(len(fs)) != string(m[1])) {
			t.Errorf("%s: %d frames (cut %v); dump-xdr printed %s records", name, len(fs), cut, m[1])
		}
		for i, f := range fs {
			r := c.run("L0", map[string]any{"kind": "xdr", "xdr_type": "LedgerCloseMeta", "path": path, "framing": "record-marked", "frame_index": i})
			wantOK(t, fmt.Sprintf("%s frame %d", name, i), r, len(f))
		}
		if cut {
			r := c.run("L0", map[string]any{"kind": "xdr", "xdr_type": "LedgerCloseMeta", "path": path, "framing": "record-marked", "frame_index": len(fs)})
			wantReject(t, fmt.Sprintf("%s incomplete frame %d", name, len(fs)), r, "decode_error")
			if reasonField(r, "entry_point") != "record marks (driver)" {
				t.Errorf("incomplete frame: %v", r)
			}
		}
		t.Logf("%s: %d frames decoded, cut %v", name, len(fs), cut)
	}
}

type ledgerVariant struct {
	entry, key, path string // key: the report's variant key
	bytes            int
	sha256           string
	manifest         *manifestEntry
}

func corpusLedgers(t *testing.T) []ledgerVariant {
	t.Helper()
	corpus := filepath.Join(root(t), "corpus")
	var out []ledgerVariant
	err := filepath.WalkDir(filepath.Join(corpus, "manifest"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		e := &manifestEntry{}
		if err := json.Unmarshal(b, e); err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if e.Kind != "ledger" {
			return nil
		}
		for _, v := range e.Variants {
			if v.Blob != nil && v.XDRType == "LedgerCloseMeta" {
				out = append(out, ledgerVariant{e.ID, e.variantKey(v.Network, v.Protocol), filepath.Join(corpus, v.Blob.Path), v.Blob.Bytes, v.Blob.SHA256, e})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	if len(out) == 0 {
		t.Fatal("the corpus has no ledger variants")
	}
	return out
}

func TestCorpusLedgers(t *testing.T) {
	c := start(t)
	expect := loadExpectations(t, root(t), pin(t, "version"))
	var decoded []ledgerVariant
	for _, v := range corpusLedgers(t) {
		b, err := os.ReadFile(v.path)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != v.sha256 || len(b) != v.bytes {
			t.Fatalf("%s: blob does not match the manifest", v.path)
		}
		r := c.run("L0", map[string]any{"kind": "xdr", "xdr_type": "LedgerCloseMeta", "path": v.path})
		what := v.entry + " (" + v.key + ")"
		if k, pending := expect.at(v.manifest, v.key, "L0"); k != nil {
			if outcome(r) != k.Outcome || (k.Match.Reason != "" && reasonField(r, "code") != k.Match.Reason) {
				t.Errorf("%s: the declared %s/%s, got %v", what, k.Outcome, k.Match.Reason, r)
			}
			continue
		} else if pending && outcome(r) != "ok" {
			continue // a divergence awaiting a finding
		}
		wantOK(t, what, r, v.bytes)
		decoded = append(decoded, v)
	}
	t.Logf("vendored ledger variants decoded: %d", len(decoded))
	if len(decoded) == 0 {
		t.Fatal("no vendored ledger variant decodes")
	}

	// The smallest one, with 4 trailing bytes and with its last 4 bytes missing.
	small := decoded[0]
	for _, v := range decoded {
		if v.bytes < small.bytes {
			small = v
		}
	}
	b, _ := os.ReadFile(small.path)
	r := c.l0("LedgerCloseMeta", append(append([]byte{}, b...), 0, 0, 0, 0))
	wantReject(t, "ledger with 4 trailing bytes", r, "trailing_bytes")
	lenient, _ := actualField(r, "lenient_entry_points").([]any)
	want := fmt.Sprintf("accepted with 4 trailing bytes (consumed %d of %d)", len(b), len(b)+4)
	if len(lenient) != 1 || lenient[0].(map[string]any)["accepted"] != true || lenient[0].(map[string]any)["note"] != want {
		t.Errorf("ledger with 4 trailing bytes: lenient entry points %v, want note %q", lenient, want)
	}
	wantReject(t, "ledger without its last 4 bytes", c.l0("LedgerCloseMeta", b[:len(b)-4]), "length_exceeds_input")
}

func TestProtocol(t *testing.T) {
	c := start(t)
	small := map[string]any{"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": "00000001"}
	for level, code := range map[string]string{"L1": "no_object_layer", "L2": "other", "L3": "no_native_layer"} {
		if r := c.run(level, small); outcome(r) != "n_a" || reasonField(r, "code") != code || reasonField(r, "message") == "" {
			t.Errorf("%s: want n_a/%s with a message, got %v", level, code, r)
		}
	}
	for _, in := range []map[string]any{
		{"kind": "api", "api_op": "strkey.encode", "args": map[string]any{}},
		{"kind": "strkey", "text": "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"},
	} {
		if r := c.run("L4", in); outcome(r) != "n_a" || reasonField(r, "code") != "op_not_supported" {
			t.Errorf("L4 %v: got %v", in["kind"], r)
		}
	}
	if r := c.run("L0", map[string]any{"kind": "xdr", "xdr_type": "NoSuchType", "xdr_hex": "00"}); outcome(r) != "n_a" || reasonField(r, "code") != "type_not_generated" {
		t.Errorf("unknown type: %v", r)
	}
	for _, name := range []string{"SCVal", "ScVal", "scval"} {
		wantOK(t, "type spelling "+name, c.l0(name, hexBytes("00000001")), 4)
	}
	r := c.run("L0", map[string]any{"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": "80000004000000018000000800000003000000ff", "framing": "record-marked", "frame_index": 1})
	wantOK(t, "record-marked frame 1", r, 8)
	if r["entry"] != "selftest/x" || r["variant"] != "none" || r["level"] != "L0" {
		t.Errorf("echo: %v", r)
	}
	if r := c.call(map[string]any{"op": "run", "entry": "selftest/x", "level": "L0", "profile": "limits-default", "input": small}); r["op"] != "protocol_error" {
		t.Errorf("a profile the driver does not offer: %v", r)
	}
	if r := c.raw("this is not JSON"); r["op"] != "protocol_error" {
		t.Errorf("garbage line: %v", r)
	}
	if r := c.call(map[string]any{"op": "fly"}); r["op"] != "protocol_error" || r["id"] == nil {
		t.Errorf("unknown op: %v", r)
	}
	if r := c.call(map[string]any{"op": "shutdown"}); r["ok"] != true || r["op"] != "shutdown" {
		t.Errorf("shutdown: %v", r)
	}
	if err := c.cmd.Wait(); err != nil {
		t.Errorf("exit after shutdown: %v", err)
	}
}

// TestReasonCodes covers the message classification and the frame reader without the binary.
func TestReasonCodes(t *testing.T) {
	for msg, code := range map[string]string{
		"xdr::pointer size must be 0 or 1":                "optional_flag_range",
		"Non-zero padding bytes encountered":              "nonzero_padding",
		"unmarshaling did not consume whole message":      "trailing_bytes",
		"xdr_generic_get: message size not multiple of 4": "decode_error",
		"insufficient buffer space in xdr_generic_get":    "length_exceeds_input",
		"stack overflow in xdr_generic_get":               "depth",
		"xstring overflow":                                "length_exceeds_max",
		"xvector overflow":                                "length_exceeds_max",
		"bad value of type in SCVal":                      "union_arm_undeclared",
		"Invalid enum value":                              "enum_undeclared",
		"something new":                                   "decode_error",
	} {
		if got := reasonCode(msg); got != code {
			t.Errorf("reasonCode(%q) = %s, want %s", msg, got, code)
		}
	}
	two := hexBytes("80000004000000018000000800000003000000ff")
	if f, err := frame(two, 1); err != nil || hex.EncodeToString(f) != "00000003000000ff" {
		t.Errorf("frame 1: %x %v", f, err)
	}
	for _, bad := range []string{"0000000400000001", "80000008000000", "80"} {
		if _, err := frame(hexBytes(bad), 0); err == nil {
			t.Errorf("frame of %s: no error", bad)
		}
	}
	if _, err := frame(two, 2); err == nil {
		t.Error("frame 2 of 2: no error")
	}
}
