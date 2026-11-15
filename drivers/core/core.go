package main

// Running the stellar-core binary and classifying what it did.
//
// Two offline commands decode XDR (stellar-core src/main/dumpxdr.cpp at the pinned tag):
//
//   - print-xdr reads the whole input as one value of the given --filetype with xdrpp's xdr_from_opaque, which
//     rejects bytes left over (evidence/core-print-xdr/out/trailing-4.txt). On failure it prints
//     `Could not decode with type '<t>' : <message>` to standard error and still exits 0.
//   - dump-xdr reads a record-marked stream whose type it picks from the file name (meta-*.xdr is
//     LedgerCloseMeta). Its record reader decodes each record without checking that the value used the whole
//     record, so it accepts bytes left over at the end of a record. On failure it logs
//     `Got an exception: <message>` and exits 1 (evidence/core-print-xdr/out/dump-xdr.txt).
//
// For dump-xdr types the driver therefore checks consumption itself. XDR decoding reads its input front to
// back and only ever asks for more bytes, so a decode that consumes k bytes of an n-byte record succeeds on
// every prefix of at least k bytes and fails on every shorter one (all lengths are multiples of 4, which
// xdrpp checks first). The value consumed the whole record exactly when the record without its last 4 bytes
// is refused; otherwise the driver finds k by bisection and reports trailing bytes.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// decoder is how one XDR type is decoded: print-xdr with a file type, or dump-xdr on a one-record stream
// whose file name selects the type.
type decoder struct {
	name     string // the XDR spelling
	filetype string // print-xdr --filetype; empty for dump-xdr types
	raw      bool   // print-xdr --raw (TransactionMeta: no change-order normalisation)
	stream   string // dump-xdr file name; it must match the command's file-name pattern for the type
}

// decoders lists every type the column can decode, in print-xdr's file-type order, then dump-xdr's.
var decoders = []decoder{
	{name: "Asset", filetype: "asset"},
	{name: "LedgerEntry", filetype: "ledgerentry"},
	{name: "LedgerHeader", filetype: "ledgerheader"},
	{name: "TransactionMeta", filetype: "meta", raw: true},
	{name: "TransactionResult", filetype: "result"},
	{name: "TransactionResultPair", filetype: "resultpair"},
	{name: "TransactionEnvelope", filetype: "tx"},
	{name: "LedgerEntryChanges", filetype: "txfee"},
	{name: "SCVal", filetype: "scval"},
	{name: "LedgerCloseMeta", stream: "meta-0.xdr"},
	{name: "LedgerHeaderHistoryEntry", stream: "ledger-0.xdr"},
	{name: "TransactionHistoryEntry", stream: "transactions-0.xdr"},
	{name: "TransactionHistoryResultEntry", stream: "results-0.xdr"},
	{name: "BucketEntry", stream: "bucket-0.xdr"},
	{name: "SCPHistoryEntry", stream: "scp-0.xdr"},
}

func typeNames() []string {
	out := make([]string, len(decoders))
	for i, d := range decoders {
		out[i] = d.name
	}
	return out
}

// lookup finds a type by name, ignoring case, so both the XDR spelling (SCVal) and the Rust one (ScVal) work.
func lookup(name string) (decoder, bool) {
	for _, d := range decoders {
		if strings.EqualFold(d.name, name) {
			return d, true
		}
	}
	return decoder{}, false
}

func (d decoder) entryPoint() string {
	if d.filetype != "" {
		ep := "stellar-core print-xdr --filetype " + d.filetype
		if d.raw {
			ep += " --raw"
		}
		return ep
	}
	return "stellar-core dump-xdr (" + d.stream + ")"
}

// Core is the located binary.
type Core struct {
	binary      string
	libDir      string
	version     string // as `stellar-core version` prints it, for example 30.0.0
	versionLine string // the whole first line, with the commit
	protocol    int    // the ledger protocol version the binary reports as its own; 0 when it prints none
	sha256      string // of the binary
	tmp         string // scratch directory for dump-xdr streams, made on first use
}

var versionRE = regexp.MustCompile(`(?m)^(stellar-core (\S+) \([0-9a-f]+\))\s*$`)

// protocolRE is the binary's own ledger protocol line; the indented ones below it are the bundled hosts'.
var protocolRE = regexp.MustCompile(`(?m)^ledger protocol version: ([0-9]+)\s*$`)

// locateCore finds the pinned package in the driver's cache ($XDRCHECK_CACHE_DIR, else the directory the build used)
// and reads the version from the binary itself.
func locateCore() (*Core, error) {
	cache := os.Getenv("XDRCHECK_CACHE_DIR")
	if cache == "" {
		cache = defaultCacheDir
	}
	if cache == "" || coreVersion == "" {
		return nil, errors.New("built without the cache directory or the pinned version; build with make build")
	}
	pkg := filepath.Join(cache, "stellar-core", coreVersion, "pkg")
	c := &Core{
		binary: filepath.Join(pkg, "usr", "bin", "stellar-core"),
		libDir: filepath.Join(pkg, "usr", "lib", "x86_64-linux-gnu"),
	}
	f, err := os.Open(c.binary)
	if err != nil {
		return nil, fmt.Errorf("no stellar-core binary (run make fetch): %w", err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return nil, err
	}
	c.sha256 = hex.EncodeToString(h.Sum(nil))
	out, errOut, _, err := c.run([]string{"version"}, nil)
	if err != nil {
		return nil, fmt.Errorf("stellar-core version: %w", err)
	}
	m := versionRE.FindSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("stellar-core version printed no version line: %q", trim(string(out)+string(errOut)))
	}
	c.versionLine, c.version = string(m[1]), string(m[2])
	if m := protocolRE.FindSubmatch(out); m != nil {
		c.protocol, _ = strconv.Atoi(string(m[1]))
	}
	return c, nil
}

func (c *Core) close() {
	if c.tmp != "" {
		os.RemoveAll(c.tmp)
	}
}

// run executes the binary with the given arguments and input. It returns standard output, standard error and
// the process state; err is set only when the process could not be started or waited for.
func (c *Core) run(args []string, stdin []byte) ([]byte, []byte, *os.ProcessState, error) {
	cmd := exec.Command(c.binary, args...)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+c.libDir)
	// The working directory is the scratch directory, so nothing core might write lands in the driver's.
	if dir, err := c.scratch(); err == nil {
		cmd.Dir = dir
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	// The decoder dies with the driver when the orchestrator kills it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		err = nil
	}
	return out.Bytes(), errOut.Bytes(), cmd.ProcessState, err
}

// scratch returns the driver's scratch directory, under $XDRCHECK_CACHE_DIR when it is set.
func (c *Core) scratch() (string, error) {
	if c.tmp != "" {
		return c.tmp, nil
	}
	base := os.TempDir()
	if cache := os.Getenv("XDRCHECK_CACHE_DIR"); cache != "" {
		if err := os.MkdirAll(filepath.Join(cache, "tmp"), 0o755); err == nil {
			base = filepath.Join(cache, "tmp")
		}
	}
	dir, err := os.MkdirTemp(base, "driver-")
	if err != nil {
		return "", err
	}
	c.tmp = dir
	return dir, nil
}

// decodeResult is what one decode did.
type decodeResult struct {
	accepted bool
	crashed  bool   // the process died or exited in a way the command never does for a decode failure
	message  string // core's error message (the part after its prefix), or the crash description
}

// decode runs one decode of raw as type d.
func (c *Core) decode(d decoder, raw []byte) (decodeResult, error) {
	if d.filetype != "" {
		args := []string{"print-xdr", "--filetype", d.filetype, "--compact"}
		if d.raw {
			args = append(args, "--raw")
		}
		// "stdin" is print-xdr's name for standard input; the whole input is read as one value.
		out, errOut, st, err := c.run(append(args, "stdin"), raw)
		if err != nil {
			return decodeResult{}, err
		}
		prefix := "Could not decode with type '" + d.filetype + "' : "
		if msg, ok := findLine(errOut, prefix); ok {
			return decodeResult{message: msg}, nil
		}
		if !st.Success() || len(bytes.TrimSpace(out)) == 0 {
			return decodeResult{crashed: true, message: crashMessage(st, errOut)}, nil
		}
		return decodeResult{accepted: true}, nil
	}
	if len(raw) > 0x7fffffff {
		return decodeResult{message: "the value is longer than one record can hold"}, nil
	}
	dir, err := c.scratch()
	if err != nil {
		return decodeResult{}, err
	}
	path := filepath.Join(dir, d.stream)
	stream := binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(len(raw)))
	if err := os.WriteFile(path, append(stream, raw...), 0o644); err != nil {
		return decodeResult{}, err
	}
	defer os.Remove(path)
	_, errOut, st, err := c.run([]string{"dump-xdr", "--compact", path}, nil)
	if err != nil {
		return decodeResult{}, err
	}
	if st.Success() {
		return decodeResult{accepted: true}, nil
	}
	if msg, ok := findLine(errOut, "Got an exception: "); ok && st.ExitCode() == 1 {
		return decodeResult{message: msg}, nil
	}
	return decodeResult{crashed: true, message: crashMessage(st, errOut)}, nil
}

// accepts reports whether core decodes raw as the named type; used for the describe probes.
func (c *Core) accepts(name string, raw []byte) bool {
	d, ok := lookup(name)
	if !ok {
		return false
	}
	r, err := c.decode(d, raw)
	return err == nil && r.accepted
}

// findLine returns the rest of the first line of b that contains prefix.
func findLine(b []byte, prefix string) (string, bool) {
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64<<10), 16<<20)
	for s.Scan() {
		if i := strings.Index(s.Text(), prefix); i >= 0 {
			return s.Text()[i+len(prefix):], true
		}
	}
	return "", false
}

func crashMessage(st *os.ProcessState, errOut []byte) string {
	lines := strings.Split(strings.TrimSpace(string(errOut)), "\n")
	lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "Warning: running non-release version") })
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return fmt.Sprintf("stellar-core %s: %s", st.String(), strings.Join(lines, " | "))
}

// reasonCode maps core's error message onto the protocol's reason codes. The messages are xdrpp's and those of
// its generated code at the submodule commit stellar-core pins; anything else is decode_error.
func reasonCode(msg string) string {
	switch {
	case strings.Contains(msg, "pointer size must be 0 or 1"):
		return "optional_flag_range"
	case strings.Contains(msg, "Non-zero padding bytes"):
		return "nonzero_padding"
	case strings.Contains(msg, "did not consume whole message"):
		return "trailing_bytes"
	case strings.Contains(msg, "insufficient buffer space"):
		return "length_exceeds_input"
	case strings.Contains(msg, "stack overflow in xdr_generic_get"):
		return "depth"
	case strings.Contains(msg, "xstring overflow"), strings.Contains(msg, "xvector overflow"):
		return "length_exceeds_max"
	case strings.HasPrefix(msg, "bad value of "):
		// Generated union code: an undeclared discriminant.
		return "union_arm_undeclared"
	case strings.Contains(msg, "Invalid enum value"):
		return "enum_undeclared"
	default:
		// Includes "message size not multiple of 4", which xdrpp checks before decoding: it cannot tell a
		// truncated value from trailing bytes.
		return "decode_error"
	}
}

// crashCode classifies a decoder process that died. Core installs a new-handler that aborts when an
// allocation fails, so running out of memory is a crash, never a decode error.
func crashCode(msg string) string {
	if l := strings.ToLower(msg); strings.Contains(l, "out of memory") || strings.Contains(l, "allocate memory") {
		return "out_of_memory"
	}
	return "other"
}

// runL0 is the L0 cell: decode, then (dump-xdr types) the consumed-length check.
func runL0(c *Core, in *xdrInput) (result, error) {
	d, ok := lookup(in.XDRType)
	if !ok {
		return result{Outcome: "n_a", Reason: &reason{
			Code:    "type_not_generated",
			Message: trim(fmt.Sprintf("stellar-core's offline decoders read only %s; not %s", strings.Join(typeNames(), ", "), in.XDRType)),
		}}, nil
	}
	raw, rej, err := inputBytes(in)
	if err != nil || rej != nil {
		if rej != nil {
			return *rej, nil
		}
		return result{}, err
	}
	r, err := c.decode(d, raw)
	if err != nil {
		return result{}, err
	}
	switch {
	case r.crashed:
		return result{Outcome: "crash", Reason: &reason{Code: crashCode(r.message), Message: trim(r.message), EntryPoint: d.entryPoint()}}, nil
	case !r.accepted:
		return result{Outcome: "reject", Reason: &reason{Code: reasonCode(r.message), Message: trim(r.message), EntryPoint: d.entryPoint()}}, nil
	}
	n := len(raw)
	if d.filetype == "" {
		k, err := c.consumed(d, raw)
		if err != nil {
			return result{}, err
		}
		if k < n {
			note := fmt.Sprintf("accepted with %d trailing bytes (consumed %d of %d)", n-k, k, n)
			return result{
				Outcome: "reject",
				Reason: &reason{
					Code:       "trailing_bytes",
					Message:    fmt.Sprintf("%s ends after %d of %d bytes; dump-xdr does not check that a record is consumed whole", d.name, k, n),
					EntryPoint: d.entryPoint() + " + consumed-length check (driver)",
				},
				Actual: &actual{LenientEntryPoints: []lenientEntryPoint{{EntryPoint: d.entryPoint(), Accepted: true, Note: note}}},
			}, nil
		}
	}
	return result{Outcome: "ok", Actual: &actual{ConsumedBytes: &n}}, nil
}

// consumed returns how many bytes of raw the dump-xdr decode of d uses, given that it accepts all of raw.
func (c *Core) consumed(d decoder, raw []byte) (int, error) {
	n := len(raw)
	accepts := func(p int) (bool, error) {
		r, err := c.decode(d, raw[:p])
		return r.accepted, err
	}
	if n < 4 {
		return n, nil
	}
	ok, err := accepts(n - 4)
	if err != nil || !ok {
		return n, err
	}
	// The smallest accepted prefix, a multiple of 4 in [0, n-4].
	lo, hi := 0, (n-4)/4 // in units of 4 bytes; hi is accepted
	for lo < hi {
		mid := (lo + hi) / 2
		ok, err := accepts(mid * 4)
		if err != nil {
			return 0, err
		}
		if ok {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return hi * 4, nil
}

// inputBytes reads an xdr input's bytes (file or inline hex) and selects the requested record-marked frame. A
// malformed record mark is a reject by the driver's own frame reader; a missing file is a protocol error.
func inputBytes(in *xdrInput) ([]byte, *result, error) {
	var raw []byte
	switch {
	case in.Path != nil:
		b, err := os.ReadFile(*in.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read input.path: %v", err)
		}
		raw = b
	case in.XDRHex != nil:
		b, err := hex.DecodeString(*in.XDRHex)
		if err != nil {
			return nil, nil, fmt.Errorf("input.xdr_hex is not hex: %v", err)
		}
		raw = b
	default:
		return nil, nil, errors.New("an xdr input needs path or xdr_hex")
	}
	switch in.Framing {
	case "", "none":
		return raw, nil, nil
	case "record-marked":
		i := 0
		if in.FrameIndex != nil {
			i = *in.FrameIndex
		}
		f, err := frame(raw, i)
		if err != nil {
			return nil, &result{Outcome: "reject", Reason: &reason{Code: "decode_error", Message: trim(err.Error()), EntryPoint: "record marks (driver)"}}, nil
		}
		return f, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown input.framing %s", in.Framing)
	}
}

// frame splits RFC 5531 record-marked bytes and returns frame index. Every frame must be a last fragment.
func frame(b []byte, index int) ([]byte, error) {
	pos := 0
	for i := 0; pos < len(b); i++ {
		if len(b)-pos < 4 {
			return nil, fmt.Errorf("frame %d: truncated record mark at offset %d", i, pos)
		}
		mark := binary.BigEndian.Uint32(b[pos:])
		if mark&0x80000000 == 0 {
			return nil, fmt.Errorf("frame %d: record mark at offset %d is not a last fragment", i, pos)
		}
		n := int(mark & 0x7fffffff)
		if n > len(b)-pos-4 {
			return nil, fmt.Errorf("frame %d: record length %d at offset %d exceeds the input", i, n, pos)
		}
		if i == index {
			return b[pos+4 : pos+4+n], nil
		}
		pos += 4 + n
	}
	return nil, fmt.Errorf("frame %d not found: the input holds fewer frames", index)
}

// Probe values, built from the XDR definitions core is compiled against (stellar-xdr v30.0).

// probeMuxedContract is an SCVal SCV_ADDRESS holding SCAddress arm 5, SC_ADDRESS_TYPE_MUXED_CONTRACT
// (MuxedContract{uint64 id; ContractID contractId}).
func probeMuxedContract() []byte {
	b := u32(nil, 18) // SCV_ADDRESS
	b = u32(b, 5)
	b = append(b, make([]byte, 8)...)  // id
	b = append(b, make([]byte, 32)...) // contractId
	return b
}

// probeLedgerHeader is a LedgerHeader whose scpValue.ext takes StellarValueType arm v: 0 BASIC (void) or 3
// STELLAR_VALUE_SIGNED_MS ({TimePointMs closeTimeMs; LedgerCloseValueSignature lcValueSignature}).
func probeLedgerHeader(v uint32) []byte {
	b := u32(nil, 30)                  // ledgerVersion
	b = append(b, make([]byte, 32)...) // previousLedgerHash
	// scpValue
	b = append(b, make([]byte, 32)...) // txSetHash
	b = append(b, make([]byte, 8)...)  // closeTime
	b = u32(b, 0)                      // upgrades<6>: none
	b = u32(b, v)
	if v == 3 {
		b = append(b, make([]byte, 8)...) // closeTimeMs
		b = u32(b, 0)                     // nodeID: PUBLIC_KEY_TYPE_ED25519
		b = append(b, make([]byte, 32)...)
		b = u32(b, 0) // signature<64>: empty
	}
	b = append(b, make([]byte, 32+32)...) // txSetResultHash, bucketListHash
	b = u32(b, 1)                         // ledgerSeq
	b = append(b, make([]byte, 8+8)...)   // totalCoins, feePool
	b = u32(b, 0)                         // inflationSeq
	b = append(b, make([]byte, 8)...)     // idPool
	b = u32(b, 100)                       // baseFee
	b = u32(b, 5000000)                   // baseReserve
	b = u32(b, 100)                       // maxTxSetSize
	b = append(b, make([]byte, 4*32)...)  // skipList
	return u32(b, 0)                      // ext: v0
}

func u32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
