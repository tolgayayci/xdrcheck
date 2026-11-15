package main

// xdrcheck repro (docs/repro.md): pack one result of a run into a self-contained bundle, run a bundle and compare
// with its expected verdict, and verify a bundle's input.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/dataset"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/ledger"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/targets"
)

func init() {
	register("repro", "pack a run's result into a self-contained bundle, run a bundle, verify its input", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return reproMain(ctx, args, os.Stdout, os.Stderr)
	})
}

// Bundle is bundle.json.
type Bundle struct {
	Schema     string             `json:"schema"`
	Tool       rundir.ToolInfo    `json:"tool"`
	Target     string             `json:"target"`
	Version    rundir.VersionInfo `json:"version"`
	Network    string             `json:"network"`
	Cluster    string             `json:"cluster"`
	Ledger     uint32             `json:"ledger"`
	Tx         *int               `json:"tx"`
	TxHash     string             `json:"tx_hash,omitempty"`
	Expect     BundleExpect       `json:"expect"`
	Command    []string           `json:"command"`
	Standalone *BundleStandalone  `json:"standalone,omitempty"`
	Inputs     []BundleInput      `json:"inputs"`
	Verify     BundleVerify       `json:"verify"`
	Created    string             `json:"created"`
}

// BundleExpect is the verdict the bundle reproduces.
type BundleExpect struct {
	Verdict string `json:"verdict"`
	Check   string `json:"check"`
	Class   string `json:"class"`
}

// BundleStandalone is the short script that shows the result without the kit.
type BundleStandalone struct {
	File  string `json:"file"`
	Setup string `json:"setup,omitempty"`
	Run   string `json:"run"`
}

// BundleInput is one file of the bundle's input.
type BundleInput struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Origin string `json:"origin,omitempty"`
}

// BundleVerify is how to show the input is a real ledger stellar-core accepts.
type BundleVerify struct {
	LedgerHeaderHash string   `json:"ledger_header_hash"`
	LakeURL          string   `json:"lake_url,omitempty"`
	Core             []string `json:"core"`
}

const bundleFile = "bundle.json"

func reproMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintf(stderr, "usage: %s repro pack RUN_DIR --cluster KEY [--tx LEDGER:INDEX] [--out DIR]\n       %s repro run BUNDLE [--version V] [--out DIR]\n       %s repro verify BUNDLE\n", hunt.Tool, hunt.Tool, hunt.Tool)
		return 2
	}
	switch args[0] {
	case "pack":
		return reproPack(args[1:], stdout, stderr)
	case "run":
		return reproRun(ctx, args[1:], stdout, stderr)
	case "verify":
		return reproVerify(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "%s repro: unknown subcommand %q (pack, run, verify)\n", hunt.Tool, args[0])
	return 2
}

// interspersed parses flags that may follow positional arguments.
func interspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// inputPaths reads the seq → object path lists a target run left in work/.
func inputPaths(runDir string) map[uint32]string {
	out := map[uint32]string{}
	for _, f := range []string{"index.tsv", "list.tsv", "lake/index.tsv"} {
		p := filepath.Join(runDir, rundir.WorkDir, f)
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			c := strings.Split(sc.Text(), "\t")
			if len(c) < 2 {
				continue
			}
			n, err := strconv.ParseUint(c[0], 10, 32)
			if err != nil {
				continue
			}
			path := c[1]
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(p), path)
			}
			out[uint32(n)] = path
		}
		fh.Close()
	}
	return out
}

func reproPack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" repro pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cluster := fs.String("cluster", "", "cluster key (check|class) from clusters.json (required)")
	txSel := fs.String("tx", "", "the example to pack, LEDGER:INDEX (default: the cluster's first example)")
	out := fs.String("out", "", "bundle directory (default bundles/<target>-<ledger>-<tx>)")
	pos, err := interspersed(fs, args)
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, hunt.Tool+" repro pack: "+format+"\n", a...)
		return 2
	}
	if err != nil {
		return 2
	}
	if len(pos) != 1 || *cluster == "" {
		return fail("want RUN_DIR and --cluster KEY")
	}
	run, err := rundir.Load(pos[0])
	if err != nil {
		return fail("%v", err)
	}
	var cl *rundir.Cluster
	for i := range run.Clusters.Clusters {
		if run.Clusters.Clusters[i].Key == *cluster {
			cl = &run.Clusters.Clusters[i]
		}
	}
	if cl == nil {
		return fail("no cluster %q in %s", *cluster, pos[0])
	}
	var ex *rundir.Verdict
	for i, v := range run.Verdicts {
		if rundir.ClusterKey(v.Check, v.Class) != *cluster {
			continue
		}
		if *txSel == "" || v.TxKey() == *txSel {
			ex = &run.Verdicts[i]
			break
		}
	}
	if ex == nil {
		return fail("cluster %s has no row for %s", *cluster, *txSel)
	}
	src := inputPaths(pos[0])[ex.Ledger]
	if src == "" {
		return fail("the run directory does not say where ledger %d is (work/ was removed?)", ex.Ledger)
	}
	if *out == "" {
		t := "ledger"
		if ex.Tx != nil {
			t = strconv.Itoa(*ex.Tx)
		}
		*out = filepath.Join("bundles", fmt.Sprintf("%s-%d-%s", run.Manifest.Target, ex.Ledger, t))
	}
	if err := os.MkdirAll(filepath.Join(*out, "ledger"), 0o755); err != nil {
		return fail("%v", err)
	}
	pass, _ := dataset.Passphrase(run.Manifest.Network)
	b := Bundle{
		Schema: hunt.SchemaID("bundle"), Tool: rundir.ToolInfo{Name: hunt.Tool, Version: hunt.Version},
		Target: run.Manifest.Target, Version: run.Manifest.Version, Network: run.Manifest.Network,
		Cluster: *cluster, Ledger: ex.Ledger, Tx: ex.Tx, TxHash: ex.TxHash,
		Expect:  BundleExpect{Verdict: ex.Verdict, Check: ex.Check, Class: ex.Class},
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	add := func(name string, data []byte, origin string) error {
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o644); err != nil {
			return err
		}
		s := sha256.Sum256(data)
		b.Inputs = append(b.Inputs, BundleInput{File: name, SHA256: hex.EncodeToString(s[:]), Bytes: int64(len(data)), Origin: origin})
		return nil
	}
	obj, err := os.ReadFile(src)
	if err != nil {
		return fail("%v", err)
	}
	objName := fmt.Sprintf("ledger/%d.xdr.zst", ex.Ledger)
	origin := ""
	for _, in := range run.Manifest.Inputs {
		if in.Ledger == ex.Ledger {
			origin = in.Object
			if s := sha256.Sum256(obj); hex.EncodeToString(s[:]) != in.SHA256 {
				return fail("ledger %d: %s no longer has the sha256 the run recorded", ex.Ledger, src)
			}
		}
	}
	if err := add(objName, obj, origin); err != nil {
		return fail("%v", err)
	}
	// the raw LedgerCloseMeta as a one-record stream, the form stellar-core dump-xdr reads
	batch, err := ledger.Batch(src)
	if err != nil || len(batch.LedgerCloseMetas) == 0 {
		return fail("ledger %d: %v", ex.Ledger, err)
	}
	lcm := batch.LedgerCloseMetas[0]
	raw, _ := lcm.MarshalBinary()
	frame := make([]byte, 4, 4+len(raw))
	binary.BigEndian.PutUint32(frame, 0x80000000|uint32(len(raw)))
	metaName := fmt.Sprintf("meta-%d.xdr", ex.Ledger)
	if err := add(metaName, append(frame, raw...), "LedgerCloseMeta of "+objName+", record-marked"); err != nil {
		return fail("%v", err)
	}
	hh := lcm.LedgerHeaderHistoryEntry()
	b.Verify.LedgerHeaderHash = hex.EncodeToString(hh.Hash[:])
	b.Verify.Core = []string{"stellar-core dump-xdr --compact " + metaName}
	if run.Manifest.Network == "pubnet" && origin != "" && !strings.HasPrefix(origin, "corpus:") && strings.HasSuffix(origin, ".xdr.zst") {
		b.Verify.LakeURL = dataset.PublicLakeURL + origin
	}
	cmd := []string{hunt.Tool, "replay", "--target", run.Manifest.Target, "--version", run.Manifest.Version.Requested,
		"--network", run.Manifest.Network, "--ledger-file", objName, "--out", "run", "--force"}
	if ex.Tx != nil {
		r, err := ledger.Envelope(src, pass, *ex.Tx)
		if err != nil {
			return fail("%v", err)
		}
		if err := add("tx.envelope.b64", []byte(r.Env+"\n"), fmt.Sprintf("envelope of transaction %d:%d", ex.Ledger, *ex.Tx)); err != nil {
			return fail("%v", err)
		}
		if err := add("tx.meta.b64", []byte(r.Meta+"\n"), fmt.Sprintf("meta of transaction %d:%d", ex.Ledger, *ex.Tx)); err != nil {
			return fail("%v", err)
		}
		b.TxHash = r.Hash
		cmd = append(cmd, "--tx", fmt.Sprintf("%d:%d", ex.Ledger, *ex.Tx))
		b.Verify.Core = append(b.Verify.Core, "stellar-core print-xdr --filetype tx --base64 tx.envelope.b64")
		if s := standalone(run.Manifest.Target, run.Manifest.Version.Resolved, run.Manifest.Version.Requested, pass, r.Hash); s != nil {
			if err := os.WriteFile(filepath.Join(*out, s.file), []byte(s.body), 0o644); err != nil {
				return fail("%v", err)
			}
			b.Standalone = &BundleStandalone{File: s.file, Setup: s.setup, Run: s.run}
		}
	}
	b.Command = cmd
	if err := rundir.WriteJSON(filepath.Join(*out, bundleFile), b); err != nil {
		return fail("%v", err)
	}
	if err := rundir.ValidateFile(rundir.SchemaBundle, filepath.Join(*out, bundleFile)); err != nil {
		return fail("%v", err)
	}
	os.WriteFile(filepath.Join(*out, "README.md"), []byte(bundleReadme(b)), 0o644)
	fmt.Fprintf(stdout, "bundle %s: %s %s, ledger %d", *out, b.Target, b.Version.Requested, b.Ledger)
	if b.Tx != nil {
		fmt.Fprintf(stdout, " tx %d", *b.Tx)
	}
	fmt.Fprintf(stdout, ", expect %s %s\n  reproduce: %s repro run %s\n", b.Expect.Check, b.Expect.Class, hunt.Tool, *out)
	return 0
}

func bundleReadme(b Bundle) string {
	var s strings.Builder
	fmt.Fprintf(&s, "# Repro bundle: %s %s, ledger %d", b.Target, b.Version.Requested, b.Ledger)
	if b.Tx != nil {
		fmt.Fprintf(&s, ", transaction %d", *b.Tx)
	}
	fmt.Fprintf(&s, "\n\nExpected: `%s` fails with class `%s` (%s network, built version %s).\n\n", b.Expect.Check, b.Expect.Class, b.Network, b.Version.Resolved)
	fmt.Fprintf(&s, "Reproduce with the kit (one command, from a checkout):\n\n    %s repro run .\n\nwhich runs, in this directory:\n\n    %s\n\n", hunt.Tool, strings.Join(b.Command, " "))
	if b.Standalone != nil {
		fmt.Fprintf(&s, "Without the kit (%s):\n\n", b.Standalone.File)
		if b.Standalone.Setup != "" {
			fmt.Fprintf(&s, "    %s\n", b.Standalone.Setup)
		}
		fmt.Fprintf(&s, "    %s\n\n", b.Standalone.Run)
	}
	fmt.Fprintf(&s, "Input is a ledger stellar-core accepts:\n\n")
	for _, c := range b.Verify.Core {
		fmt.Fprintf(&s, "    %s\n", c)
	}
	fmt.Fprintf(&s, "\nThe ledger header in the input hashes to `%s` (`%s repro verify .` recomputes it).\n", b.Verify.LedgerHeaderHash, hunt.Tool)
	if b.Verify.LakeURL != "" {
		fmt.Fprintf(&s, "The input object is byte-identical to the public lake's:\n\n    curl -s %s | sha256sum\n", b.Verify.LakeURL)
	}
	return s.String()
}

func loadBundle(dir string) (*Bundle, error) {
	if err := rundir.ValidateFile(rundir.SchemaBundle, filepath.Join(dir, bundleFile)); err != nil {
		return nil, err
	}
	var b Bundle
	if err := rundir.ReadJSON(filepath.Join(dir, bundleFile), &b); err != nil {
		return nil, err
	}
	for _, in := range b.Inputs {
		data, err := os.ReadFile(filepath.Join(dir, in.File))
		if err != nil {
			return nil, err
		}
		if s := sha256.Sum256(data); hex.EncodeToString(s[:]) != in.SHA256 {
			return nil, fmt.Errorf("%s: sha256 differs from bundle.json", in.File)
		}
	}
	return &b, nil
}

// verifyHeader recomputes the ledger header hash of the bundle's object.
func verifyHeader(dir string, b *Bundle) error {
	batch, err := ledger.Batch(filepath.Join(dir, fmt.Sprintf("ledger/%d.xdr.zst", b.Ledger)))
	if err != nil {
		return err
	}
	if len(batch.LedgerCloseMetas) == 0 {
		return fmt.Errorf("empty batch")
	}
	hh := batch.LedgerCloseMetas[0].LedgerHeaderHistoryEntry()
	hb, _ := hh.Header.MarshalBinary()
	s := sha256.Sum256(hb)
	got := hex.EncodeToString(s[:])
	if got != b.Verify.LedgerHeaderHash || hex.EncodeToString(hh.Hash[:]) != got {
		return fmt.Errorf("ledger header hash %s, recorded %s, bundle says %s", got, hex.EncodeToString(hh.Hash[:]), b.Verify.LedgerHeaderHash)
	}
	if hh.Header.LedgerSeq != 0 && uint32(hh.Header.LedgerSeq) != b.Ledger {
		return fmt.Errorf("header is ledger %d, bundle says %d", hh.Header.LedgerSeq, b.Ledger)
	}
	return nil
}

func reproVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: %s repro verify BUNDLE\n", hunt.Tool)
		return 2
	}
	b, err := loadBundle(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "%s repro verify: %v\n", hunt.Tool, err)
		return 1
	}
	if err := verifyHeader(args[0], b); err != nil {
		fmt.Fprintf(stdout, "FAIL ledger header: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "ok   files match bundle.json; ledger %d header hashes to %s\n", b.Ledger, b.Verify.LedgerHeaderHash)
	core := hunt.Env("STELLAR_CORE")
	if core == "" {
		core, _ = exec.LookPath("stellar-core")
	}
	if core == "" {
		fmt.Fprintf(stdout, "skip stellar-core checks: not available: stellar-core missing (set %s); run by hand:\n", hunt.EnvName("STELLAR_CORE"))
		for _, c := range b.Verify.Core {
			fmt.Fprintf(stdout, "       %s\n", c)
		}
		return 0
	}
	rc := 0
	for _, c := range b.Verify.Core {
		f := strings.Fields(c)
		cmd := exec.Command(core, f[1:]...)
		cmd.Dir = args[0]
		o, err := cmd.CombinedOutput()
		bad := err != nil || strings.Contains(string(o), "Could not decode") || strings.Contains(string(o), "FATAL")
		if bad {
			rc = 1
			fmt.Fprintf(stdout, "FAIL %s\n%s\n", c, tail(string(o), 600))
		} else {
			fmt.Fprintf(stdout, "ok   %s (%d bytes of output)\n", c, len(o))
		}
	}
	return rc
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func reproRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" repro run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", "", "run another version of the target than the bundle's (a fixed version should not reproduce)")
	out := fs.String("out", "", "run directory (default BUNDLE/run)")
	pos, err := interspersed(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintf(stderr, "usage: %s repro run BUNDLE [--version V] [--out DIR]\n", hunt.Tool)
		return 2
	}
	dir, _ := filepath.Abs(pos[0])
	b, err := loadBundle(dir)
	if err != nil {
		fmt.Fprintf(stderr, "%s repro run: %v\n", hunt.Tool, err)
		return 2
	}
	if err := verifyHeader(dir, b); err != nil {
		fmt.Fprintf(stderr, "%s repro run: input: %v\n", hunt.Tool, err)
		return 2
	}
	// the bundle's command, with its paths made absolute
	argv := append([]string{}, b.Command[2:]...)
	runDir := filepath.Join(dir, "run")
	if *out != "" {
		runDir, _ = filepath.Abs(*out)
	}
	for i := 0; i < len(argv)-1; i++ {
		switch argv[i] {
		case "--ledger-file":
			argv[i+1] = filepath.Join(dir, argv[i+1])
		case "--out":
			argv[i+1] = runDir
		case "--version":
			if *version != "" {
				argv[i+1] = *version
			}
		}
	}
	fmt.Fprintf(stdout, "$ %s replay %s\n", hunt.Tool, strings.Join(argv, " "))
	rc := huntReplay(ctx, argv, stdout, stderr)
	if rc == 3 {
		fmt.Fprintf(stdout, "NOT RUN: the target is not available on this machine (see %s/summary.json)\n", runDir)
		return 3
	}
	if rc == 2 {
		fmt.Fprintf(stdout, "NOT RUN: the replay failed (see %s/summary.json)\n", runDir)
		return 2
	}
	run, err := rundir.Load(runDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	found := false
	for _, v := range run.Verdicts {
		if v.Check == b.Expect.Check && v.Class == b.Expect.Class && v.Ledger == b.Ledger && (b.Tx == nil || v.Tx != nil && *v.Tx == *b.Tx) {
			found = true
		}
	}
	what := fmt.Sprintf("%s %s on ledger %d", b.Expect.Check, b.Expect.Class, b.Ledger)
	if b.Tx != nil {
		what += fmt.Sprintf(" tx %d", *b.Tx)
	}
	if found {
		fmt.Fprintf(stdout, "REPRODUCED %s with %s %s\n", what, b.Target, run.Manifest.Version.Resolved)
		return 0
	}
	fmt.Fprintf(stdout, "NOT REPRODUCED %s with %s %s\n", what, b.Target, run.Manifest.Version.Resolved)
	return 1
}

// ---- standalone scripts (≤ 20 lines), one per SDK target

type script struct{ file, setup, run, body string }

func standalone(target, resolved, requested, pass, hash string) *script {
	v := requested
	if targets.VersionKind(requested) == "path" {
		v = resolved
	}
	switch target {
	case "js":
		return &script{file: "repro.mjs", setup: "npm install @stellar/stellar-sdk@" + v, run: "node repro.mjs", body: `// Parse, hash, re-encode and rebuild one transaction with @stellar/stellar-sdk; prints each step's outcome.
import fs from "node:fs";
import { TransactionBuilder, Operation, xdr, scValToNative } from "@stellar/stellar-sdk";
const env = fs.readFileSync(new URL("./tx.envelope.b64", import.meta.url), "utf8").trim();
const step = (name, f) => { try { console.log(name, "ok", f() ?? ""); } catch (e) { console.log(name, "throws", ` + "`${e?.constructor?.name}: ${e?.message}`" + `); } };
let tx;
step("tx-parse", () => { tx = TransactionBuilder.fromXDR(env, ` + strconv.Quote(pass) + `); });
step("op-decode", () => xdr.TransactionEnvelope.fromXdr(env, "base64").value.tx.operations?.forEach((o) => Operation.fromXDRObject(o)));
if (tx) {
  step("tx-hash", () => Buffer.from(tx.hash()).toString("hex") === ` + strconv.Quote(hash) + ` ? "matches" : "DIFFERS");
  step("envelope-encode", () => tx.toEnvelope().toXdr("base64") === env ? "same bytes" : "DIFFERS");
  const inner = tx.innerTransaction ?? tx;
  step("tx-rebuild", () => Buffer.from(TransactionBuilder.cloneFrom(inner).build().hash()).equals(Buffer.from(inner.hash())) ? "same hash" : "DIFFERS");
}
const vals = [], walk = (o, d = 0) => { if (d > 60 || !o || typeof o !== "object") return; if (o instanceof xdr.ScVal) { vals.push(o); return; } for (const v of Array.isArray(o) ? o : Object.values(o)) walk(v, d + 1); };
walk(xdr.TransactionMeta.fromXdr(fs.readFileSync(new URL("./tx.meta.b64", import.meta.url), "utf8").trim(), "base64"));
step("scval-native", () => { vals.forEach((v) => scValToNative(v)); return vals.length + " values"; });
`}
	case "go":
		return &script{file: "main.go", setup: "go mod init repro && go get github.com/stellar/go-stellar-sdk/txnbuild@" + v, run: "go run .", body: `// Parse, hash and rebuild one transaction with go-stellar-sdk txnbuild; prints each step's outcome.
package main

import ("fmt"; "os"; "strings"; "github.com/stellar/go-stellar-sdk/txnbuild")

func main() {
	b, _ := os.ReadFile("tx.envelope.b64")
	g, err := txnbuild.TransactionFromXDR(strings.TrimSpace(string(b)))
	fmt.Println("tx-parse:", err)
	if err != nil { return }
	h, _ := g.HashHex(` + strconv.Quote(pass) + `)
	fmt.Println("tx-hash matches:", h == ` + strconv.Quote(hash) + `)
	tx, ok := g.Transaction()
	if fb, isFB := g.FeeBump(); isFB { tx, ok = fb.InnerTransaction(), true }
	if !ok { return }
	src := txnbuild.NewSimpleAccount(tx.SourceAccount().AccountID, tx.SequenceNumber()-1)
	_, err = txnbuild.NewTransaction(txnbuild.TransactionParams{SourceAccount: &src, IncrementSequenceNum: true, Operations: tx.Operations(), BaseFee: tx.BaseFee(), Memo: tx.Memo(), Preconditions: txnbuild.Preconditions{TimeBounds: tx.Timebounds()}})
	fmt.Println("tx-rebuild:", err)
}
`}
	case "python":
		return &script{file: "repro.py", setup: "python3 -m pip install stellar-sdk==" + v, run: "python3 repro.py", body: `# Parse, hash and re-encode one transaction with stellar-sdk, and convert its meta's contract values; prints each step.
from stellar_sdk import xdr, scval
from stellar_sdk.helpers import parse_transaction_envelope_from_xdr
env = open("tx.envelope.b64").read().strip()
def step(name, f):
    try: print(name, "ok", f() or "")
    except Exception as e: print(name, "throws", f"{type(e).__name__}: {e}")
te = None
def parse():
    global te; te = parse_transaction_envelope_from_xdr(env, ` + strconv.Quote(pass) + `)
step("tx-parse", parse)
if te is not None:
    step("tx-hash", lambda: "matches" if te.hash_hex() == ` + strconv.Quote(hash) + ` else "DIFFERS"); step("envelope-encode", lambda: "same bytes" if te.to_xdr() == env else "DIFFERS")
    step("json-roundtrip", lambda: "same bytes" if xdr.TransactionEnvelope.from_json(xdr.TransactionEnvelope.from_xdr(env).to_json()).to_xdr() == env else "DIFFERS")
def walk(o, d=0, vals=[]):
    if d > 60 or o is None or isinstance(o, (int, str, bytes, bool, float)): return
    if type(o).__qualname__.split(".")[0] == "SCVal": vals.append(o); return vals
    for v in (o if isinstance(o, list) else getattr(o, "__dict__", {}).values() or [getattr(o, k, None) for k in getattr(type(o), "__slots__", ())]): walk(v, d + 1)
walk((getattr(xdr.TransactionMeta, "from_xdr", None) or xdr.TransactionMeta.from_xdr_base64)(open("tx.meta.b64").read().strip())); vals = walk.__defaults__[1]
step("scval-native", lambda: [scval.to_native(v) for v in vals] and f"{len(vals)} values")
`}
	case "rust":
		return &script{file: "main.rs", setup: "cargo new repro && cp main.rs repro/src/ && cd repro && cargo add stellar-xdr@=" + strings.TrimPrefix(v, "v") + " --no-default-features --features std,base64,serde,serde_json && cargo add serde_json", run: "cargo run --release", body: `// Decode, re-encode and JSON round-trip one transaction envelope with rs-stellar-xdr.
use stellar_xdr::*;
fn main() {
    let env = std::fs::read_to_string("../tx.envelope.b64").unwrap();
    let env = env.trim();
    match TransactionEnvelope::from_xdr_base64(env, Limits::none()) {
        Err(e) => println!("codec: decode error: {e}"),
        Ok(t) => {
            println!("codec: re-encode same bytes: {}", t.to_xdr_base64(Limits::none()).unwrap() == env);
            let j = serde_json::to_string(&t).unwrap();
            let back: TransactionEnvelope = serde_json::from_str(&j).unwrap();
            println!("json-roundtrip: same bytes: {}", back.to_xdr_base64(Limits::none()).unwrap() == env);
        }
    }
}
`}
	}
	return nil
}
