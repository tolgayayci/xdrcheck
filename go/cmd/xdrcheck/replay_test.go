package main

// End-to-end tests of `xdrcheck replay`. The test binary doubles as a scripted fake adapter for a wallet-backend-like
// indexer (XDRCHECK_FAKE_WB set): it reads every ledger from the input the harness serves (SEP-54 directory, mock
// RPC, or the object store), and reports what a wallet-backend at the requested commit would hold, built from
// the vendored manifest's expectations with the three acceptance bugs switched on by commit position:
//
//	commit ≤ 79ea2acd                     the signed-payload signer is stored truncated (#716)
//	6e5a5910 ≤ commit ≤ 2a0a84ea           a ledger with a signed-payload signer halts ingestion (#729)
//	commit ≤ 764a4f5b                     a trustline created by a contract call has no history rows (#731)
//	commit < a9bac8d2                     the envelope stops at Protocol 29 (sdk_limit)
//
// The fake's first-parent history is a fixture, ordered so that it is consistent with the manifest's ranges.
// XDRCHECK_FAKE_FLAW breaks it on purpose: fixed-everything (no bug at any commit), halt-always (#729's halt at
// every commit), die-in-prepare.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/objstore"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

var fakeHistory = []string{
	"79ea2acd1dc65a07166133cc04b12e76db314db0",
	"6e5a59101158dc2996295450190142366062cd05",
	"2a0a84ea12523b6c92e278c0c84b443041240095",
	"2c873353c1f0f3c9b145e25a7d009023ad104a1c",
	"bb0b162b072583c7dabffbdee664d1c117e5ba56",
	"764a4f5bcbff5abb0949d93da37f769063013ea0",
	"c152783c054c765c8b51fd26ed313fd1ebc1c50c",
	"bf15e8c263c70dd5c4080593f455eabc8053b204",
	"a9bac8d2f59f7590d393c3e72e67d95b7cb2fba1",
	"e967ce8b7362b79c277e700e789181d76fbb5967",
}

const head = "e967ce8b7362b79c277e700e789181d76fbb5967"

func TestMain(m *testing.M) {
	if os.Getenv("XDRCHECK_FAKE_WB") != "" {
		os.Exit(fakeWalletBackend())
	}
	// Commands default --overlay to $XDRCHECK_OVERLAY. A test must never read or write the caller's private
	// overlay, so the variable is cleared for the whole package and for every process a test starts; a
	// test that needs an overlay builds one in a temporary directory and passes it explicitly.
	os.Unsetenv("XDRCHECK_OVERLAY")
	os.Exit(m.Run())
}

func histIndex(c string) int { return slices.Index(fakeHistory, c) }

func between(v, lo, hi string) bool {
	iv := histIndex(v)
	if iv < 0 {
		return false
	}
	return (lo == "" || iv >= histIndex(lo)) && iv <= histIndex(hi)
}

type fakeSession struct {
	network  adapter.Network
	ingested []int64
}

func fakeWalletBackend() int {
	corpus, err := manifest.Load(os.Getenv("XDRCHECK_FAKE_CORPUS"), manifest.Options{SkipBlobCheck: true, Overlay: os.Getenv("XDRCHECK_FAKE_OVERLAY")})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake:", err)
		return 4
	}
	flaw := os.Getenv("XDRCHECK_FAKE_FLAW")
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	version := ""
	sessions := map[string]*fakeSession{}
	for in.Scan() {
		var req struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			fmt.Fprintln(os.Stderr, "fake: bad request:", err)
			return 3
		}
		var result any
		var errBody *adapter.ErrorBody
		switch req.Method {
		case adapter.MethodDescribe:
			var p adapter.DescribeParams
			json.Unmarshal(req.Params, &p)
			version = p.TargetVersion
			result = fakeDescribe(version)
		case adapter.MethodPrepare:
			var p adapter.PrepareParams
			json.Unmarshal(req.Params, &p)
			if flaw == "die-in-prepare" {
				fmt.Fprintln(os.Stderr, "fake: dying in prepare")
				return 9
			}
			version = p.TargetVersion
			sessions[p.Session] = &fakeSession{network: p.Network}
			r := adapter.PrepareResult{Ready: true, TargetVersion: version, State: "clean"}
			for _, rg := range p.ResolveRanges {
				lo, hi, _ := strings.Cut(rg, "..")
				r.Ranges = append(r.Ranges, adapter.RangeAnswer{Range: rg, Contains: between(version, lo, hi)})
			}
			result = r
		case adapter.MethodIngest:
			var p adapter.IngestParams
			json.Unmarshal(req.Params, &p)
			s := sessions[p.Session]
			d := fakeDescribe(version)
			switch {
			case s == nil:
				errBody = &adapter.ErrorBody{Code: "unknown_session", Message: p.Session}
			case !slices.Contains(d.Inputs, p.Input.Kind):
				errBody = &adapter.ErrorBody{Code: "unsupported_input", Message: p.Input.Kind}
			case p.Unit != "" && !slices.Contains(d.Units, p.Unit):
				errBody = &adapter.ErrorBody{Code: "unsupported_unit", Message: p.Unit}
			}
			if errBody != nil {
				break
			}
			res, err := fakeIngest(corpus, s, p, version, flaw)
			if err != nil {
				fmt.Fprintln(os.Stderr, "fake: ingest:", err)
				errBody = &adapter.ErrorBody{Code: "environment", Message: err.Error()}
				break
			}
			result = res
		case adapter.MethodObserve:
			var p adapter.ObserveParams
			json.Unmarshal(req.Params, &p)
			s := sessions[p.Session]
			if s == nil {
				errBody = &adapter.ErrorBody{Code: "unknown_session", Message: p.Session}
				break
			}
			result = fakeObserve(corpus, s, p, version, flaw)
		case adapter.MethodTeardown:
			var p adapter.TeardownParams
			json.Unmarshal(req.Params, &p)
			delete(sessions, p.Session)
			result = adapter.TeardownResult{OK: true}
		}
		msg := map[string]any{"xcc": adapter.Protocol, "id": req.ID, "method": req.Method}
		if errBody != nil {
			msg["error"] = errBody
		} else {
			msg["result"] = result
		}
		b, _ := json.Marshal(msg)
		out.Write(append(b, '\n'))
		out.Flush()
	}
	return 0
}

func fakeDescribe(version string) adapter.DescribeResult {
	maxP, minTx := 29, 10
	if histIndex(version) >= histIndex("a9bac8d2f59f7590d393c3e72e67d95b7cb2fba1") {
		maxP = 30
	}
	sc := []string{"signer_added", "signer_removed", "signer_changed", "trustline_created", "trustline_removed", "trustline_flags_changed", "balance_changed", "account_created", "account_removed"}
	return adapter.DescribeResult{
		Adapter:         adapter.NameVersion{Name: "fake-wallet-backend", Version: "0.0.1"},
		Target:          adapter.Target{Name: "stellar/wallet-backend", Version: version, VersionKind: "commit"},
		ProtocolVersion: adapter.Protocol,
		Inputs:          []string{"sep54-s3", "sep54-dir", "rpc"},
		Units:           []string{"single", "chain"},
		Envelope:        adapter.Envelope{Enforcement: "sdk_limit", MaxProtocol: &maxP, MinProtocolWithTransactions: &minTx, Basis: "test fixture"},
		Observations: adapter.Observations{
			Receipts:     adapter.Capability{Supported: true, Subkinds: []string{"transactions", "operations"}},
			Transactions: adapter.Capability{Supported: true},
			Participants: adapter.Capability{Supported: true, Muxed: "base_only"},
			StateChanges: adapter.Capability{Supported: true, Subkinds: sc, Modelling: []string{"initial_authorization_separate"}},
			Movements:    adapter.Capability{Supported: false, Reason: "not modelled by the fixture"},
			Addresses:    adapter.Capability{Supported: true, AddressEncoding: "strkey_text"},
		},
	}
}

// fetch reads one ledger from the served input, the way a datastore or RPC client would.
func fetch(p adapter.IngestParams, seq int64) error {
	switch in := p.Input; in.Kind {
	case "sep54-dir":
		var cfg lake.Config
		b, err := os.ReadFile(filepath.Join(in.Path, lake.ConfigFile))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return err
		}
		got, _, err := lake.ReadObject(filepath.Join(in.Path, filepath.FromSlash(cfg.ObjectKey(uint32(seq)))))
		if err != nil {
			return err
		}
		if int64(got) != seq {
			return fmt.Errorf("object for %d holds %d", seq, got)
		}
	case "rpc":
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"getLedgers","params":{"startLedger":%d,"pagination":{"limit":1}}}`, seq)
		resp, err := http.Post(in.URL, "application/json", strings.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var r struct {
			Result struct {
				Ledgers []struct {
					Sequence    int64  `json:"sequence"`
					MetadataXDR string `json:"metadataXdr"`
				} `json:"ledgers"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return err
		}
		if len(r.Result.Ledgers) != 1 || r.Result.Ledgers[0].Sequence != seq || r.Result.Ledgers[0].MetadataXDR == "" {
			return fmt.Errorf("getLedgers %d: %+v", seq, r.Result.Ledgers)
		}
	case "sep54-s3":
		bucket, prefix, _ := strings.Cut(in.BucketPath, "/")
		c := objstore.Client(in.EndpointURL)
		get := func(key string) ([]byte, error) {
			o, err := c.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(prefix + "/" + key)})
			if err != nil {
				return nil, err
			}
			defer o.Body.Close()
			return io.ReadAll(o.Body)
		}
		b, err := get(lake.ConfigFile)
		if err != nil {
			return err
		}
		var cfg lake.Config
		json.Unmarshal(b, &cfg)
		obj, err := get(cfg.ObjectKey(uint32(seq)))
		if err != nil {
			return err
		}
		raw, err := lake.Decompress(obj)
		if err != nil {
			return err
		}
		if got, _, err := lake.UnwrapBatch(raw); err != nil || int64(got) != seq {
			return fmt.Errorf("object for %d holds %d (%v)", seq, got, err)
		}
	default:
		return fmt.Errorf("input %s", in.Kind)
	}
	return nil
}

// variantsAt lists the corpus variants of a ledger on a passphrase.
func variantsAt(c *manifest.Corpus, passphrase string, seq int64) []*manifest.Variant {
	var out []*manifest.Variant
	for _, e := range c.Entries {
		if e.Kind != "ledger" {
			continue
		}
		for _, v := range e.Variants {
			if v.LedgerSeq == seq && v.Passphrase == passphrase {
				out = append(out, v)
			}
		}
	}
	return out
}

var fakeIngests int

func halts(vs []*manifest.Variant, version, flaw string) bool {
	if flaw == "fixed-everything" {
		return false
	}
	if flaw == "flaky" {
		fakeIngests++
		if fakeIngests%2 == 0 {
			return false // every other session of this process behaves as fixed
		}
	}
	if flaw != "halt-always" && !between(version, "6e5a59101158dc2996295450190142366062cd05", "2a0a84ea12523b6c92e278c0c84b443041240095") {
		return false
	}
	for _, v := range vs {
		for _, sc := range v.Resolved.StateChanges {
			if sc.Signer != nil && sc.Signer.Type == "ed25519_signed_payload" {
				return true
			}
		}
	}
	return false
}

func fakeIngest(c *manifest.Corpus, s *fakeSession, p adapter.IngestParams, version, flaw string) (*adapter.IngestResult, error) {
	before := p.Range.Start - 1
	cursor := before
	if flaw == "timeout" || flaw == "timeout-unfetched" {
		if flaw == "timeout" {
			if err := fetch(p, p.Range.Start); err != nil {
				return nil, err
			}
		}
		return &adapter.IngestResult{Status: adapter.StatusTimeout, LastLedger: &before, Signals: adapter.Signals{
			CursorBefore: &before, CursorAfter: &before, ProcessExited: false, WallMS: p.DeadlineMS}}, nil
	}
	for seq := p.Range.Start; seq <= p.Range.End; seq++ {
		if err := fetch(p, seq); err != nil {
			return nil, err
		}
		if halts(variantsAt(c, p.Network.Passphrase, seq), version, flaw) {
			cur := cursor
			return &adapter.IngestResult{Status: adapter.StatusHalted, LastLedger: &cur, Signals: adapter.Signals{
				CursorBefore: &before, CursorAfter: &cur, ProcessExited: true, ExitCode: adapter.Some[int64](2), WallMS: 15420,
				FailingLedger: adapter.Some(seq), Phase: adapter.Some("persist"), RuntimePanic: adapter.Some(false),
				RowsForFailingLedger: adapter.Some[int64](0), Attempts: adapter.Some[int64](5)}}, nil
		}
		s.ingested = append(s.ingested, seq)
		cursor = seq
	}
	stopped := true
	return &adapter.IngestResult{Status: adapter.StatusCompleted, LastLedger: &cursor, Signals: adapter.Signals{
		CursorBefore: &before, CursorAfter: &cursor, ProcessExited: false, ExitCode: adapter.Some[int64](0), StoppedByAdapter: &stopped, WallMS: 300}}, nil
}

func strkeyAccount(addr string) *adapter.ObsAccount {
	return &adapter.ObsAccount{Address: addr, AsStored: &adapter.Stored{Encoding: "strkey_text", Value: addr}}
}

// truncated is #716's stored value: the version byte and the first 32 payload bytes.
func truncated(strkey string) adapter.Stored {
	a := match.MustDecode(strkey)
	return adapter.Stored{Encoding: "version_byte_payload_hex", Value: hex.EncodeToString(append([]byte{a.Version}, a.Payload[:32]...))}
}

func fakeObserve(c *manifest.Corpus, s *fakeSession, p adapter.ObserveParams, version, flaw string) *adapter.Observation {
	trunc := flaw != "fixed-everything" && between(version, "", "79ea2acd1dc65a07166133cc04b12e76db314db0")
	gap := flaw != "fixed-everything" && between(version, "", "764a4f5bcbff5abb0949d93da37f769063013ea0")
	obs := &adapter.Observation{Schema: adapter.ObservationSchema, Range: p.Range,
		Kinds: adapter.KindsSet{
			Receipts: adapter.KindStatus{Status: "provided", Subkinds: []string{"transactions", "operations"}}, Transactions: adapter.KindStatus{Status: "provided"},
			Participants: adapter.KindStatus{Status: "provided"}, StateChanges: adapter.KindStatus{Status: "provided"},
			Movements: adapter.KindStatus{Status: "not_applicable", Reason: "not modelled"}, Addresses: adapter.KindStatus{Status: "provided"}},
		Ledgers: []adapter.Ledger{}}
	for _, seq := range s.ingested {
		if seq < p.Range.Start || seq > p.Range.End {
			continue
		}
		l := adapter.Ledger{LedgerSeq: seq}
		seen := map[string]bool{}
		once := func(v any) bool {
			b, _ := json.Marshal(v)
			if seen[string(b)] {
				return false
			}
			seen[string(b)] = true
			return true
		}
		for _, v := range variantsAt(c, s.network.Passphrase, seq) {
			x := v.Resolved
			if x.Ledger != nil && l.Receipt == nil && x.Ledger.Transactions != nil && x.Ledger.Operations != nil {
				tx, ops := int64(*x.Ledger.Transactions), int64(*x.Ledger.Operations)
				l.Receipt = &adapter.Receipt{Transactions: &tx, Operations: &ops}
			}
			hashAt := map[int]string{}
			for _, t := range x.Transactions {
				hashAt[t.Index] = t.Hash
				ok, idx := t.Successful, t.Index
				ot := adapter.ObsTransaction{Hash: t.Hash, Index: &idx, Successful: &ok, ResultCode: t.ResultCode, FeeCharged: t.FeeCharged}
				if once(ot) {
					l.Transactions = append(l.Transactions, ot)
				}
			}
			focus := ""
			if v.Focus != nil {
				focus = v.Focus.TxHash
			}
			if x.Participants != nil {
				for _, a := range x.Participants.MustInclude {
					op := adapter.ObsParticipant{Locator: adapter.Locator{TxHash: focus}, Account: *strkeyAccount(a.Address)}
					if once(op) {
						l.Participants = append(l.Participants, op)
					}
					fee := adapter.ObsStateChange{Locator: adapter.Locator{TxHash: focus}, Kind: "balance_changed", Account: strkeyAccount(a.Address),
						Detail: map[string]any{"reason": "fee"}, NativeLabel: "BALANCE/DEBIT"}
					if once(fee) {
						l.StateChanges = append(l.StateChanges, fee)
					}
				}
			}
			for _, sc := range x.StateChanges {
				if gap && sc.Cause == "contract-call" {
					continue
				}
				tx := focus
				if sc.TxIndex != nil && hashAt[*sc.TxIndex] != "" {
					tx = hashAt[*sc.TxIndex]
				}
				o := adapter.ObsStateChange{Locator: adapter.Locator{TxHash: tx}, Kind: sc.Kind, Account: strkeyAccount(sc.Account.Address), Detail: sc.Detail}
				if sc.Asset != "" {
					o.Asset = sc.Asset
					if a, err := match.SACAddress(sc.Asset, s.network.Passphrase); err == nil {
						o.Asset = a.String() // wallet-backend stores the asset's contract address
					}
				}
				if sc.Signer != nil {
					st := adapter.Stored{Encoding: "strkey_text", Value: sc.Signer.Key}
					if trunc && sc.Signer.Type == "ed25519_signed_payload" {
						st = truncated(sc.Signer.Key)
					}
					o.Signer = &adapter.ObsSigner{Weight: sc.Signer.Weight, AsStored: &st}
				}
				if once(o) {
					l.StateChanges = append(l.StateChanges, o)
				}
			}
			for _, a := range x.Addresses {
				st := adapter.Stored{Encoding: "strkey_text", Value: a.Strkey}
				if trunc && a.Type == "signed_payload" {
					st = truncated(a.Strkey)
				}
				oa := adapter.ObsAddress{Locator: adapter.Locator{TxHash: focus}, Field: "state_changes.signer_account_id", AsStored: st}
				if once(oa) {
					l.Addresses = append(l.Addresses, oa)
				}
			}
		}
		obs.Ledgers = append(obs.Ledgers, l)
	}
	return obs
}

// ---- tests ----

// fakeCorpus is the corpus the fake wallet-backend runs over: every entry, without core-golden or
// scenario-generated variants (the fake looks expectations up by passphrase and ledger number, which those
// reuse).
func fakeCorpus(t *testing.T) string {
	t.Helper()
	// The fake wallet-backend has no defects, so divergences still open at the current commit cannot show.
	return testcorpus.Build(t, nil, testcorpus.Options{DropGenerated: true, DropOpenReplayAt: head})
}

func replayArgs(corpus, commit string, extra ...string) []string {
	return append([]string{"--corpus", corpus, "--pins", pinsPath, "--adapter", os.Args[0], "--target-version", commit}, extra...)
}

type replayRun struct {
	code   int
	stdout string
	stderr string
	rows   []*report.Row
	dir    string
}

func runReplay(t *testing.T, corpus, flaw string, args ...string) replayRun {
	t.Helper()
	abs, _ := filepath.Abs(corpus)
	t.Setenv("XDRCHECK_FAKE_WB", "1")
	t.Setenv("XDRCHECK_FAKE_CORPUS", abs)
	t.Setenv("XDRCHECK_FAKE_FLAW", flaw)
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := replay(context.Background(), append(args, "--report", dir), &out, &errb)
	r := replayRun{code: code, stdout: out.String(), stderr: errb.String(), dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
		if _, _, err := report.ReadFile(filepath.Join(dir, "report.json"), func(row *report.Row) error { r.rows = append(r.rows, row); return nil }); err != nil {
			t.Fatalf("report does not read back: %v\n%s", err, errb.String())
		}
	}
	return r
}

func (r replayRun) result(entry, variant string) string {
	for _, row := range r.rows {
		if row.Entry == entry && row.Variant == variant {
			return report.ResultKey(row) + " " + row.Expectation
		}
	}
	return "(no row)"
}

// validateReport checks report.json against the frozen report schema with the repository's Python jsonschema.
func validateReport(t *testing.T, path string) {
	t.Helper()
	py := "../../../.venv/bin/python"
	if _, err := os.Stat(py); err != nil {
		t.Log("no .venv: report schema validation skipped")
		return
	}
	script := `import json,sys,jsonschema
s=json.load(open(sys.argv[1]));d=json.load(open(sys.argv[2]))
errs=list(jsonschema.Draft202012Validator(s,format_checker=jsonschema.FormatChecker()).iter_errors(d))
[print(e.json_path, e.message[:200]) for e in errs[:10]]
sys.exit(1 if errs else 0)`
	out, err := exec.Command(py, "-I", "-c", script, "../../../corpus/schema/report.schema.json", path).CombinedOutput()
	if err != nil {
		t.Fatalf("report.json does not validate against report.schema.json: %v\n%s", err, out)
	}
}

func inputs(t *testing.T) []string {
	in := []string{"sep54-dir", "rpc"}
	if p, err := pins.Load(pinsPath); err == nil && objstore.Available(p.Images["seaweedfs"]) == nil && os.Getenv("XDRCHECK_TEST_SKIP_S3") == "" {
		in = append(in, "sep54-s3")
	} else {
		t.Log("sep54-s3 skipped: the pinned SeaweedFS image is not present locally")
	}
	return in
}

// A plain run over the whole vendored corpus at the current commit: every in-envelope entry passes, the report
// validates against report.schema.json, and the exit code is 0. Core-golden variants are left out: golden files
// of different core tests reuse ledger numbers under one passphrase, which the fake (it looks expectations up by
// passphrase and ledger) cannot tell apart.
func TestReplayWholeCorpus(t *testing.T) {
	corpusDir := fakeCorpus(t)
	for _, in := range inputs(t) {
		t.Run(in, func(t *testing.T) {
			r := runReplay(t, corpusDir, "", replayArgs(corpusDir, head, "--input", in)...)
			if r.code != 0 {
				t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
			}
			validateReport(t, filepath.Join(r.dir, "report.json"))
			c, _ := manifest.Load(corpusDir, manifest.Options{SkipBlobCheck: true})
			want := 0
			for _, e := range c.Entries {
				if e.Kind == "ledger" && e.IndexerScope() != "sdk-only" {
					want += len(e.Variants)
				}
			}
			if len(r.rows) != want {
				t.Fatalf("%d rows, want one per replayable ledger variant (%d)", len(r.rows), want)
			}
			passes := 0
			for _, row := range r.rows {
				switch report.ResultKey(row) {
				case "pass":
					passes++
					if row.Replay.Input != in {
						t.Errorf("%s: input %q", row.Entry, row.Replay.Input)
					}
				case "not_applicable":
				default:
					t.Errorf("%s %s: %s (%v)", row.Entry, row.Variant, report.ResultKey(row), row.Notes)
				}
			}
			if passes < 10 {
				t.Errorf("only %d passes", passes)
			}
			for _, f := range []string{"describe.json", "REPORT.md"} {
				if _, err := os.Stat(filepath.Join(r.dir, f)); err != nil {
					t.Error(err)
				}
			}
			logs, _ := filepath.Glob(filepath.Join(r.dir, "logs", "adapter-*.log"))
			if len(logs) == 0 {
				t.Error("no adapter log kept")
			}
		})
	}
}

// replay-regression against the fixture: every acceptance commit and the current one, under --assert-known, on both inputs.
func TestReplayAssertKnownAcceptanceCommits(t *testing.T) {
	corpusDir := fakeCorpus(t)
	const (
		signer = "cap-0040/signed-payload-signer-added"
		trust  = "cap-0073/sac-trust-creates-trustline"
	)
	cases := []struct {
		commit       string
		signer, p28t string
	}{
		{"2a0a84ea12523b6c92e278c0c84b443041240095", "mishandled·halt expected", "dropped·partial expected"},
		{"2c873353c1f0f3c9b145e25a7d009023ad104a1c", "pass expected", "dropped·partial expected"},
		{"79ea2acd1dc65a07166133cc04b12e76db314db0", "mishandled·wrong_value expected", "dropped·partial expected"},
		{"bb0b162b072583c7dabffbdee664d1c117e5ba56", "pass expected", "dropped·partial expected"},
		{"764a4f5bcbff5abb0949d93da37f769063013ea0", "pass expected", "dropped·partial expected"},
		{"c152783c054c765c8b51fd26ed313fd1ebc1c50c", "pass expected", "pass expected"},
		{head, "pass expected", "pass expected"},
	}
	for _, in := range []string{"sep54-dir", "rpc"} {
		for _, tc := range cases {
			t.Run(in+"-"+tc.commit[:8], func(t *testing.T) {
				r := runReplay(t, corpusDir, "", replayArgs(corpusDir, tc.commit, "--assert-known", "--input", in)...)
				if r.code != 0 {
					t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
				}
				if got := r.result(signer, "testnet"); got != tc.signer {
					t.Errorf("%s: %s, want %s", signer, got, tc.signer)
				}
				for _, v := range []string{"testnet@28", "pubnet@28"} {
					if got := r.result(trust, v); got != tc.p28t {
						t.Errorf("%s %s: %s, want %s", trust, v, got, tc.p28t)
					}
				}
				for _, row := range r.rows {
					if row.Entry == signer && row.Replay.Class == "mishandled" && row.KnownDivergence == nil {
						t.Error("an expected divergence row does not name its divergence")
					}
				}
				validateReport(t, filepath.Join(r.dir, "report.json"))
			})
		}
	}
}

// An unexpected pass (the bug no longer reproduces inside its range) and an undeclared divergence both fail.
func TestReplayAssertKnownFailures(t *testing.T) {
	corpusDir := fakeCorpus(t)
	r := runReplay(t, corpusDir, "fixed-everything", replayArgs(corpusDir, "2a0a84ea12523b6c92e278c0c84b443041240095", "--assert-known", "--input", "rpc")...)
	if r.code != 1 || r.result("cap-0040/signed-payload-signer-added", "testnet") != "pass unexpected" {
		t.Errorf("unexpected pass: exit %d, %s\n%s", r.code, r.result("cap-0040/signed-payload-signer-added", "testnet"), r.stderr)
	}
	r = runReplay(t, corpusDir, "halt-always", replayArgs(corpusDir, head, "--assert-known", "--input", "sep54-dir")...)
	if r.code != 1 || r.result("cap-0040/signed-payload-signer-added", "testnet") != "mishandled·halt unexpected" {
		t.Errorf("undeclared divergence: exit %d, %s\n%s", r.code, r.result("cap-0040/signed-payload-signer-added", "testnet"), r.stderr)
	}
}

// A manifest whose declared class is flipped (halt → wrong_value at 2a0a84ea) makes the same run fail.
func TestReplayAssertKnownFlippedExpectation(t *testing.T) {
	corpusDir := fakeCorpus(t)
	dir := filepath.Join(t.TempDir(), "corpus")
	if err := copyTree(corpusDir, dir); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "manifest", "cap-0040", "signed-payload-signer-added.json")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	flipped := strings.Replace(string(b), `"outcome": "halt",`, `"outcome": "wrong_value",`, 1)
	flipped = strings.Replace(flipped, `"qualifier": "halt"`, `"qualifier": "wrong_value"`, 1)
	if flipped == string(b) {
		t.Fatal("the divergence text was not found")
	}
	os.WriteFile(f, []byte(flipped), 0o644)
	r := runReplay(t, dir, "", replayArgs(dir, "2a0a84ea12523b6c92e278c0c84b443041240095", "--assert-known", "--input", "rpc")...)
	if r.code != 1 || r.result("cap-0040/signed-payload-signer-added", "testnet") != "mishandled·halt unexpected" {
		t.Errorf("flipped expectation: exit %d, %s\n%s", r.code, r.result("cap-0040/signed-payload-signer-added", "testnet"), r.stderr)
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

func TestReplayHarnessFaultAndArguments(t *testing.T) {
	corpusDir := fakeCorpus(t)
	r := runReplay(t, corpusDir, "die-in-prepare", replayArgs(corpusDir, head, "--input", "rpc", "--entries", "cap-0027/muxed-source-id-zero")...)
	if r.code != 2 || r.result("cap-0027/muxed-source-id-zero", "pubnet") != "harness_fault unexpected" {
		t.Errorf("adapter dying in prepare: exit %d, %s\n%s", r.code, r.result("cap-0027/muxed-source-id-zero", "pubnet"), r.stderr)
	}
	// Dying in the prepare that resolves the known divergences' ranges: the run cannot start.
	r = runReplay(t, corpusDir, "die-in-prepare", replayArgs(corpusDir, head, "--input", "rpc", "--assert-known")...)
	if r.code != 2 {
		t.Errorf("adapter dying while resolving ranges: exit %d\n%s", r.code, r.stderr)
	}
	var out, errb bytes.Buffer
	for _, args := range [][]string{
		{"--corpus", corpusDir},
		{"--corpus", corpusDir, "--adapter", "x"},
		replayArgs(corpusDir, head, "--findings", "findings"),
		replayArgs(corpusDir, head, "--input", "sep54-gcs"),
		replayArgs(corpusDir, head, "--network", "mars"),
	} {
		if code := replay(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if got, err := splitCommand(`go run ./adapter --db "postgres://x y" 'a b'`); err != nil || len(got) != 6 || got[4] != "postgres://x y" || got[5] != "a b" {
		t.Errorf("splitCommand: %q %v", got, err)
	}
}

// --overlay DIR merges DIR/corpus with the public corpus: an entry whose manifest, blob and sidecar only the
// overlay holds is replayed; without the flag it is not in the corpus; an overlay inside the tree, or a report
// inside it, is refused.
func TestReplayOverlayCorpus(t *testing.T) {
	corpusDir := fakeCorpus(t)
	const id = "cap-0027/muxed-source-id-zero"
	ov := t.TempDir()
	c, err := manifest.Load(corpusDir, manifest.Options{SkipBlobCheck: true})
	if err != nil || c.Entry(id) == nil {
		t.Fatalf("fixture: %v", err)
	}
	move := func(rel string) {
		t.Helper()
		from := filepath.Join(corpusDir, filepath.FromSlash(rel))
		copyFile(t, from, filepath.Join(ov, "corpus", filepath.FromSlash(rel)))
		if err := os.Remove(from); err != nil {
			t.Fatal(err)
		}
	}
	move("manifest/" + id + ".json")
	for _, v := range c.Entry(id).Variants {
		move(v.Blob.Path)
		move(v.Decoded)
	}
	t.Setenv("XDRCHECK_FAKE_OVERLAY", filepath.Join(ov, "corpus"))
	r := runReplay(t, corpusDir, "", replayArgs(corpusDir, head, "--input", "rpc", "--entries", id, "--overlay", ov)...)
	if r.code != 0 || r.result(id, "pubnet") != "pass expected" {
		t.Fatalf("overlay entry: exit %d, %q\n%s\n%s", r.code, r.result(id, "pubnet"), r.stdout, r.stderr)
	}
	t.Setenv("XDRCHECK_FAKE_OVERLAY", "")
	if r := runReplay(t, corpusDir, "", replayArgs(corpusDir, head, "--input", "rpc", "--entries", id)...); len(r.rows) != 0 {
		t.Errorf("the overlay entry ran without --overlay: %d rows", len(r.rows))
	}
	var out, errb bytes.Buffer
	inside := filepath.Join(filepath.Dir(corpusDir), "overlay")
	os.MkdirAll(inside, 0o755)
	for _, args := range [][]string{
		replayArgs(corpusDir, head, "--overlay", inside),
		replayArgs(corpusDir, head, "--overlay", ov, "--report", filepath.Join(filepath.Dir(corpusDir), "reports")),
	} {
		if code := replay(context.Background(), args, &out, &errb); code != 2 || !strings.Contains(errb.String(), "working tree") {
			t.Errorf("%v: exit %d, want 2\n%s", args, code, errb.String())
		}
	}
}

func TestReplaySelftest(t *testing.T) {
	corpusDir := fakeCorpus(t)
	t.Setenv("XDRCHECK_FAKE_WB", "1")
	abs, _ := filepath.Abs(corpusDir)
	t.Setenv("XDRCHECK_FAKE_CORPUS", abs)
	var out, errb bytes.Buffer
	code := replay(context.Background(), []string{"--corpus", corpusDir, "--pins", pinsPath, "--adapter", os.Args[0], "--target-version", head, "--input", "rpc", "--selftest"}, &out, &errb)
	if code != 0 {
		t.Fatalf("selftest exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	for _, check := range []string{"ingest_a", "deterministic", "unsupported_unit"} {
		if !strings.Contains(out.String(), check) {
			t.Errorf("check %s not run:\n%s", check, out.String())
		}
	}
}

// --confirm re-runs non-pass units; a result that changes is flaky, which --assert-known does not accept.
func TestReplayConfirmAndParallel(t *testing.T) {
	corpusDir := fakeCorpus(t)
	const at = "2a0a84ea12523b6c92e278c0c84b443041240095"
	r := runReplay(t, corpusDir, "", replayArgs(corpusDir, at, "--assert-known", "--input", "rpc", "--confirm", "2")...)
	if r.code != 0 || r.result("cap-0040/signed-payload-signer-added", "testnet") != "mishandled·halt expected" {
		t.Errorf("stable result under --confirm: exit %d, %s\n%s", r.code, r.result("cap-0040/signed-payload-signer-added", "testnet"), r.stderr)
	}
	// One entry only: the fake turns flaky by counting ingests across the process, so other units would shift
	// which of this entry's runs halts.
	r = runReplay(t, corpusDir, "flaky", replayArgs(corpusDir, at, "--assert-known", "--input", "rpc", "--confirm", "2", "--entries", "cap-0040/signed-payload-signer-added")...)
	if r.code != 1 || r.result("cap-0040/signed-payload-signer-added", "testnet") != "flaky unexpected" {
		t.Errorf("flaky result: exit %d, %s\n%s", r.code, r.result("cap-0040/signed-payload-signer-added", "testnet"), r.stderr)
	}
	serial := runReplay(t, corpusDir, "", replayArgs(corpusDir, at, "--input", "sep54-dir")...)
	par := runReplay(t, corpusDir, "", replayArgs(corpusDir, at, "--input", "sep54-dir", "--parallel", "4")...)
	if serial.code != par.code || len(serial.rows) != len(par.rows) {
		t.Fatalf("parallel run differs: exit %d/%d, rows %d/%d", serial.code, par.code, len(serial.rows), len(par.rows))
	}
	for _, row := range serial.rows {
		if got, want := par.result(row.Entry, row.Variant), serial.result(row.Entry, row.Variant); got != want {
			t.Errorf("%s %s: parallel %s, serial %s", row.Entry, row.Variant, got, want)
		}
	}
	logs, _ := filepath.Glob(filepath.Join(par.dir, "logs", "adapter-*.log"))
	if len(logs) < 2 {
		t.Errorf("parallel run used %d adapter process(es)", len(logs))
	}
}

// Without --keep-going the run stops at the first harness fault; with it, every unit runs.
func TestReplayKeepGoing(t *testing.T) {
	corpusDir := fakeCorpus(t)
	r := runReplay(t, corpusDir, "die-in-prepare", replayArgs(corpusDir, head, "--input", "rpc", "--entries", "cap-0027/*")...)
	if r.code != 2 || len(r.rows) != 1 {
		t.Errorf("stop at the first fault: exit %d, %d rows", r.code, len(r.rows))
	}
	r = runReplay(t, corpusDir, "die-in-prepare", replayArgs(corpusDir, head, "--input", "rpc", "--entries", "cap-0027/*", "--keep-going")...)
	if r.code != 2 || len(r.rows) != 2 {
		t.Errorf("--keep-going: exit %d, %d rows", r.code, len(r.rows))
	}
}

// An indexer alive at the deadline is a hang when the ledger was served, and a harness fault when the request
// log shows it never was; on a filesystem layout nothing observes reads, so it is a hang with a note.
func TestReplayHangAndDelivery(t *testing.T) {
	corpusDir := fakeCorpus(t)
	const e = "cap-0027/muxed-source-id-zero"
	// The pins file's directory is the root the committed pending lists are read from: a copy with none keeps
	// the classification under test independent of the repository's lists.
	root := t.TempDir()
	copyFile(t, pinsPath, filepath.Join(root, "pins.toml"))
	args := func(extra ...string) []string {
		a := replayArgs(corpusDir, head, extra...)
		a[3] = filepath.Join(root, "pins.toml")
		return a
	}
	r := runReplay(t, corpusDir, "timeout", args("--input", "rpc", "--entries", e)...)
	if r.code != 1 || r.result(e, "pubnet") != "mishandled·hang unexpected" {
		t.Errorf("served, alive at the deadline: exit %d, %s", r.code, r.result(e, "pubnet"))
	}
	r = runReplay(t, corpusDir, "timeout-unfetched", args("--input", "rpc", "--entries", e)...)
	if r.code != 2 || r.result(e, "pubnet") != "harness_fault unexpected" {
		t.Errorf("never served: exit %d, %s", r.code, r.result(e, "pubnet"))
	}
	r = runReplay(t, corpusDir, "timeout-unfetched", args("--input", "sep54-dir", "--entries", e)...)
	if r.code != 1 || r.result(e, "pubnet") != "mishandled·hang unexpected" || !slices.Contains(r.rows[0].Notes, "delivery_not_observed") {
		t.Errorf("filesystem layout: exit %d, %s %v", r.code, r.result(e, "pubnet"), r.rows)
	}
	// A pending list that names the failure row marks it pending finding review: not unexpected, so the run
	// passes; a harness fault is no failure and stays unexpected.
	os.MkdirAll(filepath.Join(root, "findings", "pending"), 0o755)
	os.WriteFile(filepath.Join(root, "findings", "pending", "replay.json"), []byte(`{"pending":[{"tool":"replay","entry":"`+e+`"}]}`), 0o644)
	r = runReplay(t, corpusDir, "timeout", args("--input", "rpc", "--entries", e)...)
	if r.code != 0 || r.result(e, "pubnet") != "mishandled·hang pending" {
		t.Errorf("pending: exit %d, %s", r.code, r.result(e, "pubnet"))
	}
	r = runReplay(t, corpusDir, "timeout-unfetched", args("--input", "rpc", "--entries", e)...)
	if r.code != 2 || r.result(e, "pubnet") != "harness_fault unexpected" {
		t.Errorf("pending list, never served: exit %d, %s", r.code, r.result(e, "pubnet"))
	}
}
