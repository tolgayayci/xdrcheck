package walletbackend

// Unit tests of the adapter's pure parts: commit ranges, the envelope from go.mod, the per-commit flag table,
// the ingest status decision, and the row mapping. The end-to-end check against real wallet-backend builds is
// `make verify-replay` (scripts/verify-replay.sh), which needs docker and the adapter's cache.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
)

const evidence = "../../../evidence"

func TestInFirstParentRange(t *testing.T) {
	hist := []string{"e", "d", "c", "b", "a"} // newest first
	cases := []struct {
		a, v string
		want bool
	}{
		{"", "c", true},  // ..B holds everything on B's history
		{"", "x", false}, // not on the history
		{"b", "c", true}, // A older than V
		{"c", "c", true}, // inclusive lower end
		{"d", "c", false},
		{"e", "e", true}, // inclusive upper end: A..B with A = B = V
		{"x", "c", false},
	}
	for _, c := range cases {
		if got := inFirstParentRange(hist, c.a, c.v); got != c.want {
			t.Errorf("inFirstParentRange(%q, %q) = %v, want %v", c.a, c.v, got, c.want)
		}
	}
}

func TestSDKVersion(t *testing.T) {
	gomod := "module github.com/stellar/wallet-backend\n\ngo 1.25.9\n\nrequire (\n\tgithub.com/stellar/go-stellar-sdk v0.7.3\n\tgithub.com/stellar/go-xdr v0.0.0-2025\n)\n"
	if m, v := sdkVersion(gomod); m != "github.com/stellar/go-stellar-sdk" || v != "v0.7.3" {
		t.Errorf("got %s %s", m, v)
	}
	if semverAtLeast("v0.7.3", 0, 8, 0) || !semverAtLeast("v0.8.0", 0, 8, 0) || !semverAtLeast("v0.8.1-0.20261101-abcdef", 0, 8, 0) || !semverAtLeast("v1.0.0", 0, 8, 0) {
		t.Error("semverAtLeast")
	}
	if m, v := sdkVersion("require github.com/stellar/go v0.0.0-2024 // indirect\n"); m != "github.com/stellar/go" || v != "v0.0.0-2024" {
		t.Errorf("old monorepo: got %s %s", m, v)
	}
}

func readFlags(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(evidence, path))
	if err != nil {
		t.Fatal(err)
	}
	return parseFlags(string(b))
}

// The flag tables saved by the executed reproductions: `ingest --help` at the current commit, and a plain list
// at a pre-fix commit. The command line differs: the current commit has no --network and no
// --stellar-environment.
func TestIngestArgsPerCommit(t *testing.T) {
	net := adapter.Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"}
	s3 := adapter.Input{Kind: "sep54-s3", EndpointURL: "http://127.0.0.1:9000", BucketPath: "ledgers/u1", Region: "us-east-1", AccessKeyID: "test", SecretAccessKey: "test"}
	for _, c := range []struct {
		file        string
		network     bool
		environment bool
	}{
		{"wallet-backend-731/logs/flags-e967ce8b.txt", false, false},
		{"wallet-backend-replay/logs/flags-2a0a84ea.txt", true, true},
	} {
		flags := readFlags(t, c.file)
		if !flags["database-url"] || !flags["datastore-endpoint-url"] {
			t.Fatalf("%s: flags not read: %v", c.file, flags)
		}
		args, env, err := ingestArgs(flags, s3, net, "postgres://postgres@/run?host=/x", 58001)
		if err != nil {
			t.Fatal(err)
		}
		line := strings.Join(args, " ")
		if strings.Contains(line, "--network testnet") != c.network || strings.Contains(line, "--stellar-environment") != c.environment {
			t.Errorf("%s: %s", c.file, line)
		}
		for _, want := range []string{"--ledger-backend-type datastore", "--archive-url http://127.0.0.1:1/", "--rpc-url http://127.0.0.1:1",
			"--datastore-bucket-path ledgers/u1", "--datastore-endpoint-url http://127.0.0.1:9000", "--ingest-server-port 58001", "--ingestion-mode live"} {
			if !strings.Contains(line, want) {
				t.Errorf("%s: missing %q in %s", c.file, want, line)
			}
		}
		if !slices.Contains(env, "AWS_ACCESS_KEY_ID=test") || slices.ContainsFunc(env, func(s string) bool { return strings.HasPrefix(s, "DATABASE_URL") }) {
			t.Errorf("env %v", env)
		}
		rpcArgs, _, err := ingestArgs(flags, adapter.Input{Kind: "rpc", URL: "http://127.0.0.1:7000/u"}, net, "db", 1)
		if err != nil || !strings.Contains(strings.Join(rpcArgs, " "), "--ledger-backend-type rpc --rpc-url http://127.0.0.1:7000/u") {
			t.Errorf("rpc args %v %v", rpcArgs, err)
		}
	}
	if _, _, err := ingestArgs(map[string]bool{"database-url": true}, s3, net, "db", 1); err == nil {
		t.Error("a command line without the required flags must be refused")
	}
}

// The halt at the #729 pre-fix commit: exit 2, the returned error wrapped in panic(…) from goroutine 1.
const haltStderr = `time="…" level=error msg="processing ledger 4437357: ingesting processed data failed after 5 attempts"
Error: running ingest
Usage:
  wallet-backend ingest [flags]

Flags:
      --admin-port int   Port for admin server
panic: executing root command: running ingest: running 'ingest' from 0 to 0: processing ledger 4437357: ingesting processed data failed after 5 attempts: batch inserting state changes: … (SQLSTATE 57014)

goroutine 1 [running]:
main.main()
`

func TestRuntimePanic(t *testing.T) {
	cases := []struct {
		name      string
		stderr    string
		exit      int
		after     bool
		panicked  bool
		decidable bool
	}{
		{"returned error before the change", haltStderr, 2, false, false, true},
		{"nil dereference before the change", "panic: runtime error: invalid memory address or nil pointer dereference\n\ngoroutine 57 [running]:\n", 2, false, true, true},
		{"root-command panic from another goroutine", "panic: executing root command: x\n\ngoroutine 9 [running]:\n", 2, false, true, true},
		{"exit 2 with no panic text before the change", "killed", 2, false, false, false},
		{"returned error after the change", "Error: x", 1, true, false, true},
		{"panic after the change", "panic: runtime error: index out of range\n", 2, true, true, true},
		{"exit 3 before the change", "", 3, false, false, false},
	}
	for _, c := range cases {
		p, ok := runtimePanic(c.stderr, c.exit, c.after)
		if p != c.panicked || ok != c.decidable {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, p, ok, c.panicked, c.decidable)
		}
	}
}

func i64(v int64) *int64 { return &v }

func TestIngestResult(t *testing.T) {
	p := adapter.IngestParams{Range: adapter.Range{Start: 4437357, End: 4437357}}
	// Completed: the cursor reached the end and the adapter stopped the process.
	r := ingestResult(p, proc.Result{ExitCode: 0, Canceled: true}, i64(4437356), i64(4437357), true, false, true, false, 300*time.Millisecond)
	if r.Status != adapter.StatusCompleted || !*r.Signals.StoppedByAdapter || r.Signals.ProcessExited {
		t.Errorf("completed: %+v", r)
	}
	// The #729 halt.
	res := proc.Result{ExitCode: 2, Stderr: proc.Tail{Data: []byte(haltStderr)}}
	r = ingestResult(p, res, i64(4437356), i64(4437356), false, false, false, false, 15*time.Second)
	if r.Status != adapter.StatusHalted {
		t.Fatalf("halt: %s", r.Status)
	}
	if v, _ := r.Signals.FailingLedger.Get(); v != 4437357 {
		t.Errorf("failing ledger %d", v)
	}
	if v, _ := r.Signals.Phase.Get(); v != "persist" {
		t.Errorf("phase %q", v)
	}
	if v, _ := r.Signals.Attempts.Get(); v != 5 {
		t.Errorf("attempts %d", v)
	}
	if v, ok := r.Signals.RuntimePanic.Get(); !ok || v {
		t.Errorf("runtime_panic %v %v", v, ok)
	}
	tail, _ := r.Signals.StderrTail.Get()
	if strings.Contains(tail, "--admin-port") || !strings.Contains(tail, "panic: executing root command") {
		t.Errorf("tail keeps usage text or loses the error: %q", tail)
	}
	// A runtime fault.
	res = proc.Result{ExitCode: 2, Stderr: proc.Tail{Data: []byte("panic: runtime error: invalid memory address\n\ngoroutine 33 [running]:\n")}}
	if r = ingestResult(p, res, i64(4437356), i64(4437356), false, false, false, false, time.Second); r.Status != adapter.StatusCrashed {
		t.Errorf("crash: %s", r.Status)
	}
	// Killed by a signal.
	if r = ingestResult(p, proc.Result{ExitCode: 137, Signal: syscall.SIGKILL}, i64(4437356), i64(4437356), false, false, false, false, time.Second); r.Status != adapter.StatusCrashed {
		t.Errorf("signal: %s", r.Status)
	} else if v, _ := r.Signals.TermSignal.Get(); v != "SIGKILL" {
		t.Errorf("term_signal %q", v)
	}
	// Still running at the deadline.
	if r = ingestResult(p, proc.Result{Canceled: true}, i64(4437356), i64(4437356), false, true, true, false, 30*time.Second); r.Status != adapter.StatusTimeout {
		t.Errorf("timeout: %s", r.Status)
	}
	// Undecidable exit: halted with runtime_panic null.
	r = ingestResult(p, proc.Result{ExitCode: 2}, i64(4437356), nil, false, false, false, false, time.Second)
	if r.Status != adapter.StatusHalted || !r.Signals.RuntimePanic.Null {
		t.Errorf("undecidable: %s %+v", r.Status, r.Signals.RuntimePanic)
	}
	b, _ := json.Marshal(r)
	if errs := adapter.ValidateMessage(append(append([]byte(`{"xcc":"xcc.adapter/1","id":3,"method":"ingest","result":`), b...), '}')); len(errs) > 0 {
		t.Errorf("ingest result does not validate: %v", errs)
	}
}

func s(v string) *string { return &v }

func hexEnc(col string) string { return "version_byte_payload_hex" }

func TestMapStateChange(t *testing.T) {
	acct := "3044ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20"
	signer41 := "7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b2000000003deadbe00"
	sac := "10" + strings.Repeat("cd", 32) // a contract key (33 bytes)
	native := "10" + strings.Repeat("ab", 32)

	f, ok := mapStateChange(scRow{Category: s("SIGNER"), Reason: s("ADD"), OpID: s("19058303195680769"), Account: s(acct), Signer: s(signer41), WNew: s("1")}, hexEnc)
	if !ok || f.Kind != "signer_added" || f.Account.Address != "GBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSBB7B" ||
		f.Signer.AsStored.Value != signer41 || f.Signer.Key != "" || *f.Signer.Weight != 1 || f.Detail != nil || f.NativeLabel != "SIGNER/ADD" {
		t.Errorf("signer: %+v %+v", f, f.Signer)
	}
	// A truncated (33-byte) signer value passes through unchanged and is never rendered.
	f, _ = mapStateChange(scRow{Category: s("SIGNER"), Reason: s("ADD"), Account: s(acct), Signer: s(signer41[:66]), WNew: s("1"), WOld: s("0")}, hexEnc)
	if f.Signer.AsStored.Value != signer41[:66] || f.Signer.Key != "" || f.Detail["weight_before"] != json.Number("0") {
		t.Errorf("truncated signer: %+v", f.Signer)
	}

	f, ok = mapStateChange(scRow{Category: s("TRUSTLINE"), Reason: s("ADD"), OpID: s("64424513537"), Account: s(acct), Token: s(sac), Limit: s("922337203685.4775807")}, hexEnc)
	if !ok || f.Kind != "trustline_created" || !strings.HasPrefix(f.Asset, "C") || f.Detail["limit_as_stored"] != "922337203685.4775807" || len(f.Detail) != 1 {
		t.Errorf("trustline: %+v", f)
	}
	f, ok = mapStateChange(scRow{Category: s("BALANCE_AUTHORIZATION"), Reason: s("SET"), Account: s(acct), Token: s(sac), Flags: s("1"), Limit: s("922337203685.4775807")}, hexEnc)
	if !ok || f.Kind != "trustline_flags_changed" || f.Detail["authorized"] != true || f.Detail["flags_as_stored"] != "1" || len(f.Detail) != 2 {
		t.Errorf("authorization (a limit is never carried on this kind, nor the XDR flags): %+v", f)
	}
	// wallet-backend's bits: 32 is clawback_enabled, 64 authorized_to_maintain_liabilities; CLEAR states them false.
	f, _ = mapStateChange(scRow{Category: s("BALANCE_AUTHORIZATION"), Reason: s("CLEAR"), Account: s(acct), Token: s(sac), Flags: s("97")}, hexEnc)
	if f.Detail["authorized"] != false || f.Detail["clawback_enabled"] != false || f.Detail["authorized_to_maintain_liabilities"] != false || f.Detail["flags"] != nil {
		t.Errorf("cleared flags: %+v", f.Detail)
	}
	// A row with no flags (a pool-share trustline's initial authorization) states none.
	f, _ = mapStateChange(scRow{Category: s("BALANCE_AUTHORIZATION"), Reason: s("SET"), Account: s(acct)}, hexEnc)
	if f.Kind != "trustline_flags_changed" || f.Detail != nil {
		t.Errorf("no flags: %+v", f)
	}
	// The master key removed is master weight 0.
	f, _ = mapStateChange(scRow{Category: s("SIGNER"), Reason: s("REMOVE"), OpType: s("SET_OPTIONS"), Account: s(acct), Signer: s(acct), WOld: s("1")}, hexEnc)
	if f.Kind != "thresholds_changed" || f.Signer != nil || f.Detail["master_weight"] != json.Number("0") || len(f.Detail) != 1 {
		t.Errorf("master key removed: %+v", f)
	}
	// A signer that is not the account's own key stays a signer, whatever the operation.
	f, _ = mapStateChange(scRow{Category: s("SIGNER"), Reason: s("ADD"), OpType: s("CREATE_ACCOUNT"), Account: s(acct), Signer: s(signer41), WNew: s("1")}, hexEnc)
	if f.Kind != "signer_added" {
		t.Errorf("other signer: %+v", f)
	}
	f, ok = mapStateChange(scRow{Category: s("BALANCE"), Reason: s("DEBIT"), OpID: s("0"), Account: s(acct), Token: s(native), Amount: s("74541")}, hexEnc)
	if !ok || f.Kind != "balance_changed" || f.Detail["delta"] != "-74541" || f.Detail["reason"] != "fee" {
		t.Errorf("fee: %+v", f)
	}
	f, _ = mapStateChange(scRow{Category: s("BALANCE"), Reason: s("CREDIT"), OpID: s("68719480833"), Account: s(acct), Token: s(native), Amount: s("12.5")}, hexEnc)
	if f.Detail["delta_as_stored"] != "12.5" || f.Detail["reason"] != "other" || f.Detail["delta"] != nil {
		t.Errorf("non-integer amount: %+v", f.Detail)
	}
	if _, ok := mapStateChange(scRow{Category: s("FLAGS"), Reason: s("SET"), Account: s(acct)}, hexEnc); ok {
		t.Error("FLAGS/SET has no neutral kind and must be left out")
	}
}

// realRows are state_changes rows wallet-backend wrote at the current pinned commit for named corpus entries
// (testdata/state-changes-e967ce8b.json), keyed by entry.
func realRows(t *testing.T) map[string]struct {
	Hash string
	Rows []scRow
} {
	t.Helper()
	b, err := os.ReadFile("testdata/state-changes-e967ce8b.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Transactions []struct {
			Entry string  `json:"entry"`
			Hash  string  `json:"tx_hash"`
			Rows  []scRow `json:"rows"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]struct {
		Hash string
		Rows []scRow
	}{}
	for _, tx := range doc.Transactions {
		out[tx.Entry] = struct {
			Hash string
			Rows []scRow
		}{tx.Hash, tx.Rows}
	}
	return out
}

// mapped maps a transaction's rows, leaving out the ambient fee and balance rows, and keeps each fact's operation
// index.
func mapped(t *testing.T, rows []scRow) (facts []adapter.ObsStateChange, left int) {
	t.Helper()
	for _, r := range rows {
		f, ok := mapStateChange(r, hexEnc)
		if !ok {
			left++
			continue
		}
		if f.Kind == "balance_changed" {
			continue
		}
		f.Locator = adapter.Locator{TxHash: r.Hash, OpIndex: opIndex(deref(r.OpID))}
		facts = append(facts, f)
	}
	return facts, left
}

// The expected facts below come from the ledger transitions the entries state (their bytes), not from
// wallet-backend: each entry's manifest records the trustline flags or thresholds before and after.
func TestMapRealRows(t *testing.T) {
	txs := realRows(t)
	flagFacts := func(entry string) []map[string]any {
		facts, _ := mapped(t, txs[entry].Rows)
		var out []map[string]any
		for _, f := range facts {
			if f.Kind != "trustline_flags_changed" {
				t.Errorf("%s: unexpected %s", entry, f.Kind)
				continue
			}
			if _, ok := f.Detail["flags"]; ok {
				t.Errorf("%s: wallet-backend's flag column is not the XDR mask, yet flags was filled: %v", entry, f.Detail)
			}
			out = append(out, f.Detail)
		}
		return out
	}
	// AllowTrust authorize = 2: the trustline goes from AUTHORIZED (1) to AUTHORIZED_TO_MAINTAIN_LIABILITIES (2).
	// The stored 64 is wallet-backend's bit for the latter; nothing in the row says AUTHORIZED is now off.
	if d := flagFacts("cap-0018/allow-trust-maintain-liabilities"); len(d) != 1 || d[0]["authorized_to_maintain_liabilities"] != true ||
		d[0]["flags_as_stored"] != "64" || len(d[0]) != 2 {
		t.Errorf("allow-trust 2: %v", d)
	}
	// The same 1 -> 2 transition by AllowTrust and by SetTrustLineFlags (clear 1, set 2): every stated boolean
	// agrees with flags 2 afterwards.
	d := flagFacts("cap-0035/allow-trust-versus-set-trust-line-flags")
	if len(d) != 3 {
		t.Fatalf("allow-trust versus set-trust-line-flags: %v", d)
	}
	for _, x := range d {
		for k, v := range x {
			want := map[string]any{"authorized": false, "authorized_to_maintain_liabilities": true, "clawback_enabled": false}[k]
			if k != "flags_as_stored" && v != want {
				t.Errorf("allow-trust versus set-trust-line-flags: %s = %v after a transition to flags 2", k, v)
			}
		}
	}
	// Revocation: flags 1 -> 0.
	if d := flagFacts("cap-0038/auth-revocation-redeems-pool-shares"); len(d) != 1 || d[0]["authorized"] != false || len(d[0]) != 2 {
		t.Errorf("revocation: %v", d)
	}

	// SetOptions: thresholds 01000000 -> ff0180ff. The master-weight change is wallet-backend's SIGNER/UPDATE of
	// the account's own key; together the four rows state master weight 255 and thresholds 1, 128, 255.
	facts, _ := mapped(t, txs["classic/set-options-thresholds-and-master-weight"].Rows)
	got := map[string]any{}
	for _, f := range facts {
		if f.Kind != "thresholds_changed" || f.Account.Address != "GAJRDHY5BWMX6NYGCX2KKDIES6QP7TTDGGEGRMSMHW5HFXGORUU2JFFR" || len(f.Detail) != 1 {
			t.Errorf("set-options: %+v", f)
		}
		for k, v := range f.Detail {
			got[k] = v
		}
	}
	if want := map[string]any{"master_weight": json.Number("255"), "low": json.Number("1"), "medium": json.Number("128"), "high": json.Number("255")}; len(facts) != 4 || !mapsEqual(got, want) {
		t.Errorf("set-options: got %v from %d facts", got, len(facts))
	}

	// A contract deployed from an address preimage is written as ACCOUNT/CREATE of the contract.
	facts, _ = mapped(t, txs["cap-0058/create-contract-v2-with-constructor"].Rows)
	if len(facts) != 1 || facts[0].Kind != "contract_deployed" || !strings.HasPrefix(facts[0].Account.Address, "C") ||
		facts[0].Detail["contract"] != facts[0].Account.Address {
		t.Errorf("contract deploy: %+v", facts)
	}

	// Six CreateAccount operations: six account_created; the six master-key rows describe the created accounts'
	// defaults and are left out.
	facts, left := mapped(t, txs["classic/create-account-funded-from-root"].Rows)
	if len(facts) != 6 || left != 6 {
		t.Fatalf("create accounts: %d facts, %d left out", len(facts), left)
	}
	for i, f := range facts {
		if f.Kind != "account_created" || f.OpIndex == nil || *f.OpIndex != i {
			t.Errorf("create accounts: fact %d %+v", i, f)
		}
	}

	// A trustline created by the Stellar Asset Contract with flags 1 (wallet-backend#731, fixed).
	facts, _ = mapped(t, txs["cap-0073/sac-trust-creates-trustline"].Rows)
	if len(facts) != 2 || facts[0].Kind != "trustline_created" || facts[1].Kind != "trustline_flags_changed" ||
		facts[1].Detail["authorized"] != true || facts[0].Asset != facts[1].Asset {
		t.Errorf("SAC trust: %+v", facts)
	}

	// Every fact mapped from the real rows is a valid observation.
	l := adapter.Ledger{LedgerSeq: 2}
	for _, tx := range txs {
		fs, _ := mapped(t, tx.Rows)
		l.StateChanges = append(l.StateChanges, fs...)
	}
	sortFacts(&l)
	obs := adapter.Observation{Schema: adapter.ObservationSchema, Range: adapter.Range{Start: 2, End: 2}, Ledgers: []adapter.Ledger{l}}
	for _, k := range adapter.AllKinds {
		*obs.Kinds.Kind(k) = adapter.KindStatus{Status: "not_applicable", Reason: "not requested"}
	}
	obs.Kinds.StateChanges = adapter.KindStatus{Status: "provided"}
	b, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if errs := adapter.ValidateObservation(b); len(errs) > 0 {
		t.Errorf("observation from real rows does not validate: %v", errs)
	}
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestObservationValidates(t *testing.T) {
	acct := "3044ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20"
	h := "d9f78749cd01297cd5f22c7f2c798c9eec93d56f399e1c4cc2f8977ca52b9fed"
	n12 := int64(12)
	l := adapter.Ledger{LedgerSeq: 4437357, Receipt: &adapter.Receipt{Transactions: &n12, Operations: &n12}}
	l.Transactions = append(l.Transactions, mapTransaction(txRow{Hash: h, ResultCode: s("TransactionResultCodeTxSuccess"), FeeCharged: s("100")}, 0))
	for _, r := range []scRow{
		{Category: s("SIGNER"), Reason: s("ADD"), OpID: s("19058303195680769"), Account: s(acct), Signer: s("78" + acct[2:] + "00000003deadbe00"), WNew: s("1")},
		{Category: s("BALANCE"), Reason: s("DEBIT"), OpID: s("0"), Account: s(acct), Amount: s("100")},
		{Category: s("BALANCE_AUTHORIZATION"), Reason: s("SET"), Account: s(acct), Flags: s("1")},
		{Category: s("TRUSTLINE"), Reason: s("ADD"), Account: s(acct), Limit: s("1.0000000")},
	} {
		f, ok := mapStateChange(r, hexEnc)
		if !ok {
			t.Fatal("unmapped")
		}
		f.Locator = adapter.Locator{TxHash: h, OpIndex: opIndex(deref(r.OpID))}
		l.StateChanges = append(l.StateChanges, f)
	}
	st := stored("version_byte_payload_hex", acct)
	l.Participants = []adapter.ObsParticipant{{Locator: adapter.Locator{TxHash: h}, Account: *account(st)}}
	l.Addresses = []adapter.ObsAddress{{Locator: adapter.Locator{TxHash: h}, Field: "transactions_accounts.account_id", AsStored: st}}
	sortFacts(&l)
	obs := adapter.Observation{Schema: adapter.ObservationSchema, Range: adapter.Range{Start: 4437357, End: 4437357}, Ledgers: []adapter.Ledger{l}}
	for _, k := range adapter.AllKinds {
		*obs.Kinds.Kind(k) = adapter.KindStatus{Status: "provided"}
	}
	obs.Kinds.Movements = adapter.KindStatus{Status: "not_applicable", Reason: "not modelled"}
	b, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if errs := adapter.ValidateObservation(b); len(errs) > 0 {
		t.Errorf("observation does not validate: %v\n%s", errs, b)
	}
	if l.Transactions[0].ResultCode != "tx_success" || l.Transactions[0].NativeLabel != "TransactionResultCodeTxSuccess" {
		t.Errorf("result code %+v", l.Transactions[0])
	}
}

func TestResultCodes(t *testing.T) {
	for label, want := range map[string]string{
		"TransactionResultCodeTxSuccess":             "tx_success",
		"TransactionResultCodeTxFailed":              "tx_failed",
		"TransactionResultCodeTxFeeBumpInnerSuccess": "tx_fee_bump_inner_success",
		"TransactionResultCodeTxBadMinSeqAgeOrGap":   "tx_bad_min_seq_age_or_gap",
		"SomethingElse":                              "SomethingElse",
	} {
		if got := resultCode(label); got != want {
			t.Errorf("%s: %s, want %s", label, got, want)
		}
	}
}

func TestOpIndex(t *testing.T) {
	if p := opIndex("19058303195680769"); p == nil || *p != 0 {
		t.Errorf("first operation: %v", p)
	}
	if p := opIndex("55834578950"); p == nil || *p != 5 {
		t.Errorf("sixth operation: %v", p)
	}
	if opIndex("0") != nil || opIndex("19058303195680768") != nil {
		t.Error("a transaction-level row has no operation")
	}
}

func TestSanitizeDBName(t *testing.T) {
	if got := sanitizeDBName("run_", "s-0007"); got != "run_s_0007" {
		t.Errorf("got %s", got)
	}
}
