package match

// The paper walk of the wallet-backend acceptance runs, made executable. Each case reads the row set a published
// transcript recorded (evidence/wallet-backend-replay, evidence/wallet-backend-731), turns the rows into an
// observation set with the reference adapter's row mapping (one stored row → one fact: SIGNER/ADD →
// signer_added, TRUSTLINE/ADD → trustline_created, BALANCE_AUTHORIZATION/SET → trustline_flags_changed,
// BALANCE/DEBIT → balance_changed; addresses passed as version_byte_payload_hex; result labels through the fixed
// table), matches it against the vendored manifest entry and checks the result the class table predicts:
//
//	#729 pre-fix 2a0a84ea  no rows                                  → nothing matched (the classifier says halt)
//	#729 fixed   2c873353  fee row + 41-byte signer                 → every fact matched or not applicable: pass
//	#716 pre-fix 79ea2acd  fee row + 33-byte signer                 → signer_added and the address wrong: wrong_value
//	#716 fixed   bb0b162b  identical to 2c873353                    → pass
//	#731 pre-fix 764a4f5b  fee row only                             → both trustline facts missing, nothing wrong: partial
//	#731 fixed   c152783c  fee + TRUSTLINE/ADD + BALANCE_AUTHORIZATION/SET → pass, fee and authorisation rows present
//	#731 head    e967ce8b  as fixed, without the contract participant → pass
//
// What the #729/#716 transcripts do not print, and how it is filled (the class table makes the same assumptions):
// they print the focus transaction's row, the per-ledger counts (12 transactions, 12 operations) and its state
// changes, but not the other eleven transaction rows nor the participant rows (only a count of 23). The other
// eleven transactions are listed by hash only (no result fields, so nothing about them is compared), and the
// focus transaction's participant is its source account as the SIGNER row's account column records it; the
// BALANCE/DEBIT row (printed only with its 33-byte account length) is attributed to the same account.

import (
	"bufio"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

const (
	corpusRoot   = "../../../corpus"
	evidenceRoot = "../../../evidence"
)

// walletBackendDescribe is the reference adapter's describe result: the worked example in the schema directory.
func walletBackendDescribe(t *testing.T) *adapter.DescribeResult {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpusRoot, "schema/examples/adapter-protocol/valid-02.json"))
	if err != nil {
		t.Fatal(err)
	}
	var msg struct {
		Result adapter.DescribeResult `json:"result"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	return &msg.Result
}

func loadVariant(t *testing.T, id, network string, protocol int) *manifest.Variant {
	t.Helper()
	return loadVariantFile(t, filepath.Join(corpusRoot, "manifest", id+".json"), network, protocol)
}

func loadVariantFile(t *testing.T, path, network string, protocol int) *manifest.Variant {
	t.Helper()
	e, err := manifest.LoadEntry(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range e.Variants {
		if v.Network == network && v.Protocol == protocol {
			return v
		}
	}
	t.Fatalf("%s has no %s@%d variant", path, network, protocol)
	return nil
}

// resultLabels is the adapter's fixed table from wallet-backend's Go enum names to XDR-JSON names.
var resultLabels = map[string]string{
	"TransactionResultCodeTxSuccess": "tx_success",
	"TransactionResultCodeTxFailed":  "tx_failed",
}

// storedHex renders a strkey as the bytes wallet-backend's BYTEA column holds (version byte ‖ payload), by plain
// base32 decoding — not through the decoder under test.
func storedHex(t *testing.T, strkey string) string {
	t.Helper()
	bin, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strkey)
	if err != nil {
		t.Fatalf("%s: %v", strkey, err)
	}
	return hex.EncodeToString(bin[:len(bin)-2])
}

// account maps a stored address column the way the adapter does: as_stored always; address only for a 33-byte
// account or contract key (version 0x30 or 0x10 and 32 bytes).
func account(storedHexValue string) *adapter.ObsAccount {
	a := &adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: storedHexValue}}
	if b, err := hex.DecodeString(storedHexValue); err == nil && len(b) == 33 && (b[0] == 0x30 || b[0] == 0x10) {
		bin := append([]byte{}, b...)
		crc := crc16(bin)
		a.Address = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(bin, byte(crc), byte(crc>>8)))
	}
	return a
}

func newObservation(seq int64) *adapter.Observation {
	return &adapter.Observation{
		Schema: adapter.ObservationSchema,
		Range:  adapter.Range{Start: seq, End: seq},
		Kinds: adapter.KindsSet{
			Receipts:     adapter.KindStatus{Status: "provided", Subkinds: []string{"transactions", "operations"}},
			Transactions: adapter.KindStatus{Status: "provided"},
			Participants: adapter.KindStatus{Status: "provided"},
			StateChanges: adapter.KindStatus{Status: "provided"},
			Movements:    adapter.KindStatus{Status: "not_applicable", Reason: "adapter v0.1 maps state changes only"},
			Addresses:    adapter.KindStatus{Status: "provided"},
		},
		Ledgers: []adapter.Ledger{},
	}
}

func i64(v int64) *int64 { return &v }
func ip(v int) *int      { return &v }

// ---- #729 / #716: evidence/wallet-backend-replay ----

func section(lines []string, header string) []string {
	var out []string
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, "-- ") || strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "$ ") {
			in = strings.HasPrefix(l, header)
			continue
		}
		if in && strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// replayObservation builds the observation of testnet ledger 4437357 from a wallet-backend replay transcript (evidence/wallet-backend-replay/).
func replayObservation(t *testing.T, file string, v *manifest.Variant) *adapter.Observation {
	lines := readLines(t, filepath.Join(evidenceRoot, "wallet-backend-replay", file))
	const seq = 4437357
	obs := newObservation(seq)
	counts := section(lines, "-- row counts")
	if len(counts) != 1 {
		t.Fatalf("%s: row counts: %q", file, counts)
	}
	n := strings.Split(counts[0], "|")
	ntx, _ := strconv.Atoi(n[0])
	nops, _ := strconv.Atoi(n[1])
	if ntx == 0 {
		return obs // no rows for the ledger: the indexer holds nothing, the ledger is absent
	}
	l := adapter.Ledger{LedgerSeq: seq, Receipt: &adapter.Receipt{Transactions: i64(int64(ntx)), Operations: i64(int64(nops))}}

	target := section(lines, "-- target tx")
	if len(target) != 1 {
		t.Fatalf("%s: target tx: %q", file, target)
	}
	tf := strings.Split(target[0], "|") // to_id|hash|result_code|ledger
	focus := tf[1]
	for _, et := range v.Resolved.Transactions {
		if et.Hash == focus {
			l.Transactions = append(l.Transactions, adapter.ObsTransaction{Hash: focus, Index: ip(et.Index), ResultCode: resultLabels[tf[2]], NativeLabel: tf[2]})
		} else {
			// Not printed by the transcript; present in the indexer (12 transaction rows). Hash only.
			l.Transactions = append(l.Transactions, adapter.ObsTransaction{Hash: et.Hash})
		}
	}
	if len(l.Transactions) != ntx {
		t.Fatalf("%s: %d transactions listed, %d counted", file, len(l.Transactions), ntx)
	}

	signer := section(lines, "-- SIGNER state changes")
	if len(signer) != 1 {
		t.Fatalf("%s: signer rows: %q", file, signer)
	}
	sf := strings.Split(signer[0], "|") // category|reason|account|signer|signer_len|weight_old|weight_new
	acct := sf[2]
	l.Participants = append(l.Participants, adapter.ObsParticipant{Locator: adapter.Locator{TxHash: focus}, Account: *account(acct)})
	for _, row := range section(lines, "-- all state changes") {
		f := strings.Split(row, "|") // category|reason|account_len|signer_len
		label := f[0] + "/" + f[1]
		switch label {
		case "BALANCE/DEBIT":
			l.StateChanges = append(l.StateChanges, adapter.ObsStateChange{Locator: adapter.Locator{TxHash: focus}, Kind: "balance_changed",
				Account: account(acct), Detail: map[string]any{"reason": "fee"}, NativeLabel: label})
		case "SIGNER/ADD":
			sc := adapter.ObsStateChange{Locator: adapter.Locator{TxHash: focus}, Kind: "signer_added", Account: account(sf[2]),
				Signer: &adapter.ObsSigner{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: sf[3]}}, NativeLabel: label}
			if w, err := strconv.Atoi(sf[6]); err == nil {
				sc.Signer.Weight = &w
			}
			if w, err := strconv.Atoi(sf[5]); err == nil {
				sc.Detail = map[string]any{"weight_before": json.Number(fmt.Sprint(w))}
			}
			l.StateChanges = append(l.StateChanges, sc)
			l.Addresses = append(l.Addresses, adapter.ObsAddress{Locator: adapter.Locator{TxHash: focus}, Field: "state_changes.signer_account_id",
				AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: sf[3]}})
		default:
			t.Fatalf("%s: unmapped row %s", file, label)
		}
		l.Addresses = append(l.Addresses, adapter.ObsAddress{Locator: adapter.Locator{TxHash: focus}, Field: "state_changes.account_id",
			AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: acct}})
	}
	obs.Ledgers = append(obs.Ledgers, l)
	return obs
}

// ---- #731: evidence/wallet-backend-731 ----

var kvRe = regexp.MustCompile(`(\w+)=([^|]*)`)

func kv(line string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(line, -1) {
		m[x[1]] = strings.TrimSpace(x[2])
	}
	return m
}

// trustObservation builds the observation of ledger 15 from one case of a wallet-backend#731 transcript (evidence/wallet-backend-731/).
func trustObservation(t *testing.T, file, input string) *adapter.Observation {
	all := readLines(t, filepath.Join(evidenceRoot, "wallet-backend-731", file))
	var lines []string
	in := false
	for _, l := range all {
		if strings.HasPrefix(l, "################ case:") {
			in = strings.HasPrefix(l, "################ case: "+input+", only15")
			continue
		}
		if in {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		t.Fatalf("%s: no %s only15 case", file, input)
	}
	const seq = 15
	obs := newObservation(seq)
	l := adapter.Ledger{LedgerSeq: seq}
	for _, row := range section(lines, "-- row counts") {
		f := kv(row)
		if f["l"] == "15" {
			tx, _ := strconv.ParseInt(f["tx"], 10, 64)
			ops, _ := strconv.ParseInt(f["ops"], 10, 64)
			l.Receipt = &adapter.Receipt{Transactions: &tx, Operations: &ops}
		}
	}
	if l.Receipt == nil {
		t.Fatalf("%s: no counts for ledger 15", file)
	}
	toHash := map[string]string{}
	for i, row := range section(lines, "-- transactions ledger>=15") {
		f := kv(row)
		toHash[f["to_id"]] = f["hash"]
		l.Transactions = append(l.Transactions, adapter.ObsTransaction{Hash: f["hash"], Index: ip(i), ResultCode: resultLabels[f["result_code"]],
			FeeCharged: f["fee_charged"], NativeLabel: f["result_code"]})
	}
	for _, row := range section(lines, "-- transactions_accounts ledger>=15") {
		f := kv(row)
		l.Participants = append(l.Participants, adapter.ObsParticipant{Locator: adapter.Locator{TxHash: f["hash"]}, Account: *account(storedHex(t, f["account"]))})
		l.Addresses = append(l.Addresses, adapter.ObsAddress{Locator: adapter.Locator{TxHash: f["hash"]}, Field: "transactions_accounts.account_id",
			AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: storedHex(t, f["account"])}})
	}
	for _, row := range section(lines, "-- state_changes ledger>=15") {
		f := kv(row)
		tx := toHash[f["to_id"]]
		label := f["cat"] + "/" + f["reason"]
		sc := adapter.ObsStateChange{Locator: adapter.Locator{TxHash: tx}, Account: account(storedHex(t, f["account"])), Asset: f["token"], NativeLabel: label}
		switch label {
		case "BALANCE/DEBIT":
			reason := "other"
			if f["operation_id"] == "0" {
				reason = "fee"
			}
			sc.Kind, sc.Detail = "balance_changed", map[string]any{"delta": "-" + f["amount"], "reason": reason}
		case "TRUSTLINE/ADD":
			sc.Kind, sc.Detail = "trustline_created", map[string]any{"limit_as_stored": f["trustline_limit_new"]}
		case "BALANCE_AUTHORIZATION/SET":
			sc.Kind, sc.Detail = "trustline_flags_changed", map[string]any{"flags": json.Number(f["flags"])}
		default:
			t.Fatalf("%s: unmapped row %s", file, label)
		}
		l.StateChanges = append(l.StateChanges, sc)
		l.Addresses = append(l.Addresses,
			adapter.ObsAddress{Locator: adapter.Locator{TxHash: tx}, Field: "state_changes.account_id", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: storedHex(t, f["account"])}},
			adapter.ObsAddress{Locator: adapter.Locator{TxHash: tx}, Field: "state_changes.token_id", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: storedHex(t, f["token"])}})
	}
	obs.Ledgers = append(obs.Ledgers, l)
	return obs
}

// ---- the table ----

type want struct {
	class    string            // what the counts imply under classifier rows 8–10 (for halt: no facts matched)
	statuses map[string]Status // "<kind>#<index>[.<field>]" → status
	extras   map[string]ExtraStatus
}

type wbCase struct {
	name string
	v    *manifest.Variant
	obs  func() *adapter.Observation
	want want
}

func factKey(f Fact) string {
	k := fmt.Sprintf("%s#%d", f.Kind, f.Index)
	if f.Field != "" {
		k += "." + f.Field
	}
	return k
}

func impliedClass(r *Result) string {
	s := r.Summary()
	switch {
	case !r.LedgerObserved:
		return "ledger-absent"
	case s.AnyWrong() || s.ReceiptExcess:
		return "wrong_value"
	case s.Missing > 0:
		return "partial"
	case s.Matched > 0:
		return "pass"
	}
	return "not_applicable"
}

func TestWalletBackendTranscripts(t *testing.T) {
	desc := walletBackendDescribe(t)
	signer := loadVariant(t, "cap-0040/signed-payload-signer-added", "testnet", 28)
	// The #731 transcripts were recorded on the research-probe ledgers (evidence/wallet-backend-731/), so
	// they are matched against the entry as it stood for those ledgers (the frozen copy testcorpus serves).
	trust := loadVariantFile(t, filepath.Join(testcorpus.Frozen(), "manifest/cap-0073/sac-trust-creates-trustline.json"), "testnet", 28)

	signerPass := map[string]Status{
		"receipt#0.transactions": Matched, "receipt#0.operations": Matched, "receipt#0.events": NotApplicable, "receipt#0.entry_changes": NotApplicable,
		"transaction#0": Matched, "transaction#3": Matched, "participant#0": Matched, "state_change#0": Matched, "movement#0": NotApplicable, "address#0": Matched,
	}
	signerWrong := map[string]Status{
		"receipt#0.transactions": Matched, "receipt#0.operations": Matched, "transaction#0": Matched, "participant#0": Matched,
		"state_change#0": Wrong, "movement#0": NotApplicable, "address#0": Wrong,
	}
	signerHalt := map[string]Status{
		"receipt#0.transactions": Missing, "receipt#0.events": NotApplicable, "transaction#0": Missing, "participant#0": Missing,
		"state_change#0": Missing, "movement#0": NotApplicable, "address#0": Missing,
	}
	trustPass := map[string]Status{
		"receipt#0.transactions": Matched, "receipt#0.operations": Matched, "receipt#0.events": NotApplicable, "receipt#0.entry_changes": NotApplicable,
		"transaction#0": Matched, "participant#0": Matched, "state_change#0": Matched, "state_change#1": Matched,
		"movement#0": NotApplicable, "movement#1": NotApplicable,
	}
	trustPartial := map[string]Status{
		"receipt#0.transactions": Matched, "receipt#0.operations": Matched, "transaction#0": Matched, "participant#0": Matched,
		"state_change#0": Missing, "state_change#1": Missing, "movement#0": NotApplicable,
	}
	feeIgnored := map[string]ExtraStatus{"state_changes#0": Ignored}

	var cases []wbCase
	for _, input := range []string{"datastore", "rpc"} {
		cases = append(cases,
			wbCase{"729-prefix-2a0a84ea-" + input, signer, func() *adapter.Observation { return replayObservation(t, "transcript-prefix-"+input+".txt", signer) }, want{"ledger-absent", signerHalt, nil}},
			wbCase{"729-fixed-2c873353-" + input, signer, func() *adapter.Observation { return replayObservation(t, "transcript-fixed-"+input+".txt", signer) }, want{"pass", signerPass, feeIgnored}},
			wbCase{"716-prefix-79ea2acd-" + input, signer, func() *adapter.Observation {
				return replayObservation(t, "transcript-716-prefix-"+input+".txt", signer)
			}, want{"wrong_value", signerWrong, feeIgnored}},
			wbCase{"716-fixed-bb0b162b-" + input, signer, func() *adapter.Observation { return replayObservation(t, "transcript-716-fixed-"+input+".txt", signer) }, want{"pass", signerPass, feeIgnored}},
			wbCase{"731-prefix-764a4f5b-" + input, trust, func() *adapter.Observation { return trustObservation(t, "transcript-prefix.txt", input) }, want{"partial", trustPartial, map[string]ExtraStatus{"state_changes#0": Ignored, "participants#0": Ignored}}},
			wbCase{"731-fixed-c152783c-" + input, trust, func() *adapter.Observation { return trustObservation(t, "transcript-fixed.txt", input) }, want{"pass", trustPass, map[string]ExtraStatus{"state_changes#0": Ignored, "participants#0": Ignored}}},
			wbCase{"731-head-e967ce8b-" + input, trust, func() *adapter.Observation { return trustObservation(t, "transcript-head.txt", input) }, want{"pass", trustPass, feeIgnored}},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := MatchVariant(tc.v, &desc.Observations, tc.obs())
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]Fact{}
			for _, f := range r.Facts {
				got[factKey(f)] = f
			}
			for k, st := range tc.want.statuses {
				f, ok := got[k]
				if !ok {
					t.Errorf("no fact %s", k)
					continue
				}
				if f.Status != st {
					t.Errorf("%s: %s (%s %v), want %s", k, f.Status, f.Reason, f.Diffs, st)
				}
			}
			gotExtras := map[string]ExtraStatus{}
			for _, e := range r.Extras {
				gotExtras[fmt.Sprintf("%s#%d", e.Kind, e.Index)] = e.Status
			}
			if tc.want.extras != nil && len(gotExtras) != len(tc.want.extras) {
				t.Errorf("extras %v, want %v", gotExtras, tc.want.extras)
			}
			for k, st := range tc.want.extras {
				if gotExtras[k] != st {
					t.Errorf("extra %s: %q, want %q (all: %v)", k, gotExtras[k], st, gotExtras)
				}
			}
			if c := impliedClass(r); c != tc.want.class {
				b, _ := json.MarshalIndent(r, "", " ")
				t.Errorf("implied class %s, want %s\n%s", c, tc.want.class, b)
			}
		})
	}

	// The #716 pre-fix wrong value names the field and both values.
	r, err := MatchVariant(signer, &desc.Observations, replayObservation(t, "transcript-716-prefix-datastore.txt", signer))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Facts {
		if f.Kind == FactStateChange {
			if len(f.Diffs) != 1 || f.Diffs[0].Field != "signer.key" || !strings.Contains(f.Diffs[0].Observed, "invalid payload length 32") {
				t.Errorf("signer diff: %+v", f.Diffs)
			}
		}
	}
}
