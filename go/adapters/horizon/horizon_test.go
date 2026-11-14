package horizon

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLedgerPath(t *testing.T) {
	for seq, want := range map[uint32]string{
		20010735: "FECF4FFF--19968000-20031999/FECEA910--20010735.xdr.zst",
		2:        "FFFFFFFF--0-63999/FFFFFFFD--2.xdr.zst",
	} {
		if got := LedgerPath(seq); got != want {
			t.Errorf("LedgerPath(%d) = %s, want %s", seq, got, want)
		}
	}
}

func TestStroops(t *testing.T) {
	for in, want := range map[string]string{
		"10.0000000": "100000000", "0.0000001": "1", "-0.0000001": "-1", "0.0000000": "0",
		"922337203685.4775807": "9223372036854775807",
		// i128 amounts from SAC events (amount.String128) are wider than int64.
		"17014118346046923173168730371588.4105727": "170141183460469231731687303715884105727",
		"5": "50000000",
	} {
		got, err := Stroops(in)
		if err != nil || got != want {
			t.Errorf("Stroops(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "1.00000001", "1e7", "abc", "."} {
		if _, err := Stroops(bad); err == nil {
			t.Errorf("Stroops(%q) accepted", bad)
		}
	}
}

func TestPlan(t *testing.T) {
	seqs := []uint32{5, 6, 7, 9, 10, 20}
	g, _ := Plan(seqs, "contiguous", 2)
	want := []Group{{5, 6}, {7, 7}, {9, 10}, {20, 20}}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("contiguous = %v, want %v", g, want)
	}
	g, _ = Plan(seqs, "single", 0)
	if len(g) != 6 || g[3] != (Group{9, 9}) {
		t.Errorf("single = %v", g)
	}
	if _, err := Plan(seqs, "x", 1); err == nil {
		t.Error("bad mode accepted")
	}
	if d := Dedup([]uint32{3, 1, 3, 2}); !reflect.DeepEqual(d, []uint32{1, 2, 3}) {
		t.Errorf("Dedup = %v", d)
	}
}

const g1 = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"
const g2 = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"

func TestExportRows(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "history_transactions.jsonl")
	lines := []string{
		`{"table":"history_ledgers","ledger":100,"ledger_hash":"ab","protocol_version":29,"closed_at":"2024-01-02T03:04:05","successful_transaction_count":1,"failed_transaction_count":1,"operation_count":2,"total_coins":1042840383615970845}`,
		`{"table":"history_transactions","ledger":100,"tx_order":1,"transaction_hash":"h1","successful":true,"fee_charged":100,"operation_count":2,"account":"` + g1 + `","memo_type":"none","tx_result":"AAAAAAAAAGQAAAAAAAAAAAAAAAA="}`,
		`{"table":"history_transaction_participants","ledger":100,"tx_order":1,"account":"` + g2 + `"}`,
		`{"table":"history_operation_participants","ledger":100,"tx_order":1,"op_order":2,"account":"` + g2 + `"}`,
		`{"table":"history_effects","ledger":100,"tx_order":1,"op_order":1,"type":3,"account":"` + g1 + `","details":{"amount":"1.5000000","asset_type":"native"}}`,
		`{"table":"history_effects","ledger":100,"tx_order":1,"op_order":1,"type":96,"account":"` + g1 + `","details":{"contract":"CC","amount":"17014118346046923173168730371588.4105727","asset_type":"credit_alphanum4","asset_code":"USD","asset_issuer":"` + g2 + `"}}`,
		`{"table":"history_effects","ledger":100,"tx_order":1,"op_order":2,"type":20,"account":"` + g1 + `","details":{"asset_type":"credit_alphanum4","asset_code":"USD","asset_issuer":"` + g2 + `"}}`,
		`{"table":"history_operations","ledger":100,"tx_order":1,"op_order":2,"type":24,"details":{"asset_balance_changes":[{"type":"transfer","from":"` + g1 + `","to":"CC","amount":"0.0000003","asset_type":"native"}]}}`,
	}
	if err := os.WriteFile(raw, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "rows.jsonl")
	counts := map[string]int{}
	if err := ExportRows(dir, out, PubnetPassphrase, "c0", counts); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"ledger": 1, "tx": 1, "participant": 1, "other": 1, "balance_change": 2, "entry_change": 1, "token_event": 1, "operation": 1}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("counts = %v, want %v", counts, want)
	}
	f, _ := os.Open(out)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var seen int
	for sc.Scan() {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(sc.Text()))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		switch m["kind"] {
		case "balance_change":
			if m["tx_hash"] != "h1" || m["tx_index"] != json.Number("0") || m["op_index"] != json.Number("0") {
				t.Errorf("balance row indexes: %v", m)
			}
			if m["asset"] == "native" && m["amount"] != "-15000000" {
				t.Errorf("debit amount: %v", m["amount"])
			}
			if m["asset"] != "native" && (m["holder"] != "CC" || m["amount"] != "170141183460469231731687303715884105727") {
				t.Errorf("contract credit: %v", m)
			}
			if c, _ := m["contract"].(string); !strings.HasPrefix(c, "C") || len(c) != 56 {
				t.Errorf("sac contract: %v", m["contract"])
			}
			seen++
		case "participant":
			if m["holder"] != g2 || m["op_index"] != nil {
				t.Errorf("participant: %v", m)
			}
		case "tx":
			if m["result_code"] != "TxSuccess" || m["fee_charged"] != "100" || m["pipeline"] != "horizon" || m["exact"] != true {
				t.Errorf("tx: %v", m)
			}
		case "operation":
			if m["op_type"] != "InvokeHostFunction" {
				t.Errorf("operation: %v", m)
			}
		case "entry_change":
			if m["entry_type"] != "trustline" || m["change"] != "created" || m["entry_key"] == nil || m["entry_key"] != m["key"] {
				t.Errorf("entry: %v", m)
			}
		case "token_event":
			if m["amount"] != "3" || m["event"] != "transfer" || m["from"] != g1 || m["to"] != "CC" {
				t.Errorf("event: %v", m)
			}
		}
	}
	if seen != 2 {
		t.Errorf("balance rows seen %d", seen)
	}
}
