package rpcmock

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
)

const chainP28 = "../../../evidence/wallet-backend-731/out/p28-testnet/run-1/meta.xdr"

func chain(t *testing.T) ([]Ledger, [][]byte) {
	t.Helper()
	f, err := os.Open(chainP28)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var raws [][]byte
	lake.ScanFrames(f, func(i int, fr lake.Frame, p []byte) error {
		raws = append(raws, bytes.Clone(p))
		return nil
	})
	var ls []Ledger
	for i, b := range raws {
		ls = append(ls, Ledger{Seq: uint32(2 + i), Load: func() ([]byte, error) { return b, nil }})
	}
	return ls, raws
}

func start(t *testing.T) (*Server, string, *lake.DeliveryLog, [][]byte) {
	t.Helper()
	ls, raws := chain(t)
	log := lake.NewDeliveryLog(nil)
	s, err := New(Config{Passphrase: "Test SDF Network ; September 2015", Nonce: "n-1", Log: log}, ls)
	if err != nil {
		t.Fatal(err)
	}
	srv, url, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return s, url, log, raws
}

func TestSDKBackendReadsChain(t *testing.T) {
	_, url, log, raws := start(t)
	ctx := context.Background()
	b := ledgerbackend.NewRPCLedgerBackend(ledgerbackend.RPCLedgerBackendOptions{RPCServerURL: url, BufferSize: 10})
	defer b.Close()
	if err := b.PrepareRange(ctx, ledgerbackend.BoundedRange(2, 24)); err != nil {
		t.Fatal(err)
	}
	for i, want := range raws {
		got, err := b.GetLedger(ctx, uint32(2+i))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := got.MarshalBinary()
		if !bytes.Equal(raw, want) {
			t.Fatalf("ledger %d differs", 2+i)
		}
	}
	methods := map[string]int{}
	for _, r := range log.Records() {
		methods[r.Method]++
	}
	if methods["getHealth"] == 0 || methods["getLedgers"] == 0 {
		t.Errorf("log: %v", methods)
	}
	for seq := uint32(2); seq <= 24; seq++ {
		if !log.Served(seq) {
			t.Errorf("ledger %d not logged as served", seq)
		}
	}
}

// call posts one request and returns the decoded result and error objects as raw JSON.
func call(t *testing.T, url, body string) (map[string]json.RawMessage, http.Header) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	var out map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out, resp.Header
}

func errOf(t *testing.T, m map[string]json.RawMessage) (int, string) {
	t.Helper()
	var e struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if m["error"] == nil {
		t.Fatalf("no error in %s", m["result"])
	}
	json.Unmarshal(m["error"], &e)
	return e.Code, e.Message
}

func TestWireTypesAndErrors(t *testing.T) {
	_, url, log, _ := start(t)

	h, hdr := call(t, url, `{"jsonrpc":"2.0","id":1,"method":"getHealth"}`)
	if hdr.Get("X-Xdrcheck-Nonce") != "n-1" {
		t.Error("nonce header missing")
	}
	var health map[string]any
	json.Unmarshal(h["result"], &health)
	if health["status"] != "healthy" || health["latestLedger"] != float64(24) || health["oldestLedger"] != float64(2) ||
		health["ledgerRetentionWindow"] != float64(120960) {
		t.Errorf("health %v", health)
	}
	if _, ok := health["latestLedgerCloseTime"].(string); !ok {
		t.Error("getHealth close time must be a string")
	}

	r, _ := call(t, url, `{"jsonrpc":"2.0","id":2,"method":"getLedgers","params":{"startLedger":15,"pagination":{"limit":2}}}`)
	var page map[string]any
	json.Unmarshal(r["result"], &page)
	ledgers := page["ledgers"].([]any)
	first := ledgers[0].(map[string]any)
	if len(ledgers) != 2 || page["cursor"] != "16" || first["sequence"] != float64(15) || first["hash"] != "c0f754e7c9a7a47a0969dbf88f861c89bf79ae0e97ffe464e90aaa8c292145b3" {
		t.Errorf("page %v", page)
	}
	if _, ok := first["ledgerCloseTime"].(string); !ok {
		t.Error("ledgerCloseTime must be a string")
	}
	if _, ok := page["latestLedgerCloseTime"].(float64); !ok {
		t.Error("getLedgers top-level close times must be numbers")
	}
	if first["headerXdr"] == "" || first["metadataXdr"] == "" {
		t.Error("xdr fields empty")
	}

	// Cursor pagination to the end, default limit.
	r, _ = call(t, url, `{"jsonrpc":"2.0","id":3,"method":"getLedgers","params":{"pagination":{"cursor":"16"}}}`)
	json.Unmarshal(r["result"], &page)
	if n := len(page["ledgers"].([]any)); n != 8 || page["cursor"] != "24" {
		t.Errorf("cursor page: %d ledgers, cursor %v", n, page["cursor"])
	}
	r, _ = call(t, url, `{"jsonrpc":"2.0","id":4,"method":"getLedgers","params":{"pagination":{"cursor":"24"}}}`)
	json.Unmarshal(r["result"], &page)
	if n := len(page["ledgers"].([]any)); n != 0 || page["cursor"] != "24" {
		t.Errorf("past the end: %d ledgers, cursor %v", n, page["cursor"])
	}

	cases := []struct {
		body string
		code int
		msg  string
	}{
		{`{"jsonrpc":"2.0","id":5,"method":"getLedgers","params":{"startLedger":2,"pagination":{"limit":201}}}`, -32600, "limit must not exceed 200"},
		{`{"jsonrpc":"2.0","id":6,"method":"getLedgers","params":{"startLedger":99999999}}`, -32600,
			"start ledger (99999999) must be between the oldest ledger: 2 and the latest ledger: 24 for this rpc instance"},
		{`{"jsonrpc":"2.0","id":7,"method":"getLedgers","params":{"startLedger":3,"pagination":{"cursor":"5"}}}`, -32600, "cannot both be set"},
		{`{"jsonrpc":"2.0","id":8,"method":"getLedgers","params":{"pagination":{"cursor":"x"}}}`, -32602, "invalid cursor"},
		{`{"jsonrpc":"2.0","id":9,"method":"getLedgers","params":[2]}`, -32602, "by name"},
		{`{"jsonrpc":"2.0","id":10,"method":"getLedgers","params":{"startLedger":2,"xdrFormat":"json"}}`, -32602, "not served"},
		{`{"jsonrpc":"2.0","id":11,"method":"getLedgers","params":{"startLedger":2,"xdrFormat":"hex"}}`, -32600, "expected base64, json"},
		{`{"jsonrpc":"2.0","id":12,"method":"getLedgerEntries","params":{"keys":[]}}`, -32601, "method not found"},
	}
	for _, c := range cases {
		m, _ := call(t, url, c.body)
		code, msg := errOf(t, m)
		if code != c.code || !strings.Contains(msg, c.msg) {
			t.Errorf("%s: %d %q", c.body, code, msg)
		}
	}

	for _, m := range []string{"getNetwork", "getVersionInfo", "getLatestLedger"} {
		res, _ := call(t, url, `{"jsonrpc":"2.0","id":20,"method":"`+m+`"}`)
		if res["result"] == nil {
			t.Errorf("%s: %s", m, res["error"])
		}
	}

	byMethod := map[string]int{}
	for _, rec := range log.Records() {
		byMethod[rec.Method+" "+rec.Status]++
	}
	if byMethod["getLedgerEntries error -32601"] != 1 || byMethod["getHealth ok"] != 1 || byMethod["getLedgers ok"] != 3 {
		t.Errorf("log %v", byMethod)
	}
	if got := len(log.Records()); got != 3+1+len(cases)+3 {
		t.Errorf("%d log records", got)
	}
}
