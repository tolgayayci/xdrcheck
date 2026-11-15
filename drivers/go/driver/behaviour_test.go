package driver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Behaviours the Go columns must show, through the built binary, on the curated corpus and on hand-encoded
// bytes. Expected values come from the manifest (core-emitted bytes and their derived facts), the schema
// probes and hand-written encodings, never from the SDK.

type variantFacts struct {
	Network    string `json:"network"`
	Passphrase string `json:"passphrase"`
	XDRType    string `json:"xdr_type"`
	Blob       struct {
		Path  string `json:"path"`
		Bytes int    `json:"bytes"`
	} `json:"blob"`
	Derived struct {
		TxHash   string            `json:"tx_hash"`
		TxHashes []string          `json:"tx_hashes"`
		L1       map[string]string `json:"l1"`
	} `json:"derived"`
	Focus *struct {
		TxIndex *int   `json:"tx_index"`
		OpIndex *int   `json:"op_index"`
		TxHash  string `json:"tx_hash"`
	} `json:"focus"`
}

type entryFacts struct {
	ID       string         `json:"id"`
	Variants []variantFacts `json:"variants"`
	Expect   struct {
		Ledger struct {
			Transactions int `json:"transactions"`
			Operations   int `json:"operations"`
		} `json:"ledger"`
		Values []struct {
			Path   string `json:"path"`
			Equals any    `json:"equals"`
		} `json:"values"`
	} `json:"expect"`
}

func loadEntry(t *testing.T, root, id string) (entryFacts, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "corpus", "manifest", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var e entryFacts
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e, filepath.Join(root, "corpus", e.Variants[0].Blob.Path)
}

func reasonCode(resp map[string]any) string {
	r, _ := resp["reason"].(map[string]any)
	s, _ := r["code"].(string)
	return s
}

func objectOf(resp map[string]any) map[string]any {
	a, _ := resp["actual"].(map[string]any)
	o, _ := a["object"].(map[string]any)
	return o
}

// The issuer-ordering defect at L1: v0.7.1 rejects the real testnet transaction (index 2 in apply order) when
// its pool ID is read back; v0.7.2 and later parse every envelope, hash them to the ledger's own transaction
// hashes in apply order, and read the focus operation's pool ID back. The counts, hashes, focus and pool ID
// all come from the manifest.
func TestLedgerIssuerOrderingAtL1(t *testing.T) {
	root := repoRoot(t)
	d := startDriver(t)
	ver := d.sdkVersion()
	e, blob := loadEntry(t, root, "cap-0038/pool-issuers-order-by-bytes-not-strkey")
	v := e.Variants[0]
	if v.Focus == nil || v.Focus.TxIndex == nil || v.Focus.OpIndex == nil {
		t.Fatal("the entry's variant has no transaction focus")
	}
	resp := d.run(&request{Entry: e.ID, Variant: v.Network, Level: "L1",
		Input: input{Kind: "xdr", XDRType: v.XDRType, Path: blob, Passphrase: v.Passphrase,
			Focus: &focus{TxIndex: v.Focus.TxIndex, OpIndex: v.Focus.OpIndex}}})
	obj := objectOf(resp)
	if obj["transactions"] != json.Number(itoa(e.Expect.Ledger.Transactions)) {
		t.Errorf("transactions %v, want %d", obj["transactions"], e.Expect.Ledger.Transactions)
	}
	got := []string{}
	if hs, isList := obj["tx_hashes"].([]any); isList {
		for _, h := range hs {
			got = append(got, h.(string))
		}
	} else {
		t.Fatalf("tx_hashes is not a list: %v", obj["tx_hashes"])
	}
	if ver == "v0.7.1" {
		rej, _ := obj["envelopes_rejected"].([]any)
		if resp["outcome"] != "reject" || reasonCode(resp) != "ordering" || len(rej) != 1 {
			t.Fatalf("v0.7.1 must reject exactly one transaction for ordering: %v", resp)
		}
		r0 := rej[0].(map[string]any)
		if r0["tx_index"] != json.Number(itoa(*v.Focus.TxIndex)) || r0["tx_hash"] != v.Focus.TxHash || r0["code"] != "ordering" {
			t.Errorf("the rejected envelope must be the focus transaction: %v", r0)
		}
		if obj["envelopes_parsed"] != json.Number(itoa(e.Expect.Ledger.Transactions-1)) {
			t.Errorf("envelopes_parsed %v", obj["envelopes_parsed"])
		}
		var want []string
		for _, h := range v.Derived.TxHashes {
			if h != v.Focus.TxHash {
				want = append(want, h)
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("tx_hashes must be the other transactions in apply order:\n got %v\nwant %v", got, want)
		}
		return
	}
	if resp["outcome"] != "ok" || obj["envelopes_parsed"] != json.Number(itoa(e.Expect.Ledger.Transactions)) {
		t.Fatalf("%s must parse every envelope: %v", ver, resp)
	}
	if obj["operations"] != json.Number(itoa(e.Expect.Ledger.Operations)) {
		t.Errorf("operations %v, want %d", obj["operations"], e.Expect.Ledger.Operations)
	}
	if strings.Join(got, ",") != strings.Join(v.Derived.TxHashes, ",") {
		t.Errorf("tx_hashes differ from the ledger's transaction hashes in apply order:\n got %v\nwant %v", got, v.Derived.TxHashes)
	}
	f, _ := obj["focus"].(map[string]any)
	if f == nil || f["tx_hash"] != v.Derived.TxHash {
		t.Fatalf("focus: %v, want tx_hash %s", f, v.Derived.TxHash)
	}
	derived, _ := f["derived"].(map[string]any)
	if derived["pool_id"] != "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e" || derived["operation_type"] != "change_trust" {
		t.Errorf("focus.derived: %v", derived)
	}
	if types, _ := f["operation_types"].([]any); len(types) == 0 || types[0] != "change_trust" {
		t.Errorf("focus.operation_types: %v", f["operation_types"])
	}
}

// The issuer-ordering defect at L4: the same two issuers in byte order give the pool ID stellar-core created;
// v0.7.1 refuses that order and accepts the strkey order instead.
func TestPoolIDIssuerOrderingAtL4(t *testing.T) {
	d := startDriver(t)
	ver := d.sdkVersion()
	const a = "USD:GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL" // key e305f885…, first as bytes
	const b = "USD:GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO" // key f7a4c0e5…
	pool := func(x, y string) map[string]any {
		return d.run(&request{Entry: "api/pool", Level: "L4", Input: input{Kind: "api", APIOp: "liquidity_pool.id",
			Args: map[string]any{"asset_a": x, "asset_b": y}}})
	}
	byteOrder, strkeyOrder := pool(a, b), pool(b, a)
	if ver == "v0.7.1" {
		if byteOrder["outcome"] != "reject" || reasonCode(byteOrder) != "ordering" || strkeyOrder["outcome"] != "ok" {
			t.Fatalf("v0.7.1 must refuse byte order and accept strkey order: %v / %v", byteOrder, strkeyOrder)
		}
		return
	}
	api, _ := byteOrder["actual"].(map[string]any)["api"].(map[string]any)
	if byteOrder["outcome"] != "ok" || api["value"] != "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e" {
		t.Fatalf("%s byte order: %v", ver, byteOrder)
	}
	if strkeyOrder["outcome"] != "reject" || reasonCode(strkeyOrder) != "ordering" {
		t.Fatalf("%s strkey order must be refused: %v", ver, strkeyOrder)
	}
}

// Protocol 30: the first SIGNED_MS ledger decodes where the schema probe says the arm exists, and is refused
// cleanly (an undeclared union arm, not a crash) where it does not; the upgrade ledger before it decodes on
// every version.
func TestProtocol30StellarValueArm(t *testing.T) {
	root := repoRoot(t)
	d := startDriver(t)
	desc := d.describe()
	p30 := desc["xdr_schema"].(map[string]any)["probes"].(map[string]any)["stellar_value_signed_ms"] == true
	if ver := d.sdkVersion(); p30 == strings.HasPrefix(ver, "v0.7.") {
		t.Fatalf("%s: stellar_value_signed_ms probe is %v", ver, p30)
	}
	for _, id := range []string{"cap-0088/first-ledger-with-signed-ms", "cap-0088/upgrade-ledger-header-30-whole-second-value"} {
		e, blob := loadEntry(t, root, id)
		v := e.Variants[0]
		for _, level := range []string{"L0", "L1", "L2"} {
			resp := d.run(&request{Entry: id, Variant: v.Network, Level: level,
				Input: input{Kind: "xdr", XDRType: v.XDRType, Path: blob, Passphrase: v.Passphrase}})
			signedMS := strings.Contains(id, "signed-ms")
			switch {
			case signedMS && !p30:
				if resp["outcome"] != "reject" || reasonCode(resp) != "union_arm_undeclared" {
					t.Errorf("%s %s: want a clean union_arm_undeclared reject, got %v %v", id, level, resp["outcome"], resp["reason"])
				}
			case resp["outcome"] != "ok":
				t.Errorf("%s %s: want ok, got %v %v", id, level, resp["outcome"], resp["reason"])
			case level == "L0":
				a := resp["actual"].(map[string]any)
				if a["consumed_bytes"] != json.Number(itoa(v.Blob.Bytes)) {
					t.Errorf("%s: consumed %v of %d bytes", id, a["consumed_bytes"], v.Blob.Bytes)
				}
			}
		}
	}
}

// The default decode depth: 749 nested ScVec levels decode, 750 are refused with reason depth.
func TestDepthBoundary(t *testing.T) {
	d := startDriver(t)
	if got := d.describe()["decode"].(map[string]any)["default_depth"]; got != json.Number("1500") {
		t.Errorf("default_depth %v", got)
	}
	for _, c := range []struct {
		n       int
		outcome string
	}{{749, "ok"}, {750, "reject"}} {
		h := strings.Repeat("000000100000000100000001", c.n) + "00000001" // SCV_VEC, present, length 1; SCV_VOID
		resp := d.run(&request{Entry: "limits/depth", Level: "L0", Input: input{Kind: "xdr", XDRType: "ScVal", XDRHex: &h}})
		if resp["outcome"] != c.outcome || (c.outcome == "reject" && reasonCode(resp) != "depth") {
			t.Errorf("%d nested vectors: %v %v", c.n, resp["outcome"], resp["reason"])
		}
	}
}

// Trailing bytes: the strict entry point refuses them, and the generated UnmarshalBinary's acceptance is
// reported as a lenient entry point.
func TestTrailingBytes(t *testing.T) {
	d := startDriver(t)
	h := "0000000000000001" + "00000000" // ScVal bool true, then four extra bytes
	resp := d.run(&request{Entry: "xdr-strict/trailing-bytes", Level: "L0", Input: input{Kind: "xdr", XDRType: "SCVal", XDRHex: &h}})
	if resp["outcome"] != "reject" || reasonCode(resp) != "trailing_bytes" {
		t.Fatalf("want reject trailing_bytes: %v", resp)
	}
	lenient := resp["actual"].(map[string]any)["lenient_entry_points"].([]any)[0].(map[string]any)
	if lenient["entry_point"] != "ScVal.UnmarshalBinary" || lenient["accepted"] != true {
		t.Errorf("lenient entry point: %v", lenient)
	}
}

// L2 pinpoints: the values the manifest states by hand for the issuer-ordering transaction.
func TestPinpoints(t *testing.T) {
	root := repoRoot(t)
	d := startDriver(t)
	e, blob := loadEntry(t, root, "cap-0038/pool-issuers-order-by-bytes-not-strkey")
	v := e.Variants[0]
	var paths []string
	for _, x := range e.Expect.Values {
		paths = append(paths, x.Path)
	}
	resp := d.run(&request{Entry: e.ID, Variant: v.Network, Level: "L2",
		Input: input{Kind: "xdr", XDRType: v.XDRType, Path: blob, Pinpoints: paths}})
	if resp["outcome"] != "ok" {
		t.Fatalf("L2: %v", resp)
	}
	pins := resp["actual"].(map[string]any)["pinpoints"].([]any)
	for i, x := range e.Expect.Values {
		p := pins[i].(map[string]any)
		want, _ := json.Marshal(x.Equals)
		got, _ := json.Marshal(p["value"])
		if p["found"] != true || string(got) != string(want) {
			t.Errorf("%s: got %v %s, want %s", x.Path, p["found"], got, want)
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// Every derived fact the manifest states for a ledger's focus (derived.l1) is reported at L1, with the same
// value, wherever the SDK parses the ledger.
func TestFocusDerivedMatchesManifest(t *testing.T) {
	root := repoRoot(t)
	d := startDriver(t)
	checked := 0
	for _, me := range loadEntries(t, root) {
		if me.Kind != "ledger" {
			continue
		}
		e, _ := loadEntry(t, root, me.ID)
		for _, v := range e.Variants {
			if v.Focus == nil || v.Focus.TxIndex == nil || len(v.Derived.L1) == 0 {
				continue
			}
			resp := d.run(&request{Entry: me.ID, Variant: v.Network, Level: "L1",
				Input: input{Kind: "xdr", XDRType: v.XDRType, Path: filepath.Join(root, "corpus", v.Blob.Path), Passphrase: v.Passphrase,
					Focus: &focus{TxIndex: v.Focus.TxIndex, OpIndex: v.Focus.OpIndex}}})
			if resp["outcome"] != "ok" {
				continue // a refusal is judged elsewhere; only an accepted ledger reports focus facts
			}
			checked++
			obj, _ := resp["actual"].(map[string]any)["object"].(map[string]any)
			f, _ := obj["focus"].(map[string]any)
			got, _ := f["derived"].(map[string]any)
			for k, want := range v.Derived.L1 {
				if got[k] != want {
					t.Errorf("%s (%s): focus.derived.%s = %v, the manifest states %s", me.ID, v.Network, k, got[k], want)
				}
			}
		}
	}
	if checked == 0 {
		t.Log("no ledger variant with derived.l1 was accepted by this version")
	}
}
