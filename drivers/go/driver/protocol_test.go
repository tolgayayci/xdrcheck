package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The driver's side of the protocol rules: a declared op never answers op_not_supported, an unusable argument
// is a protocol error, value_not_representable only for tagged values the Go type cannot hold, and every
// accepted result carries the evidence its level requires.

const (
	acctG   = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ" // the strkey of k1
	acctM   = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAICAMCAKBQHBA7T4"
	usdByte = "USD:GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL" // the first of the pair in byte order
	usdNext = "USD:GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO"
)

// apiRequest is a raw run request for an api op; send it with driverProc.send.
func apiRequest(op string, args map[string]any) map[string]any {
	return map[string]any{"xcc": protocolTag, "op": "run", "entry": "api/" + op, "level": "L4",
		"input": map[string]any{"kind": "api", "api_op": op, "args": args}}
}

// wellFormed returns one well-formed argument set per declared op. The transaction ops use the envelope of
// the matrix probe's vector 1c.
func wellFormed(t *testing.T) map[string]map[string]any {
	t.Helper()
	envelope := ""
	if root := os.Getenv("XDRCHECK_ROOT"); root != "" {
		raw, err := os.ReadFile(filepath.Join(root, "evidence", "sdk-matrix", "vectors", "vectors.json"))
		if err != nil {
			t.Fatal(err)
		}
		var vectors []probeVector
		if err := json.Unmarshal(raw, &vectors); err != nil {
			t.Fatal(err)
		}
		for _, v := range vectors {
			if v.ID == "1c" && v.Hex != nil {
				envelope = *v.Hex
			}
		}
	}
	if envelope == "" {
		t.Skip("XDRCHECK_ROOT is not set")
	}
	const testnet = "Test SDF Network ; September 2015"
	return map[string]map[string]any{
		"address.from_sc_address":    {"xdr_hex": "0000000000000000" + k1},
		"address.to_strkey":          {"xdr_hex": "00000000" + k1, "xdr_type": "MuxedAccount"},
		"asset.compare":              {"asset_a": "native", "asset_b": usdByte},
		"liquidity_pool.asset":       {"asset_a": "native", "asset_b": usdByte}, // native sorts first in every version
		"liquidity_pool.id":          {"asset_a": "native", "asset_b": usdByte, "fee": map[string]any{"native": "number", "value": "30"}},
		"memo.text_roundtrip":        {"xdr_hex": map[string]any{"hex": "00000001000000026869" + "0000"}},
		"muxed_account.decode":       {"text": acctM},
		"muxed_account.encode":       {"account": acctG, "id": map[string]any{"native": "string", "value": "5"}},
		"offer.manage_buy":           {"offer_id": map[string]any{"native": "number", "value": "7"}},
		"offer.manage_sell":          {"offer_id": map[string]any{"native": "number", "value": "7"}, "price": "0.5"},
		"operation.object_roundtrip": {"xdr_hex": "000000000000000a000000016b0000000000000100000002fffe0000"},
		"signer_key.to_strkey":       {"xdr_hex": "00000000" + k1},
		"strkey.decode":              {"text": acctG, "type": "account"},
		"strkey.encode":              {"type": "account", "payload_hex": k1},
		"transaction.hash":           {"xdr_hex": envelope, "passphrase": testnet},
		"transaction.parse":          {"xdr_hex": envelope, "passphrase": testnet},
	}
}

func declaredOps(t *testing.T, d *driverProc) []string {
	t.Helper()
	var ops []string
	for _, o := range d.describe()["api_ops"].([]any) {
		ops = append(ops, o.(string))
	}
	return ops
}

// Every declared op runs on well-formed arguments without op_not_supported, and its accepted result carries
// value, xdr_hex and self_decode as the vocabulary defines them.
func TestDeclaredOpsAnswer(t *testing.T) {
	d := startDriver(t)
	samples := wellFormed(t)
	withXDRHex := map[string]bool{"liquidity_pool.asset": true, "muxed_account.encode": true, "offer.manage_sell": true,
		"offer.manage_buy": true, "transaction.parse": true, "memo.text_roundtrip": true, "operation.object_roundtrip": true}
	strkeyOut := map[string]bool{"muxed_account.encode": true, "strkey.encode": true, "address.to_strkey": true,
		"address.from_sc_address": true, "signer_key.to_strkey": true}
	for _, op := range declaredOps(t, d) {
		args, found := samples[op]
		if !found {
			t.Errorf("%s: declared but the test has no well-formed arguments for it", op)
			continue
		}
		resp := d.send(apiRequest(op, args))
		if resp["op"] != "run" {
			t.Errorf("%s: %v", op, resp)
			continue
		}
		if resp["outcome"] == "n_a" {
			t.Errorf("%s: a declared op answered n_a/%s", op, reasonCode(resp))
			continue
		}
		if resp["outcome"] != "ok" {
			t.Errorf("%s: %v %v", op, resp["outcome"], resp["reason"])
			continue
		}
		api := resp["actual"].(map[string]any)["api"].(map[string]any)
		if _, has := api["value"]; !has {
			t.Errorf("%s: no value", op)
		}
		if _, has := api["xdr_hex"]; has != withXDRHex[op] {
			t.Errorf("%s: xdr_hex present %v, want %v", op, has, withXDRHex[op])
		}
		if _, has := api["self_decode"]; has != (withXDRHex[op] || strkeyOut[op]) {
			t.Errorf("%s: self_decode present %v", op, has)
		}
		switch op {
		case "transaction.parse":
			v, _ := api["value"].(map[string]any)
			if _, isStr := v["tx_hash"].(string); !isStr || v["operations"] == nil || len(v) != 2 {
				t.Errorf("transaction.parse value %v, want {tx_hash, operations}", api["value"])
			}
		case "operation.object_roundtrip":
			if api["value"] != true {
				t.Errorf("operation.object_roundtrip value %v, want true (bytes preserved)", api["value"])
			}
		case "muxed_account.decode":
			v, _ := api["value"].(map[string]any)
			if v["account"] != acctG || v["id"] == nil || len(v) != 2 {
				t.Errorf("muxed_account.decode value %v", api["value"])
			}
		case "memo.text_roundtrip":
			if api["value"] != "6869" {
				t.Errorf("memo.text_roundtrip value %v, want the text bytes 6869", api["value"])
			}
		case "asset.compare":
			if api["value"] != json.Number("-1") {
				t.Errorf("asset.compare value %v, want -1 (native first)", api["value"])
			}
		}
	}
	// an op the driver does not declare is the one case of op_not_supported
	resp := d.send(apiRequest("xdrjson.decode", map[string]any{"xdr_type": "ScVal", "json": "\"void\""}))
	if resp["outcome"] != "n_a" || reasonCode(resp) != "op_not_supported" {
		t.Errorf("undeclared op: %v", resp)
	}
}

// Missing, unknown and malformed arguments are protocol errors, never an SDK outcome.
func TestArgumentErrorsAreProtocolErrors(t *testing.T) {
	d := startDriver(t)
	samples := wellFormed(t)
	for _, op := range declaredOps(t, d) {
		if resp := d.send(apiRequest(op, map[string]any{})); resp["op"] != "protocol_error" {
			t.Errorf("%s with no arguments: %v", op, resp)
		}
		args := map[string]any{"not_an_argument": "x"}
		for k, v := range samples[op] {
			args[k] = v
		}
		if resp := d.send(apiRequest(op, args)); resp["op"] != "protocol_error" {
			t.Errorf("%s with an unknown argument: %v", op, resp)
		}
	}
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		// the old spellings are not aliases
		{"asset.compare", map[string]any{"a": "native", "b": usdByte}},
		{"muxed_account.encode", map[string]any{"account_id": acctG, "id": "5"}},
		{"muxed_account.decode", map[string]any{"address": acctM}},
		{"strkey.encode", map[string]any{"type": "account", "payload": k1}},
		{"transaction.hash", map[string]any{"envelope_b64": "AAAA", "passphrase": "p"}},
		{"memo.text_roundtrip", map[string]any{"xdr": "0000000000"}},
		// malformed values
		{"strkey.encode", map[string]any{"type": "ed25519_public_key", "payload_hex": k1}},
		{"strkey.encode", map[string]any{"type": "account", "payload_hex": "zz"}},
		{"liquidity_pool.id", map[string]any{"asset_a": "USD", "asset_b": usdNext}},
		{"muxed_account.encode", map[string]any{"account": acctG, "id": map[string]any{"native": "float", "value": "5"}}},
		{"address.to_strkey", map[string]any{"xdr_hex": "00000000" + k1, "xdr_type": "SignerKey"}},
		{"memo.text_roundtrip", map[string]any{"xdr_hex": "00000000"}},
	} {
		if resp := d.send(apiRequest(c.op, c.args)); resp["op"] != "protocol_error" {
			t.Errorf("%s %v: want protocol_error, got %v", c.op, c.args, resp)
		}
	}
	// the driver keeps serving after a protocol error
	if resp := d.send(apiRequest("strkey.decode", map[string]any{"text": acctG})); resp["outcome"] != "ok" {
		t.Errorf("after protocol errors: %v", resp)
	}
}

// value_not_representable: a tagged value the Go type cannot hold; a value it can hold reaches the SDK.
func TestValueNotRepresentable(t *testing.T) {
	d := startDriver(t)
	for _, c := range []struct {
		op, arg, value, outcome string
	}{
		{"muxed_account.encode", "id", "18446744073709551616", "n_a"},
		{"muxed_account.encode", "id", "-1", "n_a"},
		{"muxed_account.encode", "id", "18446744073709551615", "ok"},
		{"offer.manage_sell", "offer_id", "9223372036854775808", "n_a"},
		{"offer.manage_sell", "offer_id", "-1", "reject"},
	} {
		args := map[string]any{c.arg: map[string]any{"native": "number", "value": c.value}}
		if c.op == "muxed_account.encode" {
			args["account"] = acctG
		}
		resp := d.send(apiRequest(c.op, args))
		if resp["outcome"] != c.outcome || (c.outcome == "n_a" && reasonCode(resp) != "value_not_representable") {
			t.Errorf("%s %s=%s: %v %v, want %s", c.op, c.arg, c.value, resp["outcome"], resp["reason"], c.outcome)
		}
	}
}

// L0 evidence: an accepted decode always reports the bytes consumed and the re-encoding's hash.
func TestCodecEvidence(t *testing.T) {
	d := startDriver(t)
	h := "0000000000000001" // ScVal bool true
	resp := d.run(&request{Entry: "xdr/bool", Level: "L0", Input: input{Kind: "xdr", XDRType: "ScVal", XDRHex: &h}})
	a, _ := resp["actual"].(map[string]any)
	in, _ := hex.DecodeString(h)
	sum := sha256.Sum256(in) // a canonical value re-encodes to its own bytes
	if resp["outcome"] != "ok" || a["consumed_bytes"] != json.Number("8") || a["reencoded_sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("L0 ok evidence: %v", resp)
	}
	// a request the driver cannot use is a protocol error, not a decode refusal
	bad := "zz"
	raw := map[string]any{"xcc": protocolTag, "op": "run", "entry": "xdr/bad", "level": "L0",
		"input": map[string]any{"kind": "xdr", "xdr_type": "ScVal", "xdr_hex": bad}}
	if resp := d.send(raw); resp["op"] != "protocol_error" {
		t.Errorf("unreadable input: %v", resp)
	}
	if resp := d.send(map[string]any{"xcc": protocolTag, "op": "run", "entry": "x", "level": "L0",
		"input": map[string]any{"kind": "api", "api_op": "strkey.decode", "args": map[string]any{"text": acctG}}}); resp["op"] != "protocol_error" ||
		!strings.Contains(resp["error"].(string), "xdr input") {
		t.Errorf("api input at L0: %v", resp)
	}
}
