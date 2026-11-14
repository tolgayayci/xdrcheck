package match

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// SEP-0023 v1.4.0 published vectors.
var sepValid = map[string]string{
	"GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ":                                                           "account",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ":                                              "muxed_account",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK":                                              "muxed_account",
	"PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM": "signed_payload",
	"PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU": "signed_payload",
	"CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA":                                                           "contract",
	"LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN":                                                           "liquidity_pool",
	"BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU":                                                         "claimable_balance",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC":                                              "muxed_contract",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY":                                              "muxed_contract",
}

var sepInvalid = []string{
	"GAAAAAAAACGC6",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR",
	"GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA",
	"GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI",
	"G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I",
	"M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===",
	"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO",
	"PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM",
	"PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ",
	"PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6",
	"BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV",
	"BAAT6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGXACA",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWCA",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI",
	"W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW",
	"WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA",
}

func TestStrkeySEPVectors(t *testing.T) {
	for s, kind := range sepValid {
		a, err := DecodeStrkey(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if a.Kind() != kind || a.String() != s {
			t.Errorf("%s: kind %s, re-encoded %s", s, a.Kind(), a.String())
		}
	}
	for _, s := range sepInvalid {
		if _, err := DecodeStrkey(s); err == nil {
			t.Errorf("%s decodes but is invalid", s)
		}
	}
	m := MustDecode("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK")
	if id, _ := m.MuxedID(); id != "9223372036854775808" {
		t.Errorf("muxed id %s", id)
	}
	if b, _ := m.Base(); b.String() != "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ" {
		t.Errorf("base %s", b)
	}
}

// The truncated #716 value is a valid-looking version byte and key, but not a P address.
func TestStoredSignerTruncation(t *testing.T) {
	full := decodeStored("version_byte_payload_hex", "7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b2000000003deadbe00", ctxSigner)
	if len(full.readings) != 1 || full.readings[0].String() != "PBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSAAAAAAB55LN6AANMS" {
		t.Fatalf("41-byte value: %+v", full)
	}
	cut := decodeStored("version_byte_payload_hex", "7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20", ctxSigner)
	if len(cut.readings) != 0 || cut.err == "" {
		t.Fatalf("33-byte value decoded: %+v", cut)
	}
	key, _ := hex.DecodeString("44ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20")
	if !cut.carriesKey(key) {
		t.Error("the truncated value does not carry the key")
	}
	// XDR forms: SignerKey for signers, MuxedAccount / ScAddress for accounts (id first in XDR, last in strkeys).
	sk := decodeStored("xdr_hex", "0000000344ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b2000000003deadbe00", ctxSigner)
	if len(sk.readings) != 1 || sk.readings[0].String() != full.readings[0].String() {
		t.Errorf("SignerKey XDR: %+v", sk)
	}
	mx := decodeStored("xdr_hex", "0000010080000000000000003f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a", ctxAccount)
	if len(mx.readings) != 1 || mx.readings[0].String() != "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK" {
		t.Errorf("MuxedAccount XDR: %+v", mx)
	}
}

// The Stellar Asset Contract IDs the harness computes equal the ones core produced: in the research-probe
// runs vendored under evidence/ and in core's own golden (testdata/sac-core.json), and in the corpus
// entry's current variants.
func TestSACAddressMatchesCore(t *testing.T) {
	var anchor struct {
		Rows []struct {
			Run, Passphrase, Asset, SAC string
			NativeSAC                   string `json:"native_sac"`
		} `json:"rows"`
	}
	raw, err := os.ReadFile("testdata/sac-core.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &anchor); err != nil || len(anchor.Rows) == 0 {
		t.Fatalf("testdata/sac-core.json: %v", err)
	}
	for _, r := range anchor.Rows {
		for asset, want := range map[string]string{r.Asset: r.SAC, "native": r.NativeSAC} {
			got, err := SACAddress(asset, r.Passphrase)
			if err != nil || got.String() != want {
				t.Errorf("%s %s: %v %v, want %s", r.Run, asset, got, err, want)
			}
		}
	}
	e, err := manifest.LoadEntry(filepath.Join(corpusRoot, "manifest/cap-0073/sac-trust-creates-trustline.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range e.Variants {
		accounts, _ := v.Derived["accounts"].(map[string]any)
		issuer, _ := accounts["issuer"].(string)
		if v.Source.Kind != manifest.SourceLocalCore || issuer == "" {
			continue
		}
		want := v.Derived["contracts"].(map[string]any)["sac_usdc"].(string)
		if got, err := SACAddress("USDC:"+issuer, v.Passphrase); err != nil || got.String() != want {
			t.Errorf("%s@%d: %v %v, want %s", v.Network, v.Protocol, got, err, want)
		}
	}
}

func TestSameAsset(t *testing.T) {
	const testnet = "Test SDF Network ; September 2015"
	usdc := "USDC:GD7SJCVLFVJEJZ6LU4TV4PRZ34SPS7JAGX7CGNHNQH4S4QA7AJVSI43N"
	cases := []struct {
		exp, obs, pass string
		same           bool
	}{
		{usdc, usdc, testnet, true},
		{usdc, "CDIMMH4CNFBSU72EZCX6QVJVZ74APF4BESMFS47DELY6E2ZT2HW5BIF6", testnet, true},
		{"CDIMMH4CNFBSU72EZCX6QVJVZ74APF4BESMFS47DELY6E2ZT2HW5BIF6", usdc, testnet, true},
		{usdc, "CDIMMH4CNFBSU72EZCX6QVJVZ74APF4BESMFS47DELY6E2ZT2HW5BIF6", "Public Global Stellar Network ; September 2015", false},
		{usdc, "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC", testnet, false}, // the native SAC
		{"native", "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC", testnet, true},
		{"native", usdc, testnet, false},
		{usdc, "usdc:GD7SJCVLFVJEJZ6LU4TV4PRZ34SPS7JAGX7CGNHNQH4S4QA7AJVSI43N", testnet, false},
		{usdc, "garbage", testnet, false},
		{"liquidity_pool:3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a", "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN", testnet, true},
	}
	for _, c := range cases {
		got, err := sameAsset(c.exp, c.obs, c.pass)
		if err != nil || got != c.same {
			t.Errorf("sameAsset(%s, %s) = %v %v, want %v", c.exp, c.obs, got, err, c.same)
		}
	}
}
