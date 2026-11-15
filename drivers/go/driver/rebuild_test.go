package driver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestRebuildFact runs the rebuild fact (rebuild.go) on focus transactions of the corpus: a transaction the
// network recorded with time bounds is rebuilt through txnbuild.NewTransaction to its own hash, and the two
// Soroban footprint transactions of finding F-0056 (a RestoreFootprint and an ExtendFootprintTtl) come back
// without their SorobanTransactionData, so the rebuilt hash differs and ext is named.
func TestRebuildFact(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		manifest, network string
		protocol          int
		lostExt           bool
	}{
		{"cap-0021/precond-v2-min-seq-num-zero", "testnet", 28, false},
		{"cap-0066/p22-restore-with-backfilled-restored-changes", "pubnet", 22, true},
		{"classic/real-result-codes.testnet-5380224", "testnet", 29, true},
	}
	for _, c := range cases {
		t.Run(c.manifest, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(root, "corpus", "manifest", c.manifest+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var e struct {
				Variants []struct {
					Network    string `json:"network"`
					Passphrase string `json:"passphrase"`
					Protocol   int    `json:"protocol"`
					Blob       struct {
						Path string `json:"path"`
					} `json:"blob"`
					Focus struct {
						TxIndex int `json:"tx_index"`
					} `json:"focus"`
					Derived struct {
						TxHash string `json:"tx_hash"`
					} `json:"derived"`
				} `json:"variants"`
			}
			if err := json.Unmarshal(b, &e); err != nil {
				t.Fatal(err)
			}
			for _, v := range e.Variants {
				if v.Network != c.network || v.Protocol != c.protocol {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(root, "corpus", v.Blob.Path))
				if err != nil {
					t.Fatal(err)
				}
				if !schemaProbes()["stellar_value_signed_ms"] && v.Protocol >= 30 {
					t.Skip("the ledger needs Protocol 30 types")
				}
				ti := v.Focus.TxIndex
				res := levelObject(&input{Kind: "xdr", XDRType: "LedgerCloseMeta", Passphrase: v.Passphrase, Focus: &focus{TxIndex: &ti}}, raw)
				if res.Outcome != "ok" {
					t.Fatalf("L1 %s: %+v", res.Outcome, res.Reason)
				}
				f := res.Actual["object"].(map[string]any)["focus"].(map[string]any)
				rb := f["rebuild"].(map[string]any)
				if rb["outcome"] != "rebuilt" {
					t.Fatalf("rebuild %v", rb)
				}
				same := rb["tx_hash"] == v.Derived.TxHash
				switch {
				case c.lostExt && (same || len(rb["differs"].([]string)) != 1 || rb["differs"].([]string)[0] != "ext"):
					t.Errorf("want a rebuilt transaction that differs in ext only (F-0056), got %v", rb)
				case !c.lostExt && !same:
					t.Errorf("rebuilt to %v, the network's transaction is %s", rb, v.Derived.TxHash)
				}
				return
			}
			t.Fatalf("no variant %s@%d", c.network, c.protocol)
		})
	}
}
