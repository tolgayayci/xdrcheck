package indexer

import (
	"os"
	"strconv"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// refundInChangesAfter is the fee payer's balance increase in a transaction's changes after, read from the
// decoded ledger directly (not through the indexer).
func refundInChangesAfter(m xdr.TransactionMeta, payer string) int64 {
	var after xdr.LedgerEntryChanges
	switch m.V {
	case 2:
		after = m.V2.TxChangesAfter
	case 3:
		after = m.V3.TxChangesAfter
	case 4:
		after = m.V4.TxChangesAfter
	default:
		return 0
	}
	var pre *xdr.LedgerEntry
	var delta int64
	for _, c := range after {
		switch c.Type {
		case xdr.LedgerEntryChangeTypeLedgerEntryState:
			pre = c.State
		case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
			post := c.Updated
			if pre != nil && pre.Data.Type == xdr.LedgerEntryTypeAccount && post.Data.Type == xdr.LedgerEntryTypeAccount &&
				accountStrkey(post.Data.Account.AccountId) == payer {
				delta += int64(post.Data.Account.Balance - pre.Data.Account.Balance)
			}
		}
	}
	return delta
}

// A LedgerCloseMeta v0/v1 has no post-apply fee processing, so a Soroban refund is in the transaction's changes
// after whatever the TransactionMeta version, including the v4 meta of regenerated Protocol 20–22 lake objects.
// Over every vendored ledger of that shape, each refund the bytes show is a fee_refund movement of that amount,
// and at least one such refund exists.
func TestRefundAfterApplyWithoutPostApplyFeeProcessing(t *testing.T) {
	c, err := manifest.Load(corpusRoot, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	refunds := 0
	for _, e := range c.Entries {
		if e.Negative {
			continue
		}
		for _, v := range e.Variants {
			path := c.BlobPath(v)
			if v.XDRType != "LedgerCloseMeta" || seen[path] {
				continue
			}
			seen[path] = true
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var lcm xdr.LedgerCloseMeta
			if err := lcm.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			var procs []xdr.TransactionResultMeta
			switch lcm.V {
			case 0:
				procs = lcm.V0.TxProcessing
			case 1:
				procs = lcm.V1.TxProcessing
			default:
				continue
			}
			facts := factsOf(t, lcm, v.Passphrase)
			for i, p := range procs {
				payer := ""
				refunded := int64(0)
				for _, m := range facts.Movements {
					if m.TxIndex == nil || *m.TxIndex != i {
						continue
					}
					switch m.Kind {
					case "fee":
						payer = m.From.Address
					case "fee_refund":
						n, err := strconv.ParseInt(m.Amount, 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						refunded += n
					}
				}
				if payer == "" {
					continue
				}
				want := refundInChangesAfter(p.TxApplyProcessing, payer)
				if refunded != want {
					t.Errorf("%s tx %d: fee_refund %d, the changes after refund %d", path, i, refunded, want)
				}
				if want > 0 {
					refunds++
				}
			}
		}
	}
	if refunds == 0 {
		t.Fatal("no refund after apply in a LedgerCloseMeta v0/v1 ledger")
	}
}
