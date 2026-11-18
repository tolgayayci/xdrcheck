// Throwaway: can the go-stellar-sdk pinned by wallet-backend decode these LCMs? Usage: gocheck <lcm.xdr>...
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func main() {
	bad := 0
	for _, p := range os.Args[1:] {
		b, _ := os.ReadFile(p)
		var lcm xdr.LedgerCloseMeta
		if err := xdr.SafeUnmarshal(b, &lcm); err != nil {
			fmt.Println(p, "DECODE ERROR:", err)
			bad++
			continue
		}
		re, err := lcm.MarshalBinary()
		h := lcm.LedgerHeaderHistoryEntry()
		fmt.Printf("%s seq=%d v=%d proto=%d scpExt=%d txs=%d reencode_equal=%v err=%v\n", p, lcm.LedgerSequence(), lcm.V,
			h.Header.LedgerVersion, h.Header.ScpValue.Ext.V, lcm.CountTransactions(), bytes.Equal(re, b), err)
	}
	os.Exit(bad)
}
