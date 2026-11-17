package xdr406

import (
	"github.com/stellar/go-stellar-sdk/xdr"
)

type row struct{ Kind string }

// (a) No default: an entry type it does not handle is dropped silently.
func entryRows(changes []xdr.LedgerEntryChange, out []row) []row {
	for _, c := range changes {
		switch c.Type { // want `XDR406 \(warning\): switch over xdr.LedgerEntryChangeType writes rows and has no default, so a value it does not handle is dropped silently: it does not handle LedgerEntryState`
		case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
			out = append(out, row{Kind: "created"})
		case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
			out = append(out, row{Kind: "updated"})
		case xdr.LedgerEntryChangeTypeLedgerEntryRemoved:
			out = append(out, row{Kind: "removed"})
		case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
			out = append(out, row{Kind: "restored"})
		}
	}
	return out
}

// (b) A panicking default: a new value stops the job.
func memoRow(m xdr.Memo) row {
	switch m.Type { // want `XDR406 \(warning\): switch over xdr.MemoType writes rows and panics or exits in its default`
	case xdr.MemoTypeMemoNone, xdr.MemoTypeMemoText, xdr.MemoTypeMemoId, xdr.MemoTypeMemoHash, xdr.MemoTypeMemoReturn:
		return row{Kind: m.Type.String()}
	default:
		panic("unknown memo type")
	}
}
