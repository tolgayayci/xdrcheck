package lake

import (
	"fmt"

	goxdr "github.com/xdrpp/goxdr/xdr"

	"github.com/stellar/go-stellar-sdk/gxdr"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Header is what the servers need from a LedgerCloseMeta, read with the pinned XDR library.
type Header struct {
	Seq             uint32
	Hash            string // lowercase hex of the stored LedgerHeaderHistoryEntry.hash (not recomputed)
	PreviousHash    string
	CloseTime       int64 // scpValue.closeTime
	ProtocolVersion uint32
	Version         int32  // LedgerCloseMeta arm
	HeaderXDR       []byte // the embedded LedgerHeaderHistoryEntry, re-encoded from the decoded value
	Transactions    int
}

// Inspect decodes a LedgerCloseMeta and returns its header facts. Decoding never slices bytes by hand: the
// v1/v2 arms start with an extension that may carry a value, and Protocol 30 added StellarValue arms.
func Inspect(lcm []byte) (Header, error) {
	var m xdr.LedgerCloseMeta
	if err := m.UnmarshalBinary(lcm); err != nil {
		return Header{}, fmt.Errorf("decode LedgerCloseMeta: %w", err)
	}
	entry := m.LedgerHeaderHistoryEntry()
	hx, err := entry.MarshalBinary()
	if err != nil {
		return Header{}, err
	}
	return Header{
		Seq:             m.LedgerSequence(),
		Hash:            m.LedgerHash().HexString(),
		PreviousHash:    m.PreviousLedgerHash().HexString(),
		CloseTime:       m.LedgerCloseTime(),
		ProtocolVersion: m.ProtocolVersion(),
		Version:         m.V,
		HeaderXDR:       hx,
		Transactions:    m.CountTransactions(),
	}, nil
}

// Renumber is the stream unit's transformation (replay-harness.md §3.3): the ledger header's ledgerSeq becomes
// seq, and every lastModifiedLedgerSeq inside the meta that equalled the original sequence becomes seq too, as
// does an account's seqLedger ("sequence number bumped in this ledger") when it equalled it. Nothing else
// changes — TTL values and other ledger arithmetic keep their original numbers — so transaction hashes are kept
// while the ledger hash and the hash chain go stale. It mirrors go-stellar-sdk ingest/loadtest's update,
// restricted to the ledger's own sequence.
func Renumber(lcm []byte, seq uint32) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("renumber: %v", r)
		}
	}()
	var m gxdr.LedgerCloseMeta
	gxdr.Parse(&m, lcm)
	var hdr *gxdr.LedgerHeader
	switch m.V {
	case 0:
		hdr = &m.V0().LedgerHeader.Header
	case 1:
		hdr = &m.V1().LedgerHeader.Header
	case 2:
		hdr = &m.V2().LedgerHeader.Header
	default:
		return nil, fmt.Errorf("renumber: LedgerCloseMeta v%d", m.V)
	}
	orig := uint32(hdr.LedgerSeq)
	hdr.LedgerSeq = gxdr.Uint32(seq)
	renumberer{from: orig, to: seq}.Marshal("", &m)
	return gxdr.Dump(&m), nil
}

type renumberer struct{ from, to uint32 }

func (renumberer) Sprintf(f string, args ...interface{}) string { return fmt.Sprintf(f, args...) }

func (r renumberer) Marshal(field string, i goxdr.XdrType) {
	switch t := goxdr.XdrBaseType(i).(type) {
	case goxdr.XdrBytes, goxdr.XdrNum32, goxdr.XdrNum64, *goxdr.XdrBool, goxdr.XdrEnum:
	case *gxdr.LedgerEntry:
		if uint32(t.LastModifiedLedgerSeq) == r.from {
			t.LastModifiedLedgerSeq = gxdr.Uint32(r.to)
		}
		t.XdrRecurse(r, field)
	case *gxdr.AccountEntryExtensionV3:
		if uint32(t.SeqLedger) == r.from {
			t.SeqLedger = gxdr.Uint32(r.to)
		}
		t.XdrRecurse(r, field)
	case goxdr.XdrAggregate:
		t.XdrRecurse(r, field)
	default:
		panic(fmt.Sprintf("field %s has unexpected xdr type %T", field, t))
	}
}
