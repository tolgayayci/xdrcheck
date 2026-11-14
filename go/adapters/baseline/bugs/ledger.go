package bugs

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
)

// ledger is what a seed sees of one ledger: the bytes, the document the baseline derived, and the pass's
// passphrase. Helpers here read the envelopes again where a defect needs what the baseline deliberately ignores.
type ledger struct {
	lcm        xdr.LedgerCloseMeta
	doc        *indexer.Doc
	passphrase string
	txs        []ingest.LedgerTransaction
	read       bool
}

func (l *ledger) facts() *adapterkit.Ledger { return &l.doc.Facts }

// transactions are the ledger's transactions in apply order, read by the SDK the way the baseline reads them.
func (l *ledger) transactions() []ingest.LedgerTransaction {
	if l.read {
		return l.txs
	}
	l.read = true
	r, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(l.passphrase, l.lcm)
	if err != nil {
		return nil
	}
	defer r.Close()
	for {
		tx, err := r.Read()
		if errors.Is(err, io.EOF) || err != nil {
			break
		}
		l.txs = append(l.txs, tx)
	}
	return l.txs
}

// tx returns the baseline's row for a transaction hash.
func (l *ledger) tx(hash string) *adapterkit.ObsTransaction {
	for i := range l.doc.Facts.Transactions {
		if l.doc.Facts.Transactions[i].Hash == hash {
			return &l.doc.Facts.Transactions[i]
		}
	}
	return nil
}

func (l *ledger) successful(hash string) bool {
	t := l.tx(hash)
	return t != nil && t.Successful != nil && *t.Successful
}

func txLocator(tx ingest.LedgerTransaction) adapterkit.Locator {
	i := int(tx.Index) - 1
	return adapterkit.Locator{TxHash: tx.Hash.HexString(), TxIndex: &i}
}

// addParticipant adds an address as a participant of the transaction, once.
func (l *ledger) addParticipant(loc adapterkit.Locator, address, role string) {
	if address == "" {
		return
	}
	f := l.facts()
	for i := range f.Participants {
		p := &f.Participants[i]
		if p.TxHash == loc.TxHash && p.Account.Address == address {
			return
		}
	}
	a := account(address)
	a.Roles = []string{role}
	f.Participants = append(f.Participants, adapterkit.ObsParticipant{Locator: loc, Account: *a})
	l.addAddress(loc, "participants.address", address)
}

// addAddress records a stored address value, once per field.
func (l *ledger) addAddress(loc adapterkit.Locator, field, value string) {
	f := l.facts()
	for _, a := range f.Addresses {
		if a.TxHash == loc.TxHash && a.Field == field && a.AsStored.Value == value {
			return
		}
	}
	f.Addresses = append(f.Addresses, adapterkit.ObsAddress{Locator: adapterkit.Locator{TxHash: loc.TxHash, TxIndex: loc.TxIndex},
		Field: field, Type: strkeyType(value), AsStored: adapterkit.Stored{Encoding: "strkey_text", Value: value}})
}

// signedPayloadSigner reports whether any signer the baseline recorded is a signed-payload signer.
func (l *ledger) signedPayloadSigner() (string, bool) {
	for _, c := range l.facts().StateChanges {
		if c.Signer != nil && c.Signer.Type == "ed25519_signed_payload" {
			return c.Signer.Key, true
		}
	}
	return "", false
}

// accounts visits every account object the document holds.
func (l *ledger) accounts(fn func(*adapterkit.ObsAccount)) {
	f := l.facts()
	for i := range f.Participants {
		fn(&f.Participants[i].Account)
	}
	for i := range f.StateChanges {
		if f.StateChanges[i].Account != nil {
			fn(f.StateChanges[i].Account)
		}
	}
	for i := range f.Movements {
		for _, a := range []*adapterkit.ObsAccount{f.Movements[i].From, f.Movements[i].To} {
			if a != nil {
				fn(a)
			}
		}
	}
}

func account(address string) *adapterkit.ObsAccount {
	return &adapterkit.ObsAccount{Address: address, AsStored: &adapterkit.Stored{Encoding: "strkey_text", Value: address}}
}

// baseAddress is the base strkey of an ScAddress; muxed information is dropped.
func baseAddress(a xdr.ScAddress) string {
	enc := func(v strkey.VersionByte, b []byte) string {
		s, _ := strkey.Encode(v, b)
		return s
	}
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		k := a.AccountId.Ed25519
		return enc(strkey.VersionByteAccountID, k[:])
	case xdr.ScAddressTypeScAddressTypeContract:
		return enc(strkey.VersionByteContract, a.ContractId[:])
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		return enc(strkey.VersionByteAccountID, a.MuxedAccount.Ed25519[:])
	case xdr.ScAddressTypeScAddressTypeMuxedContract:
		return enc(strkey.VersionByteContract, a.MuxedContract.ContractId[:])
	case xdr.ScAddressTypeScAddressTypeLiquidityPool:
		return enc(strkey.VersionByteLiquidityPool, a.LiquidityPoolId[:])
	case xdr.ScAddressTypeScAddressTypeClaimableBalance:
		s, _ := a.ClaimableBalanceId.EncodeToStrkey()
		return s
	}
	return ""
}

// muxedForm renders base plus id as the M… (account) or W… (contract) strkey.
func muxedForm(base string, id uint64) string {
	switch {
	case strings.HasPrefix(base, "G"):
		m, err := xdr.MuxedAccountFromAccountId(base, id)
		if err != nil {
			return ""
		}
		s, _ := m.GetAddress()
		return s
	case strings.HasPrefix(base, "C"):
		raw, err := strkey.Decode(strkey.VersionByteContract, base)
		if err != nil {
			return ""
		}
		var b [40]byte
		copy(b[:32], raw)
		binary.BigEndian.PutUint64(b[32:], id)
		s, _ := strkey.Encode(strkey.VersionByteMuxedContract, b[:])
		return s
	}
	return ""
}

// strkeyType names an address's type from its strkey prefix (observation addresses[].type).
func strkeyType(s string) string {
	if s == "" {
		return ""
	}
	switch s[0] {
	case 'G':
		return "account"
	case 'M':
		return "muxed_account"
	case 'C':
		return "contract"
	case 'W':
		return "muxed_contract"
	case 'B':
		return "claimable_balance"
	case 'L':
		return "liquidity_pool"
	case 'P':
		return "signed_payload"
	case 'T':
		return "pre_auth_tx"
	case 'X':
		return "hash_x"
	}
	return ""
}

// opEvents returns each operation's contract events (TransactionMeta v3 and v4).
func opEvents(m xdr.TransactionMeta) [][]xdr.ContractEvent {
	switch m.V {
	case 3:
		if m.V3.SorobanMeta != nil {
			return [][]xdr.ContractEvent{m.V3.SorobanMeta.Events}
		}
	case 4:
		var out [][]xdr.ContractEvent
		for _, o := range m.V4.Operations {
			out = append(out, o.Events)
		}
		return out
	}
	return nil
}
