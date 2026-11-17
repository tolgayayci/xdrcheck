package xdr102

import (
	"errors"
	"log"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) Reduced to the base account first.
func operationParticipantsBase(op xdr.Operation, tx *ingest.LedgerTransaction, participants set) {
	if op.SourceAccount != nil {
		participants.Add(op.SourceAccount.ToAccountId().Address())
	}
	participants.Add(tx.Envelope.SourceAccount().ToAccountId().Address())
	if acc, err := tx.Account(); err == nil {
		participants.Add(acc)
	}
}

// (b) A kind switch that reduces the muxed arms and rejects claimable
// balances and pools (the shape of a project normaliser).
func storableAddress(addr xdr.ScAddress) (string, bool, error) {
	switch addr.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract:
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		muxed := addr.MustMuxedAccount()
		s, err := strkey.Encode(strkey.VersionByteAccountID, muxed.Ed25519[:])
		return s, err == nil, err
	default:
		return "", false, nil
	}
	s, err := addr.String()
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

func eventParticipantsChecked(addr xdr.ScAddress, participants set) error {
	s, ok, err := storableAddress(addr)
	if err != nil || !ok {
		return err
	}
	participants.Add(s)
	return nil
}

// (b2) The same check written as an early return.
func eventParticipantsEarlyReturn(addr xdr.ScAddress, participants set) error {
	if addr.Type != xdr.ScAddressTypeScAddressTypeAccount && addr.Type != xdr.ScAddressTypeScAddressTypeContract {
		return errors.New("not an account or contract")
	}
	s, err := addr.String()
	if err != nil {
		return err
	}
	participants.Add(s)
	return nil
}

// Normalise stands for a project's address normaliser (configured in
// sanitizersaddress).
func Normalise(addr string) string { return addr }

// (c) A configured normaliser.
func feeParticipantsNormalised(tx *ingest.LedgerTransaction, participants set) {
	fee, _ := tx.FeeAccountAddress()
	participants.Add(Normalise(fee))
}

// (d) The contract of a contract-data entry in meta: written by the host,
// never a muxed kind.
func nonceParticipants(change ingest.Change, participants set) error {
	if change.Post == nil || change.Post.Data.Type != xdr.LedgerEntryTypeContractData {
		return nil
	}
	s, err := change.Post.Data.MustContractData().Contract.String()
	if err != nil {
		return err
	}
	participants.Add(s)
	return nil
}

// (f) Rendered for a log line only.
func logAddress(addr xdr.ScAddress) {
	s, _ := addr.String()
	log.Printf("event from %s", s)
}

// (g) A muxed account known to be a plain ed25519 key.
func plainSource(acc xdr.MuxedAccount, participants set) {
	if acc.Type == xdr.CryptoKeyTypeKeyTypeEd25519 {
		participants.Add(acc.Address())
	}
}

// (h) A signer known to be an ed25519 key.
func signerColumnChecked(key xdr.SignerKey) (AddressBytea, bool) {
	if key.Type != xdr.SignerKeyTypeSignerKeyTypeEd25519 {
		return "", false
	}
	return AddressBytea(key.Address()), true
}
