package indexer

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

const testnet = "Test SDF Network ; September 2015"

func scAccount(t *testing.T, g string) xdr.ScVal {
	t.Helper()
	id := xdr.MustAddress(g)
	a := xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &id}
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &a}
}

func symbol(s string) xdr.ScVal {
	v := xdr.ScSymbol(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &v}
}

func text(s string) xdr.ScVal {
	v := xdr.ScString(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &v}
}

func amount(n int64) xdr.ScVal {
	return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &xdr.Int128Parts{Hi: 0, Lo: xdr.Uint64(n)}}
}

func event(emitter [32]byte, topics ...xdr.ScVal) xdr.ContractEvent {
	id := xdr.ContractId(emitter)
	return xdr.ContractEvent{ContractId: &id, Type: xdr.ContractEventTypeContract,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: topics, Data: amount(500)}}}
}

// Rule M-7: the emitting contract decides whose movement an event is.
func TestEmittingContractRule(t *testing.T) {
	const from, to = "GBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSBB7B", "GDJLBYYKMCXNVVNABOE66NYXQGIA5AC5D223Z2KF6ZEYK4UBCA7FKLTG"
	usdc, err := xdr.NewCreditAsset("USDC", "GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP")
	if err != nil {
		t.Fatal(err)
	}
	sac, _ := usdc.ContractID(testnet)
	other := [32]byte{1, 2, 3}
	transfer := func(emitter [32]byte, named string) xdr.ContractEvent {
		topics := []xdr.ScVal{symbol("transfer"), scAccount(t, from), scAccount(t, to)}
		if named != "" {
			topics = append(topics, text(named))
		}
		return event(emitter, topics...)
	}
	cases := []struct {
		name      string
		ev        xdr.ContractEvent
		movements int
		asset     string
		recipient bool // the recipient becomes a participant
	}{
		{"the asset's own contract", transfer(sac, "USDC:GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP"), 1, "USDC:GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP", false},
		{"another contract naming the asset (forged)", transfer(other, "USDC:GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP"), 0, "", false},
		{"another contract naming no classic asset (its own token)", transfer(other, ""), 1, contractStrkey(other), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &txBuilder{passphrase: testnet, hash: "aa"}
			b.eventMovement(0, tc.ev, []xdr.Asset{xdr.MustNewNativeAsset()})
			if len(b.movements) != tc.movements {
				t.Fatalf("%d movements: %+v", len(b.movements), b.movements)
			}
			if tc.movements == 1 && (b.movements[0].Asset != tc.asset || b.movements[0].Amount != "500" || b.movements[0].To.Address != to) {
				t.Errorf("movement %+v", b.movements[0])
			}
			if b.isParticipant(to) != tc.recipient {
				t.Errorf("recipient participant: %v", b.isParticipant(to))
			}
		})
	}
}

func TestResultCodeNames(t *testing.T) {
	if got := txResultCode(xdr.TransactionResultCodeTxFeeBumpInnerFailed); got != "tx_fee_bump_inner_failed" {
		t.Error(got)
	}
	ok := xdr.ManageSellOfferResult{Code: xdr.ManageSellOfferResultCodeManageSellOfferCrossSelf}
	res := []xdr.OperationResult{
		{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{Type: xdr.OperationTypeCreatePassiveSellOffer, CreatePassiveSellOfferResult: &ok}},
		{Code: xdr.OperationResultCodeOpBadAuth},
		{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{Type: xdr.OperationTypePathPaymentStrictSend,
			PathPaymentStrictSendResult: &xdr.PathPaymentStrictSendResult{Code: xdr.PathPaymentStrictSendResultCodePathPaymentStrictSendUnderDestmin}}},
	}
	want := []string{"create_passive_sell_offer.cross_self", "op_bad_auth", "path_payment_strict_send.under_destmin"}
	got := opResultCodes(res)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %s, want %s", i, got[i], want[i])
		}
	}
}
