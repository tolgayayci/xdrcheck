package stellaretl

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// testdata/out holds rows stellar-etl v2.8.34 wrote for pubnet ledger 64558277 (evidence/stellar-etl/), cut to two
// transactions: 6591994c… (an issuer's payment, emitted as a three-topic mint whose to_muxed_id is the text memo
// "psp:160886906") and b35be42e… (a Stellar Asset Contract mint by invoke_host_function).
const (
	fixtureLedger = 64558277
	txMemoMint    = "6591994cebe12b87e6ca9175769bbaefeb45c7082be221ba3ed23d6042fe9474"
	txSACMint     = "b35be42e08af95843a49bf8a7108b03c3356e29a71c79ad7a2ebea35b0521149"
	entryMemoMint = "cap-0067/to-muxed-id-text-from-memo.pubnet-64558277"
)

func fixtureObservation(t *testing.T, hashes ...string) adapter.Observation {
	t.Helper()
	ex, err := readExports("testdata/out")
	if err != nil {
		t.Fatal(err)
	}
	d := Describe("v2.8.34", adapter.Envelope{Enforcement: "none"})
	return observation(ex, adapter.ObserveParams{Session: "s", Range: adapter.Range{Start: fixtureLedger, End: fixtureLedger},
		Kinds: adapter.AllKinds, TxHashes: hashes}, d)
}

func TestObservationFromRows(t *testing.T) {
	obs := fixtureObservation(t)
	if len(obs.Ledgers) != 1 {
		t.Fatalf("ledgers: %d", len(obs.Ledgers))
	}
	l := obs.Ledgers[0]
	if l.LedgerSeq != fixtureLedger || l.LedgerHash == "" {
		t.Fatalf("ledger %d hash %q", l.LedgerSeq, l.LedgerHash)
	}
	if obs.Kinds.Addresses.Status != "not_applicable" || obs.Kinds.Movements.Status != "provided" {
		t.Fatalf("kinds: %+v", obs.Kinds)
	}
	if *l.Receipt.Transactions != 2 || *l.Receipt.Operations != 2 {
		t.Errorf("receipt counts the rows held: %d transactions, %d operations", *l.Receipt.Transactions, *l.Receipt.Operations)
	}

	// Transactions: index from the TOID, result codes in XDR-JSON names, fee as the stored token.
	byHash := map[string]adapter.ObsTransaction{}
	for _, tx := range l.Transactions {
		byHash[tx.Hash] = tx
	}
	memo, sac := byHash[txMemoMint], byHash[txSACMint]
	if memo.Index == nil || *memo.Index != 75 || memo.ResultCode != "tx_success" || memo.FeeCharged != "100" ||
		!slices.Equal(memo.OperationResultCodes, []string{"payment.success"}) {
		t.Errorf("memo-mint transaction: %+v", memo)
	}
	if sac.ResultCode != "tx_fee_bump_inner_success" || !slices.Equal(sac.OperationResultCodes, []string{"invoke_host_function.success"}) {
		t.Errorf("SAC-mint transaction: %+v", sac)
	}

	// The memo mint: stellar-etl#450 — the text memo comes out as an M… address with ID 0, passed through as stored.
	var mints []adapter.ObsMovement
	for _, m := range l.Movements {
		if m.Kind == "fee" {
			t.Errorf("fee rows are not mapped: %+v", m)
		}
		if m.Kind == "mint" {
			mints = append(mints, m)
		}
	}
	if len(mints) != 2 {
		t.Fatalf("mints: %+v", mints)
	}
	m := mints[0]
	if m.TxHash != txMemoMint || *m.TxIndex != 75 || *m.OpIndex != 0 || m.Amount != "807200000" ||
		m.Asset != "APSBPOUSD:GADYGHULIQ35Z53MQ5UFKNVFRTWN2GE4SBEGN4BOBECNWSURX352IV42" ||
		m.To.Address != "GBN32NH6TMWE4ZD4G245CF3UVOQRXD4FK3FDCLZ4DE5642HWFKSLLRMB" ||
		m.To.OnChainForm != "MBN32NH6TMWE4ZD4G245CF3UVOQRXD4FK3FDCLZ4DE5642HWFKSLKAAAAAAAAAAAAATXO" ||
		m.Routing == nil || m.Routing.Type != "u64" || *m.Routing.Value != "0" {
		b, _ := json.Marshal(m)
		t.Errorf("memo mint as stored: %s", b)
	}

	// The SAC mint maps to a mint movement with exact amount, asset and recipient.
	sacMint := mints[1]
	if sacMint.TxHash != txSACMint || sacMint.Amount != "9421806" || sacMint.Asset != "KALE:GBDVX4VELCDSQ54KQJYTNHXAHFLBCA77ZY2USQBM4CSHTTV7DME7KALE" ||
		sacMint.To.Address != "GB237VS5BXDSGCPKVVBDRMRMCWHU7O7WR24RPZCFWZPTJ3PM4YCSQAH4" || sacMint.Routing != nil {
		b, _ := json.Marshal(sacMint)
		t.Errorf("SAC mint: %s", b)
	}
	var credited bool
	for _, sc := range l.StateChanges {
		if sc.TxHash == txMemoMint && sc.Kind == "balance_changed" && sc.NativeLabel == "account_credited" &&
			sc.Account.Address == "GBN32NH6TMWE4ZD4G245CF3UVOQRXD4FK3FDCLZ4DE5642HWFKSLLRMB" && sc.Detail["delta_as_stored"] == "80.7200000" {
			credited = true
		}
	}
	if !credited {
		t.Errorf("the payment's account_credited effect is not a balance change: %+v", l.StateChanges)
	}

	// Participants: the transaction source, the fee-bump fee account, operation sources and effect addresses.
	want := map[string]string{
		"GBAA3ATZDF6MPSWTCJNHAMHCDZU2USAV2XDSZKRTNF6A2RAHSJB7PKF2": txMemoMint,
		"GADYGHULIQ35Z53MQ5UFKNVFRTWN2GE4SBEGN4BOBECNWSURX352IV42": txMemoMint,
		"GBN32NH6TMWE4ZD4G245CF3UVOQRXD4FK3FDCLZ4DE5642HWFKSLLRMB": txMemoMint,
		"GA2JRQOF6EA3HQWDCEDBPPMLYPJCFLDDGYZLEQGMS5SOBQIB3BAFHVAW": txSACMint,
		"GBHGP646HA463DVPM7XLQMCISD3EF53ZJMCL5GINAJLOVQZDPH7VS7QO": txSACMint,
	}
	for addr, tx := range want {
		found := false
		for _, p := range l.Participants {
			found = found || (p.Account.Address == addr && p.TxHash == tx)
		}
		if !found {
			t.Errorf("participant %s of %s missing", addr, tx[:8])
		}
	}

	// tx_hashes narrows every kind to the named transactions.
	only := fixtureObservation(t, txSACMint).Ledgers[0]
	if len(only.Transactions) != 1 || only.Transactions[0].Hash != txSACMint || len(only.Movements) != 1 {
		t.Errorf("filtered: %d transactions, %d movements", len(only.Transactions), len(only.Movements))
	}
}

// The observation is a valid observation set and deterministic.
func TestObservationValidates(t *testing.T) {
	a, _ := json.Marshal(fixtureObservation(t))
	b, _ := json.Marshal(fixtureObservation(t))
	if string(a) != string(b) {
		t.Fatal("two observations of the same rows differ")
	}
	if errs := adapter.ValidateObservation(a); len(errs) > 0 {
		t.Fatalf("%+v", errs)
	}
}

// Through the harness's matcher, the memo mint is a wrong value on its corpus entry: the routing ID differs.
func TestMatcherSeesFabricatedMuxedID(t *testing.T) {
	root := testcorpus.Build(t, []string{entryMemoMint}, testcorpus.Options{})
	c, err := manifest.Load(root, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry(entryMemoMint)
	if e == nil || len(e.Variants) != 1 {
		t.Fatalf("entry %s not loaded", entryMemoMint)
	}
	d := Describe("v2.8.34", adapter.Envelope{Enforcement: "none"})
	obs := fixtureObservation(t)
	res, err := match.MatchVariant(e.Variants[0], &d.Observations, &obs)
	if err != nil {
		t.Fatal(err)
	}
	var mint *match.Fact
	for i, f := range res.Facts {
		if f.Kind == match.FactMovement && f.TxHash == txMemoMint && f.Status != match.NotApplicable {
			mint = &res.Facts[i]
		}
	}
	if mint == nil || mint.Status != match.Wrong || len(mint.Diffs) != 1 || mint.Diffs[0].Field != "routing" ||
		mint.Diffs[0].Expected != "text:psp:160886906" || mint.Diffs[0].Observed != "u64:0" {
		t.Fatalf("mint fact: %+v", mint)
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"TransactionResultCodeTxFeeBumpInnerFailed": "tx_fee_bump_inner_failed",
		"TransactionResultCodeTxSuccess":            "tx_success",
		"SomethingElse":                             "SomethingElse",
	} {
		if got := enumName(in, "TransactionResultCode"); got != want {
			t.Errorf("enumName(%s) = %s, want %s", in, got, want)
		}
	}
	for _, c := range []struct {
		row  opRow
		want string
	}{
		{opRow{TypeString: "path_payment_strict_receive", ResultCode: "OperationResultCodeOpInner",
			TraceCode: "PathPaymentStrictReceiveResultCodePathPaymentStrictReceiveOverSendmax"}, "path_payment_strict_receive.over_sendmax"},
		{opRow{TypeString: "manage_sell_offer", ResultCode: "OperationResultCodeOpInner", TraceCode: "ManageSellOfferResultCodeManageSellOfferNotFound"}, "manage_sell_offer.not_found"},
		{opRow{TypeString: "payment", ResultCode: "OperationResultCodeOpBadAuth"}, "op_bad_auth"},
		{opRow{TypeString: "payment", ResultCode: "OperationResultCodeOpInner"}, ""},
	} {
		if got := operationResultCode(c.row); got != c.want {
			t.Errorf("operationResultCode(%+v) = %q, want %q", c.row, got, c.want)
		}
	}
	if toidOrder(277275688401420288) != 76 || toidOp(277275688401420289) != 1 || toidTx(277275688401420289) != 277275688401420288 {
		t.Error("TOID arithmetic")
	}
}

func TestToolchainAndSDK(t *testing.T) {
	gomod := "module github.com/stellar/stellar-etl/v2\n\ngo 1.27.3\n\nrequire (\n\tgithub.com/stellar/go-stellar-sdk v0.8.1-0.20261106081502-e31e3b146d00\n)\n"
	if tc := toolchainOf(gomod); tc != "go1.27.3" {
		t.Errorf("toolchain %s", tc)
	}
	if tc := toolchainOf(gomod + "toolchain go1.27.4\n"); tc != "go1.27.4" {
		t.Errorf("toolchain line %s", tc)
	}
	if v := sdkVersionOf(gomod); v != "v0.8.1-0.20261106081502-e31e3b146d00" || sdkMaxProtocol(v) != 30 {
		t.Errorf("sdk %s → %d", v, sdkMaxProtocol(v))
	}
	if sdkMaxProtocol("v0.7.3") != 29 || sdkMaxProtocol("v0.6.0") != 0 {
		t.Error("sdk table")
	}
}
