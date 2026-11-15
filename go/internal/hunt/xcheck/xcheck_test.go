package xcheck

import "testing"

func TestNormalisation(t *testing.T) {
	eq := [][3]string{
		{"operations[0].type", "ManageSellOffer", "manage_sell_offer"},
		{"operations[0].type", "ExtendFootprintTTL", "extendFootprintTtl"},
		{"operations[0].type", "revokeAccountSponsorship", "RevokeSponsorship"},
		{"operations[0].amount", "10.0000000", "1E1"},
		{"operations[0].amount", "0.0000002", "2E-7"},
		{"operations[0].price", "1/2", "2/4"},
		{"hash", "ABCD", "abcd"},
	}
	for _, c := range eq {
		a, _ := normal(c[0], c[1])
		b, _ := normal(c[0], c[2])
		if a != b {
			t.Errorf("%s: %q != %q", c[0], c[1], c[2])
		}
	}
	if a, _ := normal("operations[0].amount", "10.1"); a == "10" {
		t.Error("10.1 must not equal 10")
	}
	if !roundedEqual("23.4143783114273420875", "531391306/22695085") {
		t.Error("a decimal rendering of the fraction")
	}
	if roundedEqual("23.40", "531391306/22695085") {
		t.Error("23.40 is not within 0.01 of 23.4144")
	}
}

func TestCompareOnlySharedFields(t *testing.T) {
	a := map[string]Row{"1:0": {"ledger": 1.0, "tx": 0.0, "fee": "100", "time_bounds": map[string]any{"min": "0", "max": "0"}, "only_a": "x"}}
	b := map[string]Row{"1:0": {"ledger": 1.0, "tx": 0.0, "fee": "100", "time_bounds": nil}, "2:0": {"fee": "1"}}
	d, st := Compare("a", "b", a, b)
	if len(d) != 0 || st.Txs != 1 || st.OnlyB != 1 || st.Compared["only_a"] != 0 {
		t.Fatalf("%v %+v", d, st)
	}
	b["1:0"]["fee"] = "101"
	if d, _ := Compare("a", "b", a, b); len(d) != 1 || d[0].Field != "fee" {
		t.Fatalf("%v", d)
	}
}
