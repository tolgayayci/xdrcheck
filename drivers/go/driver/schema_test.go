package driver

import (
	"fmt"
	"testing"
)

// The reported protocol is the highest one the driver can prove for the SDK's XDR: 30 with every Protocol 30
// probe, 29 without one, none when the SDK declares enum members above the Protocol 30 ceiling.
func TestSchemaProtocolRule(t *testing.T) {
	all := map[string]bool{"sc_address_type_muxed_contract": true, "stellar_value_signed_ms": true}
	one := map[string]bool{"sc_address_type_muxed_contract": true, "stellar_value_signed_ms": false}
	cases := []struct {
		name   string
		probes map[string]bool
		beyond []string
		want   int
		ok     bool
	}{
		{"every probe", all, nil, 30, true},
		{"a probe fails", one, nil, 29, true},
		{"newer XDR than the driver knows", all, []string{"ContractCostType 95"}, 0, false},
		{"newer XDR and a probe fails", one, []string{"ScValType 23"}, 0, false},
	}
	for _, c := range cases {
		if p, ok := schemaProtocol(c.probes, c.beyond); p != c.want || ok != c.ok {
			t.Errorf("%s: got %d %v, want %d %v", c.name, p, ok, c.want, c.ok)
		}
	}
}

// Every pinned SDK version carries XDR no newer than Protocol 30, and the driver reports 30 exactly where the
// Protocol 30 probes pass. When an SDK with newer XDR is pinned this fails until the driver learns the new
// protocol's probes and ceiling.
func TestDescribeReportsProvenProtocol(t *testing.T) {
	if b := beyondKnown(); len(b) > 0 {
		t.Fatalf("the SDK declares enum members above the Protocol %d ceiling: %v; add the next protocol's probes and ceiling", knownProtocol, b)
	}
	d := startDriver(t)
	schema := d.describe()["xdr_schema"].(map[string]any)
	probes := schema["probes"].(map[string]any)
	want := 30
	for _, ok := range probes {
		if ok != true {
			want = 29
		}
	}
	if fmt.Sprint(schema["protocol"]) != fmt.Sprint(want) {
		t.Errorf("%s: xdr_schema.protocol = %v, want %v (probes %v)", d.sdkVersion(), schema["protocol"], want, probes)
	}
	// A Protocol 30 SDK declares each ceiling member itself, so the ceiling is not set too high to notice.
	for _, c := range ceiling {
		if want == 30 && !c.valid(c.max) {
			t.Errorf("%s: %s %d is not declared by a Protocol 30 SDK; the ceiling is wrong", d.sdkVersion(), c.name, c.max)
		}
	}
}
