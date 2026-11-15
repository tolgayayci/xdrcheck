package main

import "testing"

// The reported protocol is the ledger protocol the binary states, held below 30 when a Protocol 30 probe fails,
// and none when the binary states none; the version output's indented host lines are not the binary's own.
func TestSchemaProtocol(t *testing.T) {
	cases := []struct {
		binary int
		pass   bool
		want   int
		ok     bool
	}{
		{30, true, 30, true},
		{31, true, 31, true},
		{30, false, 29, true},
		{31, false, 29, true},
		{29, false, 29, true},
		{0, true, 0, false},
	}
	for _, c := range cases {
		if p, ok := schemaProtocol(c.binary, c.pass); p != c.want || ok != c.ok {
			t.Errorf("schemaProtocol(%d, %v) = %d %v, want %d %v", c.binary, c.pass, p, ok, c.want, c.ok)
		}
	}
	out := []byte("stellar-core 30.0.0 (0e49751a)\nledger protocol version: 30\nsoroban-env-host versions:\n    host[0]:\n        ledger protocol version: 21\n")
	if m := protocolRE.FindSubmatch(out); m == nil || string(m[1]) != "30" {
		t.Errorf("protocol line: %q", m)
	}
	if m := protocolRE.FindSubmatch([]byte("    host[0]:\n        ledger protocol version: 21\n")); m != nil {
		t.Errorf("a host's protocol line was taken for the binary's: %q", m)
	}
}
