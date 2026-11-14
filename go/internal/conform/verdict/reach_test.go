package verdict

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// A refusal is excused as beyond reach by protocol only when the variant's protocol exceeds the protocol the
// column's driver reports. A column that reports none (its driver cannot bound the SDK's XDR) has nothing
// beyond reach by protocol, whatever its probes say.
func TestReachByReportedProtocol(t *testing.T) {
	entry := func(protocol int) *manifest.Entry {
		e := signedMsEntry(nil, false)
		e.Protocol.Introduced = protocol
		e.Variants[0].Protocol = protocol
		return e
	}
	unbounded := &conform.Describe{XDRSchema: &conform.XDRSchema{Probes: map[string]bool{"stellar_value_signed_ms": false}}}
	cases := []struct {
		name    string
		variant int
		d       *conform.Describe
		want    bool
		verdict string
		check   string
	}{
		{"variant above the reported protocol", 31, describe(30), true, "n_a", "n_a"},
		{"variant at the reported protocol", 30, describe(30), false, "reject_valid", "undeclared"},
		{"variant below the reported protocol", 29, describe(30), false, "reject_valid", "undeclared"},
		{"no reported protocol, newer variant", 31, unbounded, false, "reject_valid", "undeclared"},
		{"no reported protocol, a probe false", 30, unbounded, false, "reject_valid", "undeclared"},
	}
	for _, c := range cases {
		o := obs(entry(c.variant), col("js", "17.4.0", ""), "L0", "reject", "union_arm_undeclared", "")
		o.Describe = c.d
		if got, _ := outOfReach(o); got != c.want {
			t.Errorf("%s: out of reach %v, want %v", c.name, got, c.want)
		}
		if a := (Engine{}).Assess(o); a.Verdict != c.verdict || a.Check != c.check {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, a.Verdict, a.Check, c.verdict, c.check)
		}
	}
}
