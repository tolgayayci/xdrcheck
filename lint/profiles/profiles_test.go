package profiles_test

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	// The rule packages register the rules a profile may name.
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr1xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr2xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr3xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr4xx"
)

// TestShippedProfilesLoad: every shipped profile parses with the strict
// decoder, names only rules this build provides, and enables every rule of
// the default set (a shipped profile may add opt-in rules, never drop one).
func TestShippedProfilesLoad(t *testing.T) {
	names := framework.ProfileNames()
	if len(names) == 0 {
		t.Fatal("no shipped profiles")
	}
	for _, name := range names {
		cfg, err := framework.Load(framework.LoadOptions{Profile: name})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err := cfg.Validate(framework.Default); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for _, id := range framework.DefaultRuleIDs {
			if r := framework.Default.Rule(id); r != nil && !cfg.Enabled(*r) {
				t.Errorf("%s: default rule %s is not enabled", name, id)
			}
		}
	}
}
