package walletbackend

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
)

// Every scope rule names a criterion and cites wallet-backend at the commit it was read at, and the rules travel
// in the capability's open out_of_scope property.
func TestScopeRulesCiteTheirSource(t *testing.T) {
	for kind, rules := range map[string][]ScopeRule{"participants": ParticipantScope, "addresses": AddressScope, "state_changes": StateChangeScope} {
		for i, r := range rules {
			if !strings.Contains(r.Basis, "wallet-backend "+ScopeSourceCommit[:12]+" ") {
				t.Errorf("%s[%d]: basis %q cites no commit", kind, i, r.Basis)
			}
			if len(r.AddressTypes)+len(r.Roles)+len(r.Kinds)+len(r.AssetTypes)+len(r.Detail) == 0 && r.Cause == "" {
				t.Errorf("%s[%d]: no criterion", kind, i)
			}
		}
	}
	c := withScope(adapter.Capability{Supported: true}, ParticipantScope)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back adapter.Capability
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	var rules []ScopeRule
	if err := json.Unmarshal(back.Extra["out_of_scope"], &rules); err != nil || len(rules) != len(ParticipantScope) {
		t.Errorf("round trip: %v %v", rules, err)
	}
}

// The scope is declared at the commit it was read at and at a commit where every cited file is the same, and not
// at a commit where one differs or is missing.
func TestScopeHoldsWhereCitedFilesAreUnchanged(t *testing.T) {
	files := ScopeCitedFiles()
	for _, want := range []string{"internal/indexer/processors/participants.go", "docs/architecture/state-changes.md", "docs/architecture/token-tracking.md", "internal/indexer/processors/contract_deploy.go", "internal/indexer/processors/token_transfer.go"} {
		if !slices.Contains(files, want) {
			t.Errorf("cited files %v lack %s", files, want)
		}
	}
	same, changed, gone := "same0000", "changed0", "gone0000"
	file := func(commit, path string) (string, error) {
		switch {
		case commit == gone && path == files[0]:
			return "", errors.New("no such path")
		case commit == changed && path == files[len(files)-1]:
			return "edited " + path, nil
		}
		return "content of " + path, nil
	}
	ctx := context.Background()
	for _, tc := range []struct {
		commit string
		want   bool
	}{{ScopeSourceCommit, true}, {same, true}, {changed, false}, {gone, false}} {
		if got, err := scopeHolds(ctx, tc.commit, file); err != nil || got != tc.want {
			t.Errorf("%s: %v %v, want %v", tc.commit, got, err, tc.want)
		}
	}
	broken := func(commit, path string) (string, error) { return "", errors.New("unreadable") }
	if _, err := scopeHolds(ctx, same, broken); err == nil {
		t.Error("an unreadable source commit is not an error")
	}
}
