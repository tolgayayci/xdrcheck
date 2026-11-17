package plugin

import (
	"strings"
	"testing"

	"github.com/golangci/plugin-module-register/register"
)

func TestRegistered(t *testing.T) {
	newPlugin, err := register.GetPlugin(Name)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPlugin(nil)
	if err != nil {
		t.Fatal(err)
	}
	as, err := p.BuildAnalyzers()
	if err != nil || len(as) == 0 {
		t.Fatalf("BuildAnalyzers: %d analyzers, %v", len(as), err)
	}
	names := map[string]bool{}
	for _, a := range as {
		names[a.Name] = true
	}
	for _, want := range []string{"unvalidated", "caps", "participants", "xdr000"} {
		if !names[want] {
			t.Errorf("no analyzer %q among %v", want, names)
		}
	}
	if p.GetLoadMode() != register.LoadModeTypesInfo {
		t.Errorf("load mode %q", p.GetLoadMode())
	}
}

func TestSettings(t *testing.T) {
	cfg, err := configFrom(map[string]any{"profile": "wallet-backend", "overflowpolicy": "skip-and-flag", "overflowflags": []any{"Truncated"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OverflowPolicy != "skip-and-flag" || len(cfg.SinksAccountKey) == 0 || len(cfg.OverflowFlags) != 1 {
		t.Errorf("profile plus inline keys: %+v", cfg)
	}
	if cfg, err := configFrom(nil); cfg != nil || err != nil {
		t.Errorf("no settings: %v, %v", cfg, err)
	}
	for _, bad := range []map[string]any{
		{"nosuchkey": true},
		{"rules": []any{"XDR999"}},
		{"profile": "no-such-profile"},
		{"config": "x.yml", "overflowpolicy": "halt-ledger"},
		{"profile": 3},
	} {
		if _, err := configFrom(bad); err == nil {
			t.Errorf("%v: accepted", bad)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%v: empty error", bad)
		}
	}
}
