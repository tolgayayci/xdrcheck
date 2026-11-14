package match

// S-7: balance changes compared at the granularity of the transaction when the reader and the reference record
// them at different granularities (one net row against one row per event, or the reverse).

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

func balChanged(acct Address, asset string, detail map[string]any) manifest.StateChange {
	return manifest.StateChange{Kind: "balance_changed", Account: manifest.Account{Address: acct.String()}, Asset: asset, Detail: detail}
}

func deltas(h string, acct Address, asset string, ds ...string) []adapter.ObsStateChange {
	var out []adapter.ObsStateChange
	for _, d := range ds {
		out = append(out, obsSC(h, "balance_changed", acct, asset, map[string]any{"delta": d}))
	}
	return out
}

func TestBalanceNetAgainstPerEvent(t *testing.T) {
	// The eleven KALE mints of cap-0067/sac-mint-eleven-events-one-tx: one net row expected, eleven rows held.
	mints := []string{"6357866", "6409599", "6784093", "7163581", "7378709", "7535345", "7841488", "8220860", "8515468", "8931413", "9069607"}
	ones := func(n int, v string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	cases := []struct {
		name     string
		expected []manifest.StateChange
		observed []adapter.ObsStateChange
		want     Status
		diff     string
	}{
		{"eleven mint rows sum to the net delta", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "84208029", "balance_after": "147648834"})},
			deltas(h0, alice, usdc, mints...), Matched, ""},
		{"a thousand one-stroop debits sum to the net delta", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "-1000"})},
			deltas(h0, alice, usdc, ones(1000, "-1")...), Matched, ""},
		{"planted: one mint row short", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "84208029"})},
			deltas(h0, alice, usdc, mints[1:]...), Wrong, "84208029/77850163"},
		{"planted: one debit row too many", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "-1000"})},
			deltas(h0, alice, usdc, ones(1001, "-1")...), Wrong, "-1000/-1001"},
		{"planted: a per-event row with a wrong sign", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "34512"})},
			deltas(h0, alice, usdc, "-39548240", "-39582752", "39582752", "-39582752"), Wrong, "34512/-79130992"},
		{"real mainnet per-operation rows sum to the net", []manifest.StateChange{balChanged(alice, "native", map[string]any{"delta": "34512"})},
			deltas(h0, alice, "native", "-39548240", "-39582752", "39582752", "39582752"), Matched, ""},
		{"per-event expected, one net row held", []manifest.StateChange{
			balChanged(alice, usdc, map[string]any{"delta": "5"}), balChanged(alice, usdc, map[string]any{"delta": "7"})},
			deltas(h0, alice, usdc, "12"), Matched, ""},
		{"planted: per-event expected, wrong net row held", []manifest.StateChange{
			balChanged(alice, usdc, map[string]any{"delta": "5"}), balChanged(alice, usdc, map[string]any{"delta": "7"})},
			deltas(h0, alice, usdc, "11"), Wrong, "12/11"},
		{"same granularity: one row each, wrong value stays wrong", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12"})},
			deltas(h0, alice, usdc, "11"), Wrong, ""},
		{"rows of another account are not summed", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12"})},
			append(deltas(h0, alice, usdc, "5", "6"), deltas(h0, bob, usdc, "1")...), Wrong, "12/11"},
		{"rows of another transaction are not summed", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12"})},
			append(deltas(h0, alice, usdc, "5", "6"), deltas(h1, alice, usdc, "1")...), Wrong, "12/11"},
		{"a row without a delta falls back to row-by-row", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12", "balance_after": "20"})},
			[]adapter.ObsStateChange{obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": "12", "balance_after": "19"}), obsSC(h0, "balance_changed", alice, usdc, map[string]any{"balance_after": "18"})}, Wrong, ""},
		{"balance_after: the last event's balance is the net row's", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12", "balance_after": "20"})},
			[]adapter.ObsStateChange{obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": "5", "balance_after": "13"}), obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": "7", "balance_after": "20"})}, Matched, ""},
		{"planted: balance_after matches no event", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12", "balance_after": "20"})},
			[]adapter.ObsStateChange{obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": "5", "balance_after": "13"}), obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": "7", "balance_after": "21"})}, Wrong, ""},
		{"numbers are summed like strings", []manifest.StateChange{balChanged(alice, usdc, map[string]any{"delta": "12"})},
			[]adapter.ObsStateChange{obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": json.Number("5")}), obsSC(h0, "balance_changed", alice, usdc, map[string]any{"delta": json.Number("7")})}, Matched, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = tc.expected
			f.l().StateChanges = tc.observed
			r := f.run(t)
			for i := range tc.expected {
				x := wantStatus(t, r, FactStateChange, i, tc.want)
				if tc.diff != "" {
					w, g, _ := strings.Cut(tc.diff, "/")
					if len(x.Diffs) != 1 || x.Diffs[0].Expected != w || x.Diffs[0].Observed != g || !strings.HasPrefix(x.Diffs[0].Field, "detail.delta (sum") {
						t.Errorf("diffs %+v, want the sums %s", x.Diffs, tc.diff)
					}
				}
			}
			if s := r.Summary(); tc.want == Matched && s.AnyWrong() {
				t.Errorf("summary %+v", s)
			}
		})
	}
}
