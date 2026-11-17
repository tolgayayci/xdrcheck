package xdr1xx_test

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/rules/xdr1xx"
)

// Seeded fixtures: every violating line carries a `// want`; the compliant
// files carry none. They import the real go-stellar-sdk v0.9.0.

func TestXDR101(t *testing.T) { fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr101") }

// The XDR102 fixture's .xdrlint.yml configures an account-key type and an
// address normaliser.
func TestXDR102(t *testing.T) { fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr102") }

func TestXDR103(t *testing.T) { fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr103") }

// XDR105 is opt-in; the fixture's .xdrlint.yml enables it.
func TestXDR105(t *testing.T) { fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr105") }

// Real-code regression fixtures: copies of upstream files at the commit just
// before a known fix carry a want comment at each documented site, and the
// copies at the fix carry want comments only where the rule still fires.
// Each side's report count is asserted (-1: not counted), so a row says how
// many sites a fix removed.
func TestRegressionBeforeAfter(t *testing.T) {
	for _, c := range []struct {
		name            string
		before, after   string
		nBefore, nAfter int
	}{
		// XDR102: wallet-backend PR #753 reduced the Soroban operation source
		// to its base account (lines 156, 259, 303, 347). The
		// ScAddress.String() calls on the authorization tree and the invocation
		// arguments (lines 66, 113, 350) remain at bb0b162 until PR #739
		// removed the harvest.
		{"wallet-backend#753", "xdr1xx/wb_contract_operations_f8e5786", "xdr1xx/wb_contract_operations_bb0b162", 7, 3},
		// XDR102: PR #739 took Soroban participants from meta; the harvest
		// sites at 666a64d are gone at e967ce8.
		{"wallet-backend#739", "wb666a64d/processors", "wbe967ce8/processors", 3, 0},
		// XDR102: wallet-backend PR #756 (finding #752), ScAddress kinds.
		{"wallet-backend#756", "xdr1xx/wb_sep41_events_ba82157", "xdr1xx/wb_sep41_events_666a64d", -1, 0},
		// XDR102: wallet-backend PR #693 narrows the same site; the rule still
		// fires after it for the kinds #756 handled later.
		{"wallet-backend#693", "xdr1xx/wb_sep41_events_79ea2acd", "xdr1xx/wb_sep41_events_6e5a5910", -1, -1},
		// XDR101: stellar-etl issue #450 (no upstream fix: the "after" copy is
		// the smallest fix, made for the fixture).
		{"stellar-etl#450", "xdr1xx/etl_token_transfer_2b24ec89", "xdr1xx/etl_token_transfer_fixed", 2, 0},
		// XDR101: the older stellar-etl shape (GetId straight into SetID).
		{"stellar-etl-dea2cd9", "xdr1xx/etl_token_transfer_dea2cd9", "", 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			check := func(dir string, want int) {
				if dir == "" {
					return
				}
				res := fixture.Run(diagnosticsOnly{t}, xdr1xx.Analyzer, "regress/"+dir)
				if n := countDiagnostics(res); want >= 0 && n != want {
					t.Errorf("%s: %d reports, want %d", dir, n, want)
				}
			}
			check(c.before, c.nBefore)
			check(c.after, c.nAfter)
		})
	}
}

// diagnosticsOnly checks the XDR1xx expectations of a fixture copied from
// upstream code; the copies shared with other rule families carry their
// expectations too, which this analyzer does not answer.
type diagnosticsOnly struct{ *testing.T }

func (d diagnosticsOnly) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "no diagnostic was reported matching `XDR") && !strings.Contains(msg, "matching `XDR1") {
		return
	}
	d.T.Error(msg)
}

func countDiagnostics(res []*analysistest.Result) int {
	n := 0
	for _, r := range res {
		n += len(r.Diagnostics)
	}
	return n
}

// XDR102 and an account-key type whose own Value() reduces muxed strkeys and
// refuses other payloads: the type, in another package, is found through a
// fact; types that store the string as given, or keep any payload length,
// are still sinks.
func TestXDR102SinkNormalises(t *testing.T) {
	fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr102sink")
}

// XDR102 and a re-parse of the same ledger entry whose ok result guarantees a
// contract holder (sac.ContractBalanceFromContractData).
func TestXDR102Reparse(t *testing.T) { fixture.Run(t, xdr1xx.Analyzer, "xdr1xx/xdr102reparse") }
