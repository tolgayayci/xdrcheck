package xdr2xx_test

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	"github.com/tolgayayci/xdrcheck/lint/rules/xdr2xx"
)

const testdata = "github.com/tolgayayci/xdrcheck/lint/testdata/"

func withConfig(t *testing.T, c *framework.Config) {
	framework.SetConfig(c)
	t.Cleanup(func() { framework.SetConfig(nil) })
}

func TestXDR201(t *testing.T) {
	withConfig(t, &framework.Config{BudgetMethods: []string{testdata + "xdr2xx/xdr201.budget.Enter"}})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr201")
}

func TestXDR202(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr202")
}

func TestXDR203(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr203")
}

func TestXDR204OptIn(t *testing.T) {
	withConfig(t, &framework.Config{Rules: append(slicesClone(framework.DefaultRuleIDs), "XDR204")})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr204")
}

func TestXDR204OffByDefault(t *testing.T) {
	withConfig(t, &framework.Config{})
	res := fixture.Run(ignoreUnmatched{t}, xdr2xx.Analyzer, "xdr2xx/xdr204")
	if n := countDiagnostics(res); n != 0 {
		t.Errorf("opt-in XDR204 reported %d times with the default rules", n)
	}
}

func TestXDR205(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr205")
}

func TestXDR206NoPolicy(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr206")
}

func TestXDR206HaltLedger(t *testing.T) {
	withConfig(t, &framework.Config{OverflowPolicy: framework.PolicyHaltLedger})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr206halt")
}

func TestXDR206SkipAndFlag(t *testing.T) {
	withConfig(t, &framework.Config{OverflowPolicy: framework.PolicySkipAndFlag, OverflowFlags: []string{"Truncated", "MarkIncomplete"}})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr206skip")
}

func TestXDR207(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr2xx.Analyzer, "xdr2xx/xdr207")
}

// TestXDR207FloorsOverride: a configured floor replaces the shipped one.
func TestXDR207FloorsOverride(t *testing.T) {
	withConfig(t, &framework.Config{Floors: map[string]int{"ScVal": 16, "ClaimPredicate": 3, "DecodeOptions.MaxDepth": 400}})
	res := fixture.Run(ignoreUnmatched{t}, xdr2xx.Analyzer, "xdr2xx/xdr207")
	var got []string
	for _, r := range res {
		for _, d := range r.Diagnostics {
			got = append(got, d.Message)
		}
	}
	// Only the authorization-tree bound (no floor established) is left.
	if len(got) != 1 || !strings.Contains(got[0], "XDR207 (info)") {
		t.Errorf("with lower floors: %q", got)
	}
}

// ignoreUnmatched drops analysistest's complaints about expectations no
// diagnostic matched (the test then counts diagnostics itself).
type ignoreUnmatched struct{ *testing.T }

func (i ignoreUnmatched) Errorf(format string, args ...any) {
	if msg := fmt.Sprintf(format, args...); !strings.Contains(msg, "no diagnostic was reported matching") {
		i.T.Error(msg)
	}
}

// diagnosticsOnly checks a fixture copied from upstream code, which other
// rule families' expectations share.
type diagnosticsOnly struct{ *testing.T }

func (d diagnosticsOnly) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "no diagnostic was reported matching `XDR") && !strings.Contains(msg, "matching `XDR2") {
		return
	}
	d.T.Error(msg)
}

// TestRegressWalletBackendCurrent: at the pinned commit e967ce8 the closure
// walkInvocation in contract_deploy.go recurses over SubInvocations with no
// depth bound (XDR201 at line 143); nothing else in the copied files reports.
func TestRegressWalletBackendCurrent(t *testing.T) {
	withConfig(t, &framework.Config{})
	res := fixture.Run(diagnosticsOnly{t}, xdr2xx.Analyzer, "regress/wbe967ce8/processors")
	if n := countDiagnostics(res); n != 1 {
		t.Errorf("%d reports at e967ce8, want 1", n)
	}
}

// TestRegressWalletBackendPreFix: at 666a64d the participant walk recursed
// with a per-level Union (XDR201 as an error at contract_operations.go line
// 98), and the declared-deploy walk in contract_deploy.go recursed with no
// bound (XDR201 at line 104; the same walk is still unbounded at e967ce8).
func TestRegressWalletBackendPreFix(t *testing.T) {
	withConfig(t, &framework.Config{})
	res := fixture.Run(diagnosticsOnly{t}, xdr2xx.Analyzer, "regress/wb666a64d/processors")
	if n := countDiagnostics(res); n != 2 {
		t.Errorf("%d reports at 666a64d, want 2", n)
	}
}

func countDiagnostics(res []*analysistest.Result) int {
	n := 0
	for _, r := range res {
		n += len(r.Diagnostics)
	}
	return n
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }
