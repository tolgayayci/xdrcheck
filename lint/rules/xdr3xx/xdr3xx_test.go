package xdr3xx_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	"github.com/tolgayayci/xdrcheck/lint/rules/xdr3xx"
)

const testdata = "github.com/tolgayayci/xdrcheck/lint/testdata/"

func withConfig(t *testing.T, c *framework.Config) {
	framework.SetConfig(c)
	t.Cleanup(func() { framework.SetConfig(nil) })
}

func TestXDR301(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr301")
}

func TestXDR301ConfiguredSink(t *testing.T) {
	withConfig(t, &framework.Config{SinksParticipant: []string{testdata + "xdr3xx/xdr301cfg.StateChangeBuilder.WithAccount"}})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr301cfg")
}

func TestXDR302(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr302")
}

func TestXDR303(t *testing.T) {
	withConfig(t, &framework.Config{})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr303")
}

func TestXDR304(t *testing.T) {
	withConfig(t, &framework.Config{SinksMovement: []string{testdata + "xdr3xx/xdr304.recordMovement"}})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr304")
}

// TestXDR304Builder: a configured participant sink reached through a
// builder chain keyed by the emitting contract (the wallet-backend SEP-41
// shape) is silent; one keyed by anything else is reported.
func TestXDR304Builder(t *testing.T) {
	withConfig(t, &framework.Config{SinksParticipant: []string{testdata + "xdr3xx/xdr304builder.stateChangeBuilder.WithAccount"}})
	fixture.Run(t, xdr3xx.Analyzer, "xdr3xx/xdr304builder")
}

// diagnosticsOnly checks the `// want` diagnostics of a fixture copied from
// upstream code, ignoring the facts the analyzer exports for its exported
// functions (marking those would mean editing the copies) and the
// expectations of other rule families, which share the regression files.
type diagnosticsOnly struct{ *testing.T }

func (d diagnosticsOnly) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "unexpected fact") ||
		strings.Contains(msg, "no diagnostic was reported matching `XDR") && !strings.Contains(msg, "matching `XDR3") {
		return
	}
	d.T.Error(msg)
}

// TestRegressWalletBackendPreFix: wallet-backend at 666a64d, before the fix
// that took Soroban participants from meta and moved the success check up.
// XDR301 fires at the authorization-tree reads, XDR302 at participants.go:167.
func TestRegressWalletBackendPreFix(t *testing.T) {
	withConfig(t, &framework.Config{})
	res := fixture.Run(diagnosticsOnly{t}, xdr3xx.Analyzer, "regress/wb666a64d/processors")
	if n := countDiagnostics(res); n != 13 {
		t.Errorf("%d reports at 666a64d, want 13 (12 XDR301, 1 XDR302)", n)
	}
}

// TestRegressWalletBackendFixed: the same files at e967ce8 are silent.
func TestRegressWalletBackendFixed(t *testing.T) {
	withConfig(t, &framework.Config{})
	res := fixture.Run(diagnosticsOnly{t}, xdr3xx.Analyzer, "regress/wbe967ce8/processors")
	if n := countDiagnostics(res); n != 0 {
		t.Errorf("%d reports at e967ce8, want none", n)
	}
}

// TestRegressDeclaredDeploys: wallet-backend issue #746, contract creations
// taken from the authorization tree. With the wallet-backend profile's
// state-change sinks (StateChangeBuilder.WithAccount and WithCreator) the
// pre-fix contract_deploy.go at 666a64d records a declared deploy with no
// meta check (XDR301 at line 62) in a builder that never reads meta (XDR303
// at line 36). At e967ce8 the nested deploys are gated on the created
// instance entries in meta (line 136), but XDR301 still reports line 69:
// emitCreate also records the operation's own top-level CreateContract
// (through emitTopLevel), whose ContractIdPreimageFromAddress.Address the
// rule reads as an authorization-tree value. That path is success-gated
// (line 50) and the host authorises the deployer. The report is a known
// false positive of the rule: the value reaches the sink through a function
// value (emitTopLevel's callback), which the type-based source cannot tell
// from the authorization-tree path; it is suppressed with a reason (see the
// rule page, Limits).
func TestRegressDeclaredDeploys(t *testing.T) {
	const (
		pre   = testdata + "regress/wb666a64d/processors"
		fixed = testdata + "regress/wbe967ce8/processors"
	)
	withConfig(t, &framework.Config{SinksParticipant: []string{
		pre + ".StateChangeBuilder.WithAccount", pre + ".StateChangeBuilder.WithCreator",
		fixed + ".StateChangeBuilder.WithAccount", fixed + ".StateChangeBuilder.WithCreator",
	}})
	for _, c := range []struct {
		dir  string
		want []string
	}{
		{"regress/wb666a64d/processors", []string{"XDR301 contract_deploy.go:62", "XDR303 contract_deploy.go:36"}},
		{"regress/wbe967ce8/processors", []string{"XDR301 contract_deploy.go:69"}},
	} {
		res := fixture.Run(positionsOnly{t}, xdr3xx.Analyzer, c.dir)
		var got []string
		for _, r := range res {
			for _, d := range r.Diagnostics {
				posn := r.Pass.Fset.Position(d.Pos)
				if strings.HasSuffix(posn.Filename, "contract_deploy.go") {
					got = append(got, fmt.Sprintf("%s contract_deploy.go:%d", d.Message[:6], posn.Line))
				}
			}
		}
		sort.Strings(got)
		if strings.Join(got, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("%s: contract_deploy.go reports %q, want %q", c.dir, got, c.want)
		}
	}
}

// positionsOnly ignores analysistest's comparison with the want comments
// (the copies carry the expectations of the default configuration); the
// test compares positions itself.
type positionsOnly struct{ *testing.T }

func (p positionsOnly) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "unexpected diagnostic") || strings.Contains(msg, "no diagnostic was reported") || strings.Contains(msg, "unexpected fact") {
		return
	}
	p.T.Error(msg)
}

func countDiagnostics(res []*analysistest.Result) int {
	n := 0
	for _, r := range res {
		n += len(r.Diagnostics)
	}
	return n
}
