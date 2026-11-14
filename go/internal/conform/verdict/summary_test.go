package verdict

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
)

// summaryRun is a small run over three api entries on a JavaScript and a Go column:
//   - x/new: JavaScript 17.2.0 answers 2 where the corpus expects 1, and no entry declares it;
//   - x/known: JavaScript 17.2.0 accepts what must be refused, declared as a known divergence with a finding;
//   - x/ok: both conform.
func summaryRun(t *testing.T, jsFixed bool) *Matrix {
	t.Helper()
	newE := apiEntry("x/new", "offer.manage_sell", false, `"1"`)
	newE.Caps = []int{38}
	newE.Validity, newE.Flags = "valid", []string{"native-number-precision"}
	k := kd(jsTarget, "<17.2.1", "L4", "accepts_invalid")
	k.Finding = "F-0042"
	knownE := apiEntry("x/known", "liquidity_pool.id", true, "", k)
	knownE.Caps = []int{38, 40}
	knownE.Validity = "invalid"
	okE := apiEntry("x/ok", "offer.manage_sell", false, `"7"`)
	js, gocol := col("js", "17.2.0", ""), col("go", "v0.9.0", "")
	jsNew := obs(newE, js, "L4", "ok", "", apiValue(`"2"`))
	if jsFixed {
		jsNew = obs(newE, js, "L4", "ok", "", apiValue(`"1"`))
	}
	all := []*conform.Observation{
		jsNew,
		obs(newE, gocol, "L4", "ok", "", apiValue(`"1"`)),
		obs(knownE, js, "L4", "ok", "", apiValue(`"abcd"`)),
		obs(knownE, gocol, "L4", "reject", "ordering", ""),
		obs(okE, js, "L4", "ok", "", apiValue(`"7"`)),
		obs(okE, gocol, "L4", "ok", "", apiValue(`"7"`)),
	}
	for _, o := range all {
		o.Request = &conform.RunRequest{} // every cell was sent to its driver: nothing is unread
	}
	return matrix(t, all)
}

// The summary lists only the rows a reader acts on, new problems first, each with the corpus's expected value,
// the wrong column's answer, the declared divergence and finding, and a repro command; matrix.md keeps the
// all-ok row folded; cross-sdk.md carries the expected value, CAPs, the wrong column and the repro.
func TestSummary(t *testing.T) {
	m := summaryRun(t, false)
	rows := m.ActionRows()
	if len(rows) != 2 || rows[0].Entry != "x/new" || rows[0].Kind != RowNew || rows[1].Entry != "x/known" || rows[1].Kind != RowKnown {
		t.Fatalf("action rows %+v", rows)
	}
	if rows[0].Expected != `value "1"` || len(rows[0].Wrong) != 1 || rows[0].Wrong[0].Column != "js@17.2.0" {
		t.Errorf("new row %+v", rows[0])
	}
	dir := t.TempDir()
	if err := m.Write(dir); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	sum := read(SummaryFile)
	for _, want := range []string{
		"1 new, 0 known but not yet triaged, 1 known divergences",
		"### `x/new` · - · L4", "CAPs: CAP-0038", "Bug class: valid: native-number-precision", `Expected: value "1"`,
		`**js@17.2.0**: accepted, but L4: value`, "new: no entry declares it",
		"Repro: `xdrcheck conform run --columns 'js@17.2.0' --entries 'x/new' --levels L4`",
		"CAPs: CAP-0038, CAP-0040", "Bug class: invalid\n", "Expected: refused", "known divergence (https://example.org/accepts_invalid, finding F-0042)",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("SUMMARY.md lacks %q:\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "x/ok") || strings.Index(sum, "x/new") > strings.Index(sum, "x/known") {
		t.Errorf("SUMMARY.md lists a conforming row, or not new problems first:\n%s", sum)
	}
	md := read(MarkdownFile)
	shown, folded := strings.Index(md, "| `x/new`"), strings.Index(md, "<details>")
	if shown < 0 || folded < 0 || shown > folded || strings.Index(md, "| `x/ok`") < folded {
		t.Errorf("matrix.md does not fold the all-ok row:\n%s", md)
	}
	cross := read(CrossSDKFile)
	for _, want := range []string{"| `x/new` | - | L4 | CAP-0038 | valid: native-number-precision | value \"1\" |", "| js@17.2.0 | new: no entry declares it |", "`xdrcheck conform run --columns 'js@17.2.0' --entries 'x/new' --levels L4`"} {
		if !strings.Contains(cross, want) {
			t.Errorf("cross-sdk.md lacks %q:\n%s", want, cross)
		}
	}
	var text bytes.Buffer
	m.SummaryText(&text)
	if !strings.HasPrefix(text.String(), "Conformance summary: 1 new") || !strings.Contains(text.String(), "repro: xdrcheck conform run --columns 'js@17.2.0'") ||
		!strings.Contains(text.String(), "KNOWN     x/known · - · L4: js@17.2.0 (https://example.org/accepts_invalid)") {
		t.Errorf("console summary:\n%s", text.String())
	}
	// The written matrix reads back strictly, with its new fields.
	back, err := ReadMatrix(filepath.Join(dir, MatrixFile))
	if err != nil || back.Expectations[RowKey("x/new", "", "L4")] != `value "1"` {
		t.Errorf("matrix.json round trip: %v", err)
	}
}

// An undeclared cell on the committed not-yet-triaged list is its own kind, after the new ones.
func TestSummaryUntriaged(t *testing.T) {
	m := summaryRun(t, false)
	for i := range m.Cells {
		if m.Cells[i].Entry == "x/new" && m.Cells[i].Column == "js@17.2.0" {
			m.Cells[i].PendingReview = true
		}
	}
	rows := m.ActionRows()
	if len(rows) != 2 || rows[0].Kind != RowUntriage || Status(&rows[0].Wrong[0]) != "known divergence, not yet triaged" {
		t.Errorf("rows %+v", rows)
	}
}

// The expected-failure list of a column: generated from a run, it passes that run; a failure the list does not
// name fails; a listed cell that now passes (the bug was fixed) fails too, so the list must shrink; a listed
// cell of a selected entry the run does not have fails; a line for an entry the run did not select is ignored.
func TestExpectedFailures(t *testing.T) {
	m := summaryRun(t, false)
	var buf bytes.Buffer
	n, err := m.WriteExpectedFailures(&buf, "js@17.2.0")
	if err != nil || n != 2 {
		t.Fatalf("wrote %d failures: %v", n, err)
	}
	list, err := ParseExpectedFailures(strings.NewReader(buf.String()), "list")
	if err != nil || len(list) != 2 {
		t.Fatalf("parse: %v %+v\n%s", err, list, buf.String())
	}
	all := func(string) bool { return true }
	if r := m.CompareFailures("js@17.2.0", list, all, false); !r.Passed() || r.Matched != 2 {
		t.Errorf("the generated list against its own run: %+v", r)
	}

	// An unexpected pass: JavaScript now answers x/new correctly, but the list still names it.
	fixed := summaryRun(t, true)
	r := fixed.CompareFailures("js@17.2.0", list, all, false)
	if r.Passed() || len(r.NowPassing) != 1 || r.NowPassing[0].Entry != "x/new" || r.Matched != 1 {
		t.Errorf("unexpected pass not caught: %+v", r)
	}
	var out bytes.Buffer
	r.Print(&out, "js.failures")
	if !strings.Contains(out.String(), "UNEXPECTED-PASS x/new - L4: listed as failing but now conforms; remove the line from js.failures") {
		t.Errorf("print:\n%s", out.String())
	}

	// A new failure: the list lacks x/known.
	short, _ := ParseExpectedFailures(strings.NewReader("x/new - L4\n"), "short")
	if r := m.CompareFailures("js@17.2.0", short, all, false); r.Passed() || len(r.New) != 1 || r.New[0].Entry != "x/known" {
		t.Errorf("new failure not caught: %+v", r)
	}

	// Lines for cells the run does not have: a selected entry fails, an unselected one is ignored.
	extra, _ := ParseExpectedFailures(strings.NewReader(buf.String()+"x/ok - L3\ny/elsewhere - L4\n"), "extra")
	r = m.CompareFailures("js@17.2.0", extra, func(id string) bool { return strings.HasPrefix(id, "x/") }, false)
	if r.Passed() || len(r.NotRun) != 1 || r.NotRun[0].Entry != "x/ok" {
		t.Errorf("not-run lines: %+v", r)
	}

	for _, bad := range []string{"x/new L4\n", "x/new - L4\nx/new - L4  # twice\n", "a b c d\n"} {
		if _, err := ParseExpectedFailures(strings.NewReader(bad), "bad"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if l, err := ParseExpectedFailures(strings.NewReader("# only comments\n\n  x/new - L4   # with a comment\n"), "ok"); err != nil || len(l) != 1 || l[0].Line != 3 {
		t.Errorf("comments and blank lines: %+v %v", l, err)
	}

	// Unread entry variants: written as `unread` lines; under require-all-read an unlisted one fails, a listed one
	// passes, and a listed one the column now reads fails like an unexpected pass.
	m.Unread = []conform.Unread{{Column: "js@17.2.0", Entry: "x/ok", Reasons: []string{"L4 n_a/op_not_supported"}}}
	buf.Reset()
	if n, _ := m.WriteExpectedFailures(&buf, "js@17.2.0"); n != 3 || !strings.Contains(buf.String(), "x/ok - unread  # never read: L4 n_a/op_not_supported") {
		t.Fatalf("unread line not written:\n%s", buf.String())
	}
	withUnread, _ := ParseExpectedFailures(strings.NewReader(buf.String()), "with-unread")
	if r := m.CompareFailures("js@17.2.0", withUnread, all, true); !r.Passed() {
		t.Errorf("listed unread item: %+v", r)
	}
	if r := m.CompareFailures("js@17.2.0", list, all, true); r.Passed() || len(r.NewUnread) != 1 {
		t.Errorf("unlisted unread item under require-all-read: %+v", r)
	}
	if r := m.CompareFailures("js@17.2.0", list, all, false); !r.Passed() {
		t.Errorf("unlisted unread item without require-all-read: %+v", r)
	}
	m.Unread = nil
	if r := m.CompareFailures("js@17.2.0", withUnread, all, false); r.Passed() || len(r.NowRead) != 1 {
		t.Errorf("a listed unread item the column now reads: %+v", r)
	}
}
