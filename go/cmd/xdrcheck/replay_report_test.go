package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// REPORT.md lists the failures first, each with its CAPs, expected versus observed and a repro command, in
// words an outsider can read; the repro command, run as written, reproduces the row.
func TestReplayReportListsFailuresFirst(t *testing.T) {
	corpusDir := fakeCorpus(t)
	const e = "cap-0040/signed-payload-signer-added"
	r := runReplay(t, corpusDir, "halt-always", replayArgs(corpusDir, head, "--input", "sep54-dir", "--entries", e)...)
	if r.code != 1 || r.result(e, "testnet") != "mishandled·halt unexpected" {
		t.Fatalf("exit %d, %s\n%s", r.code, r.result(e, "testnet"), r.stderr)
	}
	md := readReportMD(t, r.dir)
	failures, counts := strings.Index(md, "## Failures"), strings.Index(md, "## Counts")
	if failures < 0 || counts < failures {
		t.Fatalf("REPORT.md has no Failures section before the counts:\n%s", md)
	}
	for _, want := range []string{
		"### `" + e + "` (testnet): mishandled·halt",
		"- CAPs: CAP-0040",
		"- Expected `pass`, got `mishandled·halt`: unexpected",
		"- Ingest halted at ledger ",
		"--entries " + e + " --network testnet --input sep54-dir",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("REPORT.md lacks %q:\n%s", want, md)
		}
	}
	for _, jargon := range []string{"failures_without_finding", "pending finding review", "Side categories", "not clean"} {
		if strings.Contains(md+r.stderr+r.stdout, jargon) {
			t.Errorf("output uses %q", jargon)
		}
	}
	if !strings.Contains(r.stdout, "UNEXPECTED") || !strings.Contains(r.stderr, "REPORT.md") {
		t.Errorf("console does not flag the row or point at REPORT.md:\n%s\n%s", r.stdout, r.stderr)
	}

	// The repro command, run as written, gives the same row.
	m := regexp.MustCompile("(?m)^  (xdrcheck replay .*)$").FindStringSubmatch(md)
	if m == nil {
		t.Fatalf("no repro command in REPORT.md:\n%s", md)
	}
	argv, err := splitCommand(m[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDRCHECK_FAKE_WB", "1")
	t.Setenv("XDRCHECK_FAKE_CORPUS", corpusDir)
	t.Setenv("XDRCHECK_FAKE_FLAW", "halt-always")
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := replay(context.Background(), append(argv[2:], "--report", dir), &out, &errb); code != 1 {
		t.Fatalf("repro: exit %d\n%s", code, errb.String())
	}
	var rows []*report.Row
	if _, _, err := report.ReadFile(filepath.Join(dir, "report.json"), func(row *report.Row) error { rows = append(rows, row); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Entry != e || report.ResultKey(rows[0]) != "mishandled·halt" {
		t.Errorf("repro gave %d rows, first %+v", len(rows), rows)
	}
}

// A known issue inside its declared range is listed after the unexpected rows, with its reference and the
// fact that differs, expected against observed.
func TestReplayReportKnownIssue(t *testing.T) {
	corpusDir := fakeCorpus(t)
	r := runReplay(t, corpusDir, "", replayArgs(corpusDir, "79ea2acd1dc65a07166133cc04b12e76db314db0", "--assert-known", "--input", "rpc")...)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	md := readReportMD(t, r.dir)
	for _, want := range []string{"mishandled·wrong_value", "a known issue (", "), as expected", "expected `", "observed `"} {
		if !strings.Contains(md, want) {
			t.Errorf("REPORT.md lacks %q:\n%s", want, md)
		}
	}
	if !strings.Contains(r.stdout, "known issue ") {
		t.Errorf("console does not name the known issue:\n%s", r.stdout)
	}
}

func readReportMD(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
