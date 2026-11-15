package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/targets"
)

func TestTargetReplayRouting(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"--target", "go"}, true},
		{[]string{"--issue=js-stellar-sdk#1766"}, true},
		{[]string{"-tx", "1:2"}, true},
		{[]string{"--adapter", "x", "--caps", "38"}, false},
		{[]string{"--entries", "a", "--", "--target"}, false},
		{[]string{"--rig", "wallet-backend", "--ledgers", "5"}, false},
	} {
		if got := isTargetReplay(c.args); got != c.want {
			t.Errorf("%v: %v", c.args, got)
		}
	}
}

// A pipeline target whose rig is missing is reported as not available: a valid run directory with status
// unavailable, no rows, exit 3. Nothing is guessed.
func TestReplayUnavailableTarget(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("XDRCHECK_DATASET", t.TempDir())
	dir := t.TempDir()
	obj := filepath.Join(dir, "5.xdr.zst")
	z, _ := zstd.NewWriter(nil)
	os.WriteFile(obj, z.EncodeAll([]byte{0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 0}, nil), 0o644)
	out := filepath.Join(dir, "run")
	var so, se bytes.Buffer
	rc := huntReplay(context.Background(), []string{"--target", "wallet-backend", "--version", "abc", "--ledger-file", obj, "--out", out}, &so, &se)
	if rc != 3 {
		t.Fatalf("rc %d\n%s\n%s", rc, so.String(), se.String())
	}
	if bad := rundir.ValidateDir(out); len(bad) > 0 {
		t.Fatal(bad)
	}
	r, _ := rundir.Load(out)
	if r.Summary.Status != rundir.StatusUnavailable || !strings.HasPrefix(r.Summary.Message, "not available: ") || len(r.Verdicts) != 0 {
		t.Fatalf("%+v", r.Summary)
	}
}

func TestJudgeVerdictsMapping(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.jsonl")
	os.WriteFile(p, []byte(`{"ledger":9,"tx_index":1,"verdict":"ok","kind":"balance"}
{"ledger":9,"tx_index":2,"tx_hash":"`+strings.Repeat("ab", 32)+`","verdict":"missing","kind":"balance","class":"balance:missing:sac","evidence":{"holder":"G"}}
`), 0o644)
	res, err := targets.ReadJudgeVerdicts(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0].Check != "judge-balance" || res.Rows[0].Class != "balance:missing:sac" || res.Tested["judge-balance"] != 2 {
		t.Fatalf("%+v", res)
	}
}

// fakePipeline points the wallet-backend rig and the judge at shell scripts: the rig writes the given
// status.jsonl lines (one per ledger, in order) and rows.jsonl, and exits rigExit; the judge writes one halt
// verdict per ledger.
func fakePipeline(t *testing.T, statuses []string, rows string, rigExit int) {
	t.Helper()
	bin := t.TempDir()
	var st strings.Builder
	for _, s := range statuses {
		st.WriteString(`{"ledger":0,"status":"` + s + `"}\n`)
	}
	rig := "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do [ \"$1\" = --out ] && out=$2; shift; done\nmkdir -p \"$out\"\n" +
		"printf '" + st.String() + "' > \"$out/status.jsonl\"\nprintf '" + rows + "' > \"$out/rows.jsonl\"\nexit " + strconv.Itoa(rigExit) + "\n"
	judge := "#!/bin/sh\ncmd=$1; shift; o=\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && o=$2; shift; done\n" +
		"if [ \"$cmd\" = facts ]; then : > \"$o\"; else printf '{\"ledger\":5,\"verdict\":\"halt\",\"kind\":\"ledger\",\"class\":\"ledger:halt\"}\\n' > \"$o\"; fi\n"
	os.WriteFile(filepath.Join(bin, "rig"), []byte(rig), 0o755)
	os.WriteFile(filepath.Join(bin, "judge"), []byte(judge), 0o755)
	t.Setenv("XDRCHECK_RIG_WALLET_BACKEND", filepath.Join(bin, "rig"))
	t.Setenv("XDRCHECK_JUDGE", filepath.Join(bin, "judge"))
	t.Setenv("XDRCHECK_DATASET", t.TempDir())
}

func runFakePipeline(t *testing.T, ledgers int) (int, *rundir.Run, string) {
	t.Helper()
	dir := t.TempDir()
	args := []string{"--target", "wallet-backend", "--version", "abc", "--out", filepath.Join(dir, "run"), "--offline"}
	z, _ := zstd.NewWriter(nil)
	for i := 0; i < ledgers; i++ {
		obj := filepath.Join(dir, strconv.Itoa(5+i)+".xdr.zst")
		os.WriteFile(obj, z.EncodeAll([]byte{0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, byte(i)}, nil), 0o644)
		args = append(args, "--ledger-file", obj)
	}
	var so, se bytes.Buffer
	rc := huntReplay(context.Background(), args, &so, &se)
	if bad := rundir.ValidateDir(filepath.Join(dir, "run")); len(bad) > 0 {
		t.Fatalf("invalid run directory: %v\n%s\n%s", bad, so.String(), se.String())
	}
	r, err := rundir.Load(filepath.Join(dir, "run"))
	if err != nil {
		t.Fatal(err)
	}
	return rc, r, so.String() + se.String()
}

// The rig's per-ledger statuses reach the run: a halted ledger makes it partial (its halt still judged into a
// row); an empty rows file with every ledger ingested, or no status file, fails it; only a run whose every
// ledger was ingested is complete. None exits 0 except the complete one.
func TestReplayPipelineLedgerStatus(t *testing.T) {
	row := `{"kind":"x"}\n`
	for _, c := range []struct {
		name     string
		statuses []string
		rows     string
		exit     int
		rc       int
		status   string
		msg      string
	}{
		{"all halted", []string{"halted", "halted"}, "", 1, 2, rundir.StatusPartial, "2 of 2 ledgers not ingested (2 halted"},
		{"one halted", []string{"ingested", "halted"}, row, 1, 2, rundir.StatusPartial, "1 of 2 ledgers not ingested (1 halted, 1 ingested"},
		{"empty rows", []string{"ingested", "ingested"}, "", 0, 2, rundir.StatusFailed, "empty rows.jsonl for 2 ingested ledgers"},
		{"no status", nil, row, 0, 2, rundir.StatusFailed, "no per-ledger status"},
		{"complete", []string{"ingested", "ingested"}, row, 0, 0, rundir.StatusComplete, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			fakePipeline(t, c.statuses, c.rows, c.exit)
			if c.statuses == nil {
				// a rig that writes no status.jsonl at all
				bin := filepath.Dir(os.Getenv("XDRCHECK_RIG_WALLET_BACKEND"))
				os.WriteFile(filepath.Join(bin, "rig"), []byte("#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do [ \"$1\" = --out ] && out=$2; shift; done\nmkdir -p \"$out\"\nprintf '"+c.rows+"' > \"$out/rows.jsonl\"\n"), 0o755)
			}
			rc, r, out := runFakePipeline(t, 2)
			if rc != c.rc || r.Summary.Status != c.status || !strings.Contains(r.Summary.Message, c.msg) {
				t.Fatalf("rc %d status %q message %q\n%s", rc, r.Summary.Status, r.Summary.Message, out)
			}
			if c.status == rundir.StatusPartial && len(r.Verdicts) == 0 {
				t.Fatalf("the judge's halt row is missing from a partial run\n%s", out)
			}
		})
	}
}

// xdrcheck replay --help names all three forms, so the target and rig forms can be found from it.
func TestReplayHelpNamesEveryForm(t *testing.T) {
	var so, se bytes.Buffer
	replay(context.Background(), []string{"--help"}, &so, &se)
	help := so.String() + se.String()
	for _, want := range []string{"--adapter", "--target T --version V", "--rig wallet-backend|stellar-etl|horizon", "-target-version"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
}

// xdrcheck runs validate checks raw rig output (xcc.rig/v1) as its own format instead of rejecting it as a broken
// run directory, and still rejects a rig directory with a bad status line or no rows file.
func TestRunsValidateRigOutput(t *testing.T) {
	mk := func(status, rows string) string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "manifest.json"), []byte(`{"schema":"xcc.rig/v1","rig":"horizon","ledgers":2}`), 0o644)
		os.WriteFile(filepath.Join(d, "status.jsonl"), []byte(status), 0o644)
		if rows != "" {
			os.WriteFile(filepath.Join(d, "rows.jsonl"), []byte(rows), 0o644)
		}
		return d
	}
	good := mk("{\"ledger\":5,\"status\":\"ingested\"}\n{\"ledger\":6,\"status\":\"halted\"}\n", "{\"kind\":\"balance_change\"}\n")
	var so, se bytes.Buffer
	if rc := runsMain([]string{"validate", good}, &so, &se); rc != 0 || !strings.Contains(so.String(), "raw rig output, xcc.rig/v1: 1 halted, 1 ingested") {
		t.Fatalf("rc %d\n%s%s", rc, so.String(), se.String())
	}
	for _, d := range []string{
		mk("{\"ledger\":5,\"status\":\"ingested\"}\n{\"ledger\":6,\"status\":\"lost\"}\n", "{\"kind\":\"x\"}\n"),
		mk("{\"ledger\":5,\"status\":\"ingested\"}\n", "{\"kind\":\"x\"}\n"),
		mk("{\"ledger\":5,\"status\":\"ingested\"}\n{\"ledger\":6,\"status\":\"ingested\"}\n", ""),
	} {
		so.Reset()
		if rc := runsMain([]string{"validate", d}, &so, &se); rc != 1 || !strings.Contains(so.String(), "INVALID") {
			t.Fatalf("rc %d\n%s", rc, so.String())
		}
	}
}

// The Horizon rig never hands its container a lake of symbolic links: a lake without links is used as it is,
// one with links is resolved into real files, and a link that does not resolve is refused by name.
func TestContainerLakeResolvesLinks(t *testing.T) {
	real := t.TempDir()
	obj := filepath.Join(real, "obj.xdr.zst")
	os.WriteFile(obj, []byte("ledger"), 0o644)

	plain := t.TempDir()
	os.WriteFile(filepath.Join(plain, "a.xdr.zst"), []byte("x"), 0o644)
	got, links, err := containerLake(plain, filepath.Join(t.TempDir(), "lake"))
	if want, _ := filepath.EvalSymlinks(plain); err != nil || links != 0 || got != want {
		t.Fatalf("plain lake: %q %d %v", got, links, err)
	}

	linked := t.TempDir()
	os.MkdirAll(filepath.Join(linked, "FC"), 0o755)
	os.WriteFile(filepath.Join(linked, ".config.json"), []byte("{}"), 0o644)
	os.Symlink(obj, filepath.Join(linked, "FC", "5.xdr.zst"))
	dst := filepath.Join(t.TempDir(), "lake")
	got, links, err = containerLake(linked, dst)
	if err != nil || links != 1 || got != dst {
		t.Fatalf("linked lake: %q %d %v", got, links, err)
	}
	fi, err := os.Lstat(filepath.Join(dst, "FC", "5.xdr.zst"))
	b, _ := os.ReadFile(filepath.Join(dst, "FC", "5.xdr.zst"))
	if err != nil || !fi.Mode().IsRegular() || string(b) != "ledger" {
		t.Fatalf("resolved object: %v %v %q", fi, err, b)
	}
	if _, err := os.Stat(filepath.Join(dst, ".config.json")); err != nil {
		t.Fatal(err)
	}

	dangling := t.TempDir()
	os.Symlink(filepath.Join(real, "gone"), filepath.Join(dangling, "6.xdr.zst"))
	if _, _, err := containerLake(dangling, filepath.Join(t.TempDir(), "lake")); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("dangling link: %v", err)
	}
}
