package xdrdef

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitT runs git in dir with a fixed identity from the environment (test repositories only).
func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@example.org", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_DATE=2026-11-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-11-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitFile(t *testing.T, dir, name, text, msg string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, dir, "add", name)
	gitT(t, dir, "commit", "--quiet", "-m", msg)
	return gitT(t, dir, "rev-parse", "HEAD")
}

const watchBase = `namespace stellar {
typedef int int32;
struct TransactionEnvelope { int32 fee; };
union LedgerCloseMeta switch (int v) {
case 0: TransactionEnvelope v0;
};
struct LedgerCloseMetaBatch { LedgerCloseMeta metas<>; };
}
`

// TestWatchEndToEnd runs the watch over local repositories: main with a gated arm, a standing branch adding
// an ungated LedgerCloseMeta arm, another branch that is also a pull request, a pull request with no branch,
// and CAP documents (pending with a diff that applies, pending with one that does not, final).
func TestWatchEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	xdr := filepath.Join(tmp, "stellar-xdr")
	gitT(t, tmp, "init", "--quiet", "-b", "main", xdr)
	gitT(t, xdr, "config", "uploadpack.allowFilter", "true")
	gitT(t, xdr, "config", "uploadpack.allowAnySHA1InWant", "true")
	pinned := commitFile(t, xdr, "Stellar-ledger.x", watchBase, "pinned")
	mainHead := commitFile(t, xdr, "Stellar-ledger.x", strings.Replace(watchBase,
		"case 0: TransactionEnvelope v0;", "case 0: TransactionEnvelope v0;\n#ifdef CAP_0098_LCM\ncase 1: TransactionEnvelope v1;\n#endif\n", 1), "gated v1")
	gitT(t, xdr, "checkout", "--quiet", "-b", "lcm_v3")
	text, _ := os.ReadFile(filepath.Join(xdr, "Stellar-ledger.x"))
	commitFile(t, xdr, "Stellar-ledger.x", strings.Replace(string(text), "#endif", "#endif\ncase 3: TransactionEnvelope v3;\n", 1), "lcm v3")
	gitT(t, xdr, "checkout", "--quiet", "-b", "feature-x", pinned)
	featX := commitFile(t, xdr, "Stellar-ledger.x", strings.Replace(watchBase, "int32 fee;", "int32 fee; int32* tip;", 1), "tip")
	gitT(t, xdr, "checkout", "--quiet", "--detach", mainHead)
	prOnly := commitFile(t, xdr, "Stellar-ledger.x", strings.Replace(string(text), "int32 fee;", "int32 fee; int32 extra;", 1), "pr only")
	gitT(t, xdr, "update-ref", "refs/pull/7/head", prOnly)
	gitT(t, xdr, "update-ref", "refs/pull/8/head", featX)
	gitT(t, xdr, "checkout", "--quiet", "main")

	proto := filepath.Join(tmp, "stellar-protocol")
	gitT(t, tmp, "init", "--quiet", "-b", "master", proto)
	gitT(t, proto, "config", "uploadpack.allowAnySHA1InWant", "true")
	patch := "--- a/Stellar-ledger.x\n+++ b/Stellar-ledger.x\n@@ -2,3 +2,3 @@\n typedef int int32;\n-struct TransactionEnvelope { int32 fee; };\n+struct TransactionEnvelope { int32 fee; int32* memo; };\n union LedgerCloseMeta switch (int v) {\n"
	commitFile(t, proto, "core/cap-0099.md", "## Preamble\n```\nCAP: 0099\nTitle: Memos\nStatus: Draft\nProtocol version: 32\n```\n\n```diff mddiffcheck.base="+pinned+"\n"+patch+"```\n", "cap 99")
	commitFile(t, proto, "core/cap-0051.md", "Title: Stale\nStatus: Draft\nProtocol version: TBD\n\n```diff\n--- a/src/xdr/Stellar-ledger.x\n+++ b/src/xdr/Stellar-ledger.x\n@@ -1,1 +1,1 @@\n-nothing like this\n+x\n```\n", "cap 51")
	commitFile(t, proto, "core/cap-0050.md", "Title: Done\nStatus: Final\nProtocol version: 20\n\n```diff\n"+patch+"```\n", "cap 50")
	commitFile(t, proto, "core/cap-0098.md", "Title: LCM\nStatus: Accepted\nProtocol version: 31\n", "cap 98")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/stellar-xdr/pulls" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `[{"number":7,"title":"Extra","html_url":"https://example.org/pull/7","head":{"sha":%q,"ref":"x"}},
			{"number":8,"title":"Tip","html_url":"https://example.org/pull/8","head":{"sha":%q,"ref":"feature-x"}}]`, prOnly, featX)
	}))
	defer api.Close()

	out := filepath.Join(tmp, "out")
	cfg := func(prev string) *WatchConfig {
		return &WatchConfig{
			XDR:      &Repo{URL: xdr, Dir: filepath.Join(tmp, "cache", "x.git")},
			Protocol: &Repo{URL: proto, Dir: filepath.Join(tmp, "cache", "p.git"), Shallow: true},
			RepoSlug: "o/stellar-xdr", API: api.URL, Pinned: pinned, PinnedLabel: "v1.0", NextProtocol: 31,
			Standing: []string{"lcm_v3", "gone-branch"}, Out: out, Previous: prev,
			Now: time.Date(2026, 11, 14, 3, 17, 0, 0, time.UTC),
		}
	}
	res, err := Watch(cfg(""))
	if err != nil {
		t.Fatal(err)
	}
	items := map[string]*WatchItem{}
	for _, it := range res.Items {
		items[it.Kind+" "+it.Name] = it
		t.Logf("%s %s %s %v %v %s", it.Kind, it.Name, it.Status, it.CAPs, it.NewArms, it.Detail)
	}
	check := func(key, status string, protocol int, arms ...string) *WatchItem {
		it := items[key]
		if it == nil {
			t.Fatalf("no item %s", key)
		}
		if it.Status != status || it.Protocol != protocol || strings.Join(it.NewArms, ",") != strings.Join(arms, ",") {
			t.Errorf("%s: status %s protocol %d arms %v, want %s %d %v", key, it.Status, it.Protocol, it.NewArms, status, protocol, arms)
		}
		return it
	}
	if m := check("main main", "ok", 31, "LedgerCloseMeta::v1"); strings.Join(m.CAPs, ",") != "CAP-0098" {
		t.Errorf("main caps %v", m.CAPs)
	}
	check("cap CAP-0099", "ok", 32, "TransactionEnvelope.memo?none", "TransactionEnvelope.memo?some")
	if c := check("cap CAP-0051", "not-applied", 31); !strings.Contains(c.Detail, "names no base commit") {
		t.Errorf("CAP-0051 detail: %s", c.Detail)
	}
	if _, ok := items["cap CAP-0050"]; ok {
		t.Errorf("a Final CAP's diff is not watched")
	}
	if b := check("branch feature-x", "ok", 31, "TransactionEnvelope.tip?none", "TransactionEnvelope.tip?some"); b.URL != "https://example.org/pull/8" {
		t.Errorf("the pull request of a branch is reported on the branch: %+v", b)
	}
	if _, ok := items["pr #8"]; ok {
		t.Errorf("pull request #8 is the branch feature-x and must not be listed twice")
	}
	check("pr #7", "ok", 31)
	if s := check("standing lcm_v3", "ok", 31, "LedgerCloseMeta::v3"); !strings.Contains(s.Detail, "1 commits ahead of main") {
		t.Errorf("lcm_v3 detail: %q", s.Detail)
	}
	check("standing gone-branch", "gone", 31)
	for _, f := range []string{"digest.md", "digest-p31.md", "digest-p32.md", "caps.json", "items.json", "candidates.txt", "diffs/main-main.json", "diffs/cap-cap-0099.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	d31, _ := os.ReadFile(filepath.Join(out, "digest-p31.md"))
	for _, s := range []string{"# Protocol 31: XDR watch", "**`lcm_v3`** on stellar-xdr: ok: open", "`LedgerCloseMeta::v3`", "## CAP documents whose XDR diff does not apply", "**new**"} {
		if !strings.Contains(string(d31), s) {
			t.Errorf("digest-p31.md lacks %q:\n%s", s, d31)
		}
	}
	cand, _ := os.ReadFile(filepath.Join(out, "candidates.txt"))
	if string(cand) != "diffs/main-main.json\ndiffs/cap-cap-0099.json\n" {
		t.Errorf("candidates.txt: %q", cand)
	}
	// A second run carries the log over; nothing is new.
	prev := filepath.Join(tmp, "prev.jsonl")
	b, _ := os.ReadFile(filepath.Join(out, "watch-log.jsonl"))
	os.WriteFile(prev, b, 0o644)
	res2, err := Watch(cfg(prev))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res2.Items {
		if it.New {
			t.Errorf("%s %s is new on an unchanged second run", it.Kind, it.Name)
		}
	}
	f, _ := os.Open(filepath.Join(out, "watch-log.jsonl"))
	defer f.Close()
	n := 0
	for sc := bufio.NewScanner(f); sc.Scan(); n++ {
		var it WatchItem
		if err := json.Unmarshal(sc.Bytes(), &it); err != nil {
			t.Fatal(err)
		}
	}
	if n != len(res.Items)+len(res2.Items) {
		t.Errorf("log has %d lines, want %d", n, len(res.Items)+len(res2.Items))
	}
}

func TestCAPDocumentParsing(t *testing.T) {
	doc := "```\nTitle: X\nStatus: Awaiting Decision\nProtocol version: 31\n```\n```diff mddiffcheck.base=4f524bbac80c781c06e4fb5fc93a2d0d331d6705\ndiff --git a/Stellar-types.x b/Stellar-types.x\n--- a/Stellar-types.x\n+++ b/Stellar-types.x\n```\n```diff\n--- a/README.md\n+++ b/README.md\n```\n"
	if c := ParseCAPPreamble(doc); c.Title != "X" || c.Status != "Awaiting Decision" || c.Protocol != "31" {
		t.Errorf("preamble %+v", c)
	}
	p, b := CAPXDRPatches(doc)
	if len(p) != 1 || b[0] != "4f524bbac80c781c06e4fb5fc93a2d0d331d6705" {
		t.Errorf("patches %d bases %v", len(p), b)
	}
	got := normalizePatchPaths("diff --git a/src/protocol-curr/xdr/Stellar-ledger.x b/src/protocol-curr/xdr/Stellar-ledger.x\n--- a/src/xdr/A.x\n+++ b/xdr/A.x\n context a/src/xdr/kept")
	want := "diff --git a/Stellar-ledger.x b/Stellar-ledger.x\n--- a/A.x\n+++ b/A.x\n context a/src/xdr/kept"
	if got != want {
		t.Errorf("normalizePatchPaths:\n%s", got)
	}
}
