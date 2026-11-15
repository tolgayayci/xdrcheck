package targets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

// Pipeline targets run through two tools:
//
//	rig    `<tool> replay --rig <target>` of this binary (the service rigs), or the command in
//	       <TOOL>_RIG_<TARGET> (for example XDRCHECK_RIG_WALLET_BACKEND). Called as:
//	         RIG --ledgers @LIST --commit V --lake LAKE --network P --fetch none --out DIR
//	       It builds the pipeline at V (cached), ingests the listed ledgers (ascending) from the lake-layout
//	       directory into one database, and writes DIR/rows.jsonl in the judge's common row schema (and
//	       DIR/status.jsonl: ingested, halted, skipped or harness_fault per ledger). Exit 0 every ledger was
//	       ingested, 1 a ledger halted or was skipped (rows are still judged), 2 a harness fault.
//	       The per-ledger statuses reach the run (Result.LedgerStatus): a run with a ledger that was not
//	       ingested is partial (its rows are still judged); one with no status.jsonl, or with every ledger
//	       ingested and an empty rows.jsonl, fails.
//	judge  <TOOL>_JUDGE, else "xdrcheck-judge" on PATH.
//	       Called as: JUDGE facts --root LAKE --list LIST --network P -o FACTS.jsonl
//	       and:       JUDGE verdict --facts FACTS.jsonl --rows ROWS.jsonl -o VERDICTS.jsonl
//	       One verdict per line: ledger, tx_index, tx_hash, verdict, kind, class, evidence.
//
// When either tool is missing the target is not available and the run says so; nothing is guessed.
type pipeTarget struct{ name string }

func envKey(target string) string { return strings.ToUpper(strings.ReplaceAll(target, "-", "_")) }

func findTool(env, fallback, hint string) ([]string, error) {
	if v := hunt.Env(env); v != "" {
		return strings.Fields(v), nil
	}
	if p, err := exec.LookPath(fallback); err == nil {
		return []string{p}, nil
	}
	return nil, hunt.Missing(fallback, hint)
}

// rig returns the rig command: the environment override, else this binary's `replay --rig <target>` when it
// has the service rigs (a binary without them answers that --rig is not a flag).
func (p pipeTarget) rig() ([]string, error) {
	if v := hunt.Env("RIG_" + envKey(p.name)); v != "" {
		return strings.Fields(v), nil
	}
	self, err := os.Executable()
	// only the tool itself is asked (never a test binary, which would run its tests)
	if base := strings.TrimSuffix(filepath.Base(self), ".exe"); err == nil && base == hunt.Tool {
		out, _ := exec.Command(self, "replay", "--rig", p.name, "--help").CombinedOutput()
		if !strings.Contains(string(out), "flag provided but not defined: -rig") && strings.Contains(string(out), "-commit") {
			return []string{self, "replay", "--rig", p.name}, nil
		}
	}
	return nil, hunt.Missing(hunt.Tool+" replay --rig "+p.name+" (service rigs)", "build "+hunt.Tool+" with the service rigs, or set "+hunt.EnvName("RIG_"+envKey(p.name)))
}

// Judge returns the judge's command line.
func Judge() ([]string, error) {
	return findTool("JUDGE", "xdrcheck-judge", "set "+hunt.EnvName("JUDGE")+" or put xdrcheck-judge on PATH")
}

func (p pipeTarget) Build(ctx context.Context, o Options) (*Built, error) {
	r, err := p.rig()
	if err != nil {
		return nil, err
	}
	if _, err := Judge(); err != nil {
		return nil, err
	}
	// the rig builds and caches the pipeline itself, at run time
	return &Built{Target: p.name, Resolved: o.Version, Source: strings.Join(r, " "), run: r}, nil
}

// LinkLake makes a lake-layout directory under dir with one link per input at its lake key, and an index.tsv,
// so that a tool that takes one root sees every input wherever it lives.
func LinkLake(dir, passphrase string, inputs []Input) error {
	cfg := lake.NewConfig(passphrase)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(dir, lake.ConfigFile), cfg.Bytes(), 0o644)
	var idx strings.Builder
	idx.WriteString("seq\tpath\tsize\n")
	for _, in := range inputs {
		key := cfg.ObjectKey(in.Seq)
		dst := filepath.Join(dir, key)
		os.MkdirAll(filepath.Dir(dst), 0o755)
		abs, _ := filepath.Abs(in.Path)
		os.Remove(dst)
		if err := os.Symlink(abs, dst); err != nil {
			return err
		}
		st, _ := os.Stat(abs)
		var n int64
		if st != nil {
			n = st.Size()
		}
		fmt.Fprintf(&idx, "%d\t%s\t%d\n", in.Seq, key, n)
	}
	return os.WriteFile(filepath.Join(dir, "index.tsv"), []byte(idx.String()), 0o644)
}

func (p pipeTarget) Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error) {
	judge, err := Judge()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(work, "lake")
	if err := LinkLake(root, o.Passphrase, inputs); err != nil {
		return nil, err
	}
	var list strings.Builder
	for _, in := range inputs {
		fmt.Fprintf(&list, "%d\n", in.Seq)
	}
	listPath := filepath.Join(work, "ledgers.txt")
	os.WriteFile(listPath, []byte(list.String()), 0o644)
	rigOut := filepath.Join(work, "rig")
	rows := filepath.Join(rigOut, "rows.jsonl")
	log, _ := os.Create(filepath.Join(work, "rig.log"))
	defer log.Close()
	cmd := exec.CommandContext(ctx, b.run[0], append(append(b.run[1:], "--ledgers", "@"+listPath, "--commit", o.Version, "--lake", root,
		"--network", o.Passphrase, "--fetch", "none", "--out", rigOut), o.RigArgs...)...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return nil, fmt.Errorf("%s rig: %v (log: %s)", p.name, err, filepath.Join(work, "rig.log"))
		}
		// exit 1: a ledger halted or was skipped; its rows are judged like any other
	}
	if _, err := os.Stat(rows); err != nil {
		return nil, fmt.Errorf("%s rig wrote no rows.jsonl (log: %s)", p.name, filepath.Join(work, "rig.log"))
	}
	status, err := ReadRigStatus(filepath.Join(rigOut, "status.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("%s rig: %v (log: %s)", p.name, err, filepath.Join(work, "rig.log"))
	}
	// Rows are judged even when ledgers halted (the judge turns a halt into a row, so a known halt stays
	// visible to clusters and run comparison); only a rig that ingested every ledger and wrote no row fails.
	if empty, err := emptyJSONL(rows); err != nil {
		return nil, err
	} else if empty && NotIngested(status) == 0 {
		return nil, fmt.Errorf("%s rig wrote an empty rows.jsonl for %d ingested ledgers (log: %s)", p.name, status[rig.StatusIngested], filepath.Join(work, "rig.log"))
	}
	facts := filepath.Join(work, "facts.jsonl")
	fargs := append(judge[1:], "facts", "--root", root, "--list", listPath, "--network", o.Passphrase, "-o", facts)
	if o.JudgeJobs > 0 {
		fargs = append(fargs, "-j", fmt.Sprint(o.JudgeJobs))
	}
	if err := run(ctx, work, nil, log, judge[0], fargs...); err != nil {
		return nil, err
	}
	jv := filepath.Join(work, "judge-verdicts.jsonl")
	vargs := append(judge[1:], "verdict", "--facts", facts, "--rows", rows, "-o", jv)
	if o.Scope != "" {
		vargs = append(vargs, "--scope", o.Scope)
	}
	if err := run(ctx, work, nil, log, judge[0], vargs...); err != nil {
		return nil, err
	}
	res, err := ReadJudgeVerdicts(jv, len(inputs))
	if err != nil {
		return nil, err
	}
	res.LedgerStatus = status
	return res, nil
}

// ReadRigStatus counts the rig's per-ledger statuses (status.jsonl: one line per requested ledger).
func ReadRigStatus(path string) (map[string]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no per-ledger status: %v", err)
	}
	counts := map[string]int{}
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var st struct {
			Status string `json:"status"`
		}
		if err := dec.Decode(&st); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		if st.Status == "" {
			return nil, fmt.Errorf("%s: a line without a status", path)
		}
		counts[st.Status]++
	}
	if len(counts) == 0 {
		return nil, fmt.Errorf("%s holds no ledger", path)
	}
	return counts, nil
}

// NotIngested is the number of ledgers in counts whose status is anything but ingested.
func NotIngested(counts map[string]int) int {
	n := 0
	for k, v := range counts {
		if k != rig.StatusIngested {
			n += v
		}
	}
	return n
}

// StatusText lists the statuses of counts, for example "2 ingested, 1 halted".
func StatusText(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}

// emptyJSONL reports whether a JSON-lines file has no non-blank line.
func emptyJSONL(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return len(bytes.TrimSpace(b)) == 0, nil
}

// judgeVerdict is one line of the judge's verdict output.
type judgeVerdict struct {
	Ledger   uint32          `json:"ledger"`
	TxIndex  *int            `json:"tx_index"`
	TxHash   string          `json:"tx_hash"`
	Verdict  string          `json:"verdict"`
	Kind     string          `json:"kind"`
	Class    string          `json:"class"`
	Evidence json.RawMessage `json:"evidence"`
}

// ReadJudgeVerdicts converts the judge's verdicts: check = "judge-" + kind; ok rows are counted, not kept;
// unknown (the truth is incomplete) becomes verdict error; missing, extra, wrong_value, duplicate, skip and
// halt become fail.
func ReadJudgeVerdicts(path string, ledgers int) (*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res := &Result{Tested: map[string]int64{}, Ledgers: ledgers}
	txs := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var j judgeVerdict
		if err := dec.Decode(&j); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		kind := j.Kind
		if kind == "" {
			kind = "ledger"
		}
		check := "judge-" + strings.ReplaceAll(strings.ToLower(kind), "_", "-")
		res.Tested[check]++
		if j.TxIndex != nil {
			txs[fmt.Sprintf("%d:%d", j.Ledger, *j.TxIndex)] = true
		}
		switch strings.ToLower(j.Verdict) {
		case "pass", "ok", "agree", "match":
			continue
		case "out_of_scope": // the scope file names this class as by design: counted, not a row
			res.Tested["judge-out-of-scope"]++
			continue
		}
		verdict := "fail"
		if strings.ToLower(j.Verdict) == "unknown" {
			verdict = "error" // the judge's truth is incomplete for this holder and asset: not a defect
		}
		v := rundir.Verdict{Ledger: j.Ledger, Tx: j.TxIndex, Check: check, Class: j.Class, Verdict: verdict}
		if len(j.TxHash) == 64 {
			v.TxHash = j.TxHash
		}
		if v.Class == "" {
			v.Class = j.Verdict
		}
		v.Evidence = map[string]any{"judge_verdict": j.Verdict}
		if len(j.Evidence) > 0 && string(j.Evidence) != "null" {
			var e any
			json.Unmarshal(j.Evidence, &e)
			v.Evidence["judge"] = e
		}
		res.Rows = append(res.Rows, v)
	}
	res.Txs = int64(len(txs))
	return res, nil
}
