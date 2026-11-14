package stellaretl

// The service rig: the stellar-etl CLI at one commit, every export command it has, over a list of ledgers
// served from a lake-layout directory through the GCS emulator, with the rows mapped to the common schema and
// each requested ledger checked for silent drops.
//
// Ranges: each contiguous segment is exported as one range. A one-ledger segment N is exported as N..N+1
// (N+1 read from the lake, or fetched), because `export_ledger_entry_changes -s N -e N` writes nothing; rows of
// ledgers outside the request are dropped from the common rows and counted as context.
//
// The commands come from the binary's own help (`export_*`), so a commit that adds one is run without a code
// change here. Flags are each command's defaults, apart from the range, output and datastore; at the pinned
// release that means strict export (a transform error is fatal) and every entry type.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

// RigOptions configure one stellar-etl rig shard.
type RigOptions struct {
	CacheDir        string // adapter cache root (holds stellar-etl/repo.git and built binaries)
	Commit          string
	Passphrase      string
	Lake            *rig.Lake
	Segments        []rig.Segment
	Shard           int
	Out             string
	ExportMemoryMax int64
	CommandDeadline time.Duration // per export command; 0: 120 s + 2 s per ledger
	Log             io.Writer
}

// RigReport is what a shard reports besides its files.
type RigReport struct {
	Commit        string         `json:"commit"`
	Binary        string         `json:"binary_sha256"`
	Commands      []string       `json:"commands"`
	Status        map[string]int `json:"status"`
	RowsByExport  map[string]int `json:"rows_by_export"`
	ContextRows   int            `json:"context_rows"`
	Rows          int            `json:"rows"`
	Drops         int            `json:"drop_checks_failed"`
	Failures      map[string]int `json:"failed_commands"`
	TransformErrs int            `json:"failed_transforms"`
	WallMS        int64          `json:"wall_ms"`
	HarnessFaults []string       `json:"harness_faults"`
}

var commandRe = regexp.MustCompile(`(?m)^\s+(export_[a-z_]+)\s`)

// RunRig runs one shard.
func RunRig(ctx context.Context, o RigOptions) (*RigReport, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	rep := &RigReport{Status: map[string]int{}, RowsByExport: map[string]int{}, Failures: map[string]int{}, HarnessFaults: []string{}}
	// Every export runs with its working directory in the segment folder, so a relative output path would put the
	// files where readRows never looks (all exports exit 0 and the run reads 0 rows).
	if abs, err := filepath.Abs(o.Out); err == nil {
		o.Out = abs
	} else {
		return nil, err
	}
	start := time.Now()
	c := &cache{dir: filepath.Join(o.CacheDir, "stellar-etl")}
	c.repo = filepath.Join(c.dir, "repo.git")
	if err := c.ensureRepo(ctx); err != nil {
		return nil, err
	}
	commit, err := c.resolve(ctx, o.Commit)
	if err != nil {
		return nil, err
	}
	rep.Commit = commit
	b, err := c.build(ctx, commit, o.Log)
	if err != nil {
		return nil, err
	}
	rep.Binary = b.sha256
	help, _ := exec.CommandContext(ctx, b.binary, "--help").CombinedOutput()
	for _, m := range commandRe.FindAllStringSubmatch(string(help), -1) {
		if !slices.Contains(rep.Commands, m[1]) {
			rep.Commands = append(rep.Commands, m[1])
		}
	}
	if len(rep.Commands) == 0 {
		return nil, fmt.Errorf("stellar-etl %s lists no export command in --help", commit[:12])
	}
	nw, ok := networks[o.Passphrase]
	if !ok {
		return nil, fmt.Errorf("stellar-etl knows only pubnet, testnet and futurenet")
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	status, err := rig.CreateJSONL(filepath.Join(o.Out, "status.jsonl"))
	if err != nil {
		return nil, err
	}
	defer status.Close()
	rows, err := rig.CreateJSONL(filepath.Join(o.Out, "rows.jsonl"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks, err := rig.CreateJSONL(filepath.Join(o.Out, "checks.jsonl"))
	if err != nil {
		return nil, err
	}
	defer checks.Close()
	w := &etlRun{o: o, rep: rep, bin: b.binary, commit: commit, nw: nw, status: status, rows: rows, checks: checks}
	for i, seg := range o.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := w.segment(ctx, i, seg); err != nil {
			rep.HarnessFaults = append(rep.HarnessFaults, fmt.Sprintf("segment %s: %v", seg, err))
			for q := seg.First; ; q++ {
				w.put(rig.Status{Ledger: q, Status: rig.StatusHarnessFault, Segment: seg.String(), Error: err.Error()})
				if q == seg.Last {
					break
				}
			}
		}
	}
	rep.Rows = rows.Count()
	rep.WallMS = time.Since(start).Milliseconds()
	return rep, nil
}

type etlRun struct {
	o      RigOptions
	rep    *RigReport
	bin    string
	commit string
	nw     struct{ flag, suffix string }
	status *rig.JSONL
	rows   *rig.JSONL
	checks *rig.JSONL
}

// StatusDropped marks a requested ledger whose exports all ended cleanly but at least one drop check failed: the
// ledger holds a transaction, operation, event or entry change that an export that should contain it lacks.
const StatusDropped = "dropped"

// etlStatus is a ledger's status line with the names of its failed drop checks.
type etlStatus struct {
	rig.Status
	DropChecksFailed []string `json:"drop_checks_failed,omitempty"`
}

func (w *etlRun) put(st rig.Status) { w.putETL(etlStatus{Status: st}) }

func (w *etlRun) putETL(st etlStatus) {
	st.Shard = w.o.Shard
	w.rep.Status[st.Status.Status]++
	w.status.Write(st)
}

var (
	transformStatsRe = regexp.MustCompile(`failed_transforms\\?"?\s*[:=]\s*(\d+)`)
	successStatsRe   = regexp.MustCompile(`successful_transforms\\?"?\s*[:=]\s*(\d+)`)
	failedLedgerRe   = regexp.MustCompile(`ledger (\d{2,10})`)
)

type cmdResult struct {
	exit    string
	ok      bool
	errText string
	failed  int // failed transforms reported by the command
	success int // successful transforms reported by the command
	wallMS  int64
}

func (w *etlRun) segment(ctx context.Context, idx int, seg rig.Segment) error {
	from, to := seg.First, seg.Last
	if to == from {
		to = from + 1 // a one-ledger range exports no ledger entry changes
	}
	work := filepath.Join(w.o.Out, "segments", fmt.Sprintf("%04d-%s", idx, seg))
	view := filepath.Join(work, "lake")
	var seqs []uint32
	for q := from; q <= to; q++ {
		seqs = append(seqs, q)
	}
	if err := w.o.Lake.View(ctx, view, seqs); err != nil {
		return err
	}
	// Expectations from the ledgers themselves.
	want := map[uint32]*rig.LedgerInfo{}
	for q := seg.First; q <= seg.Last; q++ {
		lcm, err := w.o.Lake.Load(ctx, q)
		if err != nil {
			return err
		}
		info, err := rig.Analyze(w.o.Passphrase, lcm)
		if err != nil {
			return err
		}
		want[q] = info
	}
	emu, err := startEmulator(view, w.nw.suffix, "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("GCS emulator: %w", err)
	}
	defer emu.close()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + work, "STORAGE_EMULATOR_HOST=" + emu.host}
	deadline := w.o.CommandDeadline
	if deadline == 0 {
		deadline = 120*time.Second + time.Duration(len(seqs))*2*time.Second
	}
	results := map[string]cmdResult{}
	outs := filepath.Join(work, "out")
	for _, cmd := range w.rep.Commands {
		dir := filepath.Join(outs, cmd)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		logPath := filepath.Join(work, "logs", cmd+".log")
		os.MkdirAll(filepath.Dir(logPath), 0o755)
		logf, err := os.Create(logPath)
		if err != nil {
			return err
		}
		args := []string{cmd, "-s", strconv.FormatUint(uint64(from), 10), "-e", strconv.FormatUint(uint64(to), 10),
			"-o", dir + string(filepath.Separator), "--datastore-path", datastoreArg}
		if w.nw.flag != "" {
			args = append(args, w.nw.flag)
		}
		fmt.Fprintf(logf, "$ stellar-etl %s\n", strings.Join(args, " "))
		res, err := proc.Run(ctx, proc.Spec{Path: w.bin, Args: args, Env: env, Dir: work, Stdout: logf, Stderr: logf,
			Name: "stellar-etl", Limits: proc.Limits{Deadline: deadline, MemoryMax: w.o.ExportMemoryMax}, Grace: time.Second, TailBytes: 8 << 10})
		logf.Close()
		if err != nil {
			return fmt.Errorf("start stellar-etl: %w", err)
		}
		text, _ := os.ReadFile(logPath)
		r := cmdResult{wallMS: res.Wall.Milliseconds(), exit: "exit " + strconv.Itoa(res.ExitCode)}
		switch {
		case res.TimedOut:
			r.exit = "timeout"
		case res.Signal != 0:
			r.exit = "signal " + signalName(res.Signal)
		}
		r.ok = !res.TimedOut && res.Signal == 0 && res.ExitCode == 0
		for _, m := range transformStatsRe.FindAllStringSubmatch(string(text), -1) {
			n, _ := strconv.Atoi(m[1])
			r.failed += n
		}
		for _, m := range successStatsRe.FindAllStringSubmatch(string(text), -1) {
			n, _ := strconv.Atoi(m[1])
			r.success += n
		}
		w.rep.TransformErrs += r.failed
		if !r.ok || r.failed > 0 {
			r.errText = errorLines(string(text))
			w.rep.Failures[cmd]++
		}
		results[cmd] = r
	}
	// Rows, by ledger.
	got := w.readRows(outs, seg)
	// A command that reports successful transforms but left no output file where the rig reads is a harness fault
	// (output written elsewhere), never a clean empty export. (A transform can yield no row, e.g. a transaction
	// without effects, so the test is on files, not rows.)
	var lost []string
	for _, cmd := range w.rep.Commands {
		r := results[cmd]
		if r.ok && r.success > 0 && got.files[cmd] == 0 {
			lost = append(lost, fmt.Sprintf("%s reported %d successful transforms but wrote no file in %s", cmd, r.success, filepath.Join(outs, cmd)))
		}
	}
	if len(lost) > 0 {
		return fmt.Errorf("%s", strings.Join(lost, "; "))
	}
	// Checks and statuses.
	for q := seg.First; q <= seg.Last; q++ {
		st := rig.Status{Ledger: q, Status: rig.StatusIngested, Segment: seg.String(), Exports: map[string]string{}}
		var errs []string
		for _, cmd := range w.rep.Commands {
			r := results[cmd]
			outcome := r.exit
			if r.failed > 0 {
				outcome += fmt.Sprintf(", %d failed transforms", r.failed)
			}
			if !r.ok {
				// Which ledger did it stop on? The highest ledger it wrote rows for is a lower bound.
				if got.maxLedger[cmd] >= q && got.byLedger[cmd][q] > 0 {
					outcome += " (rows present for this ledger)"
				} else {
					st.Status = rig.StatusHalted
					errs = append(errs, cmd+": "+r.errText)
				}
			}
			st.Exports[cmd] = fmt.Sprintf("%s; %d rows", outcome, got.byLedger[cmd][q])
		}
		if st.Status == rig.StatusHalted {
			st.Error = strings.Join(errs, "\n")
			if m := failedLedgerRe.FindAllStringSubmatch(st.Error, -1); len(m) > 0 {
				if n, err := strconv.ParseUint(m[len(m)-1][1], 10, 32); err == nil {
					v := uint32(n)
					st.ErrorLedger = &v
				}
			}
		}
		es := etlStatus{Status: st}
		for _, c := range w.dropChecks(want[q], got, results) {
			w.checks.Write(c)
			if c["ok"] == false {
				w.rep.Drops++
				es.DropChecksFailed = append(es.DropChecksFailed, fmt.Sprint(c["check"], "/", c["export"]))
			}
		}
		if len(es.DropChecksFailed) > 0 && es.Status.Status == rig.StatusIngested {
			es.Status.Status = StatusDropped
		}
		w.putETL(es)
	}
	return nil
}

func errorLines(text string) string {
	var keep []string
	for _, l := range strings.Split(text, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "level=error") || strings.Contains(ll, "level=fatal") || strings.HasPrefix(l, "panic:") ||
			strings.Contains(ll, "error") && !strings.Contains(ll, "failed_transforms") {
			keep = append(keep, strings.TrimSpace(l))
		}
	}
	if len(keep) > 6 {
		keep = keep[len(keep)-6:]
	}
	s := strings.Join(keep, "\n")
	if len(s) > 3000 {
		s = s[len(s)-3000:]
	}
	return s
}

// rowsGot are the export rows of one segment, counted and keyed for the drop checks.
type rowsGot struct {
	byLedger  map[string]map[uint32]int
	files     map[string]int // output files per export
	maxLedger map[string]uint32
	txHashes  map[string]map[uint32]map[string]bool // export → ledger → tx hash
	opsPerTx  map[uint32]map[int]int                // export_operations: ledger → tx index → ops
	keyHashes map[uint32]map[string]map[string]bool // entry changes: ledger → entry type → key hash
	typeRows  map[uint32]map[string]int             // entry changes: ledger → entry type → rows
}

// entry-change export file suffix → entry type name of rig.EntryTypeName.
var entryFiles = map[string]string{"accounts": "account", "trustlines": "trustline", "offers": "offer", "liquidity_pools": "liquidity_pool",
	"claimable_balances": "claimable_balance", "contract_data": "contract_data", "contract_code": "contract_code",
	"config_settings": "config_setting", "ttl": "ttl", "restored_key": "restored_key", "restored_keys": "restored_key", "signers": "account_signer"}

func entryTypeOfFile(name string) string {
	base := strings.TrimSuffix(filepath.Base(name), ".txt")
	best := ""
	for suf := range entryFiles {
		if strings.HasSuffix(base, suf) && len(suf) > len(best) {
			best = suf
		}
	}
	if best == "" {
		return base
	}
	return entryFiles[best]
}

func (w *etlRun) readRows(outs string, seg rig.Segment) *rowsGot {
	g := &rowsGot{byLedger: map[string]map[uint32]int{}, files: map[string]int{}, maxLedger: map[string]uint32{}, txHashes: map[string]map[uint32]map[string]bool{},
		opsPerTx: map[uint32]map[int]int{}, keyHashes: map[uint32]map[string]map[string]bool{}, typeRows: map[uint32]map[string]int{}}
	// Effects are mapped after the segment's operations are read (an effect's reading depends on its operation).
	ops := opContext{}
	type effectRow struct {
		r map[string]any
		l uint32
	}
	var effects []effectRow
	clawedCB := map[opKey]string{}
	for _, cmd := range w.rep.Commands {
		g.byLedger[cmd] = map[uint32]int{}
		g.txHashes[cmd] = map[uint32]map[string]bool{}
		var files []string
		filepath.WalkDir(filepath.Join(outs, cmd), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		g.files[cmd] = len(files)
		for _, f := range files {
			etype := ""
			if cmd == "export_ledger_entry_changes" {
				etype = entryTypeOfFile(f)
			}
			fh, err := os.Open(f)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 1<<20), 512<<20)
			for sc.Scan() {
				dec := json.NewDecoder(strings.NewReader(sc.Text()))
				dec.UseNumber()
				var r map[string]any
				if dec.Decode(&r) != nil {
					continue
				}
				l := ledgerOf(cmd, r)
				g.byLedger[cmd][l]++
				w.rep.RowsByExport[cmd]++
				if l > g.maxLedger[cmd] {
					g.maxLedger[cmd] = l
				}
				if h := str(r["transaction_hash"]); h != "" {
					if g.txHashes[cmd][l] == nil {
						g.txHashes[cmd][l] = map[string]bool{}
					}
					g.txHashes[cmd][l][h] = true
				}
				if cmd == "export_operations" {
					_, tx, _ := toid(num(r["id"]))
					if g.opsPerTx[l] == nil {
						g.opsPerTx[l] = map[int]int{}
					}
					g.opsPerTx[l][tx]++
				}
				if etype != "" {
					if g.typeRows[l] == nil {
						g.typeRows[l] = map[string]int{}
						g.keyHashes[l] = map[string]map[string]bool{}
					}
					g.typeRows[l][etype]++
					if kh := entryKeyHash(etype, r); kh != "" {
						if g.keyHashes[l][etype] == nil {
							g.keyHashes[l][etype] = map[string]bool{}
						}
						g.keyHashes[l][etype][kh] = true
					}
				}
				if l < seg.First || l > seg.Last {
					w.rep.ContextRows++
					continue
				}
				switch cmd {
				case "export_operations":
					ops.add(r, l)
					for _, row := range w.opTokenEvents(r, l) {
						w.rows.Write(row)
					}
				case "export_effects":
					effects = append(effects, effectRow{r, l})
					if str(r["type_string"]) == "claimable_balance_clawed_back" {
						if d, ok := r["details"].(map[string]any); ok {
							_, tx, op := toid(num(r["operation_id"]))
							clawedCB[opKey{l, tx, op}] = cbStrkey(str(d["balance_id"]))
						}
					}
				}
				for _, row := range w.mapRow(cmd, etype, r, l) {
					w.rows.Write(row)
				}
			}
			fh.Close()
		}
	}
	for _, e := range effects {
		for _, row := range w.effectRows(e.r, e.l, ops, clawedCB) {
			w.rows.Write(row)
		}
	}
	return g
}

// dropChecks compares one requested ledger's exports with what the ledger holds.
func (w *etlRun) dropChecks(info *rig.LedgerInfo, g *rowsGot, results map[string]cmdResult) []map[string]any {
	if info == nil {
		return nil
	}
	q := info.Seq
	var out []map[string]any
	add := func(check, cmd string, ok bool, detail map[string]any) {
		if !results[cmd].ok && !ok {
			detail["command_failed"] = results[cmd].exit
		}
		c := map[string]any{"kind": "drop_check", "ledger": q, "check": check, "export": cmd, "ok": ok}
		for k, v := range detail {
			c[k] = v
		}
		out = append(out, c)
	}
	has := func(cmd string) bool { return slices.Contains(w.rep.Commands, cmd) }
	if has("export_ledgers") {
		add("ledger_present", "export_ledgers", g.byLedger["export_ledgers"][q] == 1, map[string]any{"rows": g.byLedger["export_ledgers"][q]})
	}
	for _, cmd := range []string{"export_transactions", "export_ledger_transaction"} {
		if !has(cmd) {
			continue
		}
		var missing []string
		for _, t := range info.Txs {
			if cmd == "export_transactions" && !g.txHashes[cmd][q][t.Hash] {
				missing = append(missing, fmt.Sprintf("%d:%d", q, t.Index))
			}
		}
		n := g.byLedger[cmd][q]
		add("every_transaction", cmd, len(missing) == 0 && n == len(info.Txs), map[string]any{"want": len(info.Txs), "rows": n, "missing": missing})
	}
	if has("export_operations") {
		var short []string
		want := 0
		for _, t := range info.Txs {
			want += t.Ops
			if got := g.opsPerTx[q][t.Index]; got != t.Ops {
				short = append(short, fmt.Sprintf("%d:%d want %d got %d", q, t.Index, t.Ops, got))
			}
		}
		add("every_operation", "export_operations", len(short) == 0, map[string]any{"want": want, "rows": g.byLedger["export_operations"][q], "mismatch": short})
	}
	if has("export_token_transfer") && info.Protocol >= 23 {
		// Every transaction pays a fee, and the token-transfer processor emits a fee event for each.
		var missing []string
		for _, t := range info.Txs {
			if !g.txHashes["export_token_transfer"][q][t.Hash] {
				missing = append(missing, fmt.Sprintf("%d:%d", q, t.Index))
			}
		}
		add("fee_transfer_per_transaction", "export_token_transfer", len(missing) == 0, map[string]any{"want": len(info.Txs), "missing": missing})
	}
	if has("export_contract_events") {
		n := g.byLedger["export_contract_events"][q]
		add("contract_events_at_least_meta_events", "export_contract_events", n >= info.Events, map[string]any{"meta_events": info.Events, "rows": n})
	}
	if has("export_ledger_entry_changes") {
		for typ, keys := range info.Changes {
			if typ == "data" {
				continue // stellar-etl does not track data entries (by design)
			}
			wantKeys := 0
			var missing []string
			for k, kinds := range keys {
				if slices.Contains(kinds, "created") && slices.Contains(kinds, "removed") {
					continue // compacted away within the ledger
				}
				if typ == "contract_data" && isNonceKey(k) {
					continue // stellar-etl discards nonce entries (by design: contract_data.go, ScvLedgerKeyNonce)
				}
				wantKeys++
				if typ == "contract_data" || typ == "contract_code" || typ == "account" {
					if !g.keyHashes[q][typ][keyHash(typ, k)] {
						if len(missing) < 20 {
							missing = append(missing, k)
						}
					}
				}
			}
			rows := g.typeRows[q][typ]
			add("entry_changes_"+typ, "export_ledger_entry_changes", rows >= wantKeys && len(missing) == 0,
				map[string]any{"want_keys": wantKeys, "rows": rows, "missing_keys": missing})
		}
	}
	return out
}

// isNonceKey reports whether a base64 LedgerKey is a contract-data key whose key value is a ledger-key nonce.
func isNonceKey(keyB64 string) bool {
	var k xdr.LedgerKey
	if err := xdr.SafeUnmarshalBase64(keyB64, &k); err != nil || k.ContractData == nil {
		return false
	}
	return k.ContractData.Key.Type == xdr.ScValTypeScvLedgerKeyNonce
}

// keyHash is the comparison key of a changed entry: stellar-etl's ledger_key_hash (hex SHA-256 of the key XDR)
// for contract entries, the account strkey for accounts.
func keyHash(typ, keyB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return ""
	}
	if typ == "account" {
		return accountOfKey(raw)
	}
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func entryKeyHash(typ string, r map[string]any) string {
	switch typ {
	case "contract_data", "contract_code":
		return str(r["ledger_key_hash"])
	case "account":
		return str(r["account_id"])
	}
	return ""
}

func ledgerOf(cmd string, r map[string]any) uint32 {
	for _, k := range []string{"ledger_sequence", "sequence", "ledger_seq"} {
		if v, ok := r[k]; ok {
			return uint32(num(v))
		}
	}
	if cmd == "export_assets" || cmd == "export_trades" {
		if id := num(r["history_operation_id"]); id > 0 {
			l, _, _ := toid(id)
			return l
		}
	}
	return 0
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func num(v any) int64 {
	switch x := v.(type) {
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			f, _ := x.Float64()
			return int64(f)
		}
		return i
	case string:
		i, _ := strconv.ParseInt(x, 10, 64)
		return i
	}
	return 0
}

func toid(id int64) (ledger uint32, tx int, op int) {
	return uint32(id >> 32), int((id>>12)&0xFFFFF) - 1, int(id&0xFFF) - 1
}
