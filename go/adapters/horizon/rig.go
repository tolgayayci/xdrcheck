package horizon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

//go:embed dump.sql
var dumpSQL string

// PubnetPassphrase is the default network passphrase.
const PubnetPassphrase = "Public Global Stellar Network ; September 2015"

// Config of one rig run.
type Config struct {
	Lake       string   // lake directory (SEP-54 layout), mounted read-only
	Ledgers    []uint32 // requested ledgers
	Binary     string   // stellar-horizon binary (static; run inside Image)
	Version    string   // what Binary is (tag or commit), recorded in the manifest
	Commit     string   // full commit of Binary when known
	Out        string   // run directory (created; must not hold a previous run)
	Shards     int      // parallel databases and workers
	GroupMode  string   // single | contiguous
	MaxGroup   int      // max ledgers per contiguous group
	Passphrase string   // network passphrase (custom route: --network-passphrase + an unused archive URL)
	Timeout    time.Duration
	PGImage    string
	HZImage    string
	PGMemory   string
	HZMemory   string
	Name       string // container name prefix
	Keep       bool   // keep containers after the run
	NoRows     bool   // skip the common-row export
}

// LedgerStatus is one line of status.jsonl.
type LedgerStatus struct {
	Ledger      uint32  `json:"ledger"`
	Status      string  `json:"status"` // ingested | halted | skipped | harness_fault
	Segment     string  `json:"segment,omitempty"`
	Shard       int     `json:"shard"`
	Error       string  `json:"error,omitempty"`
	ErrorLedger *uint32 `json:"error_ledger,omitempty"` // the ledger a halt is attributed to (a lone rerun fails on it)
	StoppedAt   *uint32 `json:"stopped_at,omitempty"`   // last ledger Horizon's backend returned before its segment halted
	Reason      string  `json:"reason,omitempty"`
	Attempt     string  `json:"attempt,omitempty"` // segment | probe (rerun alone after its segment halted)
	WallS       float64 `json:"wall_s,omitempty"`
	Log         string  `json:"log,omitempty"`
}

// Summary is summary.json.
type Summary struct {
	Requested      int            `json:"requested"`
	Status         map[string]int `json:"status"`
	HarnessFaults  []string       `json:"harness_faults"`
	Shards         int            `json:"shards"`
	Segments       int            `json:"segments"`
	SetupS         float64        `json:"setup_s"`
	IngestS        float64        `json:"ingest_s"`
	ExportS        float64        `json:"export_s"`
	WallS          float64        `json:"wall_s"`
	IngestSPerLdg  float64        `json:"ingest_s_per_ledger"`
	WallSPerLedger float64        `json:"wall_s_per_ledger"`
	CPUSPerLedger  float64        `json:"horizon_exec_s_per_ledger"`
	RawRows        map[string]int `json:"raw_rows"`
	Rows           map[string]int `json:"rows"`
}

var stateErrRe = regexp.MustCompile(`level=error msg="Error in ingestion state machine".* error="((?:[^"\\]|\\.)*)"`)

// rigErrRe matches failures of the rig's environment before Horizon reads a ledger (its history-archive
// bucket cache in a shared container, the database connection).
var rigErrRe = regexp.MustCompile(`^error creating history archive|cannot open Horizon DB|connection refused`)

var returnedRe = regexp.MustCompile(`msg="Ledger returned from the backend".* sequence=(\d+)`)

// Run executes the rig and writes the run directory.
func Run(ctx context.Context, cfg Config, logw io.Writer) (*Summary, error) {
	t0 := time.Now()
	if cfg.Shards < 1 {
		cfg.Shards = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	lake, err := filepath.Abs(cfg.Lake)
	if err != nil {
		return nil, err
	}
	bin, err := filepath.Abs(cfg.Binary)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(cfg.Out, "status.jsonl")); err == nil {
		return nil, fmt.Errorf("%s already holds a run", cfg.Out)
	}
	for _, d := range []string{"logs", "tables"} {
		if err := os.MkdirAll(filepath.Join(cfg.Out, d), 0o755); err != nil {
			return nil, err
		}
	}
	binSum, err := fileSHA256(bin)
	if err != nil {
		return nil, err
	}
	seqs := Dedup(cfg.Ledgers)
	have, missing := Present(lake, seqs)
	groups, err := Plan(have, cfg.GroupMode, cfg.MaxGroup)
	if err != nil {
		return nil, err
	}
	dsPath := filepath.Join(cfg.Out, "datastore.toml")
	ds := "[datastore_config]\ntype = \"Filesystem\"\n[datastore_config.params]\ndestination_path = \"/lake\"\n" +
		"[datastore_config.schema]\nledgers_per_file = 1\nfiles_per_partition = 64000\n" +
		"[buffered_storage_backend_config]\nbuffer_size = 10\nnum_workers = 2\nretry_limit = 0\nretry_wait = \"1s\"\n"
	if err := os.WriteFile(dsPath, []byte(ds), 0o644); err != nil {
		return nil, err
	}
	dsAbs, _ := filepath.Abs(dsPath)
	manifest := map[string]any{
		"rig": "horizon", "target": "stellar-horizon", "version": cfg.Version, "commit": cfg.Commit,
		"binary_sha256": binSum, "lake": lake, "requested": len(seqs), "present": len(have),
		"missing": len(missing), "shards": cfg.Shards, "group_mode": cfg.GroupMode, "max_group": cfg.MaxGroup,
		"passphrase": cfg.Passphrase, "pg_image": cfg.PGImage, "hz_image": cfg.HZImage,
		"command": "db reingest range S E --ledgerbackend datastore --datastore-config <Filesystem> " +
			"--network-passphrase P --history-archive-urls <unused> --db-url <shard db>",
		"started": t0.UTC().Format(time.RFC3339),
	}
	if err := writeJSON(filepath.Join(cfg.Out, "manifest.json"), manifest); err != nil {
		return nil, err
	}

	// Containers: one Postgres with a database per shard, one long-lived container that execs Horizon, both on
	// an internal network (no egress).
	name := cfg.Name
	net, pg, hz := name+"-net", name+"-pg", name+"-hz"
	cleanup := func() {
		if cfg.Keep {
			return
		}
		docker(context.Background(), nil, "rm", "-f", "-v", pg, hz)
		docker(context.Background(), nil, "network", "rm", net)
	}
	cleanup()
	defer cleanup()
	if _, err := docker(ctx, nil, "network", "create", "--internal", "--label", "xdrcheck.owner="+name, net); err != nil {
		return nil, err
	}
	if _, err := docker(ctx, nil, "run", "-d", "--name", pg, "--network", net, "--label", "xdrcheck.owner="+name,
		"--memory", cfg.PGMemory, "--shm-size", "4g", "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
		cfg.PGImage, "postgres", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
		"-c", "max_connections=1000", "-c", "shared_buffers=2GB"); err != nil {
		return nil, err
	}
	if _, err := docker(ctx, nil, "run", "-d", "--name", hz, "--network", net, "--label", "xdrcheck.owner="+name,
		"--memory", cfg.HZMemory, "-v", bin+":/hz/stellar-horizon:ro", "-v", lake+":/lake:ro",
		"-v", dsAbs+":/hz/datastore.toml:ro", "--entrypoint", "sleep", cfg.HZImage, "infinity"); err != nil {
		return nil, err
	}
	if err := waitPG(ctx, pg); err != nil {
		return nil, err
	}
	dbURL := func(k int) string { return fmt.Sprintf("postgres://postgres@%s/s%d?sslmode=disable", pg, k) }
	for k := 0; k < cfg.Shards; k++ {
		if _, err := psql(ctx, pg, "postgres", fmt.Sprintf("CREATE DATABASE s%d", k)); err != nil {
			return nil, err
		}
		if out, err := docker(ctx, nil, "exec", hz, "/hz/stellar-horizon", "db", "init", "--db-url", dbURL(k)); err != nil {
			return nil, fmt.Errorf("db init shard %d: %v: %s", k, err, tail(out, 5))
		}
	}
	setup := time.Since(t0)
	fmt.Fprintf(logw, "horizon-rig: %d requested, %d present, %d missing, %d groups, %d shards; setup %.1fs\n",
		len(seqs), len(have), len(missing), len(groups), cfg.Shards, setup.Seconds())

	// Ingest: groups round-robin over shards, each shard sequential.
	var mu sync.Mutex
	var statuses []LedgerStatus
	var faults []string
	var execTotal time.Duration
	for _, s := range missing {
		statuses = append(statuses, LedgerStatus{Ledger: s, Status: "skipped", Shard: -1,
			Reason: "ledger file not in lake: " + LedgerPath(s)})
	}
	reingest := func(k int, g Group) (string, time.Duration, error) {
		cctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
		st := time.Now()
		out, err := docker(cctx, nil, "exec", hz, "/hz/stellar-horizon", "db", "reingest", "range",
			fmt.Sprint(g.From), fmt.Sprint(g.To), "--ledgerbackend", "datastore",
			"--datastore-config", "/hz/datastore.toml", "--network-passphrase", cfg.Passphrase,
			"--history-archive-urls", "http://127.0.0.1:1/unused", "--history-archive-caching=false",
			"--db-url", dbURL(k))
		if cctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("timeout after %s", cfg.Timeout)
		}
		return out, time.Since(st), err
	}
	errText := func(out string, err error) string {
		if m := stateErrRe.FindAllStringSubmatch(out, -1); len(m) > 0 {
			return strings.ReplaceAll(m[len(m)-1][1], `\"`, `"`)
		}
		if t := strings.TrimSpace(tail(out, 1)); t != "" {
			return t
		}
		return err.Error()
	}
	saveLog := func(g Group, attempt, out string) string {
		p := filepath.Join("logs", fmt.Sprintf("%s.%s.log", g, attempt))
		os.WriteFile(filepath.Join(cfg.Out, p), []byte(out), 0o644)
		return p
	}
	t1 := time.Now()
	var wg sync.WaitGroup
	for k := 0; k < cfg.Shards; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			for gi := k; gi < len(groups); gi += cfg.Shards {
				if ctx.Err() != nil {
					return
				}
				g := groups[gi]
				out, d, err := reingest(k, g)
				var res []LedgerStatus
				var spent = d
				if err == nil {
					per := d.Seconds() / float64(g.To-g.From+1)
					for s := g.From; s <= g.To; s++ {
						res = append(res, LedgerStatus{Ledger: s, Status: "ingested", Segment: g.String(),
							Attempt: "segment", Shard: k, WallS: per})
					}
				} else if g.From == g.To {
					el := g.From
					res = append(res, LedgerStatus{Ledger: g.From, Status: "halted", Error: errText(out, err),
						ErrorLedger: &el, Segment: g.String(), Attempt: "segment", Shard: k, WallS: d.Seconds(),
						Log: saveLog(g, "segment", out)})
				} else {
					// A halted range commits nothing up to its flush boundary and Horizon's error does not
					// always name the ledger: rerun every ledger of the group alone to attribute it.
					saveLog(g, "segment", out)
					var stopped *uint32
					if m := returnedRe.FindAllStringSubmatch(out, -1); len(m) > 0 {
						var v uint32
						fmt.Sscan(m[len(m)-1][1], &v)
						stopped = &v
					}
					for s := g.From; s <= g.To; s++ {
						one := Group{s, s}
						o2, d2, e2 := reingest(k, one)
						spent += d2
						ls := LedgerStatus{Ledger: s, Status: "ingested", Segment: g.String(), Attempt: "probe",
							Shard: k, WallS: d2.Seconds(), StoppedAt: stopped}
						if e2 != nil {
							el := s
							ls.Status, ls.Error, ls.ErrorLedger = "halted", errText(o2, e2), &el
							ls.Log = saveLog(one, "probe", o2)
						}
						res = append(res, ls)
					}
					fmt.Fprintf(logw, "horizon-rig: segment %s halted (last ledger returned: %v): %s\n", g,
						deref(stopped), errText(out, err))
				}
				mu.Lock()
				statuses = append(statuses, res...)
				execTotal += spent
				mu.Unlock()
			}
		}(k)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ingest := time.Since(t1)

	// Cross-check: every ledger called ingested must be in its shard's history_ledgers and every halted one
	// absent; anything else is a harness fault.
	inDB := map[uint32]int{}
	for k := 0; k < cfg.Shards; k++ {
		out, err := psql(ctx, pg, fmt.Sprintf("s%d", k), "SELECT sequence FROM history_ledgers")
		if err != nil {
			faults = append(faults, fmt.Sprintf("shard %d: read history_ledgers: %v", k, err))
			continue
		}
		for _, l := range strings.Fields(out) {
			var v uint32
			fmt.Sscan(l, &v)
			inDB[v]++
		}
	}
	for i, s := range statuses {
		switch {
		case s.Status == "halted" && rigErrRe.MatchString(s.Error):
			// Horizon failed before reading the ledger, on the rig's environment: not a verdict on the ledger.
			statuses[i].Status = "harness_fault"
			faults = append(faults, fmt.Sprintf("ledger %d: %s", s.Ledger, s.Error))
		case s.Status == "ingested" && inDB[s.Ledger] != 1:
			faults = append(faults, fmt.Sprintf("ledger %d: ingested but in %d shard databases", s.Ledger, inDB[s.Ledger]))
		case s.Status == "halted" && inDB[s.Ledger] != 0:
			faults = append(faults, fmt.Sprintf("ledger %d: halted but present in a shard database", s.Ledger))
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Ledger < statuses[j].Ledger })
	if err := writeJSONL(filepath.Join(cfg.Out, "status.jsonl"), statuses); err != nil {
		return nil, err
	}

	// Export: raw dump of every shard into tables/<table>.jsonl.zst, then common rows.
	t2 := time.Now()
	sum := &Summary{Requested: len(seqs), Status: map[string]int{}, Shards: cfg.Shards, Segments: len(groups),
		RawRows: map[string]int{}, Rows: map[string]int{}}
	tw := newTableWriters(filepath.Join(cfg.Out, "tables"))
	for k := 0; k < cfg.Shards; k++ {
		if err := dumpShard(ctx, pg, fmt.Sprintf("s%d", k), tw, sum.RawRows); err != nil {
			faults = append(faults, fmt.Sprintf("shard %d: dump: %v", k, err))
		}
	}
	if err := tw.Close(); err != nil {
		faults = append(faults, fmt.Sprintf("tables: %v", err))
	}
	if !cfg.NoRows {
		if err := ExportRows(filepath.Join(cfg.Out, "tables"), filepath.Join(cfg.Out, "rows.jsonl"), cfg.Passphrase,
			cfg.Commit, sum.Rows); err != nil {
			faults = append(faults, fmt.Sprintf("rows: %v", err))
		}
	}
	export := time.Since(t2)

	for _, s := range statuses {
		sum.Status[s.Status]++
	}
	sum.HarnessFaults = append([]string{}, faults...)
	sum.SetupS, sum.IngestS, sum.ExportS = setup.Seconds(), ingest.Seconds(), export.Seconds()
	sum.WallS = time.Since(t0).Seconds()
	if n := float64(len(have)); n > 0 {
		sum.IngestSPerLdg = sum.IngestS / n
		sum.WallSPerLedger = sum.WallS / n
		sum.CPUSPerLedger = execTotal.Seconds() / n
	}
	if err := writeJSON(filepath.Join(cfg.Out, "summary.json"), sum); err != nil {
		return nil, err
	}
	return sum, nil
}

type tableWriters struct {
	dir string
	f   map[string]*os.File
	w   map[string]*zstd.Encoder
}

func newTableWriters(dir string) *tableWriters {
	return &tableWriters{dir: dir, f: map[string]*os.File{}, w: map[string]*zstd.Encoder{}}
}

func (t *tableWriters) write(table string, line []byte) error {
	w := t.w[table]
	if w == nil {
		if table == "" || strings.ContainsAny(table, "/.") {
			return fmt.Errorf("bad table name %q", table)
		}
		f, err := os.Create(filepath.Join(t.dir, table+".jsonl.zst"))
		if err != nil {
			return err
		}
		w, _ = zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedFastest))
		t.f[table], t.w[table] = f, w
	}
	if _, err := w.Write(line); err != nil {
		return err
	}
	_, err := w.Write([]byte{'\n'})
	return err
}

func (t *tableWriters) Close() error {
	var first error
	for k, w := range t.w {
		if err := w.Close(); err != nil && first == nil {
			first = err
		}
		if err := t.f[k].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func dumpShard(ctx context.Context, pg, db string, tw *tableWriters, counts map[string]int) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", pg, "psql", "-X", "-q", "-A", "-t",
		"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db, "-f", "-")
	cmd.Stdin = strings.NewReader(dumpSQL)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	var probe struct {
		Table string `json:"table"`
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		probe.Table = ""
		if err := json.Unmarshal(line, &probe); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return fmt.Errorf("dump line not JSON: %.200s", line)
		}
		counts[probe.Table]++
		if err := tw.write(probe.Table, line); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%v: %s", err, tail(stderr.String(), 3))
	}
	return nil
}

func deref(p *uint32) any {
	if p == nil {
		return "none"
	}
	return *p
}

func docker(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = stdin
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	return b.String(), err
}

func psql(ctx context.Context, pg, db, sql string) (string, error) {
	out, err := docker(ctx, strings.NewReader(sql), "exec", "-i", pg, "psql", "-X", "-q", "-A", "-t",
		"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db, "-f", "-")
	if err != nil {
		return out, fmt.Errorf("psql %s: %v: %s", db, err, tail(out, 3))
	}
	return strings.TrimSpace(out), nil
}

func waitPG(ctx context.Context, pg string) error {
	for i := 0; i < 120; i++ {
		// pg_isready on the socket passes during the init phase's temporary server; a real query over TCP
		// after the final start is the reliable check.
		if _, err := docker(ctx, nil, "exec", pg, "psql", "-h", "127.0.0.1", "-U", "postgres", "-Atc", "SELECT 1"); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := docker(ctx, nil, "logs", "--tail", "20", pg)
	return errors.New("postgres did not start: " + logs)
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

func writeJSONL[T any](p string, vs []T) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, v := range vs {
		if err := enc.Encode(v); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
