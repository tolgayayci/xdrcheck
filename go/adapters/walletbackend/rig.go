package walletbackend

// The service rig: wallet-backend at one commit, its real database, live ingestion over a list of ledgers into
// one database, and every table it writes exported to the common rows (go/internal/rig).
//
// How a run goes:
//
//  1. Build the commit (cached per commit), start TimescaleDB, migrate a template, clone the run's database.
//  2. Seed what production gets from the history-archive checkpoint, which the seeded cursor skips: a
//     contract_tokens row (type SAC) for every Stellar Asset Contract the run's ledgers touch, verified by
//     hashing the asset; and, from a state seed (current ledger entries fetched once from an RPC), the
//     protocol_wasms / protocol_contracts rows of every WASM contract the ledgers touch.
//  3. Run the commit's own `protocol-setup` for every registered protocol against a local RPC that serves the
//     seed's entries, so classification (SEP-41, Blend) is wallet-backend's, not ours.
//  4. Per contiguous segment: set the ingest cursor and every classified protocol's history and current-state
//     cursors to first-1 (what a finished `protocol-migrate` leaves), serve the segment's ledgers from the mock
//     RPC, run `ingest` in live mode with one ledger per commit, and poll the cursor to see each commit.
//  5. A segment that stops short: the ledger after the durable cursor halted; the error text and the ledger it
//     names are kept. The process is started once more without touching the cursor to see whether the halt
//     repeats (production restarts resume at the same ledger), then the rest of the segment is skipped, or run
//     past the halted ledger when SkipHalted is set.
//  6. Dump every table, map the rows.

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
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

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
	"github.com/tolgayayci/xdrcheck/go/internal/rpcmock"
)

// RigOptions configure one wallet-backend rig shard.
type RigOptions struct {
	Pins       string
	CacheDir   string // adapter cache root (holds wallet-backend/repo.git and built binaries)
	NamePrefix string // docker container prefix, unique per shard
	Commit     string
	Passphrase string
	Lake       *rig.Lake
	Segments   []rig.Segment
	Shard      int
	Out        string // the shard's run directory
	MemoryMax  int64  // database container memory cap (bytes)
	Seed       map[string]protocol.LedgerEntryResult
	// Protocols to classify and enable; nil: every protocol the commit registers.
	Protocols []string
	// SkipHalted runs the rest of a segment past a halted ledger (the cursor is moved over it), which production
	// never does; off, the rest of the segment is skipped.
	SkipHalted bool
	// RetryHalt starts the service once more after a halt, without touching the cursor.
	RetryHalt       bool
	SegmentDeadline time.Duration // per segment; 0: 90 s + 3 s per ledger
	LogLevel        string        // the service's log level (default INFO)
	Log             io.Writer
}

// RigReport is what a shard reports besides its files.
type RigReport struct {
	Commit        string         `json:"commit"`
	Binary        string         `json:"binary_sha256"`
	SDK           string         `json:"sdk"`
	Tables        map[string]int `json:"tables"`
	Unmapped      map[string]int `json:"unmapped_tables"`
	Seed          SeedReport     `json:"seed"`
	Status        map[string]int `json:"status"`
	IngestWallMS  int64          `json:"ingest_wall_ms"`
	SetupWallMS   int64          `json:"setup_wall_ms"`
	ExportWallMS  int64          `json:"export_wall_ms"`
	Rows          int            `json:"rows"`
	HarnessFaults []string       `json:"harness_faults"`
	DisabledLines int            `json:"production_disabled_lines"`
}

// SeedReport says what the rig put into the database before ingestion.
type SeedReport struct {
	SACTokens          int               `json:"sac_contract_tokens"`
	ProtocolWasms      int               `json:"protocol_wasms"`
	ProtocolContracts  int               `json:"protocol_contracts"`
	ContractsNoSeed    int               `json:"wasm_contracts_without_seed_entry"`
	ProtocolSetup      map[string]string `json:"protocol_setup"` // protocol → classification_status
	Classified         map[string]int    `json:"classified_wasms"`
	ProtocolSetupError string            `json:"protocol_setup_error,omitempty"`
	ProtocolsEnabled   []string          `json:"protocols_enabled"`
}

const statusFile, rowsFile, checksFile = "status.jsonl", "rows.jsonl", "checks.jsonl"

// RunRig runs one shard. Files: status.jsonl, rows.jsonl, checks.jsonl, tables/, logs/ under o.Out.
func RunRig(ctx context.Context, o RigOptions) (*RigReport, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	rep := &RigReport{Tables: map[string]int{}, Unmapped: map[string]int{}, Status: map[string]int{}, HarnessFaults: []string{}}
	logs := filepath.Join(o.Out, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		return nil, err
	}
	cfg, err := loadConfig(o.Pins, o.CacheDir, o.NamePrefix)
	if err != nil {
		return nil, err
	}
	s := &server{cfg: cfg, cacheFlag: true, sessions: map[string]*session{}, log: o.Log}
	defer s.shutdown()
	setupStart := time.Now()
	r, err := s.getRepo()
	if err != nil {
		return nil, err
	}
	commit, err := r.resolve(ctx, o.Commit)
	if err != nil {
		return nil, err
	}
	rep.Commit = commit
	if gomod, err := r.file(ctx, commit, "go.mod"); err == nil {
		m, v := sdkVersion(gomod)
		rep.SDK = m + " " + v
	}
	b, err := r.build(ctx, commit, o.Log)
	if err != nil {
		return nil, fmt.Errorf("build %s: %w", commit[:12], err)
	}
	rep.Binary = b.SHA256
	mem := o.MemoryMax
	db, err := s.database(ctx, &adapterkit.Limits{MemoryMaxBytes: &mem})
	if err != nil {
		return nil, err
	}
	tmpl, _, err := s.template(ctx, db, commit, b.Path)
	if err != nil {
		return nil, err
	}
	dbName := fmt.Sprintf("rig_%d", o.Shard)
	db.Drop(ctx, dbName)
	if err := db.CreateFrom(ctx, dbName, tmpl); err != nil {
		return nil, err
	}
	w := &rigRun{o: o, s: s, db: db, dbName: dbName, bin: b, commit: commit, logs: logs, rep: rep}

	// Read every ledger once: what the seed needs and the expected transactions.
	var infos []*rig.LedgerInfo
	for _, seg := range o.Segments {
		for q := seg.First; ; q++ {
			lcm, err := o.Lake.Load(ctx, q)
			if err != nil {
				return nil, err
			}
			info, err := rig.Analyze(o.Passphrase, lcm)
			if err != nil {
				return nil, err
			}
			infos = append(infos, info)
			if q == seg.Last {
				break
			}
		}
	}
	w.returns = map[string]string{}
	for _, in := range infos {
		for k, v := range in.Returns {
			w.returns[k] = v
		}
	}
	if err := w.seed(ctx, infos); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	rep.SetupWallMS = time.Since(setupStart).Milliseconds()

	if w.status, err = rig.CreateJSONL(filepath.Join(o.Out, statusFile)); err != nil {
		return nil, err
	}
	defer w.status.Close()
	if w.checks, err = rig.CreateJSONL(filepath.Join(o.Out, checksFile)); err != nil {
		return nil, err
	}
	defer w.checks.Close()
	ingestStart := time.Now()
	for i, seg := range o.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := w.segment(ctx, i, seg); err != nil {
			// A rig error on one segment is a harness fault for its ledgers; the run goes on.
			rep.HarnessFaults = append(rep.HarnessFaults, fmt.Sprintf("segment %s: %v", seg, err))
			for q := seg.First; ; q++ {
				w.put(rig.Status{Ledger: q, Status: rig.StatusHarnessFault, Segment: seg.String(), Error: err.Error()})
				if q == seg.Last {
					break
				}
			}
		}
	}
	rep.IngestWallMS = time.Since(ingestStart).Milliseconds()

	exportStart := time.Now()
	n, err := w.export(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	rep.Rows = n
	rep.ExportWallMS = time.Since(exportStart).Milliseconds()
	return rep, nil
}

type rigRun struct {
	o      RigOptions
	s      *server
	db     *dbServer
	dbName string
	bin    *buildResult
	commit string
	logs   string
	rep    *RigReport
	status *rig.JSONL
	checks *rig.JSONL
	// protocols whose cursors the rig sets (classification succeeded)
	enabled []string
	oldest  bool
	// returns: recorded results of zero-argument contract calls in the run's ledgers ("contract|function" →
	// base64 ScVal), the stand-in for the RPC simulations the service makes for token metadata.
	returns map[string]string
}

func (w *rigRun) put(st rig.Status) {
	st.Shard = w.o.Shard
	w.rep.Status[st.Status]++
	w.status.Write(st)
}

func (w *rigRun) tableCols(ctx context.Context, table string) (map[string]bool, error) {
	out, err := w.db.Query(ctx, w.dbName, "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name="+quoteLiteral(table))
	if err != nil {
		return nil, err
	}
	cols := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			cols[l] = true
		}
	}
	return cols, nil
}

// contractUUID is wallet-backend's DeterministicContractID: UUID v5 (SHA-1) of the contract strkey in the
// namespace UUIDv5(DNS, "contract_tokens").
func contractUUID(contract string) string {
	ns := uuid5([16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}, "contract_tokens")
	u := uuid5(ns, contract)
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func uuid5(ns [16]byte, name string) [16]byte {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func (w *rigRun) seed(ctx context.Context, infos []*rig.LedgerInfo) error {
	rep := &w.rep.Seed
	rep.ProtocolSetup = map[string]string{}
	rep.Classified = map[string]int{}
	var sql strings.Builder
	// 1. SAC tokens, as the checkpoint bootstrap writes them for every SAC instance.
	if cols, err := w.tableCols(ctx, "contract_tokens"); err != nil {
		return err
	} else if cols["type"] && cols["code"] && cols["issuer"] {
		sacs := seedSACs(infos)
		keys := make([]string, 0, len(sacs))
		for c := range sacs {
			keys = append(keys, c)
		}
		sort.Strings(keys)
		for _, c := range keys {
			code, issuer := "", ""
			if a := sacs[c]; a != "native" {
				code, issuer, _ = strings.Cut(a, ":")
			}
			name := code + ":" + issuer
			sql.WriteString(fmt.Sprintf("INSERT INTO contract_tokens (id, contract_id, type, code, issuer, name, symbol, decimals) VALUES (%s, %s, 'SAC', %s, %s, %s, %s, 7) ON CONFLICT DO NOTHING;\n",
				quoteLiteral(contractUUID(c)), quoteLiteral(c), quoteLiteral(code), quoteLiteral(issuer), quoteLiteral(name), quoteLiteral(code)))
		}
		rep.SACTokens = len(keys)
	}
	// 2. WASM contracts from the state seed.
	hasProtocols, _ := w.tableCols(ctx, "protocol_contracts")
	if len(hasProtocols) > 0 {
		wasms, bound := seedBindings(infos, func(c string) (string, bool) { return seedWasm(w.o.Seed, c) })
		for _, h := range wasms {
			sql.WriteString(fmt.Sprintf("INSERT INTO protocol_wasms (wasm_hash) VALUES ('\\x%s') ON CONFLICT DO NOTHING;\n", h))
			rep.ProtocolWasms++
		}
		for c, h := range bound {
			if h == "" {
				rep.ContractsNoSeed++
				continue
			}
			raw, err := strkey.Decode(strkey.VersionByteContract, c)
			if err != nil {
				continue
			}
			sql.WriteString(fmt.Sprintf("INSERT INTO protocol_contracts (contract_id, wasm_hash) VALUES ('\\x%x', '\\x%s') ON CONFLICT DO NOTHING;\n", raw, h))
			rep.ProtocolContracts++
		}
	}
	if sql.Len() > 0 {
		if err := w.db.Exec(ctx, w.dbName, sql.String()); err != nil {
			return fmt.Errorf("seed rows: %w", err)
		}
	}
	if len(hasProtocols) == 0 {
		return nil
	}
	// 3. The commit's own protocol-setup.
	ids := w.o.Protocols
	if ids == nil {
		out, err := w.db.Query(ctx, w.dbName, "SELECT id FROM protocols ORDER BY id")
		if err != nil {
			return err
		}
		ids = strings.Fields(out)
		if len(ids) == 0 {
			ids = w.registeredProtocols()
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if err := w.protocolSetup(ctx, ids); err != nil {
		rep.ProtocolSetupError = err.Error()
	}
	out, err := w.db.Query(ctx, w.dbName, "SELECT id || ' ' || classification_status FROM protocols ORDER BY id")
	if err != nil {
		return err
	}
	for _, l := range strings.Split(out, "\n") {
		if id, st, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			rep.ProtocolSetup[id] = st
			if st == "success" && slices.Contains(ids, id) {
				w.enabled = append(w.enabled, id)
			}
		}
	}
	out, _ = w.db.Query(ctx, w.dbName, "SELECT coalesce(protocol_id,'-') || ' ' || count(*) FROM protocol_wasms GROUP BY 1")
	for _, l := range strings.Split(out, "\n") {
		if id, n, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			rep.Classified[id], _ = strconv.Atoi(n)
		}
	}
	rep.ProtocolsEnabled = w.enabled
	if len(w.enabled) > 0 {
		var st strings.Builder
		for _, id := range w.enabled {
			st.WriteString(fmt.Sprintf("UPDATE protocols SET history_migration_status='success', current_state_migration_status='success' WHERE id=%s;\n", quoteLiteral(id)))
		}
		if err := w.db.Exec(ctx, w.dbName, st.String()); err != nil {
			return err
		}
	}
	return nil
}

// registeredProtocols reads the protocol ids from the binary's embedded registration files (`INSERT INTO
// protocols (id) VALUES ('X')`), for a commit whose `migrate up` does not insert them.
func (w *rigRun) registeredProtocols() []string {
	data, err := os.ReadFile(w.bin.Path)
	if err != nil {
		return nil
	}
	var ids []string
	for _, m := range regexp.MustCompile(`INSERT INTO protocols \(id\) VALUES \('([A-Z0-9_]+)'\)`).FindAllSubmatch(data, -1) {
		if id := string(m[1]); !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// seedWasm returns a contract's WASM hash from the seed's instance entry.
func seedWasm(seed map[string]protocol.LedgerEntryResult, contract string) (string, bool) {
	k, err := InstanceKey(contract)
	if err != nil {
		return "", false
	}
	e, ok := seed[k]
	if !ok {
		return "", false
	}
	var d xdr.LedgerEntryData
	if err := xdr.SafeUnmarshalBase64(e.DataXDR, &d); err != nil || d.ContractData == nil {
		return "", false
	}
	inst, ok := d.ContractData.Val.GetInstance()
	if !ok || inst.Executable.Type != xdr.ContractExecutableTypeContractExecutableWasm || inst.Executable.WasmHash == nil {
		return "", false
	}
	return hex.EncodeToString(inst.Executable.WasmHash[:]), true
}

// seedSACs are the Stellar Asset Contracts the seed writes as contract_tokens rows: every SAC the ledgers touch,
// except one deployed inside the replayed ledgers (live ingestion writes that row itself when it sees the deploy).
func seedSACs(infos []*rig.LedgerInfo) map[string]string {
	created := map[string]bool{}
	for _, in := range infos {
		for c := range in.InstancesCreated {
			created[c] = true
		}
	}
	sacs := map[string]string{}
	for _, in := range infos {
		for c, a := range in.SACs {
			if !created[c] {
				sacs[c] = a
			}
		}
	}
	return sacs
}

// seedBindings plans the WASM rows of the seed: the wasm hashes to pre-register in protocol_wasms (sorted) and the
// contract → wasm bindings for protocol_contracts ("" when the state seed has no binding). A contract's binding is
// the one it had before the first replayed ledger that changed its instance (that ledger's pre-image), else the
// state seed's current binding. Nothing is pre-registered for a contract deployed or a WASM uploaded inside the
// replayed ledgers: live ingestion sees those happen and classifies them itself, and a pre-inserted row would
// stand in front of its own (the service writes with ON CONFLICT DO NOTHING).
func seedBindings(infos []*rig.LedgerInfo, seedLookup func(contract string) (string, bool)) ([]string, map[string]string) {
	created, uploaded := map[string]bool{}, map[string]bool{}
	for _, in := range infos {
		for c := range in.InstancesCreated {
			created[c] = true
		}
		for h := range in.WasmsUploaded {
			uploaded[h] = true
		}
	}
	wasms := map[string]bool{}
	bound := map[string]string{}
	register := func(h string) bool {
		if h == "" || uploaded[h] {
			return false
		}
		wasms[h] = true
		return true
	}
	// Pass 1: ledger-time bindings of contracts that existed before the run, from the earliest replayed ledger that
	// changed each instance; every hash such an instance points at during the run is registered too, so a rebinding
	// seen during the run classifies like production (unless that WASM was itself uploaded during the run).
	for _, in := range infos {
		for c, h := range in.InstancesBefore {
			if created[c] {
				continue
			}
			if _, ok := bound[c]; !ok && register(h) {
				bound[c] = h
			}
		}
		for c, h := range in.Instances {
			if !created[c] {
				register(h)
			}
		}
	}
	// Pass 2: every other WASM contract the ledgers touch, bound as the state seed has it today.
	for _, in := range infos {
		for _, c := range in.Contracts {
			if _, sac := in.SACs[c]; sac || created[c] {
				continue
			}
			if _, ok := bound[c]; ok {
				continue
			}
			h, ok := seedLookup(c)
			if !ok || !register(h) {
				h = ""
			}
			bound[c] = h
		}
	}
	list := make([]string, 0, len(wasms))
	for h := range wasms {
		list = append(list, h)
	}
	sort.Strings(list)
	return list, bound
}

// InstanceKey is the base64 LedgerKey of a contract's instance entry.
func InstanceKey(contract string) (string, error) {
	raw, err := strkey.Decode(strkey.VersionByteContract, contract)
	if err != nil {
		return "", err
	}
	var id xdr.ContractId
	copy(id[:], raw)
	k := xdr.LedgerKey{Type: xdr.LedgerEntryTypeContractData, ContractData: &xdr.LedgerKeyContractData{
		Contract:   xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &id},
		Key:        xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyContractInstance},
		Durability: xdr.ContractDataDurabilityPersistent}}
	b, err := k.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CodeKey is the base64 LedgerKey of a WASM's code entry.
func CodeKey(hash string) (string, error) {
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("wasm hash %q", hash)
	}
	var h xdr.Hash
	copy(h[:], raw)
	k := xdr.LedgerKey{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.LedgerKeyContractCode{Hash: h}}
	b, err := k.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SeedWasmHashes lists the WASM hashes the seed's instance entries bind contracts to, plus extra hashes (those
// the replayed ledgers' instances point at).
func SeedWasmHashes(seed map[string]protocol.LedgerEntryResult, contracts []string, extra ...string) []string {
	set := map[string]bool{}
	for _, h := range extra {
		set[h] = true
	}
	for _, c := range contracts {
		if h, ok := seedWasm(seed, c); ok {
			set[h] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// mockFor serves a segment's ledgers and the seed's entries.
func (w *rigRun) mockFor(ctx context.Context, seg rig.Segment) (*rpcmock.Server, error) {
	var ls []rpcmock.Ledger
	for q := seg.First; ; q++ {
		q := q
		ls = append(ls, rpcmock.Ledger{Seq: q, Load: func() ([]byte, error) { return w.o.Lake.Load(ctx, q) }})
		if q == seg.Last {
			break
		}
	}
	entries := w.o.Seed
	if entries == nil {
		entries = map[string]protocol.LedgerEntryResult{}
	}
	sim := func(contract, fn string, args int) (string, bool) {
		if args != 0 {
			return "", false
		}
		v, ok := w.returns[contract+"|"+fn]
		return v, ok
	}
	return rpcmock.New(rpcmock.Config{Passphrase: w.o.Passphrase, Entries: entries, Simulate: sim}, ls)
}

func (w *rigRun) protocolSetup(ctx context.Context, ids []string) error {
	seg := w.o.Segments[0]
	mock, err := w.mockFor(ctx, rig.Segment{First: seg.First, Last: seg.First})
	if err != nil {
		return err
	}
	hs, url, err := mock.Listen("127.0.0.1:0")
	if err != nil {
		return err
	}
	defer hs.Close()
	args := []string{"protocol-setup", "--database-url", w.db.URL(w.dbName), "--rpc-url", url, "--network-passphrase", w.o.Passphrase}
	for _, id := range ids {
		args = append(args, "--protocol-id", id)
	}
	logf, err := os.Create(filepath.Join(w.logs, "protocol-setup.log"))
	if err != nil {
		return err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "$ wallet-backend %s\n", strings.Join(args, " "))
	res, err := proc.Run(ctx, proc.Spec{Path: w.bin.Path, Args: args, Env: baseEnv(), Dir: w.o.Out, Name: "wallet-backend-protocol-setup",
		Stdout: logf, Stderr: logf, Limits: proc.Limits{Deadline: 5 * time.Minute}, TailBytes: 4 << 10})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || res.TimedOut {
		return fmt.Errorf("protocol-setup exit %d: %s", res.ExitCode, lastLines(string(res.Stderr.Data)+string(res.Stdout.Data), 5))
	}
	return nil
}

// cursorsSQL sets the ingest cursor and the enabled protocols' cursors to seq.
func (w *rigRun) cursorsSQL(seq uint32, oldest bool) string {
	var b strings.Builder
	set := func(k string, v uint32) {
		b.WriteString(fmt.Sprintf("DELETE FROM ingest_store WHERE key = %s; INSERT INTO ingest_store (key, value) VALUES (%s, '%d');\n", quoteLiteral(k), quoteLiteral(k), v))
	}
	set("latest_ingest_ledger", seq)
	if oldest {
		set("oldest_ingest_ledger", seq+1)
	}
	for _, id := range w.enabled {
		set("protocol_"+id+"_history_cursor", seq)
		set("protocol_"+id+"_current_state_cursor", seq)
	}
	return b.String()
}

var ledgerInErr = regexp.MustCompile(`(?:ledger|ledgers) (\d{2,10})`)

// segment ingests one contiguous segment (and, with SkipHalted, the rest of it after a halt).
func (w *rigRun) segment(ctx context.Context, idx int, seg rig.Segment) error {
	first := seg.First
	for attempt := 0; first <= seg.Last; attempt++ {
		sub := rig.Segment{First: first, Last: seg.Last}
		if err := w.db.Exec(ctx, w.dbName, w.cursorsSQL(sub.First-1, !w.oldest)); err != nil {
			return fmt.Errorf("seeding cursors: %w", err)
		}
		w.oldest = true
		res, err := w.ingestOnce(ctx, fmt.Sprintf("seg%04d-%d", idx, attempt), sub)
		// Another process can take the free port between the rig's check and the service's bind: start again
		// with a new port (the cursor is untouched by a process that never started its pipeline).
		for try := 1; err == nil && res.portClash && try <= 3; try++ {
			res, err = w.ingestOnce(ctx, fmt.Sprintf("seg%04d-%d-port%d", idx, attempt, try), sub)
		}
		if err != nil {
			return err
		}
		durable := int64(sub.First) - 1
		if res.cursor != nil {
			durable = *res.cursor
		}
		for q := sub.First; q <= seg.Last && int64(q) <= durable; q++ {
			w.put(rig.Status{Ledger: q, Status: rig.StatusIngested, Segment: seg.String()})
		}
		if durable >= int64(seg.Last) {
			return nil
		}
		// Stopped short.
		halted := uint32(durable + 1)
		st := rig.Status{Ledger: halted, Status: rig.StatusHalted, Segment: seg.String(), Error: res.errText, DurableCursor: &durable}
		if m := ledgerInErr.FindAllStringSubmatch(res.errText, -1); len(m) > 0 {
			if n, err := strconv.ParseUint(m[len(m)-1][1], 10, 32); err == nil {
				v := uint32(n)
				st.ErrorLedger = &v
			}
		}
		if res.timedOut {
			st.Reason = "deadline: the process was still running with the cursor behind"
		}
		if res.harness != "" {
			st.Status, st.Reason = rig.StatusHarnessFault, res.harness
			w.rep.HarnessFaults = append(w.rep.HarnessFaults, fmt.Sprintf("ledger %d: %s", halted, res.harness))
		}
		check := map[string]any{"kind": "halt", "ledger": halted, "durable_cursor": durable, "error": res.errText, "exit": res.exit}
		if w.o.RetryHalt && st.Status == rig.StatusHalted {
			again, err := w.ingestOnce(ctx, fmt.Sprintf("seg%04d-%d-retry", idx, attempt), sub)
			if err == nil {
				after := durable
				if again.cursor != nil {
					after = *again.cursor
				}
				check["retry_cursor"] = after
				check["retry_error"] = again.errText
				check["retry_repeats_halt"] = after == durable
			}
		}
		w.checks.Write(check)
		w.put(st)
		if !w.o.SkipHalted || st.Status != rig.StatusHalted {
			for q := halted + 1; q <= seg.Last && q > halted; q++ {
				w.put(rig.Status{Ledger: q, Status: rig.StatusSkipped, Segment: seg.String(), Reason: fmt.Sprintf("ledger %d of the segment halted", halted)})
			}
			return nil
		}
		first = halted + 1
	}
	return nil
}

type ingestRes struct {
	cursor   *int64
	errText  string
	exit     string
	timedOut bool
	harness  string // non-empty: the stop was the rig's own fault
	// portClash: the service could not bind its ingest-server port
	portClash bool
}

var (
	errLineRe      = regexp.MustCompile(`(?i)(level=error|level=fatal|^panic:|\berror\b.*ledger|failed after)`)
	disabledLineRe = regexp.MustCompile(`production disabled; cursor not initialized`)
)

func (w *rigRun) ingestOnce(ctx context.Context, name string, seg rig.Segment) (*ingestRes, error) {
	mock, err := w.mockFor(ctx, seg)
	if err != nil {
		return nil, err
	}
	hs, url, err := mock.Listen("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer hs.Close()
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	args, env, err := ingestArgs(w.bin.Flags, adapterkit.Input{Kind: "rpc", URL: url}, adapterkit.Network{Passphrase: w.o.Passphrase, Name: networkName(w.o.Passphrase)}, w.db.URL(w.dbName), port)
	if err != nil {
		return nil, err
	}
	if w.o.LogLevel != "" {
		for i := range args {
			if args[i] == "--log-level" && i+1 < len(args) {
				args[i+1] = w.o.LogLevel
			}
		}
	}
	if w.bin.Flags["live-persist-max-batch-size"] {
		args = append(args, "--live-persist-max-batch-size", "1")
	}
	logPath := filepath.Join(w.logs, name+".log")
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(logf, "$ wallet-backend %s\n", strings.Join(args, " "))
	deadline := w.o.SegmentDeadline
	if deadline == 0 {
		deadline = 90*time.Second + time.Duration(seg.Len())*3*time.Second
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	start := time.Now()
	child, err := proc.Start(runCtx, proc.Spec{Path: w.bin.Path, Args: args, Env: env, Dir: w.o.Out, Name: "wallet-backend",
		Stdout: logf, Stderr: logf, Grace: 5 * time.Second, TailBytes: 32 << 10})
	if err != nil {
		logf.Close()
		return nil, err
	}
	res := &ingestRes{}
	var last int64 = -1
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	reached := false
poll:
	for {
		select {
		case <-child.Done():
			break poll
		case <-tick.C:
		}
		if c, err := w.s.cursor(ctx, w.dbName); err == nil && c != nil {
			res.cursor = c
			if *c != last {
				if last >= 0 && *c > last {
					w.checks.Write(map[string]any{"kind": "commit", "cursor": *c, "previous": last, "at_ms": time.Since(start).Milliseconds(), "run": name})
				}
				last = *c
			}
			if *c >= int64(seg.Last) {
				reached = true
				break poll
			}
		}
		if time.Since(start) >= deadline {
			res.timedOut = true
			break poll
		}
	}
	stopped := false
	select {
	case <-child.Done():
	default:
		stopped = true
		stop()
	}
	pr := child.Wait()
	logf.Close()
	if c, err := w.s.cursor(ctx, w.dbName); err == nil && c != nil {
		res.cursor = c
	}
	switch {
	case pr.Signal != 0 && !stopped:
		res.exit = "signal " + signalName(pr.Signal)
	case stopped:
		res.exit = "stopped by the rig"
	default:
		res.exit = "exit " + strconv.Itoa(pr.ExitCode)
	}
	text, _ := os.ReadFile(logPath)
	w.rep.DisabledLines += len(disabledLineRe.FindAll(text, -1))
	if !reached {
		var errs []string
		for _, l := range strings.Split(string(text), "\n") {
			if errLineRe.MatchString(l) {
				errs = append(errs, strings.TrimSpace(l))
			}
		}
		if len(errs) > 6 {
			errs = errs[len(errs)-6:]
		}
		res.errText = strings.Join(errs, "\n")
		if res.errText == "" {
			res.errText = tailText(string(text), 1500)
		}
		res.portClash = strings.Contains(string(text), "address already in use")
		if pr.OOMKills > 0 || res.portClash {
			res.harness = "the rig's process environment failed (OOM kill or port in use)"
		}
		if strings.Contains(string(text), "connection refused") && strings.Contains(string(text), "database") {
			res.harness = "the database was not reachable"
		}
	}
	return res, nil
}

func networkName(passphrase string) string {
	if strings.HasPrefix(passphrase, "Public Global Stellar Network") {
		return "pubnet"
	}
	return "testnet"
}

// dumpTable streams one table as JSON lines into path and returns the row count.
func (w *rigRun) dumpTable(ctx context.Context, table, path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", w.db.Container, "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
		"-h", sockMount, "-U", "postgres", "-d", w.dbName, "-c", "SELECT row_to_json(t) FROM "+quoteIdent(table)+" t")
	var stderr strings.Builder
	cw := &countWriter{w: f}
	cmd.Stdout, cmd.Stderr = cw, &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("dump %s: %v: %s", table, err, stderr.String())
	}
	return cw.lines, nil
}

type countWriter struct {
	w     io.Writer
	lines int
}

func (c *countWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			c.lines++
		}
	}
	return c.w.Write(p)
}
