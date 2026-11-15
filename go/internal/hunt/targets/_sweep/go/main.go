// Go sweep: every check of the kit's Go target over a list of ledgers, against whichever go-stellar-sdk version
// go.mod requires (the kit rewrites go.mod per version and builds this program once per version).
//
// Checks (the check column of every row):
//
//	codec                 batch decode and re-encode give the same bytes
//	tx-hash, envelope-encode, tx-parse
//	                      txnbuild parse of every envelope, its hash and its base64 form
//	op-rebuild            every operation rebuilt from its parsed form (BuildXDR) gives the same bytes
//	tx-rebuild, feebump-rebuild
//	                      the transaction rebuilt through NewTransaction / NewFeeBumpTransaction, fed back the
//	                      original preconditions and fee (inclusion fee per operation plus the Soroban resource
//	                      fee); what txnbuild cannot express is tagged (fee:not-multiple, retry:infinite-timeout)
//	helper-panic, helper-error
//	                      every ingest.LedgerTransaction helper, with panic recovery
//	byte-presence         values read straight from the XDR structs against the ingest and ingest/ledger helpers
//	token-transfer-modes  token-transfer events with readFromUnifiedEvents false and true, order-normalised
//	verify-events         VerifyEvents false and true per ledger
//	sac-event             support/contractevents on every transfer, mint, burn and clawback event
//	cb-id, pool-id, contract-id
//	                      ClaimableBalanceID, a pool-share line's GetLiquidityPoolID and xdr.Asset.ContractID against
//	                      the ids the result and the meta state
//
// Output in -out: state.json (cluster counts, tested counts per check, examples), hits.tsv.zst (one line per
// failing row of a cluster that is not noise), ttp-ledgers.tsv, and with -rows FILE every failing row as JSONL
// (check, class, ledger, tx, hash, op, op_type, detail). A rerun with the same -out resumes.
//
// usage: sweep -index index.tsv -root DIR -out DIR [-rows FILE] [-only seqs.txt] [-passphrase P]
//
//	[-dispositions FILE] [-shard i -nshards n] [-deadline RFC3339]
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/ingest"
	ledgerh "github.com/stellar/go-stellar-sdk/ingest/ledger"
	"github.com/stellar/go-stellar-sdk/processors/token_transfer"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/support/contractevents"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

var pass = "Public Global Stellar Network ; September 2015"

const pkgName = "go"

// version is the go-stellar-sdk version this binary was built with (its module version, or "(devel)" for a
// replaced local checkout).
var version = sdkVersion()

func sdkVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/stellar/go-stellar-sdk" {
				if d.Replace != nil {
					return d.Replace.Path + "@" + d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

var exPerStratum = 20

// ------------------------------------------------------------------ aggregation state

type Ex struct {
	Seq    uint32 `json:"seq"`
	Tx     int    `json:"tx"`
	Hash   string `json:"hash"`
	Op     string `json:"op"`
	OpType string `json:"op_type"`
	Detail string `json:"detail"`
	Size   int    `json:"size"`
	Strata string `json:"strata"`
}

type OpAgg struct {
	Rows    int64  `json:"rows"`
	Txs     int64  `json:"txs"`
	Ledgers int64  `json:"ledgers"`
	First   uint32 `json:"first"`
	Last    uint32 `json:"last"`
	LastTx  string `json:"-"`
	LastLed uint32 `json:"-"`
}

type Cluster struct {
	Check    string            `json:"check"`
	Class    string            `json:"class"`
	Rows     int64             `json:"rows"`
	Txs      int64             `json:"txs"`
	Ledgers  int64             `json:"ledgers"`
	First    uint32            `json:"first"`
	Last     uint32            `json:"last"`
	ByOp     map[string]*OpAgg `json:"by_op"`
	Strata   map[string]int64  `json:"strata"`
	ExCount  map[string]int    `json:"ex_count"`
	Examples []Ex              `json:"examples"`
	Smallest *Ex               `json:"smallest"`
	lastTx   string
	lastLed  uint32
}

type State struct {
	Tag        string                      `json:"tag"`
	Done       []uint32                    `json:"done"`
	Clusters   map[string]*Cluster         `json:"clusters"`
	Tested     map[string]int64            `json:"tested"`      // check -> calls
	TestedTx   map[string]map[string]int64 `json:"tested_tx"`   // stratum -> {txs, ledgers, ops}
	TTPTypes   map[string]map[string]int64 `json:"ttp_types"`   // mode -> event type -> count
	CheckCPU   map[string]float64          `json:"check_cpu_s"` // wall seconds inside each check (single thread)
	CPU        float64                     `json:"cpu_s"`       // cumulative process CPU over all runs
	Wall       float64                     `json:"wall_s"`      // cumulative wall
	PeakRSSMB  float64                     `json:"peak_rss_mb"` // max over runs
	Ledgers    int64                       `json:"ledgers"`
	Txs        int64                       `json:"txs"`
	ReadErrors map[string]string           `json:"read_errors"` // seq -> error
	Runs       []string                    `json:"runs"`
	Extra      map[string]map[string]int64 `json:"extra"`
	HitsOffset int64                       `json:"hits_offset"`
	HitsLines  int64                       `json:"hits_lines"`
}

// ------------------------------------------------------------------ uncapped hit list (known + candidate clusters)

type dispRule struct {
	chk, cls *regexp.Regexp
	disp     string
}

var (
	dispRules []dispRule
	dispCache = map[string]string{}
	noiseDisp = map[string]bool{"recipe-artefact": true, "builder-default": true, "by-design": true, "dialect": true, "expected-refusal": true}
	hitsFile  *os.File
	hitsZ     *zstd.Encoder
)

func loadDispositions(path string) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "package\t") {
			continue
		}
		p := strings.Split(l, "\t")
		if len(p) < 4 || (p[0] != "go" && p[0] != "*") {
			continue
		}
		dispRules = append(dispRules, dispRule{regexp.MustCompile("^(?:" + p[1] + ")$"), regexp.MustCompile("^(?:" + p[2] + ")$"), p[3]})
	}
}

func disposition(check, class string) string {
	k := check + "\x00" + class
	if d, ok := dispCache[k]; ok {
		return d
	}
	d := "candidate"
	for _, r := range dispRules {
		if r.chk.MatchString(check) && r.cls.MatchString(class) {
			d = r.disp
			break
		}
	}
	dispCache[k] = d
	return d
}

func hit(check, class string, seq uint32, tx int, op string) {
	if hitsZ == nil || noiseDisp[disposition(check, class)] {
		return
	}
	fmt.Fprintf(hitsZ, "%s|%s|%s|%s\t%d\t%d\t%s\n", pkgName, version, check, class, seq, tx, op)
	st.HitsLines++
}

// openHits truncates the hit file to the last snapshot's offset (drops lines of an unfinished interval) and
// starts a new zstd frame; every snapshot closes the frame, so the file is a valid multi-frame zstd stream.
func openHits(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		panic(err)
	}
	if err := f.Truncate(st.HitsOffset); err != nil {
		panic(err)
	}
	f.Seek(st.HitsOffset, io.SeekStart)
	hitsFile = f
	hitsZ, _ = zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
}

func rollHits() {
	if hitsZ == nil {
		return
	}
	hitsZ.Close()
	hitsFile.Sync()
	off, _ := hitsFile.Seek(0, io.SeekCurrent)
	st.HitsOffset = off
	hitsZ.Reset(hitsFile)
}

var rowsOut *bufio.Writer

var (
	st         *State
	done       = map[uint32]bool{}
	strataOf   = map[uint32]string{}
	curSeq     uint32
	curStrata  string
	maxCluster = 20000
)

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// fail records one failure row into the aggregates.
func fail(check, class string, seq uint32, tx int, hash string, op any, opType, detail string, size int) {
	if class == "" {
		class = "unclassified"
	}
	key := check + "\x00" + class
	c := st.Clusters[key]
	if c == nil {
		if len(st.Clusters) >= maxCluster {
			key = check + "\x00overflow"
			class = "overflow"
			c = st.Clusters[key]
		}
		if c == nil {
			c = &Cluster{Check: check, Class: class, ByOp: map[string]*OpAgg{}, Strata: map[string]int64{}, ExCount: map[string]int{}}
			st.Clusters[key] = c
		}
	}
	c.Rows++
	txk := fmt.Sprintf("%d:%d", seq, tx)
	newTx := c.lastTx != txk
	if newTx {
		c.Txs++
		c.lastTx = txk
		for _, s := range strings.Split(curStrata, ",") {
			c.Strata[s]++
		}
	}
	if c.lastLed != seq {
		c.Ledgers++
		c.lastLed = seq
	}
	if c.First == 0 || seq < c.First {
		c.First = seq
	}
	if seq > c.Last {
		c.Last = seq
	}
	if opType == "" {
		opType = "-"
	}
	oa := c.ByOp[opType]
	if oa == nil {
		if len(c.ByOp) >= 300 {
			opType = "other"
			oa = c.ByOp[opType]
		}
		if oa == nil {
			oa = &OpAgg{}
			c.ByOp[opType] = oa
		}
	}
	oa.Rows++
	if oa.LastTx != txk {
		oa.Txs++
		oa.LastTx = txk
	}
	if oa.LastLed != seq {
		oa.Ledgers++
		oa.LastLed = seq
	}
	if oa.First == 0 || seq < oa.First {
		oa.First = seq
	}
	if seq > oa.Last {
		oa.Last = seq
	}
	ops := ""
	if op != nil {
		ops = fmt.Sprint(op)
	}
	if newTx || ops != "" {
		hit(check, class, seq, tx, ops)
	}
	if rowsOut != nil {
		b, _ := json.Marshal(map[string]any{"check": check, "class": class, "ledger": seq, "tx": tx, "hash": hash, "op": ops, "op_type": opType, "detail": clip(detail, 400)})
		rowsOut.Write(append(b, '\n'))
	}
	ex := Ex{Seq: seq, Tx: tx, Hash: hash, Op: ops, OpType: opType, Detail: clip(detail, 400), Size: size, Strata: curStrata}
	if newTx {
		for _, s := range strings.Split(curStrata, ",") {
			if c.ExCount[s] < exPerStratum {
				c.ExCount[s]++
				c.Examples = append(c.Examples, ex)
				break
			}
		}
	}
	if size > 0 && (c.Smallest == nil || size < c.Smallest.Size) {
		e := ex
		c.Smallest = &e
	}
}

func tested(check string, n int64) { st.Tested[check] += n }

func timed(check string, f func()) {
	t := time.Now()
	f()
	st.CheckCPU[check] += time.Since(t).Seconds()
}

// guard runs f and turns a panic into a failure row of the given check.
func guard(check, what string, seq uint32, tx int, hash, opType string, size int, f func()) {
	defer func() {
		if r := recover(); r != nil {
			fail(check, what+":panic:"+panicKind(fmt.Sprint(r)), seq, tx, hash, nil, opType, fmt.Sprint(r), size)
		}
	}()
	f()
}

// ------------------------------------------------------------------ class helpers

var (
	reStrkey = regexp.MustCompile(`\b[GCMLBPTA][A-Z2-7]{55,}\b`)
	reHex    = regexp.MustCompile(`\b(0x)?[0-9a-fA-F]{16,}\b`)
	reQuoted = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	reNum    = regexp.MustCompile(`(^|[^A-Za-z_])-?\d+(\.\d+)?`)
	reTime   = regexp.MustCompile(`\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(\.\d+)?( ?[+-]\d{4})?( UTC| \+0000 UTC)?`)
)

func strip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = reTime.ReplaceAllString(s, "TIME")
	s = reStrkey.ReplaceAllString(s, "STRKEY")
	s = reHex.ReplaceAllString(s, "HEX")
	s = reQuoted.ReplaceAllString(s, "S")
	s = reNum.ReplaceAllString(s, "${1}N")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func panicKind(m string) string {
	switch {
	case strings.Contains(m, "nil pointer dereference"):
		return "nil-deref"
	case strings.Contains(m, "index out of range"):
		return "index-out-of-range"
	case strings.Contains(m, "slice bounds out of range"):
		return "slice-bounds"
	}
	return strip(m)
}

func opName(t xdr.OperationType) string { return strings.TrimPrefix(t.String(), "OperationType") }

func opTypes(ops []xdr.Operation) string {
	seen := map[string]bool{}
	var s []string
	for _, o := range ops {
		n := opName(o.Body.Type)
		if !seen[n] {
			seen[n] = true
			s = append(s, n)
		}
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, "+")
}

func mb(v interface{ MarshalBinary() ([]byte, error) }) []byte { b, _ := v.MarshalBinary(); return b }

// ------------------------------------------------------------------ raw (byte-side) accessors

type rawTx struct {
	envType   xdr.EnvelopeType
	isFB      bool
	fee       uint32 // inner tx fee
	seq       int64
	ops       []xdr.Operation
	memoType  xdr.MemoType
	srcEd     []byte
	srcMuxed  bool
	sorobanOK bool
	resFee    int64
	fbFee     int64
}

func readRaw(e xdr.TransactionEnvelope) rawTx {
	var r rawTx
	r.envType = e.Type
	switch e.Type {
	case xdr.EnvelopeTypeEnvelopeTypeTxV0:
		t := e.V0.Tx
		r.fee, r.seq, r.ops, r.memoType = uint32(t.Fee), int64(t.SeqNum), t.Operations, t.Memo.Type
		r.srcEd = append([]byte{}, t.SourceAccountEd25519[:]...)
	case xdr.EnvelopeTypeEnvelopeTypeTx, xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
		v1 := e.V1
		if e.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
			r.isFB = true
			r.fbFee = int64(e.FeeBump.Tx.Fee)
			v1 = e.FeeBump.Tx.InnerTx.V1
		}
		t := v1.Tx
		r.fee, r.seq, r.ops, r.memoType = uint32(t.Fee), int64(t.SeqNum), t.Operations, t.Memo.Type
		switch t.SourceAccount.Type {
		case xdr.CryptoKeyTypeKeyTypeEd25519:
			r.srcEd = append([]byte{}, t.SourceAccount.Ed25519[:]...)
		case xdr.CryptoKeyTypeKeyTypeMuxedEd25519:
			r.srcMuxed = true
			r.srcEd = append([]byte{}, t.SourceAccount.Med25519.Ed25519[:]...)
		}
		if t.Ext.V == 1 && t.Ext.SorobanData != nil {
			r.sorobanOK = true
			r.resFee = int64(t.Ext.SorobanData.ResourceFee)
		}
	}
	return r
}

// ------------------------------------------------------------------ B: txnbuild

func innerTx(gt *txnbuild.GenericTransaction) *txnbuild.Transaction {
	if tx, ok := gt.Transaction(); ok {
		return tx
	}
	if fb, ok := gt.FeeBump(); ok {
		return fb.InnerTransaction()
	}
	return nil
}

var precondName = map[xdr.PreconditionType]string{xdr.PreconditionTypePrecondNone: "none", xdr.PreconditionTypePrecondTime: "time", xdr.PreconditionTypePrecondV2: "v2"}

// txDiff lists the differing fields, structural ones first (ext, ops, source, seq, memo) then cond and fee.
func txDiff(orig, rebuilt xdr.TransactionEnvelope, feeNotMultiple bool) (cls string, detail string) {
	inner := func(e xdr.TransactionEnvelope) xdr.TransactionEnvelope {
		if e.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
			return xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: e.FeeBump.Tx.InnerTx.V1}
		}
		return e
	}
	var c, d []string
	if orig.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump && rebuilt.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		if !bytes.Equal(mb(orig.FeeBump.Tx.FeeSource), mb(rebuilt.FeeBump.Tx.FeeSource)) {
			c = append(c, "feebump.source:differs")
			d = append(d, "feeBump.feeSource")
		}
	}
	a, b := inner(orig), inner(rebuilt)
	var ea, eb []byte
	if a.Type == xdr.EnvelopeTypeEnvelopeTypeTx {
		ea = mb(a.V1.Tx.Ext)
	} else {
		ea = []byte{0, 0, 0, 0}
	}
	if b.Type == xdr.EnvelopeTypeEnvelopeTypeTx {
		eb = mb(b.V1.Tx.Ext)
	} else {
		eb = []byte{0, 0, 0, 0}
	}
	if !bytes.Equal(ea, eb) {
		switch {
		case len(ea) > 4 && len(eb) == 4:
			c = append(c, "ext:lost")
		case len(ea) == 4 && len(eb) > 4:
			c = append(c, "ext:added")
		default:
			c = append(c, "ext:differs")
		}
		d = append(d, fmt.Sprintf("tx.ext(orig %d bytes, rebuilt %d bytes)", len(ea), len(eb)))
	}
	oa, ob := a.Operations(), b.Operations()
	if len(oa) != len(ob) {
		c = append(c, "op-count:differs")
		d = append(d, "op count")
	} else {
		for i := range oa {
			if !bytes.Equal(mb(oa[i]), mb(ob[i])) {
				c = append(c, "op:differs:"+opName(oa[i].Body.Type))
				d = append(d, fmt.Sprintf("op[%d %s]", i, opName(oa[i].Body.Type)))
				break
			}
		}
	}
	sa, sb := a.SourceAccount(), b.SourceAccount()
	if !bytes.Equal(mb(sa), mb(sb)) {
		c = append(c, "source:differs")
		d = append(d, "sourceAccount("+sa.Type.String()+")")
	}
	if a.SeqNum() != b.SeqNum() {
		c = append(c, "seq:differs")
		d = append(d, "seqNum")
	}
	ma, mm := a.Memo(), b.Memo()
	if !bytes.Equal(mb(ma), mm2(mm)) {
		c = append(c, "memo:differs")
		d = append(d, "memo("+ma.Type.String()+")")
	}
	ca, cb := a.Preconditions(), b.Preconditions()
	if !bytes.Equal(mb(ca), mb(cb)) {
		c = append(c, "cond:"+precondName[ca.Type]+">"+precondName[cb.Type])
		d = append(d, "cond("+ca.Type.String()+"->"+cb.Type.String()+")")
	}
	if a.Fee() != b.Fee() {
		if feeNotMultiple {
			c = append(c, "fee:not-multiple")
		} else {
			c = append(c, "fee:differs")
		}
		d = append(d, fmt.Sprintf("fee %d->%d (ops=%d)", a.Fee(), b.Fee(), len(oa)))
	}
	if orig.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump && rebuilt.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump &&
		orig.FeeBump.Tx.Fee != rebuilt.FeeBump.Tx.Fee {
		if feeNotMultiple {
			c = append(c, "feebump.fee:not-multiple")
		} else {
			c = append(c, "feebump.fee:differs")
		}
		d = append(d, fmt.Sprintf("feeBump.fee %d->%d", orig.FeeBump.Tx.Fee, rebuilt.FeeBump.Tx.Fee))
	}
	if len(c) == 0 {
		return "no-field-differs", "no field differs (envelope type " + orig.Type.String() + ")"
	}
	return strings.Join(c, ";"), strings.Join(d, "; ")
}

func mm2(m xdr.Memo) []byte { return mb(m) }

// rebuildTx: recipe (a). Source, sequence, operations, memo and preconditions from the parsed object; base fee =
// (inner fee - Soroban resource fee) / operations (txnbuild adds the resource fee from the operation's ext).
func rebuildTx(tx *txnbuild.Transaction, raw rawTx) (n *txnbuild.Transaction, retry, notMult bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	sa := tx.SourceAccount()
	var p txnbuild.Preconditions
	p.FromXDR(tx.ToXDR().Preconditions())
	ops := tx.Operations()
	nops := int64(len(ops))
	incl := int64(raw.fee) - raw.resFee
	base := int64(0)
	if nops > 0 {
		base = incl / nops
		notMult = incl%nops != 0
	}
	params := txnbuild.TransactionParams{SourceAccount: &sa, IncrementSequenceNum: false, Operations: ops,
		BaseFee: base, Memo: tx.Memo(), Preconditions: p}
	n, err = txnbuild.NewTransaction(params)
	if err != nil && strings.Contains(err.Error(), "timebounds must be constructed") {
		params.Preconditions.TimeBounds = txnbuild.NewInfiniteTimeout()
		retry = true
		n, err = txnbuild.NewTransaction(params)
	}
	return
}

// rebuildFeeBump: recipe (a). Base fee = (fee-bump fee - inner Soroban resource fee) / (inner operations + 1).
func rebuildFeeBump(fb *txnbuild.FeeBumpTransaction, raw rawTx) (n *txnbuild.FeeBumpTransaction, notMult bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	k := int64(len(raw.ops) + 1)
	incl := raw.fbFee - raw.resFee
	notMult = incl%k != 0
	n, err = txnbuild.NewFeeBumpTransaction(txnbuild.FeeBumpTransactionParams{Inner: fb.InnerTransaction(), FeeAccount: fb.FeeAccount(), BaseFee: incl / k})
	return
}

func checkB(tx *ingest.LedgerTransaction, raw rawTx, seq uint32, idx int, hash, types string, size int) {
	envB, err := tx.Envelope.MarshalBinary()
	if err != nil {
		fail("codec", "tx-envelope-encode:"+strip(err.Error()), seq, idx, hash, nil, types, err.Error(), size)
		return
	}
	env64 := base64.StdEncoding.EncodeToString(envB)
	var gt *txnbuild.GenericTransaction
	timed("tx-parse", func() {
		tested("tx-parse", 1)
		guard("tx-parse", "TransactionFromXDR", seq, idx, hash, types, size, func() {
			var e error
			gt, e = txnbuild.TransactionFromXDR(env64)
			if e != nil {
				gt = nil
				fail("tx-parse", "parse-error:"+strip(e.Error()), seq, idx, hash, nil, types, e.Error(), size)
			}
		})
	})
	if gt == nil {
		return
	}
	timed("tx-hash", func() {
		tested("tx-hash", 1)
		guard("tx-hash", "HashHex", seq, idx, hash, types, size, func() {
			h, e := gt.HashHex(pass)
			if e != nil {
				fail("tx-hash", "hash-error:"+strip(e.Error()), seq, idx, hash, nil, types, e.Error(), size)
			} else if h != hash {
				fail("tx-hash", "hash-differs", seq, idx, hash, nil, types, "sdk hash "+h, size)
			}
		})
	})
	timed("envelope-encode", func() {
		tested("envelope-encode", 1)
		guard("envelope-encode", "MarshalText", seq, idx, hash, types, size, func() {
			b, e := gt.MarshalText()
			if e != nil {
				fail("envelope-encode", "base64-error:"+strip(e.Error()), seq, idx, hash, nil, types, e.Error(), size)
			} else if string(b) != env64 {
				fail("envelope-encode", "base64-differs", seq, idx, hash, nil, types, "Base64() differs from input", size)
			}
		})
	})
	itx := innerTx(gt)
	if itx == nil {
		fail("tx-parse", "no-inner-transaction", seq, idx, hash, nil, types, "", size)
		return
	}
	timed("op-rebuild", func() {
		ops := itx.Operations()
		if len(ops) != len(raw.ops) {
			tested("op-rebuild", 1)
			fail("op-rebuild", "op-count-differs", seq, idx, hash, nil, types, fmt.Sprintf("parsed %d ops, envelope has %d", len(ops), len(raw.ops)), size)
			return
		}
		for i, o := range ops {
			tested("op-rebuild", 1)
			ot := opName(raw.ops[i].Body.Type)
			func() {
				defer func() {
					if p := recover(); p != nil {
						fail("op-rebuild", "buildxdr-panic:"+panicKind(fmt.Sprint(p)), seq, idx, hash, i, ot, fmt.Sprintf("%T.BuildXDR panic: %v", o, p), size)
					}
				}()
				built, e := o.BuildXDR()
				if e != nil {
					fail("op-rebuild", "buildxdr-error:"+strip(e.Error()), seq, idx, hash, i, ot, fmt.Sprintf("%T.BuildXDR error: %v", o, e), size)
					return
				}
				if !bytes.Equal(mb(built), mb(raw.ops[i])) {
					fail("op-rebuild", "buildxdr-differs", seq, idx, hash, i, ot, fmt.Sprintf("%T.BuildXDR differs from the operation's bytes", o), size)
				}
			}()
		}
	})
	timed("tx-rebuild", func() {
		tested("tx-rebuild", 1)
		want, _ := itx.HashHex(pass)
		n, retry, notMult, e := rebuildTx(itx, raw)
		if e != nil {
			c := "rebuild-error:" + strip(e.Error())
			if raw.isFB && int64(raw.fee) < raw.resFee {
				c += ";inner-fee-below-resource-fee"
			}
			fail("tx-rebuild", c, seq, idx, hash, nil, types, "NewTransaction: "+e.Error(), size)
			return
		}
		if h, _ := n.HashHex(pass); h != want {
			c, d := txDiff(itx.ToXDR(), n.ToXDR(), notMult)
			if retry {
				c += ";retry:infinite-timeout"
				d += " [no time bounds: retried with NewInfiniteTimeout]"
			}
			fail("tx-rebuild", "rebuild-differs:"+c, seq, idx, hash, nil, types, d, size)
		}
	})
	if fb, isFB := gt.FeeBump(); isFB {
		timed("feebump-rebuild", func() {
			tested("feebump-rebuild", 1)
			n, notMult, e := rebuildFeeBump(fb, raw)
			if e != nil {
				_ = notMult
				c := "rebuild-error:" + strip(e.Error())
				fail("feebump-rebuild", c, seq, idx, hash, nil, types, "NewFeeBumpTransaction: "+e.Error(), size)
				return
			}
			if h, _ := n.HashHex(pass); h != hash {
				c, d := txDiff(tx.Envelope, n.ToXDR(), notMult)
				fail("feebump-rebuild", "rebuild-differs:"+c, seq, idx, hash, nil, types, d, size)
			}
		})
	}
	timed("cb-id", func() { checkIDs(tx, itx, raw, seq, idx, hash, types, size) })
}

// checkIDs judges the computed id helpers against the ids the result and the meta state: ClaimableBalanceID
// (cb-id), the pool id of a pool-share ChangeTrust line (pool-id), xdr.Asset.ContractID for a contract created from
// an asset (contract-id).
func checkIDs(tx *ingest.LedgerTransaction, itx *txnbuild.Transaction, raw rawTx, seq uint32, idx int, hash, types string, size int) {
	if !tx.Result.Successful() {
		return
	}
	res, ok := tx.Result.Result.OperationResults()
	if !ok {
		return
	}
	ops := itx.Operations()
	for i, op := range raw.ops {
		ot := opName(op.Body.Type)
		switch op.Body.Type {
		case xdr.OperationTypeCreateClaimableBalance:
			if i >= len(res) || res[i].Tr == nil || res[i].Tr.CreateClaimableBalanceResult == nil || res[i].Tr.CreateClaimableBalanceResult.BalanceId == nil {
				continue
			}
			want, _ := xdr.MarshalHex(*res[i].Tr.CreateClaimableBalanceResult.BalanceId)
			tested("cb-id", 1)
			guard("cb-id", "ClaimableBalanceID", seq, idx, hash, types, size, func() {
				got, e := itx.ClaimableBalanceID(i)
				if e != nil {
					fail("cb-id", "error:"+strip(e.Error()), seq, idx, hash, i, ot, e.Error(), size)
				} else if !strings.EqualFold(got, want) {
					fail("cb-id", "id-differs", seq, idx, hash, i, ot, "ClaimableBalanceID "+got+" ledger "+want, size)
				}
			})
		case xdr.OperationTypeChangeTrust:
			if op.Body.ChangeTrustOp.Line.Type != xdr.AssetTypeAssetTypePoolShare || i >= len(ops) {
				continue
			}
			want := ""
			if chs, err := tx.GetOperationChanges(uint32(i)); err == nil {
				for _, c := range chs {
					e := c.Post
					if e == nil {
						e = c.Pre
					}
					if c.Type == xdr.LedgerEntryTypeTrustline && e != nil && e.Data.TrustLine != nil && e.Data.TrustLine.Asset.LiquidityPoolId != nil {
						id := *e.Data.TrustLine.Asset.LiquidityPoolId
						want = hex.EncodeToString(id[:])
					}
				}
			}
			if want == "" {
				continue
			}
			tested("pool-id", 1)
			guard("pool-id", "GetLiquidityPoolID", seq, idx, hash, types, size, func() {
				ct, ok := ops[i].(*txnbuild.ChangeTrust)
				if !ok {
					fail("pool-id", fmt.Sprintf("not-change-trust:%T", ops[i]), seq, idx, hash, i, ot, "", size)
					return
				}
				id, ok := ct.Line.GetLiquidityPoolID()
				if !ok {
					fail("pool-id", "no-pool-id", seq, idx, hash, i, ot, "GetLiquidityPoolID returned false", size)
				} else if got := hex.EncodeToString(id[:]); got != want {
					fail("pool-id", "id-differs", seq, idx, hash, i, ot, "GetLiquidityPoolID "+got+" ledger "+want, size)
				}
			})
		case xdr.OperationTypeInvokeHostFunction:
			hf := op.Body.InvokeHostFunctionOp.HostFunction
			var pre *xdr.ContractIdPreimage
			if hf.CreateContract != nil {
				pre = &hf.CreateContract.ContractIdPreimage
			} else if hf.CreateContractV2 != nil {
				pre = &hf.CreateContractV2.ContractIdPreimage
			}
			if pre == nil || pre.FromAsset == nil {
				continue
			}
			want := ""
			if chs, err := tx.GetOperationChanges(uint32(i)); err == nil {
				for _, c := range chs {
					if c.Type != xdr.LedgerEntryTypeContractData || c.Pre != nil || c.Post == nil || c.Post.Data.ContractData == nil {
						continue
					}
					cd := c.Post.Data.ContractData
					if cd.Key.Type == xdr.ScValTypeScvLedgerKeyContractInstance && cd.Contract.ContractId != nil {
						id := *cd.Contract.ContractId
						want, _ = strkey.Encode(strkey.VersionByteContract, id[:])
					}
				}
			}
			if want == "" {
				continue
			}
			tested("contract-id", 1)
			guard("contract-id", "Asset.ContractID", seq, idx, hash, types, size, func() {
				id, e := pre.FromAsset.ContractID(pass)
				if e != nil {
					fail("contract-id", "error:"+strip(e.Error()), seq, idx, hash, i, ot, e.Error(), size)
					return
				}
				if got, _ := strkey.Encode(strkey.VersionByteContract, id[:]); got != want {
					fail("contract-id", "asset-contract-id-differs", seq, idx, hash, i, ot, "Asset.ContractID "+got+" ledger "+want, size)
				}
			})
		}
	}
}

// ------------------------------------------------------------------ helper-panic: reflection sweep over LedgerTransaction

var errType = reflect.TypeOf((*error)(nil)).Elem()

func callHelpers(tx *ingest.LedgerTransaction, seq uint32, idx int, hash, types string, nops int, size int) {
	v := reflect.ValueOf(tx)
	t := v.Type()
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		mt := m.Type
		var argsets [][]reflect.Value
		switch {
		case mt.NumIn() == 1:
			argsets = [][]reflect.Value{{}}
		case mt.NumIn() == 2 && mt.In(1).Kind() == reflect.Uint32:
			for o := 0; o < nops; o++ {
				argsets = append(argsets, []reflect.Value{reflect.ValueOf(uint32(o)).Convert(mt.In(1))})
			}
		default:
			continue
		}
		for _, args := range argsets {
			tested("helper-panic", 1)
			var opi any
			if len(args) == 1 {
				opi = args[0].Uint()
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						fail("helper-panic", m.Name+":panic:"+panicKind(fmt.Sprint(r)), seq, idx, hash, opi, types, fmt.Sprintf("%s: panic: %v", m.Name, r), size)
					}
				}()
				res := v.Method(i).Call(args)
				for _, r := range res {
					if r.Type().Implements(errType) && !r.IsNil() {
						tested("helper-error", 1)
						e := r.Interface().(error)
						fail("helper-error", m.Name+":error:"+strip(e.Error()), seq, idx, hash, opi, types, fmt.Sprintf("%s: error: %v", m.Name, e), size)
					}
				}
			}()
		}
	}
}

// ------------------------------------------------------------------ byte-presence rule

// cmpE compares one helper answer with the bytes. present/bytesVal from the XDR; ok/helperVal from the helper.
func cmpE(name string, present bool, bytesVal any, ok bool, helperVal any, seq uint32, idx int, hash, types, tag string, size int) {
	tested("byte-presence", 1)
	bv, hv := fmt.Sprint(bytesVal), fmt.Sprint(helperVal)
	switch {
	case present && !ok:
		fail("byte-presence", name+":helper-absent-while-present"+tag, seq, idx, hash, nil, types, fmt.Sprintf("%s: bytes hold %s, helper says absent", name, bv), size)
	case !present && ok:
		fail("byte-presence", name+":helper-present-while-absent"+tag, seq, idx, hash, nil, types, fmt.Sprintf("%s: bytes hold nothing, helper says %s", name, hv), size)
	case present && ok && bv != hv:
		fail("byte-presence", name+":helper-value-differs"+tag, seq, idx, hash, nil, types, fmt.Sprintf("%s: bytes %s, helper %s", name, bv, hv), size)
	}
}

// callE runs a helper with panic recovery; a panic is recorded as its own byte-presence class.
func callE(name string, seq uint32, idx int, hash, types string, size int, f func()) {
	defer func() {
		if r := recover(); r != nil {
			tested("byte-presence", 1)
			fail("byte-presence", name+":helper-panics:"+panicKind(fmt.Sprint(r)), seq, idx, hash, nil, types, fmt.Sprintf("%s: panic: %v", name, r), size)
		}
	}()
	f()
}

func sorobanMetaV1(meta xdr.TransactionMeta) (present bool, nonRef, ref, rent int64) {
	var ext *xdr.SorobanTransactionMetaExt
	switch meta.V {
	case 3:
		if meta.V3 != nil && meta.V3.SorobanMeta != nil {
			ext = &meta.V3.SorobanMeta.Ext
		}
	case 4:
		if meta.V4 != nil && meta.V4.SorobanMeta != nil {
			ext = &meta.V4.SorobanMeta.Ext
		}
	}
	if ext == nil || ext.V != 1 || ext.V1 == nil {
		return false, 0, 0, 0
	}
	return true, int64(ext.V1.TotalNonRefundableResourceFeeCharged), int64(ext.V1.TotalRefundableResourceFeeCharged), int64(ext.V1.RentFeeCharged)
}

func checkE(tx *ingest.LedgerTransaction, raw rawTx, proto uint32, seq uint32, idx int, hash, types string, size int) {
	meta := tx.UnsafeMeta
	present, nonRef, ref, rent := sorobanMetaV1(meta)
	tag := ""
	callE("SorobanTotalNonRefundableResourceFeeCharged", seq, idx, hash, types, size, func() {
		v, ok := tx.SorobanTotalNonRefundableResourceFeeCharged()
		cmpE("SorobanTotalNonRefundableResourceFeeCharged", present, nonRef, ok, v, seq, idx, hash, types, tag, size)
	})
	callE("SorobanTotalRefundableResourceFeeCharged", seq, idx, hash, types, size, func() {
		v, ok := tx.SorobanTotalRefundableResourceFeeCharged()
		cmpE("SorobanTotalRefundableResourceFeeCharged", present, ref, ok, v, seq, idx, hash, types, tag, size)
	})
	callE("SorobanRentFeeCharged", seq, idx, hash, types, size, func() {
		v, ok := tx.SorobanRentFeeCharged()
		cmpE("SorobanRentFeeCharged", present, rent, ok, v, seq, idx, hash, types, tag, size)
	})
	callE("OperationCount", seq, idx, hash, types, size, func() {
		cmpE("OperationCount", true, len(raw.ops), true, tx.OperationCount(), seq, idx, hash, types, "", size)
	})
	callE("FeeCharged", seq, idx, hash, types, size, func() {
		v, ok := tx.FeeCharged()
		t := ""
		if raw.sorobanOK && raw.isFB && proto < 21 {
			t = "[p20-soroban-feebump]"
		}
		cmpE("FeeCharged", true, int64(tx.Result.Result.FeeCharged), ok, v, seq, idx, hash, types, t, size)
	})
	callE("Account", seq, idx, hash, types, size, func() {
		want, _ := strkey.Encode(strkey.VersionByteAccountID, raw.srcEd)
		v, err := tx.Account()
		cmpE("Account", true, want, err == nil, v, seq, idx, hash, types, "", size)
	})
	callE("AccountMuxed", seq, idx, hash, types, size, func() {
		_, ok := tx.AccountMuxed()
		cmpE("AccountMuxed", raw.srcMuxed, true, ok, true, seq, idx, hash, types, "", size)
	})
	callE("MemoType", seq, idx, hash, types, size, func() {
		cmpE("MemoType", true, int32(raw.memoType), true, int32(tx.Envelope.Memo().Type), seq, idx, hash, types, "", size)
		_ = tx.MemoType()
	})
	callE("AccountSequence", seq, idx, hash, types, size, func() {
		cmpE("AccountSequence", true, raw.seq, true, tx.AccountSequence(), seq, idx, hash, types, "", size)
	})
	callE("MaxFee", seq, idx, hash, types, size, func() {
		cmpE("MaxFee", true, raw.fee, true, tx.MaxFee(), seq, idx, hash, types, "", size)
	})
	callE("NewMaxFee", seq, idx, hash, types, size, func() {
		v, ok := tx.NewMaxFee()
		cmpE("NewMaxFee", raw.isFB, raw.fbFee, ok, v, seq, idx, hash, types, "", size)
	})
	callE("InnerTransactionHash", seq, idx, hash, types, size, func() {
		v, ok := tx.InnerTransactionHash()
		bv := ""
		if p := tx.Result.Result.Result.InnerResultPair; p != nil {
			bv = hex.EncodeToString(p.TransactionHash[:])
		}
		cmpE("InnerTransactionHash", raw.isFB, bv, ok, v, seq, idx, hash, types, "", size)
	})
	callE("IsSorobanTx", seq, idx, hash, types, size, func() {
		cmpE("IsSorobanTx", true, raw.sorobanOK, true, tx.IsSorobanTx(), seq, idx, hash, types, "", size)
	})
	callE("SorobanResourceFee", seq, idx, hash, types, size, func() {
		v, ok := tx.SorobanResourceFee()
		cmpE("SorobanResourceFee", raw.sorobanOK, raw.resFee, ok, v, seq, idx, hash, types, "", size)
	})
	callE("Successful", seq, idx, hash, types, size, func() {
		c := tx.Result.Result.Result.Code
		ok := c == xdr.TransactionResultCodeTxSuccess || c == xdr.TransactionResultCodeTxFeeBumpInnerSuccess
		cmpE("Successful", true, ok, true, tx.Successful(), seq, idx, hash, types, "", size)
	})
	callE("FeeAccountAddress", seq, idx, hash, types, size, func() {
		v, ok := tx.FeeAccountAddress()
		var want string
		switch raw.envType {
		case xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
			want = tx.Envelope.FeeBump.Tx.FeeSource.Address()
		case xdr.EnvelopeTypeEnvelopeTypeTx:
			want = tx.Envelope.V1.Tx.SourceAccount.Address()
		case xdr.EnvelopeTypeEnvelopeTypeTxV0:
			want, _ = strkey.Encode(strkey.VersionByteAccountID, raw.srcEd)
		}
		t := ""
		if raw.envType == xdr.EnvelopeTypeEnvelopeTypeTxV0 {
			t = "[tx-v0]"
		}
		cmpE("FeeAccountAddress", true, want, ok, v, seq, idx, hash, types, t, size)
	})
	if raw.sorobanOK {
		callE("GetContractEvents", seq, idx, hash, types, size, func() {
			var n int
			pres := false
			switch meta.V {
			case 3:
				if meta.V3.SorobanMeta != nil {
					pres, n = true, len(meta.V3.SorobanMeta.Events)
				}
			case 4:
				pres = true
				if len(meta.V4.Operations) > 0 {
					n = len(meta.V4.Operations[0].Events)
				}
			}
			ev, err := tx.GetContractEvents()
			cmpE("GetContractEvents.len", pres, n, err == nil, len(ev), seq, idx, hash, types, "", size)
		})
		callE("GetDiagnosticEvents", seq, idx, hash, types, size, func() {
			var n int
			pres := false
			switch meta.V {
			case 3:
				if meta.V3.SorobanMeta != nil {
					pres, n = true, len(meta.V3.SorobanMeta.DiagnosticEvents)
				}
			case 4:
				pres, n = true, len(meta.V4.DiagnosticEvents)
			}
			ev, err := tx.GetDiagnosticEvents()
			cmpE("GetDiagnosticEvents.len", pres, n, err == nil, len(ev), seq, idx, hash, types, "", size)
		})
	}
}

func checkELedger(lcm xdr.LedgerCloseMeta, nTx, nOK, nOps, nOpsOK int) {
	seq := uint32(0)
	var hdr xdr.LedgerHeader
	var ext *xdr.LedgerCloseMetaExt
	var live uint64
	liveOK := false
	nProc := 0
	switch lcm.V {
	case 0:
		hdr = lcm.V0.LedgerHeader.Header
		nProc = len(lcm.V0.TxProcessing)
	case 1:
		hdr, ext, live, liveOK, nProc = lcm.V1.LedgerHeader.Header, &lcm.V1.Ext, uint64(lcm.V1.TotalByteSizeOfLiveSorobanState), true, len(lcm.V1.TxProcessing)
	case 2:
		hdr, ext, live, liveOK, nProc = lcm.V2.LedgerHeader.Header, &lcm.V2.Ext, uint64(lcm.V2.TotalByteSizeOfLiveSorobanState), true, len(lcm.V2.TxProcessing)
	}
	seq = uint32(hdr.LedgerSeq)
	L := func(name string, f func()) { callE("ledger."+name, seq, -1, "", "-", 0, f) }
	E := func(name string, present bool, bv any, ok bool, hv any) {
		cmpE("ledger."+name, present, bv, ok, hv, seq, -1, "", "-", "", 0)
	}
	L("Sequence", func() { E("Sequence", true, uint32(hdr.LedgerSeq), true, ledgerh.Sequence(lcm)) })
	L("LedgerVersion", func() { E("LedgerVersion", true, uint32(hdr.LedgerVersion), true, ledgerh.LedgerVersion(lcm)) })
	L("CloseTime", func() { E("CloseTime", true, int64(hdr.ScpValue.CloseTime), true, ledgerh.CloseTime(lcm)) })
	L("BaseFee", func() { E("BaseFee", true, uint32(hdr.BaseFee), true, ledgerh.BaseFee(lcm)) })
	L("CountTransactions", func() { E("CountTransactions", true, nProc, true, lcm.CountTransactions()) })
	L("TransactionCounts", func() {
		ok, total := ledgerh.TransactionCounts(lcm)
		E("TransactionCounts.total", true, nTx, true, int(total))
		E("TransactionCounts.success", true, nOK, true, int(ok))
	})
	L("OperationCounts", func() {
		ok, total := ledgerh.OperationCounts(lcm)
		E("OperationCounts.total", true, nOps, true, int(total))
		E("OperationCounts.success", true, nOpsOK, true, int(ok))
	})
	L("SorobanFeeWrite1Kb", func() {
		v, ok := ledgerh.SorobanFeeWrite1Kb(lcm)
		pres := ext != nil && ext.V == 1 && ext.V1 != nil
		var bv int64
		if pres {
			bv = int64(ext.V1.SorobanFeeWrite1Kb)
		}
		E("SorobanFeeWrite1Kb", pres, bv, ok, v)
	})
	L("TotalByteSizeOfLiveSorobanState", func() {
		v, ok := ledgerh.TotalByteSizeOfLiveSorobanState(lcm)
		E("TotalByteSizeOfLiveSorobanState", liveOK, live, ok, v)
	})
}

// ------------------------------------------------------------------ T: token transfer

func evKey(e *token_transfer.TokenTransferEvent) (typ, key string) {
	typ = e.GetEventType()
	m := e.GetMeta()
	var parts []string
	if m != nil {
		parts = append(parts, fmt.Sprint(m.GetOperationIndex()), m.GetContractAddress())
		if mi := m.GetToMuxedInfo(); mi != nil {
			parts = append(parts, "mux="+mi.String())
		}
	}
	asset := ""
	if a := e.GetAsset(); a != nil {
		asset = a.String()
	}
	switch {
	case e.GetTransfer() != nil:
		x := e.GetTransfer()
		parts = append(parts, x.GetFrom(), x.GetTo(), x.GetAmount())
	case e.GetMint() != nil:
		x := e.GetMint()
		parts = append(parts, x.GetTo(), x.GetAmount())
	case e.GetBurn() != nil:
		x := e.GetBurn()
		parts = append(parts, x.GetFrom(), x.GetAmount())
	case e.GetClawback() != nil:
		x := e.GetClawback()
		parts = append(parts, x.GetFrom(), x.GetAmount())
	case e.GetFee() != nil:
		x := e.GetFee()
		parts = append(parts, x.GetFrom(), x.GetAmount())
	}
	parts = append(parts, asset)
	return typ, typ + "|" + strings.Join(parts, "|")
}

func ttpTx(p *token_transfer.EventsProcessor, tx ingest.LedgerTransaction) (evs []*token_transfer.TokenTransferEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	te, err := p.EventsFromTransaction(tx)
	if err != nil {
		return nil, err
	}
	evs = append(evs, te.FeeEvents...)
	evs = append(evs, te.OperationEvents...)
	return evs, nil
}

func modeDiff(a, b []*token_transfer.TokenTransferEvent) string {
	cnt := map[string]int{}
	typ := map[string]string{}
	for _, e := range a {
		t, k := evKey(e)
		cnt[k]++
		typ[k] = t
	}
	for _, e := range b {
		t, k := evKey(e)
		cnt[k]--
		typ[k] = t
	}
	lo, uo := map[string]bool{}, map[string]bool{}
	for k, n := range cnt {
		if n > 0 {
			lo[typ[k]] = true
		} else if n < 0 {
			uo[typ[k]] = true
		}
	}
	if len(lo) == 0 && len(uo) == 0 {
		return ""
	}
	var parts []string
	if len(lo) > 0 {
		parts = append(parts, "legacy-only:"+keys(lo))
	}
	if len(uo) > 0 {
		parts = append(parts, "unified-only:"+keys(uo))
	}
	return strings.Join(parts, ";")
}

func keys(m map[string]bool) string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

var reTxHash = regexp.MustCompile(`txHash: ([0-9a-f]{64})`)

func verifyClass(mode string, err error) (string, string) {
	m := err.Error()
	h := ""
	if mm := reTxHash.FindStringSubmatch(m); mm != nil {
		h = mm[1]
	}
	first := strings.SplitN(m, "\n", 2)[0]
	if i := strings.Index(first, " for ledgerSequence"); i > 0 {
		first = first[:i]
	}
	return "verify-" + mode + ":" + strip(first), h
}

// ------------------------------------------------------------------ sac-event: contractevents parse

var vocab = map[string]bool{"transfer": true, "mint": true, "burn": true, "clawback": true}

func scKind(v xdr.ScVal) string { return strings.TrimPrefix(v.Type.String(), "ScValTypeScv") }

// sacAssetOf: independent SAC test. The last topic is a canonical asset string and its contract id is the emitter.
func sacAssetOf(ev xdr.ContractEvent) bool {
	if ev.ContractId == nil || ev.Body.V != 0 {
		return false
	}
	t := ev.Body.V0.Topics
	if len(t) < 2 {
		return false
	}
	s, ok := t[len(t)-1].GetStr()
	if !ok {
		return false
	}
	var asset xdr.Asset
	str := string(s)
	if str == "native" {
		asset = xdr.MustNewNativeAsset()
	} else {
		parts := strings.Split(str, ":")
		if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 12 {
			return false
		}
		a, err := xdr.NewCreditAsset(parts[0], parts[1])
		if err != nil {
			return false
		}
		asset = a
	}
	id, err := asset.ContractID(pass)
	if err != nil {
		return false
	}
	return xdr.ContractId(id) == *ev.ContractId
}

func checkS(evs []xdr.ContractEvent, seq uint32, idx int, hash, types string, opIdx int, size int) {
	for _, ev := range evs {
		if ev.Type != xdr.ContractEventTypeContract || ev.Body.V != 0 || len(ev.Body.V0.Topics) == 0 {
			continue
		}
		sym, ok := ev.Body.V0.Topics[0].GetSym()
		if !ok || !vocab[string(sym)] {
			continue
		}
		tested("sac-event", 1)
		var kinds []string
		for _, t := range ev.Body.V0.Topics {
			kinds = append(kinds, scKind(t))
		}
		shape := fmt.Sprintf("%s:t%d:%s:d=%s", sym, len(ev.Body.V0.Topics), strings.Join(kinds, ","), scKind(ev.Body.V0.Data))
		isSAC := sacAssetOf(ev)
		var perr error
		func() {
			defer func() {
				if r := recover(); r != nil {
					perr = fmt.Errorf("panic: %v", r)
				}
			}()
			e := ev
			_, perr = contractevents.NewStellarAssetContractEvent(&e, pass)
		}()
		switch {
		case perr == nil && isSAC:
			// parsed
		case perr == nil && !isSAC:
			fail("sac-event", "accepted-non-sac:"+shape, seq, idx, hash, opIdx, types, "parsed although the emitter is not the asset's contract", size)
		case isSAC:
			fail("sac-event", "sac-parse-error:"+shape+":"+strip(perr.Error()), seq, idx, hash, opIdx, types, perr.Error(), size)
		default:
			fail("sac-event", "not-sac:"+shape+":"+strip(errorsRoot(perr)), seq, idx, hash, opIdx, types, perr.Error(), size)
		}
	}
}

func errorsRoot(e error) string {
	m := e.Error()
	if i := strings.Index(m, ": "); i > 0 && strings.HasPrefix(m, "event was not") {
		return m[:i]
	}
	if errors.Is(e, contractevents.ErrNotStellarAssetContract) {
		return contractevents.ErrNotStellarAssetContract.Error()
	}
	return m
}

func contractEventsOf(meta xdr.TransactionMeta) map[int][]xdr.ContractEvent {
	out := map[int][]xdr.ContractEvent{}
	switch meta.V {
	case 3:
		if meta.V3.SorobanMeta != nil {
			out[0] = meta.V3.SorobanMeta.Events
		}
	case 4:
		for i, op := range meta.V4.Operations {
			if len(op.Events) > 0 {
				out[i] = op.Events
			}
		}
	}
	return out
}

// ------------------------------------------------------------------ per ledger

var zdec *zstd.Decoder

func decode(raw []byte) (xdr.LedgerCloseMetaBatch, error) {
	var b xdr.LedgerCloseMetaBatch
	err := xdr.SafeUnmarshal(raw, &b)
	return b, err
}

type ledgerLine struct {
	seq                     uint32
	proto                   uint32
	txs                     int
	legacy, unified         map[string]int
	verifyFalse, verifyTrue string
	ms                      float64
}

func processLedger(seq0 uint32, path string, ttpOut *bufio.Writer) {
	t0 := time.Now()
	z, err := os.ReadFile(path)
	if err != nil {
		st.ReadErrors[fmt.Sprint(seq0)] = clip(err.Error(), 200)
		return
	}
	raw := z
	if strings.HasSuffix(path, ".zst") {
		raw, err = zdec.DecodeAll(z, nil)
		if err != nil {
			fail("codec", "zstd-error:"+strip(err.Error()), seq0, -1, "", nil, "-", err.Error(), 0)
			return
		}
	}
	var batch xdr.LedgerCloseMetaBatch
	okA := false
	timed("codec", func() {
		tested("codec", 1)
		b, e := decode(raw)
		if e != nil {
			fail("codec", "decode-error:"+strip(e.Error()), seq0, -1, "", nil, "-", e.Error(), 0)
			return
		}
		batch = b
		okA = true
		enc, e := batch.MarshalBinary()
		if e != nil {
			fail("codec", "encode-error:"+strip(e.Error()), seq0, -1, "", nil, "-", e.Error(), 0)
		} else if !bytes.Equal(enc, raw) {
			fail("codec", "re-encode-differs", seq0, -1, "", nil, "-", "re-encode differs", 0)
		}
	})
	if !okA {
		return
	}
	// a second, independent decode for token-transfer and VerifyEvents, so helper calls cannot hand them changed values
	batchT, _ := decode(raw)
	for li, lcm := range batch.LedgerCloseMetas {
		lcmT := batchT.LedgerCloseMetas[li]
		seq := lcm.LedgerSequence()
		proto := lcm.ProtocolVersion()
		st.Ledgers++
		bump := func(k string, n int64) {
			for _, s := range strings.Split(curStrata, ",") {
				if st.TestedTx[s] == nil {
					st.TestedTx[s] = map[string]int64{}
				}
				st.TestedTx[s][k] += n
			}
		}
		bump("ledgers", 1)
		line := ledgerLine{seq: seq, proto: proto, legacy: map[string]int{}, unified: map[string]int{}}
		rd, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(pass, lcm)
		if err != nil {
			fail("helper-error", "reader:"+strip(err.Error()), seq, -1, "", nil, "-", err.Error(), 0)
			continue
		}
		rdT, errT := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(pass, lcmT)
		pLegacy := token_transfer.NewEventsProcessor(pass)
		pUnified := token_transfer.NewEventsProcessorForUnifiedEvents(pass)
		band := "p>=23"
		if proto < 23 {
			band = "p<23"
		}
		nTx, nOK, nOps, nOpsOK := 0, 0, 0, 0
		for {
			tx, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				fail("helper-error", "reader.Read:"+strip(err.Error()), seq, -1, "", nil, "-", err.Error(), 0)
				break
			}
			var txT ingest.LedgerTransaction
			haveT := false
			if errT == nil {
				if t, e := rdT.Read(); e == nil {
					txT, haveT = t, true
				}
			}
			idx := int(tx.Index) - 1
			hash := hex.EncodeToString(tx.Hash[:])
			raw := readRaw(tx.Envelope)
			types := opTypes(raw.ops)
			size := len(mb(tx.Envelope))
			st.Txs++
			bump("txs", 1)
			bump("ops", int64(len(raw.ops)))
			nTx++
			nOps += len(raw.ops)
			if c := tx.Result.Result.Result.Code; c == xdr.TransactionResultCodeTxSuccess || c == xdr.TransactionResultCodeTxFeeBumpInnerSuccess {
				nOK++
				if rs, ok := tx.Result.Result.OperationResults(); ok {
					nOpsOK += len(rs)
				}
			}
			// T first, on its own decode
			if haveT {
				timed("token-transfer-modes", func() {
					tested("token-transfer-modes", 1)
					a, ea := ttpTx(pLegacy, txT)
					b, eb := ttpTx(pUnified, txT)
					for _, e := range a {
						line.legacy[e.GetEventType()]++
					}
					for _, e := range b {
						line.unified[e.GetEventType()]++
					}
					if ea != nil {
						fail("token-transfer-modes", "events-error:legacy:"+band+":"+strip(ea.Error()), seq, idx, hash, nil, types, ea.Error(), size)
					}
					if eb != nil {
						fail("token-transfer-modes", "events-error:unified:"+band+":"+strip(eb.Error()), seq, idx, hash, nil, types, eb.Error(), size)
					}
					if ea == nil && eb == nil {
						if d := modeDiff(a, b); d != "" {
							fail("token-transfer-modes", "mode-diff:"+band+":"+d, seq, idx, hash, nil, types, d, size)
						}
					}
				})
			}
			checkB(&tx, raw, seq, idx, hash, types, size)
			timed("byte-presence", func() { checkE(&tx, raw, proto, seq, idx, hash, types, size) })
			timed("sac-event", func() {
				guard("sac-event", "scan", seq, idx, hash, types, size, func() {
					for opi, evs := range contractEventsOf(tx.UnsafeMeta) {
						checkS(evs, seq, idx, hash, types, opi, size)
					}
				})
			})
			timed("helper-panic", func() { callHelpers(&tx, seq, idx, hash, types, len(raw.ops), size) })
		}
		timed("byte-presence", func() { checkELedger(lcm, nTx, nOK, nOps, nOpsOK) })
		line.txs = nTx
		timed("verify-events", func() {
			for _, mode := range []bool{false, true} {
				tested("verify-events", 1)
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							err = fmt.Errorf("panic: %v", r)
						}
					}()
					err = token_transfer.VerifyEvents(lcmT, pass, mode)
				}()
				name := "legacy"
				if mode {
					name = "unified"
				}
				if err != nil {
					c, h := verifyClass(name+":"+band, err)
					fail("verify-events", c, seq, -1, h, nil, "-", err.Error(), 0)
					if mode {
						line.verifyTrue = clip(err.Error(), 80)
					} else {
						line.verifyFalse = clip(err.Error(), 80)
					}
				}
			}
		})
		for k, n := range line.legacy {
			if st.TTPTypes["legacy"] == nil {
				st.TTPTypes["legacy"] = map[string]int64{}
			}
			st.TTPTypes["legacy"][k] += int64(n)
		}
		for k, n := range line.unified {
			if st.TTPTypes["unified"] == nil {
				st.TTPTypes["unified"] = map[string]int64{}
			}
			st.TTPTypes["unified"][k] += int64(n)
		}
		line.ms = float64(time.Since(t0).Microseconds()) / 1000
		fmt.Fprintf(ttpOut, "%d\t%d\t%d\t%s\t%s\t%s\t%s\t%.1f\n", seq, proto, line.txs, typeCounts(line.legacy), typeCounts(line.unified),
			okOr(line.verifyFalse), okOr(line.verifyTrue), line.ms)
	}
}

func okOr(s string) string {
	if s == "" {
		return "ok"
	}
	return strings.ReplaceAll(s, "\t", " ")
}

func typeCounts(m map[string]int) string {
	var s []string
	for _, k := range []string{"transfer", "mint", "burn", "clawback", "fee"} {
		s = append(s, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(s, ",")
}

// ------------------------------------------------------------------ main loop, snapshot, resume

func rusage() (cpu float64, rssMB float64) {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpu = float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	return cpu, float64(ru.Maxrss) / 1024
}

var cpuBase, wallBase float64
var runStart time.Time

func snapshot(dir string, ttpOut *bufio.Writer) {
	ttpOut.Flush()
	rollHits()
	cpu, rss := rusage()
	st.CPU = cpuBase + cpu
	st.Wall = wallBase + time.Since(runStart).Seconds()
	if rss > st.PeakRSSMB {
		st.PeakRSSMB = rss
	}
	st.Done = st.Done[:0]
	for s := range done {
		st.Done = append(st.Done, s)
	}
	sort.Slice(st.Done, func(i, j int) bool { return st.Done[i] < st.Done[j] })
	b, err := json.Marshal(st)
	if err != nil {
		panic(err)
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		panic(err)
	}
	f, _ := os.Open(tmp)
	f.Sync()
	f.Close()
	if err := os.Rename(tmp, filepath.Join(dir, "state.json")); err != nil {
		panic(err)
	}
}

func statusLine(path, state, note string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\t%s\t%s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"), state, note)
}

func priority(strata string) int {
	switch {
	case strings.Contains(strata, "S0"):
		return 0
	case strings.Contains(strata, "S3"), strings.Contains(strata, "S4"), strings.Contains(strata, "S5"):
		return 1
	case strings.Contains(strata, "S2"):
		return 2
	}
	return 3
}

func main() {
	runtime.GOMAXPROCS(1)
	index := flag.String("index", "", "index TSV: seq path size (header line allowed)")
	root := flag.String("root", "", "root for relative paths in the index")
	strataPath := flag.String("strata", "", "lists/all.tsv")
	outDir := flag.String("out", "", "output directory (state.json, ttp-ledgers.tsv)")
	only := flag.String("only", "", "file with sequences to restrict to")
	shard := flag.Int("shard", 0, "shard number")
	nshards := flag.Int("nshards", 1, "number of shards")
	deadline := flag.String("deadline", "", "RFC3339: stop starting new ledgers after this time")
	statusPath := flag.String("status", "", "stage status file to append progress lines to")
	tag := flag.String("tag", "go", "name in status lines")
	every := flag.Int("snapshot-every", 500, "ledgers between snapshots")
	flag.IntVar(&exPerStratum, "examples", 20, "example rows kept per cluster per stratum")
	dispPath := flag.String("dispositions", "", "dispositions table (hits are written for non-noise clusters)")
	rowsPath := flag.String("rows", "", "write every failing row as JSONL to this file")
	flag.StringVar(&pass, "passphrase", pass, "network passphrase")
	fieldsOut := flag.String("fields", "", "fields mode: write each transaction's fields as JSONL here (needs -cut and -list)")
	cutDir := flag.String("cut", "", "fields mode: directory of the reference cut (<seq>.jsonl.zst)")
	listPath := flag.String("list", "", "fields mode: ledger list (seq<TAB>path)")
	flag.Parse()
	if *fieldsOut != "" {
		fieldsMode(*fieldsOut, *cutDir, *listPath)
		return
	}
	if *rowsPath != "" {
		f, err := os.Create(*rowsPath)
		if err != nil {
			panic(err)
		}
		rowsOut = bufio.NewWriterSize(f, 1<<16)
		defer func() { rowsOut.Flush(); f.Close() }()
	}
	runStart = time.Now()
	zdec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	os.MkdirAll(*outDir, 0o755)

	if *strataPath != "" {
		f, err := os.Open(*strataPath)
		if err != nil {
			panic(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), "\t")
			if len(p) < 2 {
				continue
			}
			if n, err := strconv.ParseUint(p[0], 10, 32); err == nil {
				strataOf[uint32(n)] = p[1]
			}
		}
		f.Close()
	}
	var onlySet map[uint32]bool
	if *only != "" {
		onlySet = map[uint32]bool{}
		b, _ := os.ReadFile(*only)
		for _, l := range strings.Fields(string(b)) {
			if n, err := strconv.ParseUint(l, 10, 32); err == nil {
				onlySet[uint32(n)] = true
			}
		}
	}
	type item struct {
		seq  uint32
		path string
		pri  int
	}
	var items []item
	{
		f, err := os.Open(*index)
		if err != nil {
			panic(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), "\t")
			n, err := strconv.ParseUint(p[0], 10, 32)
			if err != nil || len(p) < 2 {
				continue
			}
			s := uint32(n)
			if onlySet != nil && !onlySet[s] {
				continue
			}
			path := p[1]
			if !filepath.IsAbs(path) {
				path = filepath.Join(*root, path)
			}
			items = append(items, item{s, path, priority(strataOf[s])})
		}
		f.Close()
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].pri != items[j].pri {
			return items[i].pri < items[j].pri
		}
		return items[i].seq > items[j].seq // newest first inside a priority band
	})
	var mine []item
	for i, it := range items {
		if i%*nshards == *shard {
			mine = append(mine, it)
		}
	}

	// resume
	st = &State{Tag: *tag, Clusters: map[string]*Cluster{}, Tested: map[string]int64{}, TestedTx: map[string]map[string]int64{},
		TTPTypes: map[string]map[string]int64{}, CheckCPU: map[string]float64{}, ReadErrors: map[string]string{}, Extra: map[string]map[string]int64{}}
	if b, err := os.ReadFile(filepath.Join(*outDir, "state.json")); err == nil {
		if err := json.Unmarshal(b, st); err != nil {
			panic(err)
		}
		for _, s := range st.Done {
			done[s] = true
		}
		cpuBase, wallBase = st.CPU, st.Wall
	}
	st.Runs = append(st.Runs, time.Now().UTC().Format(time.RFC3339))
	loadDispositions(*dispPath)
	openHits(filepath.Join(*outDir, "hits.tsv.zst"))
	ttpF, err := os.OpenFile(filepath.Join(*outDir, "ttp-ledgers.tsv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		panic(err)
	}
	ttpOut := bufio.NewWriterSize(ttpF, 1<<16)
	var dl time.Time
	if *deadline != "" {
		dl, err = time.Parse(time.RFC3339, *deadline)
		if err != nil {
			panic(err)
		}
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	stopped := false
	todo := 0
	for _, it := range mine {
		if !done[it.seq] {
			todo++
		}
	}
	statusLine(*statusPath, "progress", fmt.Sprintf("%s: run start, %d ledgers in shard, %d to do", *tag, len(mine), todo))
	n := 0
	lastStatus := time.Now()
	lastSnap := time.Now()
	reason := "complete"
	for _, it := range mine {
		if done[it.seq] {
			continue
		}
		select {
		case <-stop:
			stopped = true
			reason = "signal"
		default:
		}
		if !stopped && !dl.IsZero() && time.Now().After(dl) {
			stopped = true
			reason = "deadline"
		}
		if stopped {
			break
		}
		curSeq = it.seq
		curStrata = strataOf[it.seq]
		if curStrata == "" {
			curStrata = "none"
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					fail("codec", "ledger-panic:"+panicKind(fmt.Sprint(r)), it.seq, -1, "", nil, "-", fmt.Sprint(r), 0)
				}
			}()
			processLedger(it.seq, it.path, ttpOut)
		}()
		done[it.seq] = true
		n++
		if n%*every == 0 || time.Since(lastSnap) > 2*time.Minute {
			snapshot(*outDir, ttpOut)
			lastSnap = time.Now()
		}
		if time.Since(lastStatus) > 5*time.Minute {
			statusLine(*statusPath, "progress", fmt.Sprintf("%s: %d/%d ledgers this run, %d done in shard, %d txs, cpu %.0fs, rss %.0f MB",
				*tag, n, todo, len(done), st.Txs, st.CPU, st.PeakRSSMB))
			lastStatus = time.Now()
		}
	}
	snapshot(*outDir, ttpOut)
	hitsZ.Close()
	hitsFile.Close()
	ttpF.Close()
	left := 0
	for _, it := range mine {
		if !done[it.seq] {
			left++
		}
	}
	statusLine(*statusPath, "progress", fmt.Sprintf("%s: run end (%s): %d ledgers this run, %d left in shard, %d txs total, cpu %.0fs, peak rss %.0f MB",
		*tag, reason, n, left, st.Txs, st.CPU, st.PeakRSSMB))
	fmt.Printf("%s: %s, %d ledgers this run, %d left, %d txs, cpu %.1fs, rss %.0f MB\n", *tag, reason, n, left, st.Txs, st.CPU, st.PeakRSSMB)
}
