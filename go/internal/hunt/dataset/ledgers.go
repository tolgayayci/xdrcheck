package dataset

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// TxRef is one transaction: a ledger and the 0-based position of the transaction in the ledger's apply order.
// Tx < 0 means the whole ledger.
type TxRef struct {
	Ledger uint32
	Tx     int
}

func (t TxRef) String() string {
	if t.Tx < 0 {
		return strconv.FormatUint(uint64(t.Ledger), 10)
	}
	return fmt.Sprintf("%d:%d", t.Ledger, t.Tx)
}

// MaxRange is the largest ledger range one argument may name.
const MaxRange = 1_000_000

// ParseLedgers parses a ledger list: comma-separated sequences and ranges (a-b, inclusive), and @FILE for a
// file with one sequence (or ledger<TAB>tx) per line. The result is sorted and without duplicates.
func ParseLedgers(s string) ([]uint32, error) {
	seen := map[uint32]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
			continue
		case strings.HasPrefix(part, "@"):
			refs, err := ReadRefs(part[1:])
			if err != nil {
				return nil, err
			}
			for _, r := range refs {
				seen[r.Ledger] = true
			}
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			lo, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
			hi, err2 := strconv.ParseUint(strings.TrimSpace(b), 10, 32)
			if err1 != nil || err2 != nil || hi < lo || lo == 0 {
				return nil, fmt.Errorf("bad ledger range %q", part)
			}
			if hi-lo+1 > MaxRange {
				return nil, fmt.Errorf("range %q is longer than %d ledgers", part, MaxRange)
			}
			for x := lo; x <= hi; x++ {
				seen[uint32(x)] = true
			}
		default:
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("bad ledger %q", part)
			}
			seen[uint32(n)] = true
		}
	}
	out := make([]uint32, 0, len(seen))
	for x := range seen {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ParseTx parses "ledger:index". (A transaction hash is resolved by the caller.)
func ParseTx(s string) (TxRef, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return TxRef{}, fmt.Errorf("bad transaction %q: want LEDGER:INDEX or a 64-hex hash", s)
	}
	l, err1 := strconv.ParseUint(a, 10, 32)
	t, err2 := strconv.ParseUint(b, 10, 31)
	if err1 != nil || err2 != nil || l == 0 {
		return TxRef{}, fmt.Errorf("bad transaction %q: want LEDGER:INDEX", s)
	}
	return TxRef{Ledger: uint32(l), Tx: int(t)}, nil
}

// IsHash reports whether s is a 64-character hex transaction hash.
func IsHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// OpenText opens a text file, decompressing it when its name ends in .zst.
func OpenText(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".zst") {
		return f, nil
	}
	d, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(1<<30))
	if err != nil {
		f.Close()
		return nil, err
	}
	return &zrc{d, f}, nil
}

type zrc struct {
	d *zstd.Decoder
	f *os.File
}

func (z *zrc) Read(p []byte) (int, error) { return z.d.Read(p) }
func (z *zrc) Close() error               { z.d.Close(); return z.f.Close() }

// ReadRefs reads a ledger or transaction list: one ledger per line, or ledger<TAB>tx_index (more columns are
// ignored); a header line and # comments are skipped. Rows of the first form get Tx = -1.
func ReadRefs(path string) ([]TxRef, error) {
	rc, err := OpenText(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var out []TxRef
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.FieldsFunc(l, func(r rune) bool { return r == '\t' || r == ' ' || r == ':' || r == ',' })
		n, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			continue // header
		}
		r := TxRef{Ledger: uint32(n), Tx: -1}
		if len(f) > 1 {
			if t, err := strconv.ParseUint(f[1], 10, 31); err == nil {
				r.Tx = int(t)
			}
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Ledgers returns the distinct ledgers of refs, sorted.
func Ledgers(refs []TxRef) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, r := range refs {
		if !seen[r.Ledger] {
			seen[r.Ledger] = true
			out = append(out, r.Ledger)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SetRefs reads a named set of the dataset.
func (m *Manifest) SetRefs(name string) ([]TxRef, error) {
	s := m.Sets[name]
	if s == nil {
		return nil, fmt.Errorf("no set %q in dataset %s (sets: %s)", name, m.Version, strings.Join(m.SetNames(), ", "))
	}
	if s.Missing != "" || s.File == nil {
		return nil, fmt.Errorf("not available: set %s missing (%s)", name, s.Missing)
	}
	return ReadRefs(m.Resolve(s.File.Path))
}
