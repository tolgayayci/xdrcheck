// Package horizon is the Horizon service rig: it feeds real ledgers from a lake directory (SEP-54 layout, one
// ledger per file, 64,000 files per partition) to an unmodified stellar-horizon binary through
// `db reingest range --ledgerbackend datastore` with a Filesystem datastore, records a status per ledger
// (ingested, halted with Horizon's error text, skipped), and exports every history table Horizon filled, raw and
// as common rows. See README.md.
package horizon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const filesPerPartition = 64000

// LedgerPath is the path of a ledger's file inside a lake directory (one ledger per file).
func LedgerPath(seq uint32) string {
	p := seq / filesPerPartition * filesPerPartition
	return fmt.Sprintf("%08X--%d-%d/%08X--%d.xdr.zst", uint32(0xFFFFFFFF)-p, p, p+filesPerPartition-1,
		uint32(0xFFFFFFFF)-seq, seq)
}

// ParseRange parses `S-E` or `S` (inclusive).
func ParseRange(s string) ([]uint32, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		b = a
	}
	lo, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
	hi, err2 := strconv.ParseUint(strings.TrimSpace(b), 10, 32)
	if err1 != nil || err2 != nil || lo < 2 || hi < lo {
		return nil, fmt.Errorf("bad range %q (want S-E with 2 <= S <= E)", s)
	}
	out := make([]uint32, 0, hi-lo+1)
	for v := lo; v <= hi; v++ {
		out = append(out, uint32(v))
	}
	return out, nil
}

// ReadList reads ledger sequences, one per line; only the first whitespace-separated field counts, and lines
// whose first field is not a number (headers, comments) are ignored.
func ReadList(path string) ([]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []uint32
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fs[0], 10, 32)
		if err != nil || v < 2 {
			continue
		}
		out = append(out, uint32(v))
	}
	return out, sc.Err()
}

// Dedup sorts and removes duplicates.
func Dedup(seqs []uint32) []uint32 {
	s := append([]uint32(nil), seqs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Group is one `db reingest range From To` call.
type Group struct{ From, To uint32 }

func (g Group) String() string { return fmt.Sprintf("%d-%d", g.From, g.To) }

// Plan splits sorted, present ledgers into groups. In "single" mode every ledger is its own group (Horizon's
// history reingest needs no neighbours: a ledger ingested alone gives the same rows as inside a dense range). In
// "contiguous" mode maximal runs of consecutive ledgers become one group of at most maxGroup ledgers.
func Plan(seqs []uint32, mode string, maxGroup int) ([]Group, error) {
	if maxGroup < 1 {
		maxGroup = 1
	}
	var gs []Group
	switch mode {
	case "single":
		for _, s := range seqs {
			gs = append(gs, Group{s, s})
		}
	case "contiguous":
		for i := 0; i < len(seqs); {
			j := i
			for j+1 < len(seqs) && seqs[j+1] == seqs[j]+1 && j+1-i < maxGroup {
				j++
			}
			gs = append(gs, Group{seqs[i], seqs[j]})
			i = j + 1
		}
	default:
		return nil, fmt.Errorf("unknown group mode %q (single, contiguous)", mode)
	}
	return gs, nil
}

// Present splits ledgers into those whose file exists in the lake and those that do not (skipped, never sent to
// Horizon: a missing file would be the harness's gap, not Horizon's).
func Present(lake string, seqs []uint32) (have, missing []uint32) {
	for _, s := range seqs {
		if st, err := os.Stat(filepath.Join(lake, LedgerPath(s))); err == nil && st.Mode().IsRegular() {
			have = append(have, s)
		} else {
			missing = append(missing, s)
		}
	}
	return have, missing
}
