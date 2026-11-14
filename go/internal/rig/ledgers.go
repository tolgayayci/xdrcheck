// Package rig holds what the service rigs share: the ledger list and its contiguous segments, a read view of a
// lake-layout directory (with neighbours fetched on demand), a ledger analysis made with the SDK's own readers
// (the expected ledgers, transactions and entry keys a drop check compares exports with), and the run directory
// writers (manifest, per-ledger status, common rows).
//
// A rig drives a real pipeline built from source at a commit over real ledger bytes; it decides nothing about
// the rows. The judge reads them.
package rig

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// ParseLedgers reads a ledger spec: "A-B" (inclusive range), "A,B,C" (list; items may be ranges), or "@FILE"
// (first whitespace-separated column of each line; non-numeric lines such as a header are skipped). The result
// is sorted and without duplicates.
func ParseLedgers(spec string) ([]uint32, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty ledger spec")
	}
	var out []uint32
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) == 0 {
				continue
			}
			n, err := strconv.ParseUint(fs[0], 10, 32)
			if err != nil {
				continue
			}
			out = append(out, uint32(n))
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else {
		for _, item := range strings.Split(spec, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			a, b, isRange := strings.Cut(item, "-")
			lo, err := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("ledger %q: %v", item, err)
			}
			hi := lo
			if isRange {
				if hi, err = strconv.ParseUint(strings.TrimSpace(b), 10, 32); err != nil {
					return nil, fmt.Errorf("ledger %q: %v", item, err)
				}
			}
			if hi < lo || hi-lo > 10_000_000 {
				return nil, fmt.Errorf("ledger range %q is empty or too large", item)
			}
			for s := lo; s <= hi; s++ {
				out = append(out, uint32(s))
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ledger spec %q names no ledger", spec)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Segment is a run of consecutive ledgers, both ends inclusive.
type Segment struct {
	First, Last uint32
}

func (s Segment) String() string {
	if s.First == s.Last {
		return strconv.FormatUint(uint64(s.First), 10)
	}
	return fmt.Sprintf("%d-%d", s.First, s.Last)
}

// Len is the number of ledgers in the segment.
func (s Segment) Len() int { return int(s.Last-s.First) + 1 }

// Segments splits a sorted list into its contiguous runs.
func Segments(seqs []uint32) []Segment {
	var out []Segment
	for _, s := range seqs {
		if n := len(out); n > 0 && out[n-1].Last+1 == s {
			out[n-1].Last = s
			continue
		}
		out = append(out, Segment{s, s})
	}
	return out
}

// Shard deals segments to n shards round-robin by size (largest first), so shards get similar ledger counts.
func Shard(segs []Segment, n int) [][]Segment {
	if n < 1 {
		n = 1
	}
	order := slices.Clone(segs)
	slices.SortStableFunc(order, func(a, b Segment) int { return b.Len() - a.Len() })
	out := make([][]Segment, n)
	load := make([]int, n)
	for _, s := range order {
		i := slices.Index(load, slices.Min(load))
		out[i] = append(out[i], s)
		load[i] += s.Len()
	}
	for i := range out {
		slices.SortFunc(out[i], func(a, b Segment) int { return int(a.First) - int(b.First) })
	}
	return slices.DeleteFunc(out, func(s []Segment) bool { return len(s) == 0 })
}
