package conform

import (
	"fmt"
	"sort"
	"strings"
)

// The all-entries-read check. A column that answers n_a to every level of an entry, or whose driver declares no
// level the entry needs, has not read that entry at all; such a run can pass while the SDK never saw the bytes.
// Unread lists, per column, every selected entry variant that no cell of the column read: no cell where the
// driver was asked and gave an answer other than n_a, or crashed on it. A refusal, beyond the column's XDR schema
// or not, is a read: the SDK met the bytes. `xdrcheck conform run --require-all-read` fails on any item.

// Unread is one entry variant a column never read, with why.
type Unread struct {
	Column  string   `json:"column"`
	Entry   string   `json:"entry"`
	Variant string   `json:"variant,omitempty"`
	Reasons []string `json:"reasons"` // "<level> n_a/<reason>", "<level> not run", in level order
}

func (u Unread) String() string {
	v := u.Variant
	if v == "" {
		v = "-"
	}
	return fmt.Sprintf("%s %s %s: %s", u.Column, u.Entry, v, strings.Join(u.Reasons, ", "))
}

// read reports whether the observation shows the column's SDK met the input.
func (o *Observation) read() bool {
	switch {
	case o.Request == nil || o.ProtocolError != "" || o.NotRun != "":
		return false
	case o.Source == "orchestrator":
		return o.Outcome == "crash"
	}
	return o.Outcome != "" && o.Outcome != "n_a"
}

// Unread returns the entry variants each column never read, ordered by column, entry and variant.
func (r *Result) Unread() []Unread {
	type key struct{ column, entry, variant string }
	read := map[key]bool{}
	why := map[key][]string{}
	var order []key
	for _, o := range r.Observations {
		k := key{o.Cell.Column.ID, o.Cell.Entry.ID, o.Cell.VariantKey}
		if _, seen := read[k]; !seen {
			read[k] = false
			order = append(order, k)
		}
		if o.read() {
			read[k] = true
			continue
		}
		reason := o.Cell.Level + " not run"
		if o.NotRun == "" && o.ProtocolError == "" {
			reason = o.Cell.Level + " n_a/" + orDash(o.Reason)
		}
		why[k] = append(why[k], reason)
	}
	var out []Unread
	for _, k := range order {
		if !read[k] {
			out = append(out, Unread{Column: k.column, Entry: k.entry, Variant: k.variant, Reasons: why[k]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Column != out[j].Column {
			return out[i].Column < out[j].Column
		}
		return false
	})
	return out
}

// ReadCounts returns, per column, how many selected entry variants the run has for it and how many it read.
func (r *Result) ReadCounts() map[string][2]int {
	type key struct{ column, entry, variant string }
	read := map[key]bool{}
	for _, o := range r.Observations {
		k := key{o.Cell.Column.ID, o.Cell.Entry.ID, o.Cell.VariantKey}
		read[k] = read[k] || o.read()
	}
	out := map[string][2]int{}
	for k, ok := range read {
		c := out[k.column]
		c[0]++
		if ok {
			c[1]++
		}
		out[k.column] = c
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
