// Package xcheck compares what two or more targets (or versions) compute for the same transactions. Each target
// writes one JSON row of fields per transaction; only fields both sides produced are compared, after the
// normalisation rules below, which are the whole of what xcheck forgives.
package xcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Rule is one normalisation rule.
type Rule struct {
	ID, Fields, What string
}

// Rules is the visible rule table (docs/xcheck.md prints it; `xcheck --rules` too).
var Rules = []Rule{
	{"op-type", "operations[].type", "operation names compared without case and underscores: ManageSellOffer, manageSellOffer and manage_sell_offer are equal; revoke*Sponsorship spellings are one name"},
	{"amount", "operations[].amount, limit, send_amount, dest_min, send_max, dest_amount", "decimal amounts compared as exact decimals: 10, 10.0, 10.0000000 and 1E1 are equal"},
	{"price", "operations[].price", "prices compared as exact reduced fractions (1/2, 2/4 and 0.5 are equal); a decimal with k fractional digits equals a fraction it is within 10^-k of (a rounded rendering)"},
	{"time-bounds", "time_bounds", "absent time bounds and min = max = 0 are equal"},
	{"hex", "hash, memo.value of hash and return memos", "hex compared lower-case"},
	{"integer", "fee, op_count", "integers compared as numbers"},
	{"text", "source, fee_source, destination, assets, memo text", "compared exactly (strkeys keep their M… form when muxed)"},
}

// Row is one target's fields of one transaction.
type Row map[string]any

// Read reads a fields JSONL file into ledger:tx → row.
func Read(path string) (map[string]Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]Row{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r Row
		// numbers stay exact: a float64 would round integers above 2^53 (ids, sequence numbers, amounts)
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.UseNumber()
		if err := d.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		out[fmt.Sprintf("%v:%v", num(r["ledger"]), num(r["tx"]))] = r
	}
	return out, sc.Err()
}

func num(v any) string {
	switch x := v.(type) {
	case float64:
		return fmt.Sprintf("%.0f", x)
	case json.Number:
		return x.String()
	}
	return fmt.Sprint(v)
}

// Diff is one field that two targets compute differently.
type Diff struct {
	Ledger string `json:"ledger"`
	Tx     string `json:"tx"`
	Field  string `json:"field"`
	A      string `json:"a"`
	AValue any    `json:"a_value"`
	B      string `json:"b"`
	BValue any    `json:"b_value"`
	Rule   string `json:"rule,omitempty"`
}

// Stats counts comparisons per field.
type Stats struct {
	Compared map[string]int `json:"compared"`
	Differ   map[string]int `json:"differ"`
	OnlyA    int            `json:"only_a"`
	OnlyB    int            `json:"only_b"`
	Txs      int            `json:"txs"`
}

var (
	camel   = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	revoke  = regexp.MustCompile(`^revoke_.*sponsorship$`)
	decimal = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][-+]?\d+)?$`)
)

func opType(s string) string {
	s = strings.ToLower(camel.ReplaceAllString(s, "${1}_${2}"))
	if revoke.MatchString(s) {
		return "revokesponsorship"
	}
	return strings.ReplaceAll(s, "_", "")
}

func rat(s string) (*big.Rat, bool) {
	r := new(big.Rat)
	if n, d, ok := strings.Cut(s, "/"); ok {
		a, ok1 := new(big.Int).SetString(n, 10)
		b, ok2 := new(big.Int).SetString(d, 10)
		if !ok1 || !ok2 || b.Sign() == 0 {
			return nil, false
		}
		return r.SetFrac(a, b), true
	}
	if !decimal.MatchString(s) {
		return nil, false
	}
	_, ok := r.SetString(s)
	return r, ok
}

// normal returns the normalised form of a field's value and the rule applied.
func normal(field string, v any) (string, string) {
	if v == nil {
		return "null", ""
	}
	s := fmt.Sprint(v)
	if f, ok := v.(float64); ok {
		s = fmt.Sprintf("%.0f", f)
	}
	if n, ok := v.(json.Number); ok {
		s = n.String()
	}
	base := field[strings.LastIndex(field, ".")+1:]
	switch base {
	case "type":
		if strings.HasPrefix(field, "operations") {
			return opType(s), "op-type"
		}
	case "amount", "limit", "send_amount", "dest_min", "send_max", "dest_amount", "price":
		if r, ok := rat(s); ok {
			if base == "price" {
				return r.RatString(), "price"
			}
			return r.RatString(), "amount"
		}
	case "hash":
		return strings.ToLower(s), "hex"
	case "fee", "op_count":
		return s, "integer"
	}
	if field == "memo.value" {
		return s, "text"
	}
	return s, ""
}

// flatten turns a row into field → value, operations indexed.
func flatten(prefix string, v any, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, y, out)
		}
	case []any:
		for i, y := range x {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), y, out)
		}
	default:
		out[prefix] = v
	}
}

var opIndex = regexp.MustCompile(`\[\d+\]`)

// Compare compares two targets' rows.
func Compare(a, b string, ra, rb map[string]Row) ([]Diff, Stats) {
	st := Stats{Compared: map[string]int{}, Differ: map[string]int{}}
	var diffs []Diff
	keys := map[string]bool{}
	for k := range ra {
		keys[k] = true
	}
	for k := range rb {
		keys[k] = true
	}
	var ks []string
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		x, okA := ra[k]
		y, okB := rb[k]
		switch {
		case !okA:
			st.OnlyB++
			continue
		case !okB:
			st.OnlyA++
			continue
		}
		st.Txs++
		led, tx, _ := strings.Cut(k, ":")
		ea, eb := x["error"], y["error"]
		if ea != nil || eb != nil {
			st.Compared["parse"]++
			if (ea == nil) != (eb == nil) {
				st.Differ["parse"]++
				diffs = append(diffs, Diff{Ledger: led, Tx: tx, Field: "parse", A: a, AValue: orOK(ea), B: b, BValue: orOK(eb)})
			}
			continue
		}
		fa, fb := map[string]any{}, map[string]any{}
		flatten("", map[string]any(x), fa)
		flatten("", map[string]any(y), fb)
		// absent time bounds on one side equal zero bounds on the other
		for _, f := range []map[string]any{fa, fb} {
			if f["time_bounds.min"] == "0" && f["time_bounds.max"] == "0" {
				delete(f, "time_bounds.min")
				delete(f, "time_bounds.max")
				f["time_bounds"] = nil
			}
		}
		var fields []string
		for f := range fa {
			if _, ok := fb[f]; ok && f != "ledger" && f != "tx" {
				fields = append(fields, f)
			}
		}
		sort.Strings(fields)
		for _, f := range fields {
			generic := opIndex.ReplaceAllString(f, "[]")
			st.Compared[generic]++
			na, rule := normal(f, fa[f])
			nb, _ := normal(f, fb[f])
			if na != nb && rule == "price" && roundedEqual(fmt.Sprint(fa[f]), fmt.Sprint(fb[f])) {
				continue
			}
			if na != nb {
				st.Differ[generic]++
				diffs = append(diffs, Diff{Ledger: led, Tx: tx, Field: f, A: a, AValue: fa[f], B: b, BValue: fb[f], Rule: rule})
			}
		}
	}
	return diffs, st
}

func orOK(v any) any {
	if v == nil {
		return "ok"
	}
	return v
}

// roundedEqual reports whether one price is a decimal rendering of the other (within 10^-k for k digits).
func roundedEqual(a, b string) bool {
	for _, p := range [][2]string{{a, b}, {b, a}} {
		dec, frac := p[0], p[1]
		if strings.Contains(dec, "/") || !strings.Contains(frac, "/") {
			continue
		}
		x, ok1 := rat(dec)
		y, ok2 := rat(frac)
		if !ok1 || !ok2 {
			continue
		}
		k := 0
		if i := strings.IndexByte(dec, '.'); i >= 0 {
			k = len(dec) - i - 1
		}
		tol := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(k)), nil))
		d := new(big.Rat).Sub(x, y)
		if d.Abs(d).Cmp(tol) < 0 {
			return true
		}
	}
	return false
}
