package conform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The acceptance assertions for the three JavaScript SDK defects the conformance runner must reproduce on their
// pre-fix releases and see fixed on the next one: js-stellar-sdk#1766 (asset order by strkey text instead of
// bytes; pre-fix 17.2.0, fixed 17.2.1), #1785 (offer and muxed IDs encoded as another ID; pre-fix 17.2.1, fixed
// 17.3.0) and #1789 (map entries dropped when keys collide in scValToNative; pre-fix 17.2.1, fixed 17.3.0).
//
// Each row names one entry, one or more columns and one level, and states what the cell must show: the driver's
// outcome (and reason), the verdict the engine reached against the manifest, the check against the entry's known
// divergences, and the facts that make the row specific (envelope counts, the rejected envelope, the value).
// The pre-fix rows require check "known": the divergence must be declared on the entry and observed inside its
// range, so removing a known divergence from an entry turns its row red. The fixed rows require check
// "conform". Nothing here is an expected value of its own: values the rows name are the manifest's (an entry's
// derived values and api expectations) or the defects' own published values.

// SDKRegressionColumns are the columns the assertions run on.
var SDKRegressionColumns = []string{"js@17.2.0", "js@17.2.1", "js@17.3.0"}

// SDKRegressionRow is one acceptance assertion.
type SDKRegressionRow struct {
	ID      string // a1 … c3
	Check   string // sdk-regression/js-1766, sdk-regression/js-1785, sdk-regression/js-1789
	Issue   string // the upstream defect
	Entry   string
	Columns []string
	Level   string
	Variant func(network string, protocol int) bool // nil: the entry has no variants (api) or any variant
	Want    SDKRegressionWant
}

// SDKRegressionWant is what a cell must show. Empty fields are not asserted.
type SDKRegressionWant struct {
	Outcome, Reason, Verdict, Check string
	// Facts asserts the row's specific facts on the observation and returns what differs.
	Facts func(o *Observation) []string
}

// SDKRegressionResult is one row on one column.
type SDKRegressionResult struct {
	Row      *SDKRegressionRow `json:"-"`
	ID       string            `json:"id"`
	Check    string            `json:"check"`
	Entry    string            `json:"entry"`
	Variant  string            `json:"variant,omitempty"`
	Column   string            `json:"column"`
	Level    string            `json:"level"`
	Observed string            `json:"observed"` // outcome/reason -> verdict, check
	Pass     bool              `json:"pass"`
	Problems []string          `json:"problems,omitempty"`
}

const (
	poolID          = "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"
	focusTx         = "0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f"
	reversedPoolID  = "c1324f878b3d11af9f923abb7d692fc74e0a7bcfd9a4edefd564efe5fdae9fdb"
	issuerLedger    = "cap-0038/pool-issuers-order-by-bytes-not-strkey"
	offerUnsafeNum  = "classic/api-offer-id-encoding.id-2-pow-53-plus-1-number"
	offerUnsafeStr  = "classic/api-offer-id-encoding.id-2-pow-53-plus-1-string"
	collidingKeyMap = "cap-0046/scval-map-keys-collide-u32-symbol"
)

func testnetP29(network string, protocol int) bool { return network == "testnet" && protocol == 29 }

// SDKRegressionRows returns the assertions a1–a7, b1–b5 and c1–c3.
func SDKRegressionRows() []*SDKRegressionRow {
	a, b, c := "https://github.com/stellar/js-stellar-sdk/issues/1766", "https://github.com/stellar/js-stellar-sdk/issues/1785", "https://github.com/stellar/js-stellar-sdk/issues/1789"
	known := func(outcome, reason, verdict string, facts func(*Observation) []string) SDKRegressionWant {
		return SDKRegressionWant{Outcome: outcome, Reason: reason, Verdict: verdict, Check: "known", Facts: facts}
	}
	conform := func(outcome, reason string, facts func(*Observation) []string) SDKRegressionWant {
		return SDKRegressionWant{Outcome: outcome, Reason: reason, Verdict: "conform", Check: "conform", Facts: facts}
	}
	return []*SDKRegressionRow{
		{ID: "a1", Check: "sdk-regression/js-1766", Issue: a, Entry: issuerLedger, Columns: []string{"js@17.2.0"}, Level: "L1", Variant: testnetP29,
			Want: known("reject", "ordering", "reject_valid", all(envelopesParsed(18), rejectedOnly(2)))},
		{ID: "a2", Check: "sdk-regression/js-1766", Issue: a, Entry: issuerLedger, Columns: []string{"js@17.2.1"}, Level: "L1", Variant: testnetP29,
			Want: conform("ok", "", all(envelopesParsed(19), focusHash(focusTx), focusDerived("pool_id", poolID)))},
		{ID: "a3", Check: "sdk-regression/js-1766", Issue: a, Entry: issuerLedger, Columns: []string{"js@17.2.0", "js@17.2.1"}, Level: "L0", Variant: testnetP29,
			Want: conform("ok", "", reencodedIdentical)},
		{ID: "a4", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0038/api-liquidity-pool-issuer-ordering.network-order", Columns: []string{"js@17.2.0"}, Level: "L4",
			Want: known("reject", "ordering", "reject_valid", nil)},
		{ID: "a4", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0038/api-liquidity-pool-issuer-ordering.network-order", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: conform("ok", "", apiValue(`"`+poolID+`"`))},
		{ID: "a5", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", Columns: []string{"js@17.2.0"}, Level: "L4",
			Want: known("ok", "", "accepts_invalid", apiValue(`"`+reversedPoolID+`"`))},
		{ID: "a5", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: conform("reject", "", nil)},
		{ID: "a6", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0046/api-scval-map-sort-order.u32-keys", Columns: []string{"js@17.2.0"}, Level: "L4",
			Want: known("ok", "", "diverge", apiValue(`["u32:10","u32:9"]`))},
		{ID: "a6", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0046/api-scval-map-sort-order.u32-keys", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: conform("ok", "", apiValue(`["u32:9","u32:10"]`))},
		{ID: "a7", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0046/api-scval-map-sort-order.bytes-keys", Columns: []string{"js@17.2.0"}, Level: "L4",
			Want: known("ok", "", "diverge", apiValue(`["bytes:0a","bytes:09"]`))},
		{ID: "a7", Check: "sdk-regression/js-1766", Issue: a, Entry: "cap-0046/api-scval-map-sort-order.bytes-keys", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: conform("ok", "", apiValue(`["bytes:09","bytes:0a"]`))},
		// #1785. An offer ID of 2^53+1 is valid (an int64); an SDK must encode it exactly or refuse the unsafe
		// JavaScript number it arrives as. 17.2.1 encodes 2^53 instead.
		{ID: "b1", Check: "sdk-regression/js-1785", Issue: b, Entry: offerUnsafeNum, Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: known("ok", "", "diverge", apiValue(`"9007199254740992"`))},
		{ID: "b2", Check: "sdk-regression/js-1785", Issue: b, Entry: offerUnsafeNum, Columns: []string{"js@17.3.0"}, Level: "L4",
			Want: conform("reject", "value_out_of_range", nil)},
		{ID: "b3", Check: "sdk-regression/js-1785", Issue: b, Entry: offerUnsafeStr, Columns: []string{"js@17.2.1", "js@17.3.0"}, Level: "L4",
			Want: conform("ok", "", apiValue(`"9007199254740993"`))},
		{ID: "b4", Check: "sdk-regression/js-1785", Issue: b, Entry: "cap-0027/api-muxed-account-id-encoding.id-hex-string", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: known("ok", "", "accepts_invalid", muxedID("0000000000000010"))},
		{ID: "b4", Check: "sdk-regression/js-1785", Issue: b, Entry: "cap-0027/api-muxed-account-id-encoding.id-hex-string", Columns: []string{"js@17.3.0"}, Level: "L4",
			Want: conform("reject", "", nil)},
		{ID: "b5", Check: "sdk-regression/js-1785", Issue: b, Entry: "classic/api-offer-id-encoding.id-negative", Columns: []string{"js@17.2.1"}, Level: "L4",
			Want: known("ok", "", "accepts_invalid", apiValue(`"-1"`))},
		{ID: "b5", Check: "sdk-regression/js-1785", Issue: b, Entry: "classic/api-offer-id-encoding.id-negative", Columns: []string{"js@17.3.0"}, Level: "L4",
			Want: conform("reject", "", nil)},
		// #1789: keys U32(1) and Symbol("1") both become the property "1" in scValToNative.
		{ID: "c1", Check: "sdk-regression/js-1789", Issue: c, Entry: collidingKeyMap, Columns: []string{"js@17.2.1"}, Level: "L3",
			Want: known("ok", "", "diverge", mapEntries(1))},
		{ID: "c2", Check: "sdk-regression/js-1789", Issue: c, Entry: collidingKeyMap, Columns: []string{"js@17.3.0"}, Level: "L3",
			Want: conform("reject", "lossy_conversion_refused", nil)},
		{ID: "c3", Check: "sdk-regression/js-1789", Issue: c, Entry: collidingKeyMap, Columns: []string{"js@17.2.1", "js@17.3.0"}, Level: "L0",
			Want: conform("ok", "", reencodedIdentical)},
	}
}

// SDKRegressionEntries returns the entry IDs the assertions use, sorted.
func SDKRegressionEntries() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range SDKRegressionRows() {
		if !seen[r.Entry] {
			seen[r.Entry] = true
			out = append(out, r.Entry)
		}
	}
	sort.Strings(out)
	return out
}

// AssertSDKRegression checks every row against judged observations (Result.Apply already run). A row whose cell is
// missing, was not judged, or broke the protocol fails.
func AssertSDKRegression(obs []*Observation) []SDKRegressionResult {
	var out []SDKRegressionResult
	for _, row := range SDKRegressionRows() {
		for _, col := range row.Columns {
			r := SDKRegressionResult{Row: row, ID: row.ID, Check: row.Check, Entry: row.Entry, Column: col, Level: row.Level}
			var cell *Observation
			for _, o := range obs {
				c := o.Cell
				if c.Entry.ID != row.Entry || c.Column.ID != col || c.Level != row.Level {
					continue
				}
				if row.Variant != nil && (c.Variant == nil || !row.Variant(c.Variant.Network, c.Variant.Protocol)) {
					continue
				}
				cell = o
				break
			}
			switch {
			case cell == nil:
				r.Problems = []string{"no such cell in the run (entry, variant, column or level missing)"}
			case cell.ProtocolError != "":
				r.Problems = []string{"protocol error: " + cell.ProtocolError}
			case cell.NotRun != "":
				r.Problems = []string{"not run: " + cell.NotRun}
			case cell.Judgement == nil:
				r.Problems = []string{"not judged"}
			default:
				r.Variant = cell.Cell.VariantKey
				r.Problems = row.Want.assert(cell)
				j := cell.Judgement
				r.Observed = fmt.Sprintf("%s%s -> %s, %s", cell.Outcome, slashed(cell.Reason), j.Verdict, j.Check)
			}
			r.Pass = len(r.Problems) == 0
			out = append(out, r)
		}
	}
	return out
}

func slashed(s string) string {
	if s == "" {
		return ""
	}
	return "/" + s
}

func (w SDKRegressionWant) assert(o *Observation) []string {
	var p []string
	want := func(what, got, want string) {
		if want != "" && got != want {
			p = append(p, fmt.Sprintf("%s %s, want %s", what, orNone(got), want))
		}
	}
	want("outcome", o.Outcome, w.Outcome)
	want("reason", o.Reason, w.Reason)
	want("verdict", o.Judgement.Verdict, w.Verdict)
	want("check", o.Judgement.Check, w.Check)
	if w.Check == "known" && o.Judgement.Check != "known" {
		p = append(p, "the entry must declare this divergence for the column (a known divergence observed inside its range)")
	}
	if w.Facts != nil {
		p = append(p, w.Facts(o)...)
	}
	return p
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func all(fs ...func(*Observation) []string) func(*Observation) []string {
	return func(o *Observation) []string {
		var p []string
		for _, f := range fs {
			p = append(p, f(o)...)
		}
		return p
	}
}

func object(o *Observation) *ObjectFacts {
	if o.Response == nil || o.Response.Actual == nil {
		return nil
	}
	return o.Response.Actual.Object
}

func envelopesParsed(n int64) func(*Observation) []string {
	return func(o *Observation) []string {
		ob := object(o)
		if ob == nil || ob.EnvelopesParsed == nil || *ob.EnvelopesParsed != n {
			return []string{fmt.Sprintf("envelopes_parsed %s, want %d", int64Text(ob, func(f *ObjectFacts) *int64 { return f.EnvelopesParsed }), n)}
		}
		return nil
	}
}

// rejectedOnly: exactly one envelope rejected, at apply index idx, for the asset-order rule.
func rejectedOnly(idx int64) func(*Observation) []string {
	return func(o *Observation) []string {
		ob := object(o)
		if ob == nil || len(ob.EnvelopesRejected) != 1 {
			n := 0
			if ob != nil {
				n = len(ob.EnvelopesRejected)
			}
			return []string{fmt.Sprintf("%d rejected envelopes, want exactly one", n)}
		}
		e := ob.EnvelopesRejected[0]
		var p []string
		if e.TxIndex == nil || *e.TxIndex != idx {
			p = append(p, fmt.Sprintf("rejected envelope at apply index %s, want %d", int64Ptr(e.TxIndex), idx))
		}
		if e.Code == nil || *e.Code != "ordering" {
			p = append(p, fmt.Sprintf("rejected envelope's reason %s, want ordering", strPtrText(e.Code)))
		}
		return p
	}
}

func focusHash(h string) func(*Observation) []string {
	return func(o *Observation) []string {
		ob := object(o)
		if ob == nil || ob.Focus == nil || ob.Focus.TxHash == nil || !strings.EqualFold(*ob.Focus.TxHash, h) {
			return []string{"focus transaction hash is not " + h}
		}
		return nil
	}
}

func focusDerived(key, want string) func(*Observation) []string {
	return func(o *Observation) []string {
		ob := object(o)
		if ob == nil || ob.Focus == nil || !strings.EqualFold(ob.Focus.Derived[key], want) {
			got := ""
			if ob != nil && ob.Focus != nil {
				got = ob.Focus.Derived[key]
			}
			return []string{fmt.Sprintf("focus derived %s %s, want %s", key, orNone(got), want)}
		}
		return nil
	}
}

// reencodedIdentical: the codec re-encoded the whole value byte for byte (the blob's hash and length).
func reencodedIdentical(o *Observation) []string {
	v := o.Cell.Variant
	if v == nil || o.Response == nil || o.Response.Actual == nil {
		return []string{"no re-encoding reported"}
	}
	a := o.Response.Actual
	if a.ReencodedSHA256 == nil || *a.ReencodedSHA256 != v.Blob.SHA256 || a.ConsumedBytes == nil || *a.ConsumedBytes != v.Blob.Bytes {
		return []string{"the re-encoding is not byte-identical to the blob"}
	}
	return nil
}

func apiResult(o *Observation) *APIResult {
	if o.Response == nil || o.Response.Actual == nil {
		return nil
	}
	return o.Response.Actual.API
}

// apiValue: the api value equals want as JSON (hex compared without regard to case).
func apiValue(want string) func(*Observation) []string {
	return func(o *Observation) []string {
		r := apiResult(o)
		if r == nil || r.Value == nil {
			return []string{"no api value, want " + want}
		}
		var g, w any
		if json.Unmarshal(r.Value, &g) != nil || json.Unmarshal([]byte(want), &w) != nil || !sameJSON(g, w) {
			return []string{fmt.Sprintf("api value %s, want %s", r.Value, want)}
		}
		return nil
	}
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.EqualFold(x, y)
}

// muxedID: the encoded MuxedAccount (KEY_TYPE_MUXED_ED25519, then the 64-bit ID) carries this ID.
func muxedID(idHex string) func(*Observation) []string {
	return func(o *Observation) []string {
		r := apiResult(o)
		if r == nil || r.XDRHex == nil || len(*r.XDRHex) < 24 || !strings.EqualFold((*r.XDRHex)[:8], "00000100") || !strings.EqualFold((*r.XDRHex)[8:24], idHex) {
			return []string{"the encoded muxed account does not carry ID 0x" + strings.TrimLeft(idHex, "0")}
		}
		return nil
	}
}

func mapEntries(n int64) func(*Observation) []string {
	return func(o *Observation) []string {
		if o.Response == nil || o.Response.Actual == nil || o.Response.Actual.Native == nil || o.Response.Actual.Native.MapEntries == nil || *o.Response.Actual.Native.MapEntries != n {
			return []string{fmt.Sprintf("native map entries not %d", n)}
		}
		return nil
	}
}

func int64Text(ob *ObjectFacts, get func(*ObjectFacts) *int64) string {
	if ob == nil {
		return "none"
	}
	return int64Ptr(get(ob))
}

func int64Ptr(p *int64) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprint(*p)
}

func strPtrText(p *string) string {
	if p == nil {
		return "none"
	}
	return *p
}
