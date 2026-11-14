// Package verdict is the conformance verdict engine. It judges each observed cell twice:
//
//   - the verdict: the driver's outcome against the entry's reference (network, protocol-rule or spec). A
//     refusal of an input that must be refused is conform; an acceptance of it is accepts_invalid; a refusal of
//     a valid input is reject_valid; an acceptance with a value that differs from the manifest is diverge.
//     Which inputs must be refused is the validity (docs/manifest.md §9.5; a variant's own overrides its
//     entry's): malformed and invalid inputs must be refused, and an acceptable one is "exact or refuse": a
//     refusal conforms, and so does an acceptance with exactly the expected result. Values come only from the manifest (blob hashes,
//     derived values, expect.values pinpoints, expect.native, api expectations), never from another reader.
//     A negative entry whose core_behaviour says stellar-core's own decoder accepts the input is still to be
//     refused by the SDK columns, but on the core column (kind core) acceptance is the expected outcome and conforms.
//   - the check: the verdict against the entry's known divergences for the column's SDK, version and profile.
//     Inside a declared range the declared outcome (with its declared detail) is known, conform is
//     unexpected-conform and any other result is known-changed; outside every range conform is conform and
//     anything else is undeclared.
//
// Schema reach: a variant that needs an XDR feature the column's describe probes report absent (its
// `requires` list; without one, a protocol above the column's) is beyond the column's reach. There the only
// expected outcome is a clean refusal, at L0 or at a higher level when L0 of the same column was refused, for
// an undeclared union arm or enum value (Rust's stellar-xdr reports such refusals only as decode_error, which is
// accepted for it). Such a refusal is n_a; a crash is a failure; an acceptance is judged normally; known
// divergences are not evaluated there. A negative entry beyond reach is n_a.
//
// Level cascade: when a column's L0 cell for a variant is a known divergence, or a refusal beyond reach, its L1
// and L2 cells for that variant are n_a (blocked by L0).
//
// The package also builds the divergence matrix (matrix.go) and the views over it: check, diff, readiness. The
// rules are stated publicly in docs/conformance-protocol.md.
package verdict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// Assessment is the engine's full reasoning about one cell.
type Assessment struct {
	Reference       string // network, protocol-rule, spec
	Expected        string // accept, refuse, exact-or-refuse
	Verdict         string
	Check           string
	ExpectedVerdict string // what the manifest said this cell's verdict should be
	OutOfReach      bool   // the variant needs XDR the column's schema lacks
	BlockedByL0     bool   // n_a because the same column's L0 cell is known or refused beyond reach
	CoreLenient     bool   // stellar-core itself accepts this negative input (core_behaviour)
	Mismatches      []string
	Known           *manifest.KnownDivergence // the in-range divergence the check used
	Notes           []string
}

// Engine is the verdict engine. It implements conform.Judge.
type Engine struct{}

// Judge implements conform.Judge.
func (e Engine) Judge(o *conform.Observation) conform.Judgement {
	a := e.Assess(o)
	j := conform.Judgement{Verdict: a.Verdict, Check: a.Check, Expectation: "expected", Notes: a.Notes}
	if !expectedCheck(a.Check) {
		j.Expectation = "unexpected"
	}
	if k := a.Known; k != nil {
		j.Expected = &report.Expected{Source: "known_divergence", Result: a.ExpectedVerdict + " at " + o.Cell.Level}
		j.KnownDivergence = &report.DivergenceMatch{Reference: k.Reference, Status: statusOr(k.Status), InRange: true, FixedIn: k.FixedIn}
		if findingRe.MatchString(k.Finding) {
			f := k.Finding
			j.Finding = &f
		}
	} else {
		j.Expected = &report.Expected{Source: "default", Result: a.ExpectedVerdict + " at " + o.Cell.Level}
	}
	return j
}

var findingRe = regexp.MustCompile(`^F-[0-9]{4}$`)

func statusOr(s string) string {
	if s == "" {
		return "open"
	}
	return s
}

func expectedCheck(c string) bool { return c == "conform" || c == "known" || c == "n_a" }

// FailingCheck reports whether a check fails `xdrcheck conform check`.
func FailingCheck(c string) bool {
	return c == "undeclared" || c == "unexpected-conform" || c == "known-changed"
}

// Reference returns the entry's reference kind: its own, else network for positive ledger and xdr entries,
// protocol-rule for api entries and spec for negative xdr and every strkey entry.
func Reference(e *manifest.Entry) string {
	if e.Reference != "" {
		return e.Reference
	}
	switch {
	case e.Kind == "strkey", e.Kind == "xdr" && Negative(e, nil):
		return "spec"
	case e.Kind == "api":
		return "protocol-rule"
	}
	return "network"
}

// Validity is what a correct reader does with the cell's input (docs/manifest.md §9.5): the variant's own
// validity, else the entry's; "" when neither states one (an entry written before the field existed).
func Validity(e *manifest.Entry, v *manifest.Variant) string {
	if v != nil && v.Validity != "" {
		return v.Validity
	}
	return e.Validity
}

// MustRefuse reports whether the input must (or, for exact-or-refuse, may) be refused: its validity is
// malformed, invalid or acceptable. Without a validity, the entry's negative flag and reject expectations say it.
func MustRefuse(e *manifest.Entry, v *manifest.Variant) bool {
	switch Validity(e, v) {
	case "malformed", "invalid", "acceptable":
		return true
	case "valid":
		return false
	}
	return e.Negative || e.Expect.Reject != nil || (e.API != nil && e.API.ExpectReject)
}

// ExactOrRefuse reports whether either a refusal or exactly the expected result conforms: validity acceptable.
// Without a validity, an api entry with expect_reject and an exact expected result.
func ExactOrRefuse(e *manifest.Entry, v *manifest.Variant) bool {
	switch Validity(e, v) {
	case "acceptable":
		return true
	case "":
		return e.API != nil && e.API.ExpectReject && (e.API.ExpectXDRHex != "" || len(e.API.ExpectValue) > 0)
	}
	return false
}

// Negative reports whether a correct reader must refuse the input outright: validity malformed or invalid.
// Without a validity, the entry's negative flag.
func Negative(e *manifest.Entry, v *manifest.Variant) bool {
	switch Validity(e, v) {
	case "malformed", "invalid":
		return true
	case "":
		return e.Negative
	}
	return false
}

// divergenceVerdict maps a manifest known-divergence outcome to the verdict it predicts.
func divergenceVerdict(outcome string) string {
	switch outcome {
	case "reject":
		return "reject_valid"
	case "wrong_value":
		return "diverge"
	case "accepts_invalid":
		return "accepts_invalid"
	case "crash", "hang":
		return "crash"
	}
	return ""
}

// predicts reports whether a known divergence's outcome predicts the verdict. A wrong value predicts every
// verdict of an accepted value that differs: diverge, and at the json level schema_invalid and
// roundtrip_changed. A reject at the json level also predicts roundtrip_refused: the converter refuses the JSON
// it wrote for a valid value.
func predicts(outcome, verdict string) bool {
	if outcome == "wrong_value" && (verdict == "schema_invalid" || verdict == "roundtrip_changed") {
		return true
	}
	if outcome == "reject" && verdict == "roundtrip_refused" {
		return true
	}
	return divergenceVerdict(outcome) == verdict
}

// specAbsent reports whether a spec entry's Wasm has no spec section: a reader may return an empty interface or
// report the absence as an error, and both conform.
func specAbsent(e *manifest.Entry) bool {
	s := e.Expect.Spec
	return e.Kind == "spec" && s != nil && s.Sections != nil && *s.Sections == 0 && len(s.Entries) == 0 && s.CleanEnd
}

// schemaRefusalReasons are the reasons of a clean refusal of XDR the column's schema does not have.
var schemaRefusalReasons = map[string]bool{"union_arm_undeclared": true, "enum_undeclared": true}

// schemaRefusal reports whether a refusal beyond reach is the clean, expected one: an undeclared union arm or
// enum value; for a strkey text, an unknown version byte (the strkey form the SDK does not know); the Rust
// stellar-xdr column cannot tell those apart from other decode errors.
func schemaRefusal(o *conform.Observation) bool {
	switch {
	case schemaRefusalReasons[o.Reason]:
		return true
	case o.Cell.Entry.Kind == "strkey" && o.Reason == "strkey_version":
		return true
	}
	return o.Cell.Column.SDK == "rust" && o.Reason == "decode_error"
}

// Assess judges one observed cell.
func (Engine) Assess(o *conform.Observation) Assessment {
	c := o.Cell
	e := c.Entry
	a := Assessment{Reference: Reference(e), Expected: "accept"}
	refuse := MustRefuse(e, c.Variant)
	exact := ExactOrRefuse(e, c.Variant)
	switch {
	case exact:
		a.Expected = "exact-or-refuse"
	case refuse:
		a.Expected = "refuse"
	}
	if e.CoreBehaviour != nil && e.CoreBehaviour.Accepts && refuse {
		a.CoreLenient = true
		a.Notes = append(a.Notes, "core-lenient: stellar-core's own decoder accepts this input ("+e.CoreBehaviour.Observed+")")
		if c.Column.Kind == "core" {
			// The entry records that stellar-core accepts: on the core column that acceptance is what is expected.
			a.Expected = "accept"
			refuse, exact = false, false
		}
	}
	var reachNote string
	a.OutOfReach, reachNote = outOfReach(o)
	a.ExpectedVerdict = "conform"

	// The level cascade: a value L0 could not take (a known divergence, or a refusal beyond reach) never reaches
	// the object or value levels.
	if (c.Level == "L1" || c.Level == "L2") && o.L0 != nil && o.L0.Judgement != nil {
		j := o.L0.Judgement
		switch {
		case j.Check == "known":
			a.BlockedByL0 = true
			a.Notes = append(a.Notes, "n_a: blocked by L0 (a known divergence at L0)")
		case j.Verdict == "n_a" && o.L0.Outcome == "reject":
			a.BlockedByL0 = true
			a.Notes = append(a.Notes, "n_a: blocked by L0 (refused at L0 beyond the column's XDR schema)")
		}
		if a.BlockedByL0 {
			a.Verdict, a.Check = "n_a", "n_a"
			return a
		}
	}
	// Beyond reach, a refusal is expected at the first level the value meets: L0, a higher level when L0 of the
	// same column was refused too, or the only level an api or strkey entry has.
	firstLevel := c.Level == "L0" || o.L0 == nil || o.L0.Outcome == "reject"

	switch o.Outcome {
	case "n_a":
		a.Verdict = "n_a"
	case "crash":
		a.Verdict = "crash"
		if a.OutOfReach {
			a.Notes = append(a.Notes, "a crash on a variant beyond the column's XDR schema ("+reachNote+"): only a clean refusal is expected")
		}
	case "reject":
		switch {
		case a.OutOfReach && Negative(e, c.Variant):
			a.Verdict = "n_a"
			a.Notes = append(a.Notes, fmt.Sprintf("negative entry beyond the column's XDR schema (%s): its refusal (%s) cannot be told from the schema's", reachNote, o.Reason))
		case a.OutOfReach && firstLevel && schemaRefusal(o):
			a.Verdict = "n_a"
			a.Notes = append(a.Notes, fmt.Sprintf("clean refusal of a variant beyond the column's XDR schema (%s): %s, expected", reachNote, o.Reason))
		case refuse:
			a.Verdict = "conform"
			if want := rejectReason(e); want != "" && o.Reason != "" && o.Reason != want && o.Reason != "decode_error" && o.Reason != "other" {
				a.Notes = append(a.Notes, fmt.Sprintf("refused for %s; the entry names %s", o.Reason, want))
			}
		case c.Level == "spec" && specAbsent(e):
			a.Verdict = "conform"
			a.Notes = append(a.Notes, "the reader reports a Wasm without a contractspecv0 section as an error ("+o.Reason+"); an empty interface would conform too")
		case c.Level == "L3" && o.Reason == "lossy_conversion_refused" && nativeErrorOnLoss(e):
			// The entry says a conversion that would lose entries must fail: refusing it is the conforming answer.
			a.Verdict = "conform"
		default:
			a.Verdict = "reject_valid"
			if a.OutOfReach {
				a.Notes = append(a.Notes, fmt.Sprintf("a variant beyond the column's XDR schema (%s) was refused for %s, not as an undeclared union arm or enum value", reachNote, o.Reason))
			}
		}
	case "diverge":
		a.Verdict = "diverge"
		if refuse && !exact {
			a.Verdict = "accepts_invalid"
		}
		a.Mismatches = append(a.Mismatches, "driver: "+o.Reason)
	case "ok":
		if refuse && !exact {
			a.Verdict = "accepts_invalid"
			break
		}
		a.Mismatches = compare(o)
		a.Verdict = "conform"
		if len(a.Mismatches) > 0 {
			a.Verdict = "diverge"
		}
		if c.Level == conform.JSONLevel && o.Response != nil && o.Response.Actual != nil {
			// The three json verdicts are kept apart: the JSON breaks the converter's own schema; or its round
			// trip back to XDR changes or refuses the bytes. Bindings that differ from each other are a
			// cross-SDK split, not a cell verdict.
			if v := jsonVerdict(o.Response.Actual.JSON); v != "" {
				a.Verdict = v
			}
		}
	default:
		a.Verdict = "n_a"
	}
	if len(a.Mismatches) > 0 {
		a.Notes = append(a.Notes, a.Mismatches...)
	}

	// The check against the known divergences.
	if a.Verdict == "n_a" {
		a.Check = "n_a"
		return a
	}
	var inRange []*manifest.KnownDivergence
	if !a.OutOfReach {
		var err error
		if inRange, err = Applicable(e, c.Column, c.Level, c.Sandbox); err != nil {
			a.Notes = append(a.Notes, err.Error())
		}
	}
	if len(inRange) == 0 {
		a.Check = "undeclared"
		if a.Verdict == "conform" {
			a.Check = "conform"
		}
		return a
	}
	a.Known = inRange[0]
	a.ExpectedVerdict = divergenceVerdict(inRange[0].Outcome)
	var detailMiss []string
	for _, k := range inRange {
		if !predicts(k.Outcome, a.Verdict) {
			continue
		}
		if miss := detailMismatch(k, o); miss != "" {
			detailMiss = append(detailMiss, miss)
			a.Known = k
			continue
		}
		a.Known, a.ExpectedVerdict, a.Check = k, a.Verdict, "known"
		return a
	}
	if a.Verdict == "conform" {
		a.Check = "unexpected-conform"
	} else {
		a.Check = "known-changed"
		a.Notes = append(a.Notes, detailMiss...)
	}
	return a
}

// detailMismatch compares an observed cell with a known divergence's declared detail; "" when it matches. The
// stated fields of `match` must equal the driver's report; and an L1 refusal on a ledger whose variant names a
// focus transaction must list that transaction among the rejected envelopes, because the divergence is about
// the entry's pattern.
func detailMismatch(k *manifest.KnownDivergence, o *conform.Observation) string {
	var ob *conform.ObjectFacts
	if r := o.Response; r != nil && r.Actual != nil {
		ob = r.Actual.Object
	}
	if m := k.Match; m != nil {
		if m.Reason != "" && m.Reason != o.Reason {
			return fmt.Sprintf("known divergence %s declares reason %s; the driver reports %s", k.Versions, m.Reason, orDash(o.Reason))
		}
		if m.EnvelopesParsed != nil && (ob == nil || ob.EnvelopesParsed == nil || *ob.EnvelopesParsed != int64(*m.EnvelopesParsed)) {
			return fmt.Sprintf("known divergence %s declares %d envelopes parsed; the driver reports %s", k.Versions, *m.EnvelopesParsed, int64Str(ob, func(f *conform.ObjectFacts) *int64 { return f.EnvelopesParsed }))
		}
		if m.RejectedTxIndex != nil && !rejectedAt(ob, *m.RejectedTxIndex, "") {
			return fmt.Sprintf("known divergence %s declares the envelope at apply index %d rejected; the driver does not list it", k.Versions, *m.RejectedTxIndex)
		}
	}
	v := o.Cell.Variant
	if k.Outcome == "reject" && o.Cell.Level == "L1" && v != nil && v.Focus != nil && ob != nil && len(ob.EnvelopesRejected) > 0 {
		idx := -1
		if v.Focus.TxIndex != nil {
			idx = *v.Focus.TxIndex
		}
		hash := v.Focus.TxHash
		if hash == "" {
			hash = derivedString(v.Derived, "tx_hash")
		}
		if (idx >= 0 || hash != "") && !rejectedAt(ob, idx, hash) {
			return fmt.Sprintf("known divergence %s is about the focus transaction (apply index %d); the driver rejected other envelopes", k.Versions, idx)
		}
	}
	return ""
}

// rejectedAt reports whether the object lists a rejected envelope at apply index idx (when idx >= 0) or with
// the given hash (when not "").
func rejectedAt(ob *conform.ObjectFacts, idx int, hash string) bool {
	if ob == nil {
		return false
	}
	for _, r := range ob.EnvelopesRejected {
		if idx >= 0 && r.TxIndex != nil && *r.TxIndex == int64(idx) {
			return true
		}
		if hash != "" && r.TxHash != nil && strings.EqualFold(*r.TxHash, hash) {
			return true
		}
	}
	return false
}

func int64Str(ob *conform.ObjectFacts, get func(*conform.ObjectFacts) *int64) string {
	if ob == nil || get(ob) == nil {
		return "none"
	}
	return fmt.Sprint(*get(ob))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Applicable returns the entry's known divergences that cover the column at the level: same target, a
// conformance level equal to the cell's (or none given), a profile equal to the column's decode profile or to
// the address-space sandbox the cell ran under, restricted to the decode profile that sandbox names if any (or
// none given; conform.ProfileCovers), and a version range that contains the column's
// version. An unparsable range is an error (CheckRanges refuses it before a run).
func Applicable(e *manifest.Entry, col *conform.Column, level, sandbox string) ([]*manifest.KnownDivergence, error) {
	if e.Conformance == nil {
		return nil, nil
	}
	var out []*manifest.KnownDivergence
	for i := range e.Conformance.KnownDivergences {
		k := &e.Conformance.KnownDivergences[i]
		if k.Target != col.Target || k.Level == "replay" || (k.Level != "" && k.Level != level) {
			continue
		}
		if !conform.ProfileCovers(k.Profile, col.Profile, sandbox) {
			continue
		}
		ok, err := InRange(col.Version, k.Versions)
		if err != nil {
			return nil, fmt.Errorf("%s: known divergence for %s: version range %q: %v", e.ID, k.Target, k.Versions, err)
		}
		if ok {
			out = append(out, k)
		}
	}
	return out, nil
}

// CheckRanges returns an error naming every entry whose conformance known divergences (every level but replay)
// carry a version range that does not parse. A run refuses to start on such a corpus: a range that cannot be
// read would silently assert nothing.
func CheckRanges(entries []*manifest.Entry) error {
	var bad []string
	for _, e := range entries {
		if e.Conformance == nil {
			continue
		}
		for _, k := range e.Conformance.KnownDivergences {
			if k.Level == "replay" {
				continue
			}
			if _, err := InRange("0.0.0", k.Versions); err != nil {
				bad = append(bad, fmt.Sprintf("%s: known divergence for %s: version range %q: %v", e.ID, k.Target, k.Versions, err))
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("unparsable known-divergence version ranges:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

func nativeErrorOnLoss(e *manifest.Entry) bool {
	return e.Expect.Native != nil && e.Expect.Native.OnLossyConversion == "error"
}

func rejectReason(e *manifest.Entry) string {
	if e.Expect.Reject != nil {
		return e.Expect.Reject.Reason
	}
	return ""
}

// featureProbes maps a variant's required XDR feature to the describe probe that says whether the column's
// schema has it. A feature not listed here is its own probe name.
var featureProbes = map[string]string{}

func probeFor(feature string) string {
	if p, ok := featureProbes[feature]; ok {
		return p
	}
	return feature
}

// outOfReach reports whether the cell's variant is beyond what the column's generated XDR can represent, and
// why. A variant with a `requires` list is out of reach only if the column's describe reports a probe for a
// required feature as false (a feature without a probe is assumed present). Without the list, the protocol
// rule applies: the variant's protocol (the entry's, for api and strkey entries) above the column's
// xdr_schema.protocol. A column that reports no protocol (its driver cannot bound the SDK's XDR, for example
// one newer than the driver's probes) has nothing beyond reach by protocol: a refusal is judged, never excused.
func outOfReach(o *conform.Observation) (bool, string) {
	d := o.Describe
	if d == nil || d.XDRSchema == nil {
		return false, ""
	}
	if v := o.Cell.Variant; v != nil && v.Requires != nil {
		for _, f := range v.Requires {
			if has, ok := d.XDRSchema.Probes[probeFor(f)]; ok && !has {
				return true, "needs " + f
			}
		}
		return false, ""
	}
	if d.XDRSchema.Protocol == nil {
		return false, ""
	}
	reach := *d.XDRSchema.Protocol
	p := o.Cell.Entry.Protocol.Introduced
	if v := o.Cell.Variant; v != nil {
		p = v.Protocol
	}
	if p > reach {
		return true, fmt.Sprintf("protocol %d, the schema reaches %d", p, reach)
	}
	return false, ""
}

// compare checks an accepted cell's facts against the manifest. It returns the differences. The driver
// protocol guarantees the evidence an accepted cell needs is present (conform.CheckEvidence), and a missing
// fact the manifest states is a difference here too; only a selftest column (the orchestrator's stub, which
// wraps no SDK) is compared on the facts it reports. A fact the manifest does not state is not compared.
func compare(o *conform.Observation) []string {
	if o.Response == nil {
		return nil
	}
	act := o.Response.Actual
	c := o.Cell
	e, v := c.Entry, c.Variant
	var diffs []string
	bad := func(format string, args ...any) { diffs = append(diffs, fmt.Sprintf(format, args...)) }
	strict := c.Column == nil || c.Column.Kind != "selftest"
	switch c.Level {
	case "L0":
		if v == nil {
			break
		}
		if conform.NoReencode(c) {
			// The stellar-core column never re-encodes: it must have read exactly the input.
			switch {
			case act == nil || act.ConsumedBytes == nil:
				bad("L0: no consumed byte count")
			case *act.ConsumedBytes != v.Blob.Bytes:
				bad("L0: consumed %d bytes of %d", *act.ConsumedBytes, v.Blob.Bytes)
			}
			break
		}
		if act == nil || act.ReencodedSHA256 == nil || act.ConsumedBytes == nil {
			if strict {
				bad("L0: no re-encoding hash or consumed byte count")
			}
			break
		}
		if *act.ReencodedSHA256 != v.Blob.SHA256 {
			bad("L0: re-encoding sha256 %s, the blob is %s", *act.ReencodedSHA256, v.Blob.SHA256)
		}
		if *act.ConsumedBytes != v.Blob.Bytes {
			bad("L0: consumed %d bytes of %d", *act.ConsumedBytes, v.Blob.Bytes)
		}
	case "L1":
		if v == nil {
			break
		}
		if act == nil || act.Object == nil {
			if strict {
				bad("L1: no object facts")
			}
			break
		}
		compareObject(act.Object, e, v, strict, bad)
	case "L2":
		var want []manifest.Value
		if v != nil && v.Resolved != nil {
			want = v.Resolved.Values
		}
		if len(want) == 0 {
			break
		}
		got := map[string]conform.PinpointResult{}
		if act != nil {
			for _, p := range act.Pinpoints {
				got[*p.Path] = p
			}
		}
		for _, w := range want {
			p, ok := got[w.Path]
			switch {
			case !ok:
				bad("L2: pinpoint %s not returned", w.Path)
			case !*p.Found:
				bad("L2: pinpoint %s not found in the SDK's value", w.Path)
			default:
				var val any
				if err := decodeNumber(p.Value, &val); err != nil {
					bad("L2: pinpoint %s: %v", w.Path, err)
				} else if !equalValues(val, w.Equals) {
					bad("L2: %s is %s, the manifest says %s", w.Path, short(p.Value), short(mustJSON(w.Equals)))
				}
			}
		}
	case "L3":
		n := e.Expect.Native
		if v != nil && v.Resolved != nil && v.Resolved.Native != nil {
			n = v.Resolved.Native
		}
		if n == nil {
			break
		}
		if act == nil || act.Native == nil {
			bad("L3: no native facts")
			break
		}
		if n.MapEntries != nil && (act.Native.MapEntries == nil || int64(*n.MapEntries) != *act.Native.MapEntries) {
			bad("L3: native map has %s entries, the value has %d", int64Ptr(act.Native.MapEntries), *n.MapEntries)
		}
		if n.BytesPreserved != nil && (act.Native.BytesPreserved == nil || *n.BytesPreserved != *act.Native.BytesPreserved) {
			bad("L3: bytes_preserved %s, the manifest says %v", boolPtr(act.Native.BytesPreserved), *n.BytesPreserved)
		}
		if w := n.Error; w != nil {
			g := act.Native.Error
			switch {
			case g == nil:
				bad("L3: no native error facts; the value is Error(%s, %s)", w.Type, w.Code)
			default:
				if g.Type == nil || *g.Type != w.Type {
					bad("L3: the native error carries type %s, the value is Error(%s, %s)", strOrNone(g.Type), w.Type, w.Code)
				}
				if g.Code == nil || *g.Code != w.Code {
					bad("L3: the native error carries code %s, the value is Error(%s, %s)", strOrNone(g.Code), w.Type, w.Code)
				}
			}
		}
	case "L4":
		compareAPI(o, bad)
	case "spec":
		compareSpec(e.Expect.Spec, act, strict, bad)
	case conform.JSONLevel:
		compareJSON(act, v, bad)
	}
	return diffs
}

// compareSpec compares a spec reader's entries with expect.spec: the same entries in the same order, each with
// the same kind, name, args and outputs; and the section count when the driver reports one.
func compareSpec(want *manifest.SpecExpect, act *conform.Actual, strict bool, bad func(string, ...any)) {
	if want == nil {
		return
	}
	if act == nil || act.Spec == nil {
		if strict {
			bad("spec: no entries")
		}
		return
	}
	got := act.Spec
	if want.Sections != nil && got.Sections != nil && *got.Sections != int64(*want.Sections) {
		bad("spec: the reader saw %d contractspecv0 sections, the module has %d", *got.Sections, *want.Sections)
	}
	if len(got.Entries) != len(want.Entries) {
		bad("spec: %d entries, the bytes hold %d", len(got.Entries), len(want.Entries))
	}
	for i := 0; i < len(got.Entries) && i < len(want.Entries); i++ {
		g, w := got.Entries[i], want.Entries[i]
		if g.Kind != w.Kind || g.Name != w.Name {
			bad("spec: entry %d is %s %q, the bytes say %s %q", i, g.Kind, short([]byte(g.Name)), w.Kind, short([]byte(w.Name)))
			return
		}
		if !slices.Equal(g.Args, w.Args) || !slices.Equal(g.Outputs, w.Outputs) {
			bad("spec: entry %d (%s %s) reads %s, the bytes say %s", i, w.Kind, short([]byte(w.Name)),
				short(mustJSON(map[string]any{"args": g.Args, "outputs": g.Outputs})),
				short(mustJSON(map[string]any{"args": w.Args, "outputs": w.Outputs})))
			return
		}
	}
}

// compareJSON checks a converter's own round trip: its JSON back to XDR must be the input bytes, and the JSON
// must validate against the converter's schema. The facts become the json verdicts (jsonVerdict).
func compareJSON(act *conform.Actual, v *manifest.Variant, bad func(string, ...any)) {
	if act == nil || act.JSON == nil {
		bad("json: no facts")
		return
	}
	j := act.JSON
	if deref(j.Schema) == "invalid" {
		bad("json: the JSON does not validate against the converter's own schema: %s", strings.Join(j.SchemaErrors, "; "))
	}
	switch deref(j.Roundtrip) {
	case "changed":
		bad("json: JSON back to XDR gives other bytes (sha256 %s, the blob is %s)", deref(j.RoundtripSHA256), v.Blob.SHA256)
	case "refused":
		bad("json: the converter refuses its own JSON: %s", j.RoundtripError)
	case "identical":
		if j.RoundtripSHA256 != nil && *j.RoundtripSHA256 != v.Blob.SHA256 {
			bad("json: round trip reported identical, but its sha256 %s is not the blob's %s", *j.RoundtripSHA256, v.Blob.SHA256)
		}
	}
	compareJSONValues(j.Pinpoints, v, bad)
}

// compareJSONValues compares an XDR-JSON converter's own JSON at each pinpoint with the value the manifest
// states there (expect.values), exactly as JSON: SEP-51 writes a 64-bit integer as a string, so a number where
// the manifest states a string is a different value. Pinpoints the driver did not return are not judged (a
// converter that predates the json pinpoints).
func compareJSONValues(got []conform.PinpointResult, v *manifest.Variant, bad func(string, ...any)) {
	if v == nil || v.Resolved == nil || len(got) == 0 {
		return
	}
	byPath := map[string]conform.PinpointResult{}
	for _, p := range got {
		if p.Path != nil {
			byPath[*p.Path] = p
		}
	}
	for _, w := range v.Resolved.Values {
		p, ok := byPath[w.Path]
		if !ok {
			continue
		}
		if p.Found == nil || !*p.Found {
			bad("json: %q is not in the converter's JSON; the manifest says %s", w.Path, short(mustJSON(w.Equals)))
			continue
		}
		if canonJSON(p.Value) != canonJSON(mustJSON(w.Equals)) {
			bad("json: %q is %s, the manifest says %s", w.Path, short(p.Value), short(mustJSON(w.Equals)))
		}
	}
}

// canonJSON renders JSON with sorted keys and numbers as written, so that only a difference in value or JSON
// type compares unequal.
func canonJSON(b []byte) string {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return string(b)
	}
	out, _ := json.Marshal(x)
	return string(out)
}

// jsonVerdict is the json level's own verdict for accepted bytes: roundtrip_changed when the converter's JSON
// comes back to other bytes, roundtrip_refused when the converter refuses its own JSON, else schema_invalid when
// the JSON breaks the
// converter's own schema; "" when neither.
func jsonVerdict(j *conform.JSONFacts) string {
	if j == nil {
		return ""
	}
	switch {
	case deref(j.Roundtrip) == "changed":
		return "roundtrip_changed"
	case deref(j.Roundtrip) == "refused":
		return "roundtrip_refused"
	case deref(j.Schema) == "invalid":
		return "schema_invalid"
	}
	return ""
}

func int64Ptr(p *int64) string {
	if p == nil {
		return "no"
	}
	return fmt.Sprint(*p)
}

func boolPtr(p *bool) string {
	if p == nil {
		return "missing"
	}
	return fmt.Sprint(*p)
}

// compareObject compares L1 facts with the manifest (the canonical L1 keys): for a ledger, the transaction and
// operation counts with expect.ledger, the hashes in apply order with derived.tx_hashes, the focus
// transaction's hash with derived.tx_hash and its derived facts with derived.l1; for any other value, the hash,
// the object's re-serialisation and the derived facts.
func compareObject(ob *conform.ObjectFacts, e *manifest.Entry, v *manifest.Variant, strict bool, bad func(string, ...any)) {
	r := v.Resolved
	l1 := derivedMap(v.Derived, "l1")
	if v.XDRType == conform.LedgerXDRType {
		if r != nil && r.Ledger != nil {
			cnt := func(name string, got *int64, want *int) {
				switch {
				case want == nil:
				case got == nil:
					if strict {
						bad("L1: no %s count; the ledger has %d", name, *want)
					}
				case *got != int64(*want):
					bad("L1: %s %d, the ledger has %d", name, *got, *want)
				}
			}
			cnt("transactions", ob.Transactions, r.Ledger.Transactions)
			cnt("operations", ob.Operations, r.Ledger.Operations)
			cnt("envelopes_parsed", ob.EnvelopesParsed, r.Ledger.Transactions)
			if ob.Events != nil {
				cnt("events", ob.Events, r.Ledger.Events)
			}
		}
		if want, ok := derivedStrings(v.Derived, "tx_hashes"); ok && (strict || ob.TxHashes != nil) {
			if !equalHashes(ob.TxHashes, want) {
				bad("L1: transaction hashes in apply order %s, the manifest says %s", short(mustJSON(ob.TxHashes)), short(mustJSON(want)))
			}
		} else if r != nil {
			// Without the ordered list, each expected transaction's hash must be among those the SDK computed.
			have := map[string]bool{}
			for _, h := range ob.TxHashes {
				have[strings.ToLower(h)] = true
			}
			for _, t := range r.Transactions {
				if t.Hash != "" && !have[strings.ToLower(t.Hash)] {
					bad("L1: transaction %s is not among the hashes the SDK computed", t.Hash)
				}
			}
		}
		if f := ob.Focus; f != nil {
			want := derivedString(v.Derived, "tx_hash")
			if want == "" && v.Focus != nil {
				want = v.Focus.TxHash
			}
			if want != "" && (f.TxHash == nil || !strings.EqualFold(*f.TxHash, want)) {
				bad("L1: focus tx_hash %s, the manifest says %s", strPtr(f.TxHash), want)
			}
			compareDerived("focus.derived", f.Derived, l1, bad)
			compareRebuild("focus.rebuild", f.Rebuild, want, bad)
		}
		return
	}
	if want := derivedString(v.Derived, "tx_hash"); want != "" && ob.TxHash != nil && !strings.EqualFold(*ob.TxHash, want) {
		bad("L1: tx_hash %s, the manifest says %s", *ob.TxHash, want)
	}
	compareRebuild("rebuild", ob.Rebuild, derivedString(v.Derived, "tx_hash"), bad)
	if ob.ReencodedSHA256 != nil && e.Kind == "xdr" && *ob.ReencodedSHA256 != v.Blob.SHA256 {
		bad("L1: object re-serialisation sha256 %s, the blob is %s", *ob.ReencodedSHA256, v.Blob.SHA256)
	}
	compareDerived("derived", ob.Derived, l1, bad)
}

// compareRebuild judges the rebuild fact (docs/conformance-protocol.md, "The rebuild fact"): a transaction the
// SDK's builder rebuilt must hash to the transaction the network recorded (want, the manifest's tx_hash); a
// builder that refuses a transaction its declaration can express diverges; not_rebuilt is not judged.
func compareRebuild(name string, r *conform.RebuildFacts, want string, bad func(string, ...any)) {
	if r == nil || r.Outcome == nil || want == "" {
		return
	}
	switch *r.Outcome {
	case "rebuilt":
		if r.TxHash == nil || !strings.EqualFold(*r.TxHash, want) {
			differs := ""
			if len(r.Differs) > 0 {
				differs = " (" + strings.Join(r.Differs, ", ") + " differ)"
			}
			bad("L1: %s through %s hashes to %s%s, the network's transaction is %s", name, strPtr(r.EntryPoint), strPtr(r.TxHash), differs, want)
		}
	case "refused":
		bad("L1: %s: %s refuses to rebuild the transaction: %s", name, strPtr(r.EntryPoint), r.Message)
	}
}

// compareDerived compares each derived key the manifest states (variants[].derived.l1) with the driver's.
func compareDerived(name string, got map[string]string, want map[string]any, bad func(string, ...any)) {
	for k, w := range want {
		ws, ok := w.(string)
		if !ok || !conform.DerivedKeys[k] {
			continue
		}
		g, have := got[k]
		switch {
		case !have:
			bad("L1: %s.%s not reported; the manifest says %s", name, k, ws)
		case !strings.EqualFold(g, ws) || (!hexStr.MatchString(ws) && g != ws):
			bad("L1: %s.%s is %s, the manifest says %s", name, k, g, ws)
		}
	}
}

func equalHashes(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !strings.EqualFold(got[i], want[i]) {
			return false
		}
	}
	return true
}

func strPtr(p *string) string {
	if p == nil {
		return "none"
	}
	return *p
}

// derivedString looks up a dotted path in a variant's derived values; "" when absent or not a string.
func derivedString(d map[string]any, path string) string {
	var cur any = d
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

// derivedStrings returns a derived list of strings; ok is false when the key is absent or not such a list.
func derivedStrings(d map[string]any, key string) ([]string, bool) {
	raw, ok := d[key].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func derivedMap(d map[string]any, key string) map[string]any {
	m, _ := d[key].(map[string]any)
	return m
}

func compareAPI(o *conform.Observation, bad func(string, ...any)) {
	e := o.Cell.Entry
	var res *conform.APIResult
	if a := o.Response.Actual; a != nil {
		res = a.API
	}
	if res != nil && res.SelfDecode != nil && *res.SelfDecode == "rejected" {
		bad("L4: the SDK's own decoder rejects what it produced")
	}
	switch {
	case e.API != nil:
		if want := e.API.ExpectXDRHex; want != "" {
			switch {
			case res == nil || res.XDRHex == nil:
				bad("L4: no xdr_hex returned; the manifest expects %s", short([]byte(want)))
			case !strings.EqualFold(*res.XDRHex, want):
				bad("L4: xdr_hex %s, the manifest expects %s", short([]byte(*res.XDRHex)), short([]byte(want)))
			}
		}
		if len(e.API.ExpectValue) > 0 {
			var want, got any
			if err := decodeNumber(e.API.ExpectValue, &want); err != nil {
				bad("L4: expect_value: %v", err)
				return
			}
			switch {
			case res == nil || res.Value == nil:
				bad("L4: no value returned; the manifest expects %s", short(e.API.ExpectValue))
			case decodeNumber(res.Value, &got) != nil:
				bad("L4: value is not JSON")
			case !equalValues(got, want):
				bad("L4: value %s, the manifest expects %s", short(res.Value), short(e.API.ExpectValue))
			}
		}
	case e.Strkey != nil && e.Strkey.PayloadHex != "":
		want := strings.ToLower(e.Strkey.PayloadHex)
		got := ""
		if res != nil {
			var s string
			if res.Value != nil && json.Unmarshal(res.Value, &s) == nil {
				got = strings.ToLower(s)
			} else if res.XDRHex != nil {
				got = strings.ToLower(*res.XDRHex)
			}
		}
		if got != want {
			bad("L4: payload %q, the vector's payload is %s", got, want)
		}
	}
}

// equalValues compares what an SDK produced (got) with what the manifest states (want), both JSON values.
// Integers are compared by value only where the manifest states an integer (a JSON integer, or a decimal
// string in canonical form, as 64-bit values are written): got may then be a JSON integer or a canonical
// decimal string, never a string with leading zeros or a sign the manifest's does not have. Hex strings are
// compared without regard to case; objects without regard to key order; everything else exactly.
func equalValues(got, want any) bool {
	if wi, ok := intOf(want, true); ok {
		gi, ok := intOf(got, true)
		return ok && gi.Cmp(wi) == 0
	}
	switch w := want.(type) {
	case json.Number:
		g, ok := got.(json.Number)
		return ok && g.String() == w.String()
	case float64:
		g, ok := got.(float64)
		return ok && g == w
	case string:
		g, ok := got.(string)
		if !ok {
			return false
		}
		if hexStr.MatchString(w) && hexStr.MatchString(g) {
			return strings.EqualFold(g, w)
		}
		return g == w
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok || !equalValues(gv, wv) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !equalValues(g[i], w[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(got, want)
}

var (
	hexStr     = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2})+$`)
	decimalStr = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
	intNumber  = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
)

// intOf returns v as an integer when it is a JSON integer or (strings allowed) a canonical decimal string.
func intOf(v any, strings bool) (*big.Int, bool) {
	switch x := v.(type) {
	case json.Number:
		if intNumber.MatchString(x.String()) {
			return new(big.Int).SetString(x.String(), 10)
		}
	case float64:
		if x == float64(int64(x)) {
			return big.NewInt(int64(x)), true
		}
	case int:
		return big.NewInt(int64(x)), true
	case int64:
		return big.NewInt(x), true
	case string:
		if strings && decimalStr.MatchString(x) {
			return new(big.Int).SetString(x, 10)
		}
	}
	return nil, false
}

// canon renders a JSON value in the form the cross-SDK fingerprint compares: JSON integers as decimal strings,
// hex strings lower-cased, everything else as is. It never rewrites a string's digits ("0010" stays "0010").
func canon(v any) any {
	switch x := v.(type) {
	case json.Number, float64, int, int64:
		if n, ok := intOf(x, false); ok {
			return n.String()
		}
		return fmt.Sprint(x)
	case string:
		if hexStr.MatchString(x) {
			return strings.ToLower(x)
		}
		return x
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = canon(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = canon(e)
		}
		return s
	}
	return v
}

func decodeNumber(raw json.RawMessage, v *any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func short(b []byte) string {
	s := string(b)
	if len(s) > 80 {
		return s[:77] + "…"
	}
	return s
}

func strOrNone(p *string) string {
	if p == nil {
		return "none"
	}
	return *p
}
