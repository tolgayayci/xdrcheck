package conform

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Evidence rules: what a schema-valid run response must also carry, given the request it answers and the
// driver's describe. The schema cannot say these things (they depend on the level, the input and the op), and
// without them a cell would be judged on facts the driver never reported: an ok with no re-encoding hash, an L1
// ok with no hashes, an api op the driver declares answered "not supported". A response that breaks one is a
// protocol error, exactly like a schema violation. The public statement of the rules is docs/conformance-protocol.md.

// DerivedKeys is the closed list of derived facts an L1 object may report.
var DerivedKeys = set("operation_type", "operation_source", "pool_id", "asset", "address", "muxed_id", "offer_id", "memo_type")

// LedgerXDRType is the XDR type of a ledger input.
const LedgerXDRType = "LedgerCloseMeta"

var snakeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// decodeReasons are the reason codes of a value that did not decode at all: an L1 reject on a ledger for one of
// these carries no per-envelope facts, because no envelope was reached.
var decodeReasons = set("decode_error", "union_arm_undeclared", "enum_undeclared", "bool_range", "optional_flag_range",
	"nonzero_padding", "trailing_bytes", "length_exceeds_max", "length_exceeds_input", "depth", "type_not_generated",
	"schema_too_old", "stack_overflow", "out_of_memory")

// apiValueOps are the api ops whose result has a value; apiXDROps those whose result has xdr_hex; apiStrkeyOps
// those that produce a strkey. An op without a defined result (price.encode) has no requirements until an entry
// defines it.
var (
	apiValueOps = set("asset.compare", "liquidity_pool.id", "liquidity_pool.asset", "muxed_account.encode", "muxed_account.decode",
		"offer.manage_sell", "offer.manage_buy", "scval.from_native", "scval.sort_map", "scval.to_native", "scval.native_roundtrip",
		"strkey.encode", "strkey.decode", "transaction.parse", "transaction.hash", "memo.text_roundtrip", "address.to_strkey",
		"address.from_sc_address", "signer_key.to_strkey", "operation.object_roundtrip", "asset.from_operation",
		"xdr.custom_union_encode")
	apiXDROps = set("liquidity_pool.asset", "muxed_account.encode", "offer.manage_sell", "offer.manage_buy", "scval.from_native",
		"scval.sort_map", "scval.native_roundtrip", "transaction.parse", "memo.text_roundtrip", "operation.object_roundtrip", "xdrjson.decode",
		"xdr.custom_union_encode")
	apiStrkeyOps = set("muxed_account.encode", "strkey.encode", "address.to_strkey", "address.from_sc_address", "signer_key.to_strkey")
)

// CheckEvidence returns a protocol error when a validated response lacks evidence its cell needs. Columns of
// kind selftest (the orchestrator's own stub, which wraps no SDK) are held only to the op rules, not to the
// evidence of an accepted value.
func CheckEvidence(cell *Cell, req *RunRequest, d *Describe, r *RunResponse, line []byte) error {
	var errs []string
	bad := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	in := req.Input
	outcome, code := r.OutcomeString(), r.ReasonCode()
	if outcome == "n_a" {
		checkNA(in, d, code, bad)
	}
	if a := r.Actual; a != nil && a.Object != nil {
		checkDerived("actual.object.derived", a.Object.Derived, bad)
		checkOpTypes("actual.object.operation_types", a.Object.OperationTypes, bad)
		if f := a.Object.Focus; f != nil {
			checkDerived("actual.object.focus.derived", f.Derived, bad)
			checkOpTypes("actual.object.focus.operation_types", f.OperationTypes, bad)
		}
	}
	if cell == nil || cell.Column == nil || cell.Column.Kind != "selftest" {
		switch outcome {
		case "ok":
			checkOK(cell, req, d, r, bad)
		case "reject":
			if req.Level == "L1" && in.Kind == "xdr" && in.XDRType == LedgerXDRType && !decodeReasons[code] {
				checkLedgerReject(r, bad)
			}
		}
	}
	if len(errs) > 0 {
		return protoErr(line, "run %s %s: %s", req.Entry, req.Level, strings.Join(errs, "; "))
	}
	return nil
}

// checkNA: a declared api op, and a strkey text for a driver that declares strkey.decode, are never "not
// supported"; a value the language cannot hold, or a tag kind the SDK parameter does not take, is reported only
// for a tagged native argument.
func checkNA(in Input, d *Describe, code string, bad func(string, ...any)) {
	declares := func(op string) bool {
		if d != nil {
			for _, x := range d.APIOps {
				if x == op {
					return true
				}
			}
		}
		return false
	}
	switch in.Kind {
	case "api":
		declared := declares(in.APIOp)
		switch {
		case !declared:
			// An op the driver does not declare is n_a for any reason.
		case code == "value_not_representable", code == "argument_type_not_accepted":
			if !hasNativeTag(in.Args) {
				bad("n_a/%s for %s, but no argument carries a native type tag", code, in.APIOp)
			}
		case code == "type_not_generated":
		default:
			bad("the driver declares api op %s but answers n_a/%s (a declared op may answer n_a only with value_not_representable, argument_type_not_accepted or type_not_generated)", in.APIOp, code)
		}
	case "strkey":
		if declares("strkey.decode") && code != "type_not_generated" {
			bad("the driver declares strkey.decode but a strkey text answered n_a/%s (only type_not_generated is allowed)", code)
		}
	}
}

// NoReencode reports whether the cell's column decodes without re-encoding (the stellar-core column, kind
// core): its L0 evidence is the consumed byte count alone, which must equal the input's length.
func NoReencode(cell *Cell) bool {
	return cell != nil && cell.Column != nil && cell.Column.Kind == "core"
}

func hasNativeTag(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["native"]; ok {
			return true
		}
		for _, e := range x {
			if hasNativeTag(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasNativeTag(e) {
				return true
			}
		}
	}
	return false
}

func checkDerived(name string, d map[string]string, bad func(string, ...any)) {
	for k := range d {
		if !DerivedKeys[k] {
			bad("%s has key %q, which is not in the closed list", name, k)
		}
	}
}

func checkOpTypes(name string, ts []string, bad func(string, ...any)) {
	for _, t := range ts {
		if !snakeRe.MatchString(t) {
			bad("%s has %q, not an XDR-JSON snake_case operation arm", name, t)
			return
		}
	}
}

func checkOK(cell *Cell, req *RunRequest, d *Describe, r *RunResponse, bad func(string, ...any)) {
	a := r.Actual
	in := req.Input
	switch req.Level {
	case "L0":
		switch {
		case NoReencode(cell):
			// The stellar-core column decodes and prints; it never re-encodes.
			if a == nil || a.ConsumedBytes == nil {
				bad("L0 ok needs actual.consumed_bytes")
			}
		case a == nil || a.ReencodedSHA256 == nil || a.ConsumedBytes == nil:
			bad("L0 ok needs actual.reencoded_sha256 and actual.consumed_bytes")
		}
	case "L1":
		if a == nil || a.Object == nil {
			bad("L1 ok needs actual.object")
			return
		}
		o := a.Object
		switch in.XDRType {
		case LedgerXDRType:
			if o.Transactions == nil || o.EnvelopesParsed == nil || o.Operations == nil || o.TxHashes == nil {
				bad("L1 ok on a ledger needs object.transactions, envelopes_parsed, operations and tx_hashes")
				return
			}
			if *o.EnvelopesParsed != *o.Transactions {
				bad("L1 ok on a ledger with envelopes_parsed %d of %d transactions", *o.EnvelopesParsed, *o.Transactions)
			}
			if int64(len(o.TxHashes)) != *o.EnvelopesParsed {
				bad("L1 ok on a ledger with %d tx_hashes for %d parsed envelopes", len(o.TxHashes), *o.EnvelopesParsed)
			}
			if len(o.EnvelopesRejected) > 0 {
				bad("L1 ok on a ledger with rejected envelopes")
			}
			if in.Focus != nil && in.Focus.TxIndex != nil {
				f := o.Focus
				if f == nil || f.TxHash == nil || f.OperationTypes == nil || f.Derived == nil {
					bad("L1 ok on a ledger with a focus transaction needs object.focus with tx_hash, operation_types and derived")
				} else {
					checkStatedDerived("object.focus.derived", f.Derived, cell, bad)
					checkRebuildDeclared("object.focus.rebuild", f.Rebuild, d, true, bad)
				}
			}
		case "TransactionEnvelope":
			// The hash depends on the passphrase: a passphrase-independent envelope may come without one.
			if (o.TxHash == nil && in.Passphrase != "") || o.OperationTypes == nil || o.Operations == nil || o.ReencodedSHA256 == nil || o.Derived == nil {
				bad("L1 ok on a TransactionEnvelope needs object.tx_hash (under a passphrase), operation_types, operations, reencoded_sha256 and derived")
			}
			checkRebuildDeclared("object.rebuild", o.Rebuild, d, in.Passphrase != "", bad)
			checkStatedDerived("object.derived", o.Derived, cell, bad)
		default:
			if o.Derived == nil {
				bad("L1 ok needs object.derived ({} when the object yields none)")
			}
			checkStatedDerived("object.derived", o.Derived, cell, bad)
		}
	case "L3":
		n := (*NativeFacts)(nil)
		if a != nil {
			n = a.Native
		}
		if n == nil || n.Type == "" || n.BytesPreserved == nil {
			bad("L3 ok needs actual.native with type and bytes_preserved")
			return
		}
		if cell != nil && cell.Entry != nil {
			want := cell.Entry.Expect.Native
			if v := cell.Variant; v != nil && v.Resolved != nil && v.Resolved.Native != nil {
				want = v.Resolved.Native
			}
			if want != nil && want.MapEntries != nil && n.MapEntries == nil {
				bad("L3 ok needs actual.native.map_entries: the entry states a map's entry count")
			}
		}
	case "L4":
		checkAPI(in, a, bad)
	case "spec":
		if a == nil || a.Spec == nil {
			bad("spec ok needs actual.spec with entries")
		}
	case "json":
		if a == nil || a.JSON == nil {
			bad("json ok needs actual.json with json_sha256, schema and roundtrip")
		}
	}
}

func checkAPI(in Input, a *Actual, bad func(string, ...any)) {
	if a == nil || a.API == nil {
		bad("L4 ok needs actual.api")
		return
	}
	p := a.API
	op := in.APIOp
	if in.Kind == "strkey" {
		op = "strkey.decode"
	}
	if apiValueOps[op] && p.Value == nil {
		bad("L4 ok on %s needs actual.api.value", op)
	}
	if apiXDROps[op] && p.XDRHex == nil {
		bad("L4 ok on %s needs actual.api.xdr_hex", op)
	}
	if (p.XDRHex != nil || apiStrkeyOps[op]) && p.SelfDecode == nil {
		bad("L4 ok on %s needs actual.api.self_decode", op)
	}
	if p.Value == nil {
		return
	}
	var v any
	if err := json.Unmarshal(p.Value, &v); err != nil {
		bad("actual.api.value is not JSON")
		return
	}
	shape := func(ok bool, want string) {
		if !ok {
			bad("actual.api.value of %s must be %s", op, want)
		}
	}
	switch op {
	case "scval.native_roundtrip", "operation.object_roundtrip":
		_, ok := v.(bool)
		shape(ok, "a boolean (bytes_preserved)")
	case "asset.compare":
		n, ok := v.(float64)
		shape(ok && (n == -1 || n == 0 || n == 1), "the integer -1, 0 or 1")
	case "transaction.parse":
		m, ok := v.(map[string]any)
		_, h := m["tx_hash"].(string)
		_, n := m["operations"].(float64)
		shape(ok && h && n && len(m) == 2, `{"tx_hash", "operations"}`)
	case "muxed_account.decode":
		m, ok := v.(map[string]any)
		_, acc := m["account"].(string)
		_, id := m["id"].(string)
		shape(ok && acc && id && len(m) == 2, `{"account", "id"} with a decimal-string id`)
	case "asset.from_operation":
		_, ok := v.(map[string]any)
		shape(ok, `{"type", "code", "issuer"}`)
	case "scval.sort_map":
		_, ok := v.([]any)
		shape(ok, "the list of keys in the resulting order")
	case "scval.from_native", "scval.to_native":
	default:
		if apiValueOps[op] {
			_, ok := v.(string)
			shape(ok, "a string")
		}
	}
}

func checkLedgerReject(r *RunResponse, bad func(string, ...any)) {
	var o *ObjectFacts
	if r.Actual != nil {
		o = r.Actual.Object
	}
	if o == nil || o.Transactions == nil || o.EnvelopesParsed == nil || o.TxHashes == nil || len(o.EnvelopesRejected) == 0 {
		bad("L1 reject on a ledger (reason %s) needs object.transactions, envelopes_parsed, tx_hashes and envelopes_rejected", r.ReasonCode())
		return
	}
	if *o.EnvelopesParsed+int64(len(o.EnvelopesRejected)) != *o.Transactions {
		bad("L1 reject on a ledger: %d parsed and %d rejected of %d transactions", *o.EnvelopesParsed, len(o.EnvelopesRejected), *o.Transactions)
	}
	if int64(len(o.TxHashes)) != *o.EnvelopesParsed {
		bad("L1 reject on a ledger with %d tx_hashes for %d parsed envelopes", len(o.TxHashes), *o.EnvelopesParsed)
	}
	for i, e := range o.EnvelopesRejected {
		if e.TxHash == nil {
			bad("actual.object.envelopes_rejected[%d] needs tx_hash", i)
		}
		if e.TxIndex != nil && *e.TxIndex >= *o.Transactions {
			bad("actual.object.envelopes_rejected[%d].tx_index %d is beyond the ledger's %d transactions", i, *e.TxIndex, *o.Transactions)
		}
	}
}

// checkStatedDerived: every derived fact the manifest states for the variant (variants[].derived.l1) must be
// reported, so that it is compared rather than skipped.
func checkStatedDerived(name string, got map[string]string, cell *Cell, bad func(string, ...any)) {
	if cell == nil || cell.Variant == nil {
		return
	}
	l1, _ := cell.Variant.Derived["l1"].(map[string]any)
	for k := range l1 {
		if _, ok := got[k]; !ok && DerivedKeys[k] {
			bad("%s lacks %s, which the manifest states for this variant", name, k)
		}
	}
}

// checkRebuildDeclared: a driver whose describe declares object_rebuild reports the rebuild fact on every
// transaction it parses under a passphrase (want), with that entry point; a driver that does not declare it
// never reports one. A missing fact is never read as agreement.
func checkRebuildDeclared(name string, r *RebuildFacts, d *Describe, want bool, bad func(string, ...any)) {
	declared := d != nil && d.ObjectRebuild != ""
	switch {
	case !declared && r != nil:
		bad("%s reported, but describe declares no object_rebuild", name)
	case declared && want && r == nil:
		bad("L1 ok needs %s: describe declares object_rebuild %s", name, d.ObjectRebuild)
	case declared && r != nil && r.EntryPoint != nil && *r.EntryPoint != d.ObjectRebuild:
		bad("%s entry_point %s, describe declares %s", name, *r.EntryPoint, d.ObjectRebuild)
	}
}
