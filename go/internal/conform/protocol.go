package conform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// ProtocolTag is the driver protocol tag every message carries (driver-protocol.schema.json).
const ProtocolTag = "xcc.driver/1"

// Levels are the conformance levels in order.
// spec is the contract-spec reader (spec entries); json is the XDR-JSON converters (SEP-51) of the json columns.
var Levels = []string{"L0", "L1", "L2", "L3", "L4", "spec", "json"}

// Outcomes a driver may report.
var Outcomes = []string{"ok", "diverge", "reject", "crash", "n_a"}

// reasonCodes is the closed enum of runResponse.reason.code.
var reasonCodes = set(
	"reencode_mismatch", "object_reencode_mismatch", "own_output_rejected", "native_reencode_mismatch",
	"decode_error", "union_arm_undeclared", "enum_undeclared", "bool_range", "optional_flag_range",
	"nonzero_padding", "trailing_bytes", "length_exceeds_max", "length_exceeds_input", "depth", "spec_sections",
	"object_validation", "value_out_of_range", "ordering", "lossy_conversion_refused",
	"unsupported_address_type", "strkey_checksum", "strkey_length", "strkey_version", "strkey_padding",
	"strkey_noncanonical", "strkey_payload", "stack_overflow", "out_of_memory", "panic", "internal_error",
	"type_not_generated", "no_object_layer", "no_native_layer", "op_not_supported", "value_not_representable", "argument_type_not_accepted",
	"schema_too_old",
	"other",
)

var (
	ecosystems       = set("npm", "go", "crates.io", "pypi", "maven", "nuget", "pub", "other")
	levelSet         = set(Levels...)
	outcomeSet       = set(Outcomes...)
	selfDecode       = set("accepted", "rejected", "not_checked")
	specKinds        = set("function", "struct", "union", "enum", "error_enum", "event")
	jsonSchemaStates = set("valid", "invalid", "not_checked")
	jsonRoundtrips   = set("identical", "changed", "refused", "not_supported")
	sha256Re         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexRe            = regexp.MustCompile(`^([0-9a-f]{2})*$`)
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// RunRequest is one `run` request: one entry, one variant, one level.
type RunRequest struct {
	XDRCHECK string `json:"xcc"`
	ID       int    `json:"id"`
	Op       string `json:"op"`
	Entry    string `json:"entry"`
	Variant  string `json:"variant,omitempty"`
	Level    string `json:"level"`
	Profile  string `json:"profile,omitempty"`
	Input    Input  `json:"input"`
}

// Input is the run request's input: an XDR value (kind xdr), an api call (kind api) or a strkey text (kind
// strkey). Only the fields of the kind are set.
type Input struct {
	Kind string `json:"kind"`

	XDRType    string    `json:"xdr_type,omitempty"`
	Path       string    `json:"path,omitempty"`
	XDRHex     string    `json:"xdr_hex,omitempty"`
	Framing    string    `json:"framing,omitempty"`
	FrameIndex *int      `json:"frame_index,omitempty"`
	Passphrase string    `json:"passphrase,omitempty"`
	Focus      *ReqFocus `json:"focus,omitempty"`
	Pinpoints  []string  `json:"pinpoints,omitempty"`

	APIOp string         `json:"api_op,omitempty"`
	Args  map[string]any `json:"args,omitempty"`

	Text         string `json:"text,omitempty"`
	DeclaredType string `json:"declared_type,omitempty"`

	// Spec inputs: the container and, for a Wasm module, where the corpus's own reader found each
	// contractspecv0 section payload.
	Container string        `json:"container,omitempty"`
	Sections  []SpecSection `json:"sections,omitempty"`
}

// SpecSection is where a contractspecv0 section's payload lies in a Wasm module.
type SpecSection struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

// ReqFocus is where in a ledger the pattern is.
type ReqFocus struct {
	TxIndex *int   `json:"tx_index,omitempty"`
	OpIndex *int   `json:"op_index,omitempty"`
	Path    string `json:"path,omitempty"`
}

type simpleRequest struct {
	XDRCHECK string `json:"xcc"`
	ID       int    `json:"id"`
	Op       string `json:"op"`
}

// Describe is a validated `describe` response.
type Describe struct {
	XDRCHECK         *string           `json:"xcc"`
	ID               *int              `json:"id"`
	Op               *string           `json:"op"`
	Driver           *DriverInfo       `json:"driver"`
	SDK              *SDKInfo          `json:"sdk"`
	Runtime          *RuntimeInfo      `json:"runtime"`
	XDRSchema        *XDRSchema        `json:"xdr_schema"`
	Levels           []string          `json:"levels"`
	ObjectParsers    map[string]string `json:"object_parsers,omitempty"`
	ObjectRebuild    string            `json:"object_rebuild,omitempty"`
	NativeConverters map[string]string `json:"native_converters,omitempty"`
	APIOps           []string          `json:"api_ops"`
	Decode           *DecodeInfo       `json:"decode"`
}

// DriverInfo names the driver program.
type DriverInfo struct {
	Name    *string `json:"name"`
	Version *string `json:"version"`
	Adapter string  `json:"adapter,omitempty"`
}

// SDKInfo is the SDK under test as read from the installed package.
type SDKInfo struct {
	Ecosystem    *string      `json:"ecosystem"`
	Package      *string      `json:"package"`
	Version      *string      `json:"version"`
	Integrity    string       `json:"integrity,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Dependency is a behaviour-deciding library's resolved version.
type Dependency struct {
	Package   *string `json:"package"`
	Version   *string `json:"version"`
	Integrity string  `json:"integrity,omitempty"`
}

// RuntimeInfo is the language runtime the driver runs on.
type RuntimeInfo struct {
	Name       *string `json:"name"`
	Version    *string `json:"version"`
	OS         string  `json:"os,omitempty"`
	Arch       string  `json:"arch,omitempty"`
	StackBytes *int64  `json:"stack_bytes,omitempty"`
}

// XDRSchema is what the SDK's generated XDR can represent.
type XDRSchema struct {
	Protocol *int            `json:"protocol,omitempty"`
	Probes   map[string]bool `json:"probes"`
	Types    []string        `json:"types,omitempty"`
}

// DecodeInfo says how the driver decodes at L0.
type DecodeInfo struct {
	EntryPoint           *string         `json:"entry_point"`
	DefaultDepth         json.RawMessage `json:"default_depth"` // integer >= 0 or null; required
	DepthConfigurable    *bool           `json:"depth_configurable,omitempty"`
	ChecksConsumedLength *bool           `json:"checks_consumed_length"`
	Profiles             []string        `json:"profiles,omitempty"`
}

// HasLevel reports whether the driver declared the level.
func (d *Describe) HasLevel(l string) bool {
	for _, x := range d.Levels {
		if x == l {
			return true
		}
	}
	return false
}

// RunResponse is a validated `run` response.
type RunResponse struct {
	XDRCHECK  *string    `json:"xcc"`
	ID        *int       `json:"id"`
	Op        *string    `json:"op"`
	Entry     *string    `json:"entry"`
	Variant   *string    `json:"variant,omitempty"`
	Level     *string    `json:"level"`
	Profile   *string    `json:"profile,omitempty"`
	Outcome   *string    `json:"outcome"`
	Reason    *Reason    `json:"reason,omitempty"`
	Actual    *Actual    `json:"actual,omitempty"`
	Resources *Resources `json:"resources,omitempty"`
}

// Reason is the typed reason of a non-ok outcome.
type Reason struct {
	Code       *string `json:"code"`
	Message    string  `json:"message,omitempty"`
	ErrorClass string  `json:"error_class,omitempty"`
	EntryPoint string  `json:"entry_point,omitempty"`
}

// Actual is what the SDK produced.
type Actual struct {
	ConsumedBytes      *int64           `json:"consumed_bytes,omitempty"`
	ReencodedSHA256    *string          `json:"reencoded_sha256,omitempty"`
	ReencodedHex       *string          `json:"reencoded_hex,omitempty"`
	LenientEntryPoints []LenientEntry   `json:"lenient_entry_points,omitempty"`
	Object             *ObjectFacts     `json:"object,omitempty"`
	Projection         json.RawMessage  `json:"projection,omitempty"`
	Pinpoints          []PinpointResult `json:"pinpoints,omitempty"`
	Native             *NativeFacts     `json:"native,omitempty"`
	API                *APIResult       `json:"api,omitempty"`
	Spec               *SpecFacts       `json:"spec,omitempty"`
	JSON               *JSONFacts       `json:"json,omitempty"`
}

// SpecFacts are what an SDK's contract-spec reader returned (spec level), in the neutral rendering.
type SpecFacts struct {
	Sections   *int64               `json:"sections,omitempty"`
	Entries    []manifest.SpecEntry `json:"entries"`
	EntryPoint string               `json:"entry_point,omitempty"`
}

// JSONFacts are what an XDR-JSON converter did (json level): the canonical JSON's hash, the JSON against the
// converter's own schema, and the round trip back to XDR.
type JSONFacts struct {
	JSONSHA256      *string  `json:"json_sha256"`
	JSONBytes       *int64   `json:"json_bytes,omitempty"`
	Schema          *string  `json:"schema"`                  // valid, invalid, not_checked
	SchemaErrors    []string `json:"schema_errors,omitempty"` // at most 5
	Roundtrip       *string  `json:"roundtrip"`               // identical, changed, refused, not_supported
	RoundtripSHA256 *string  `json:"roundtrip_sha256,omitempty"`
	RoundtripError  string   `json:"roundtrip_error,omitempty"`
	// Pinpoints are the converter's own JSON at the request's pinpoints (docs/conformance-protocol.md, the json
	// level's expected values), compared with the manifest exactly as JSON.
	Pinpoints []PinpointResult `json:"pinpoints,omitempty"`
}

// LenientEntry is another decode entry point's behaviour on the same bytes.
type LenientEntry struct {
	EntryPoint *string `json:"entry_point"`
	Accepted   *bool   `json:"accepted"`
	Note       string  `json:"note,omitempty"`
}

// ObjectFacts are L1 facts read back from the SDK object.
type ObjectFacts struct {
	TxHash            *string           `json:"tx_hash,omitempty"`
	OperationTypes    []string          `json:"operation_types,omitempty"`
	Transactions      *int64            `json:"transactions,omitempty"`
	Operations        *int64            `json:"operations,omitempty"`
	Events            *int64            `json:"events,omitempty"`
	ReencodedSHA256   *string           `json:"reencoded_sha256,omitempty"`
	Derived           map[string]string `json:"derived,omitempty"`
	Rebuild           *RebuildFacts     `json:"rebuild,omitempty"`
	EnvelopesParsed   *int64            `json:"envelopes_parsed,omitempty"`
	EnvelopesRejected []RejectedEnv     `json:"envelopes_rejected,omitempty"`
	TxHashes          []string          `json:"tx_hashes,omitempty"`
	Focus             *FocusFacts       `json:"focus,omitempty"`
}

// FocusFacts are what the SDK's object says about a ledger's focus transaction.
type FocusFacts struct {
	TxHash         *string           `json:"tx_hash"`
	OperationTypes []string          `json:"operation_types"`
	Derived        map[string]string `json:"derived"`
	Rebuild        *RebuildFacts     `json:"rebuild,omitempty"`
}

// RebuildFacts are the rebuild fact (docs/conformance-protocol.md, "The rebuild fact"): the parsed transaction
// rebuilt through the SDK's builder and hashed under the request's passphrase.
type RebuildFacts struct {
	EntryPoint *string  `json:"entry_point"`
	Outcome    *string  `json:"outcome"` // rebuilt, refused, not_rebuilt
	TxHash     *string  `json:"tx_hash,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Message    string   `json:"message,omitempty"`
	Differs    []string `json:"differs,omitempty"`
}

// RejectedEnv is one envelope of a ledger the SDK's transaction parser rejected.
type RejectedEnv struct {
	TxIndex *int64  `json:"tx_index"`
	TxHash  *string `json:"tx_hash,omitempty"`
	Code    *string `json:"code"`
	Message string  `json:"message,omitempty"`
}

// PinpointResult is an L2 value at a requested JSON Pointer.
type PinpointResult struct {
	Path  *string         `json:"path"`
	Found *bool           `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
}

// NativeFacts are L3 facts.
type NativeFacts struct {
	Type            string  `json:"type,omitempty"`
	MapEntries      *int64  `json:"map_entries,omitempty"`
	ReencodedSHA256 *string `json:"reencoded_sha256,omitempty"`
	BytesPreserved  *bool   `json:"bytes_preserved,omitempty"`
	Summary         string  `json:"summary,omitempty"`
	// Error is what the native value of an scvError carries (docs/conformance-protocol.md, "The native error
	// fact"): its ScErrorType and ScErrorCode as XDR-JSON names, each left out when the native value does not carry it.
	Error *NativeError `json:"error,omitempty"`
}

// NativeError is the native error fact of L3.
type NativeError struct {
	Type *string `json:"type"`
	Code *string `json:"code"`
}

// APIResult is an L4 call's result.
type APIResult struct {
	XDRHex     *string         `json:"xdr_hex,omitempty"`
	Value      json.RawMessage `json:"value,omitempty"`
	SelfDecode *string         `json:"self_decode,omitempty"`
}

// Resources are what the driver measured itself.
type Resources struct {
	WallMS    *float64 `json:"wall_ms,omitempty"`
	PeakRSSKB *int64   `json:"peak_rss_kb,omitempty"`
}

// OutcomeString returns the response's outcome.
func (r *RunResponse) OutcomeString() string { return deref(r.Outcome) }

// ReasonCode returns the reason code, or "".
func (r *RunResponse) ReasonCode() string {
	if r.Reason == nil {
		return ""
	}
	return deref(r.Reason.Code)
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// ProtocolError is a driver message or behaviour that breaks the driver protocol. The orchestrator never
// trusts such a response: the cell is not judged and the run exits 2.
type ProtocolError struct {
	Msg  string
	Line []byte // the offending line, possibly truncated
}

func (e *ProtocolError) Error() string { return "driver protocol: " + e.Msg }

func protoErr(line []byte, format string, args ...any) *ProtocolError {
	if len(line) > 2048 {
		line = append(line[:2048:2048], "…"...)
	}
	return &ProtocolError{Msg: fmt.Sprintf(format, args...), Line: line}
}

// Validator checks driver responses against the driver protocol schema. The schema's api operation list is
// owned by the manifest schema; APIOps holds it.
type Validator struct {
	APIOps map[string]bool
}

// LoadAPIOps reads the api operation list from the manifest entry schema ($defs.apiOp.enum).
func LoadAPIOps(manifestSchemaPath string) (map[string]bool, error) {
	data, err := os.ReadFile(manifestSchemaPath)
	if err != nil {
		return nil, err
	}
	var s struct {
		Defs struct {
			APIOp struct {
				Enum []string `json:"enum"`
			} `json:"apiOp"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestSchemaPath, err)
	}
	if len(s.Defs.APIOp.Enum) == 0 {
		return nil, fmt.Errorf("%s: no $defs.apiOp.enum", manifestSchemaPath)
	}
	return set(s.Defs.APIOp.Enum...), nil
}

// peek is the part of every driver message used to dispatch it.
type peek struct {
	XDRCHECK any    `json:"xcc"`
	Op       any    `json:"op"`
	Error    string `json:"error"`
}

// checkEnvelope rejects non-JSON lines, nulls where the schema allows none, and protocol_error messages.
func checkEnvelope(line []byte, allowNull func(path string) bool) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return protoErr(line, "not a JSON object: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return protoErr(line, "trailing data after the JSON object")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return protoErr(line, "not a JSON object")
	}
	if obj["op"] == "protocol_error" {
		var p peek
		json.Unmarshal(line, &p)
		return protoErr(line, "the driver answered protocol_error: %s", p.Error)
	}
	if obj["xcc"] != ProtocolTag {
		return protoErr(line, "xcc is %v, want %q", obj["xcc"], ProtocolTag)
	}
	if p := findNull(v, "", allowNull); p != "" {
		return protoErr(line, "%s is null", p)
	}
	return nil
}

// findNull returns the JSON Pointer of the first null that allowNull does not permit, or "". Array indexes are
// written as "*".
func findNull(v any, path string, allowNull func(string) bool) string {
	switch x := v.(type) {
	case nil:
		if allowNull(path) {
			return ""
		}
		return orRoot(path)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "/" + k
			if allowNull(p) {
				continue
			}
			if r := findNull(x[k], p, allowNull); r != "" {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := findNull(e, path+"/*", allowNull); r != "" {
				return r
			}
		}
	}
	return ""
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func decodeStrict(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return protoErr(line, "%v", err)
	}
	return nil
}

// ParseDescribe validates a describe response to the request with the given id.
func (v *Validator) ParseDescribe(line []byte, id int) (*Describe, error) {
	err := checkEnvelope(line, func(p string) bool { return p == "/decode/default_depth" })
	if err != nil {
		return nil, err
	}
	var d Describe
	if err := decodeStrict(line, &d); err != nil {
		return nil, err
	}
	var errs []string
	bad := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if deref(d.Op) != "describe" {
		bad("op is %q, want describe", deref(d.Op))
	}
	if d.ID == nil || *d.ID != id {
		bad("id %v does not echo the request id %d", ptrString(d.ID), id)
	}
	switch {
	case d.Driver == nil:
		bad("driver is missing")
	case d.Driver.Name == nil || d.Driver.Version == nil:
		bad("driver needs name and version")
	}
	switch {
	case d.SDK == nil:
		bad("sdk is missing")
	case d.SDK.Ecosystem == nil || d.SDK.Package == nil || d.SDK.Version == nil:
		bad("sdk needs ecosystem, package and version")
	case !ecosystems[*d.SDK.Ecosystem]:
		bad("sdk.ecosystem %q is not in the enum", *d.SDK.Ecosystem)
	}
	if d.SDK != nil {
		for i, dep := range d.SDK.Dependencies {
			if dep.Package == nil || dep.Version == nil {
				bad("sdk.dependencies[%d] needs package and version", i)
			}
		}
	}
	switch {
	case d.Runtime == nil:
		bad("runtime is missing")
	case d.Runtime.Name == nil || d.Runtime.Version == nil:
		bad("runtime needs name and version")
	case d.Runtime.StackBytes != nil && *d.Runtime.StackBytes < 0:
		bad("runtime.stack_bytes is negative")
	}
	switch {
	case d.XDRSchema == nil:
		bad("xdr_schema is missing")
	case d.XDRSchema.Probes == nil:
		bad("xdr_schema.probes is missing")
	default:
		for _, p := range []string{"sc_address_type_muxed_contract", "stellar_value_signed_ms"} {
			if _, ok := d.XDRSchema.Probes[p]; !ok {
				bad("xdr_schema.probes lacks %s", p)
			}
		}
		if p := d.XDRSchema.Protocol; p != nil && *p < 0 {
			bad("xdr_schema.protocol is negative")
		}
	}
	if d.Levels == nil {
		bad("levels is missing")
	}
	if err := uniqueIn("levels", d.Levels, levelSet); err != "" {
		bad("%s", err)
	}
	if d.APIOps == nil {
		bad("api_ops is missing")
	}
	if err := uniqueIn("api_ops", d.APIOps, v.APIOps); err != "" {
		bad("%s", err)
	}
	switch {
	case d.Decode == nil:
		bad("decode is missing")
	case d.Decode.EntryPoint == nil || d.Decode.ChecksConsumedLength == nil || d.Decode.DefaultDepth == nil:
		bad("decode needs entry_point, default_depth and checks_consumed_length")
	default:
		if s := string(d.Decode.DefaultDepth); s != "null" {
			var n int64
			if err := json.Unmarshal(d.Decode.DefaultDepth, &n); err != nil || n < 0 {
				bad("decode.default_depth %s is not a non-negative integer or null", s)
			}
		}
	}
	if len(errs) > 0 {
		return nil, protoErr(line, "describe: %s", strings.Join(errs, "; "))
	}
	return &d, nil
}

// ParseRun validates a run response to req.
func (v *Validator) ParseRun(line []byte, req *RunRequest) (*RunResponse, error) {
	err := checkEnvelope(line, func(p string) bool {
		return p == "/actual/projection" || p == "/actual/pinpoints/*/value" || p == "/actual/json/pinpoints/*/value" || p == "/actual/api/value"
	})
	if err != nil {
		return nil, err
	}
	var r RunResponse
	if err := decodeStrict(line, &r); err != nil {
		return nil, err
	}
	var errs []string
	bad := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if deref(r.Op) != "run" {
		bad("op is %q, want run", deref(r.Op))
	}
	if r.ID == nil || *r.ID != req.ID {
		bad("id %v does not echo the request id %d", ptrString(r.ID), req.ID)
	}
	if r.Entry == nil || *r.Entry != req.Entry {
		bad("entry %v does not echo %q", ptrString(r.Entry), req.Entry)
	}
	if r.Level == nil || *r.Level != req.Level {
		bad("level %v does not echo %q", ptrString(r.Level), req.Level)
	}
	if r.Variant != nil && *r.Variant != req.Variant {
		bad("variant %q does not echo %q", *r.Variant, req.Variant)
	}
	if r.Profile != nil && *r.Profile != req.Profile {
		bad("profile %q does not echo %q", *r.Profile, req.Profile)
	}
	switch {
	case r.Outcome == nil:
		bad("outcome is missing")
	case !outcomeSet[*r.Outcome]:
		bad("outcome %q is not in the enum", *r.Outcome)
	case *r.Outcome != "ok" && r.Reason == nil:
		bad("outcome %s needs a reason", *r.Outcome)
	}
	if rs := r.Reason; rs != nil {
		switch {
		case rs.Code == nil:
			bad("reason.code is missing")
		case !reasonCodes[*rs.Code]:
			bad("reason.code %q is not in the enum", *rs.Code)
		}
		if n := utf8.RuneCountInString(rs.Message); n > 500 {
			bad("reason.message has %d characters, at most 500", n)
		}
	}
	if a := r.Actual; a != nil {
		checkActual(a, bad)
	}
	if rs := r.Resources; rs != nil {
		if rs.WallMS != nil && *rs.WallMS < 0 {
			bad("resources.wall_ms is negative")
		}
		if rs.PeakRSSKB != nil && *rs.PeakRSSKB < 0 {
			bad("resources.peak_rss_kb is negative")
		}
	}
	if len(errs) > 0 {
		return nil, protoErr(line, "run: %s", strings.Join(errs, "; "))
	}
	return &r, nil
}

func checkActual(a *Actual, bad func(string, ...any)) {
	nonNeg := func(name string, p *int64) {
		if p != nil && *p < 0 {
			bad("%s is negative", name)
		}
	}
	sha := func(name string, p *string) {
		if p != nil && !sha256Re.MatchString(*p) {
			bad("%s %q is not a lower-case sha256", name, *p)
		}
	}
	nonNeg("actual.consumed_bytes", a.ConsumedBytes)
	sha("actual.reencoded_sha256", a.ReencodedSHA256)
	if a.ReencodedHex != nil && !hexRe.MatchString(*a.ReencodedHex) {
		bad("actual.reencoded_hex is not lower-case hex")
	}
	for i, l := range a.LenientEntryPoints {
		if l.EntryPoint == nil || l.Accepted == nil {
			bad("actual.lenient_entry_points[%d] needs entry_point and accepted", i)
		}
	}
	if o := a.Object; o != nil {
		sha("actual.object.tx_hash", o.TxHash)
		sha("actual.object.reencoded_sha256", o.ReencodedSHA256)
		nonNeg("actual.object.transactions", o.Transactions)
		nonNeg("actual.object.operations", o.Operations)
		nonNeg("actual.object.events", o.Events)
		nonNeg("actual.object.envelopes_parsed", o.EnvelopesParsed)
		for i, e := range o.EnvelopesRejected {
			if e.TxIndex == nil || e.Code == nil {
				bad("actual.object.envelopes_rejected[%d] needs tx_index and code", i)
			}
			nonNeg(fmt.Sprintf("actual.object.envelopes_rejected[%d].tx_index", i), e.TxIndex)
			sha(fmt.Sprintf("actual.object.envelopes_rejected[%d].tx_hash", i), e.TxHash)
			if n := utf8.RuneCountInString(e.Message); n > 500 {
				bad("actual.object.envelopes_rejected[%d].message has %d characters, at most 500", i, n)
			}
		}
		for i, h := range o.TxHashes {
			h := h
			sha(fmt.Sprintf("actual.object.tx_hashes[%d]", i), &h)
		}
		checkRebuild("actual.object.rebuild", o.Rebuild, bad)
		if f := o.Focus; f != nil {
			if f.TxHash == nil || f.OperationTypes == nil || f.Derived == nil {
				bad("actual.object.focus needs tx_hash, operation_types and derived")
			}
			sha("actual.object.focus.tx_hash", f.TxHash)
			checkRebuild("actual.object.focus.rebuild", f.Rebuild, bad)
		}
	}
	if a.Projection != nil && a.Pinpoints != nil {
		bad("actual.projection and actual.pinpoints are mutually exclusive")
	}
	for i, p := range a.Pinpoints {
		if p.Path == nil || p.Found == nil {
			bad("actual.pinpoints[%d] needs path and found", i)
		}
	}
	if n := a.Native; n != nil {
		nonNeg("actual.native.map_entries", n.MapEntries)
		sha("actual.native.reencoded_sha256", n.ReencodedSHA256)
		if c := utf8.RuneCountInString(n.Summary); c > 300 {
			bad("actual.native.summary has %d characters, at most 300", c)
		}
	}
	if s := a.Spec; s != nil {
		nonNeg("actual.spec.sections", s.Sections)
		if s.Entries == nil {
			bad("actual.spec needs entries")
		}
		for i, e := range s.Entries {
			if !specKinds[e.Kind] || e.Args == nil {
				bad("actual.spec.entries[%d] needs a kind (%q) and args", i, e.Kind)
			}
		}
	}
	if j := a.JSON; j != nil {
		sha("actual.json.json_sha256", j.JSONSHA256)
		sha("actual.json.roundtrip_sha256", j.RoundtripSHA256)
		nonNeg("actual.json.json_bytes", j.JSONBytes)
		switch {
		case j.JSONSHA256 == nil || j.Schema == nil || j.Roundtrip == nil:
			bad("actual.json needs json_sha256, schema and roundtrip")
		case !jsonSchemaStates[*j.Schema]:
			bad("actual.json.schema %q is not in the enum", *j.Schema)
		case !jsonRoundtrips[*j.Roundtrip]:
			bad("actual.json.roundtrip %q is not in the enum", *j.Roundtrip)
		}
		if len(j.SchemaErrors) > 5 {
			bad("actual.json.schema_errors has %d items, at most 5", len(j.SchemaErrors))
		}
	}
	if p := a.API; p != nil {
		if p.XDRHex != nil && !hexRe.MatchString(*p.XDRHex) {
			bad("actual.api.xdr_hex is not lower-case hex")
		}
		if p.SelfDecode != nil && !selfDecode[*p.SelfDecode] {
			bad("actual.api.self_decode %q is not in the enum", *p.SelfDecode)
		}
	}
}

// ParseShutdown validates a shutdown response.
func (v *Validator) ParseShutdown(line []byte, id int) error {
	if err := checkEnvelope(line, func(string) bool { return false }); err != nil {
		return err
	}
	var r struct {
		XDRCHECK *string `json:"xcc"`
		ID       *int    `json:"id"`
		Op       *string `json:"op"`
		OK       *bool   `json:"ok"`
	}
	if err := decodeStrict(line, &r); err != nil {
		return err
	}
	if deref(r.Op) != "shutdown" || r.ID == nil || *r.ID != id || r.OK == nil || !*r.OK {
		return protoErr(line, "shutdown: want {op: shutdown, id: %d, ok: true}", id)
	}
	return nil
}

func uniqueIn(name string, xs []string, allowed map[string]bool) string {
	seen := map[string]bool{}
	for _, x := range xs {
		if allowed != nil && !allowed[x] {
			return fmt.Sprintf("%s: %q is not in the enum", name, x)
		}
		if seen[x] {
			return fmt.Sprintf("%s: %q appears twice", name, x)
		}
		seen[x] = true
	}
	return ""
}

func ptrString[T any](p *T) string {
	if p == nil {
		return "(missing)"
	}
	return fmt.Sprintf("%v", *p)
}

// IsProtocolError reports whether err is a driver protocol violation.
func IsProtocolError(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe)
}

// rebuildReasons are the reasons a transaction is not rebuilt: what the builder's declaration cannot express.
var rebuildReasons = map[string]bool{"fee_bump": true, "no_time_bounds": true, "fee_not_per_operation": true,
	"soroban_memo": true, "soroban_muxed_source": true}

// checkRebuild checks the shape of a rebuild fact: rebuilt carries tx_hash, refused a message, not_rebuilt a
// reason from the closed list.
func checkRebuild(name string, r *RebuildFacts, bad func(string, ...any)) {
	if r == nil {
		return
	}
	if r.EntryPoint == nil || *r.EntryPoint == "" || r.Outcome == nil {
		bad("%s needs entry_point and outcome", name)
		return
	}
	switch *r.Outcome {
	case "rebuilt":
		if r.TxHash == nil || !sha256Re.MatchString(*r.TxHash) {
			bad("%s rebuilt needs a lower-case sha256 tx_hash", name)
		}
	case "refused":
		if r.Message == "" {
			bad("%s refused needs a message", name)
		}
	case "not_rebuilt":
		if !rebuildReasons[r.Reason] {
			bad("%s not_rebuilt has reason %q, not one of the closed list", name, r.Reason)
		}
	default:
		bad("%s outcome %q is not rebuilt, refused or not_rebuilt", name, *r.Outcome)
	}
}
