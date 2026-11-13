package adapterkit

// Message validation exactly as the harness does it: the two frozen JSON Schemas, embedded, and the checks on a
// response line that a schema cannot express (the echoed id and method, no wall-clock values).

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// The frozen protocol schemas, copied byte for byte from corpus/schema (a test checks the copies are identical).
//
//go:embed schemas/adapter-protocol.schema.json schemas/observation.schema.json
var schemaFS embed.FS

const (
	protocolSchemaID    = "urn:xcc:schema:adapter-protocol:v1"
	observationSchemaID = "urn:xcc:schema:observation:v1"
)

var schemas = func() *schemaSet {
	a, err1 := schemaFS.ReadFile("schemas/adapter-protocol.schema.json")
	o, err2 := schemaFS.ReadFile("schemas/observation.schema.json")
	if err1 != nil || err2 != nil {
		panic("adapterkit: embedded schemas missing")
	}
	s, err := newSchemaSet(a, o)
	if err != nil {
		panic("adapterkit: embedded schemas: " + err.Error())
	}
	return s
}()

// Reasons a message breaks the protocol (ProtocolError.Reason). The selftest reports them as they are.
const (
	ReasonMalformed         = "malformed_message"            // not one UTF-8 JSON object on one line
	ReasonWrongProtocol     = "wrong_protocol_tag"           // xdrcheck is not xcc.adapter/1
	ReasonIDMismatch        = "id_mismatch"                  // the request id is not echoed
	ReasonMethodMismatch    = "method_mismatch"              // the request method is not echoed
	ReasonMissingField      = "missing_field"                // a required property is absent
	ReasonUnknownField      = "unknown_field"                // a property the schema does not allow
	ReasonSchema            = "schema_violation"             // any other schema failure
	ReasonWallClock         = "wall_clock_field"             // an observation carries a wall-clock value
	ReasonUnsolicited       = "unsolicited_output"           // a line on stdout with no request pending
	ReasonLineTooLong       = "line_too_long"                // a response line above the client's limit
	ReasonVersionNotOffered = "protocol_version_not_offered" // describe picked a version the harness did not list
)

// ProtocolError is a message that breaks the protocol. The harness records it as a harness_fault for the
// entries affected; it never says anything about the indexer.
type ProtocolError struct {
	Method string
	ID     int64
	Reason string
	Detail string
	Errors []SchemaError // the schema errors, when Reason comes from schema validation
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("adapter protocol violation in %s response (id %d): %s: %s", e.Method, e.ID, e.Reason, e.Detail)
}

// ValidateMessage validates one message (request or response) against the whole adapter-protocol schema.
func ValidateMessage(data []byte) []SchemaError {
	v, err := decodeAny(data)
	if err != nil {
		return []SchemaError{{Keyword: "json", Message: err.Error()}}
	}
	return schemas.validate(protocolSchemaID+"#", v)
}

// ValidateObservation validates an observation set against observation.schema.json.
func ValidateObservation(data []byte) []SchemaError {
	v, err := decodeAny(data)
	if err != nil {
		return []SchemaError{{Keyword: "json", Message: err.Error()}}
	}
	return schemas.validate(observationSchemaID+"#", v)
}

// ValidateRequest validates one request line of the method against its request definition.
func ValidateRequest(method string, data []byte) []SchemaError {
	v, err := decodeAny(data)
	if err != nil {
		return []SchemaError{{Keyword: "json", Message: err.Error()}}
	}
	return schemas.validate(defFor(method, false), v)
}

// JoinSchemaErrors renders schema errors on one line (the first eight, then a count).
func JoinSchemaErrors(errs []SchemaError) string { return joinErrors(errs) }

// SameJSON reports whether two documents are the same JSON value: object member order and the spelling of a
// number do not matter.
func SameJSON(a, b []byte) (bool, error) {
	x, err := decodeAny(a)
	if err != nil {
		return false, err
	}
	y, err := decodeAny(b)
	if err != nil {
		return false, err
	}
	return jsonEqual(x, y), nil
}

// defFor names the schema definition a message of this method and direction must satisfy.
func defFor(method string, response bool) string {
	suffix := "Request"
	if response {
		suffix = "Response"
	}
	return protocolSchemaID + "#/$defs/" + method + suffix
}

// schemaReason picks the protocol-error reason that best describes a list of schema errors.
func schemaReason(errs []SchemaError) string {
	for _, e := range errs {
		if e.Keyword == "required" {
			return ReasonMissingField
		}
	}
	for _, e := range errs {
		if e.Keyword == "additionalProperties" {
			return ReasonUnknownField
		}
	}
	return ReasonSchema
}

func joinErrors(errs []SchemaError) string {
	var parts []string
	for i, e := range errs {
		if i == 8 {
			parts = append(parts, fmt.Sprintf("… %d more", len(errs)-i))
			break
		}
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

// CheckResponse validates one response line for the request (id, method) as the harness does — UTF-8, one JSON
// object, the protocol tag, the echoed id and method, the schema definition of the method's response (or of an
// error response), and no wall-clock value in an observation set — and returns the decoded message, numbers
// kept as json.Number.
func CheckResponse(line []byte, id int64, method string) (map[string]any, *ProtocolError) {
	perr := func(reason, format string, a ...any) *ProtocolError {
		return &ProtocolError{Method: method, ID: id, Reason: reason, Detail: fmt.Sprintf(format, a...)}
	}
	if !utf8.Valid(line) {
		return nil, perr(ReasonMalformed, "the line is not valid UTF-8")
	}
	v, err := decodeAny(line)
	if err != nil {
		return nil, perr(ReasonMalformed, "not a JSON value: %v (line starts %q)", err, head(line))
	}
	msg, ok := v.(map[string]any)
	if !ok {
		return nil, perr(ReasonMalformed, "the line is %s, not a JSON object", typeName(v))
	}
	if tag, present := msg["xcc"]; !present {
		return nil, perr(ReasonMissingField, `required property "xcc" is missing`)
	} else if tag != Protocol {
		return nil, perr(ReasonWrongProtocol, "xdrcheck is %s, want %q", compact(tag), Protocol)
	}
	if gotID, present := msg["id"]; !present {
		return nil, perr(ReasonMissingField, `required property "id" is missing`)
	} else if n, isNum := gotID.(json.Number); !isNum || n.String() != fmt.Sprint(id) {
		return nil, perr(ReasonIDMismatch, "id is %s, want %d", compact(gotID), id)
	}
	if gotMethod, present := msg["method"]; !present {
		return nil, perr(ReasonMissingField, `required property "method" is missing`)
	} else if gotMethod != method {
		return nil, perr(ReasonMethodMismatch, "method is %s, want %q", compact(gotMethod), method)
	}
	def := defFor(method, true)
	if _, isErr := msg["error"]; isErr {
		def = protocolSchemaID + "#/$defs/errorResponse"
	}
	if method == MethodObserve {
		if res, ok := msg["result"].(map[string]any); ok {
			if where := findWallClock(res, "/result"); where != "" {
				return nil, perr(ReasonWallClock, "%s (results carry no wall-clock values; durations only as wall_ms in ingest and prepare)", where)
			}
		}
	}
	if errs := schemas.validate(def, msg); len(errs) > 0 {
		pe := perr(schemaReason(errs), "%s", joinErrors(errs))
		pe.Errors = errs
		return nil, pe
	}
	return msg, nil
}

func head(b []byte) string {
	if len(b) > 60 {
		return string(b[:60]) + "…"
	}
	return string(b)
}

// Wall-clock detection for observation sets (adapter-protocol.md §5). Nothing in observation.schema.json is a
// time, so any key that names one, and any string value that is a calendar timestamp outside free-text fields,
// is a wall-clock value that leaked from the indexer's rows (ingested_at, closed_at, updated, …).
var (
	wallClockKey  = regexp.MustCompile(`(?i)((^|_)(at|ts|ms|epoch|now)$|time|date|clock|^(created|updated|modified|ingested)$)`)
	timestampText = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}(:?\d{2})?)?)?$`)
	freeTextKeys  = map[string]bool{"message": true, "reason": true, "native_label": true, "field": true, "cause": true}
)

// findWallClock returns where the first wall-clock value in v is, or "".
func findWallClock(v any, path string) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "/" + escapePointer(k)
			if wallClockKey.MatchString(k) {
				return fmt.Sprintf("%s: property %q names a time", p, k)
			}
			if s, ok := x[k].(string); ok && !freeTextKeys[k] && timestampText.MatchString(s) {
				return fmt.Sprintf("%s: %q is a timestamp", p, s)
			}
			if w := findWallClock(x[k], p); w != "" {
				return w
			}
		}
	case []any:
		for i, e := range x {
			if s, ok := e.(string); ok && timestampText.MatchString(s) {
				return fmt.Sprintf("%s/%d: %q is a timestamp", path, i, s)
			}
			if w := findWallClock(e, fmt.Sprintf("%s/%d", path, i)); w != "" {
				return w
			}
		}
	}
	return ""
}
