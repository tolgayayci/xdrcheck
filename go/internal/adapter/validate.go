package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// Validation lives in adapterkit, where the frozen schemas are embedded; these names keep the harness's code
// reading adapter.X.

// SchemaError is one place where an instance does not satisfy a schema.
type SchemaError = adapterkit.SchemaError

// ProtocolError is a message that breaks the protocol.
type ProtocolError = adapterkit.ProtocolError

// Reasons a message breaks the protocol (ProtocolError.Reason).
const (
	ReasonMalformed         = adapterkit.ReasonMalformed
	ReasonWrongProtocol     = adapterkit.ReasonWrongProtocol
	ReasonIDMismatch        = adapterkit.ReasonIDMismatch
	ReasonMethodMismatch    = adapterkit.ReasonMethodMismatch
	ReasonMissingField      = adapterkit.ReasonMissingField
	ReasonUnknownField      = adapterkit.ReasonUnknownField
	ReasonSchema            = adapterkit.ReasonSchema
	ReasonWallClock         = adapterkit.ReasonWallClock
	ReasonUnsolicited       = adapterkit.ReasonUnsolicited
	ReasonLineTooLong       = adapterkit.ReasonLineTooLong
	ReasonVersionNotOffered = adapterkit.ReasonVersionNotOffered
)

// ValidateMessage validates one message (request or response) against the whole adapter-protocol schema.
func ValidateMessage(data []byte) []SchemaError { return adapterkit.ValidateMessage(data) }

// ValidateObservation validates an observation set against observation.schema.json.
func ValidateObservation(data []byte) []SchemaError { return adapterkit.ValidateObservation(data) }

// AdapterError is an error response: the adapter or its environment failed (never a statement about the
// indexer's handling of a ledger).
type AdapterError struct {
	Method string
	ErrorBody
}

func (e *AdapterError) Error() string {
	return fmt.Sprintf("adapter error in %s: %s: %s", e.Method, e.Code, e.Message)
}

func head(b []byte) string {
	if len(b) > 60 {
		return string(b[:60]) + "…"
	}
	return string(b)
}

// decodeAny decodes one JSON value with numbers kept as json.Number.
func decodeAny(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
