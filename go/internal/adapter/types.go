package adapter

// The protocol types live in the public package adapterkit, so that an adapter outside this repository can use
// them; these aliases keep the harness's own code reading adapter.X.

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// Protocol and schema tags.
const (
	Protocol          = adapterkit.Protocol
	ObservationSchema = adapterkit.ObservationSchema
)

// The five methods, in session order.
const (
	MethodDescribe = adapterkit.MethodDescribe
	MethodPrepare  = adapterkit.MethodPrepare
	MethodIngest   = adapterkit.MethodIngest
	MethodObserve  = adapterkit.MethodObserve
	MethodTeardown = adapterkit.MethodTeardown
)

// Observation kinds.
const (
	KindReceipts     = adapterkit.KindReceipts
	KindTransactions = adapterkit.KindTransactions
	KindParticipants = adapterkit.KindParticipants
	KindStateChanges = adapterkit.KindStateChanges
	KindMovements    = adapterkit.KindMovements
	KindAddresses    = adapterkit.KindAddresses
)

// AllKinds lists the six observation kinds.
var AllKinds = adapterkit.AllKinds

// Ingest statuses.
const (
	StatusCompleted = adapterkit.StatusCompleted
	StatusHalted    = adapterkit.StatusHalted
	StatusCrashed   = adapterkit.StatusCrashed
	StatusRefused   = adapterkit.StatusRefused
	StatusTimeout   = adapterkit.StatusTimeout
)

// Opt is an optional value that may also be an explicit JSON null.
type Opt[T any] = adapterkit.Opt[T]

// Some returns a set, non-null Opt.
func Some[T any](v T) Opt[T] { return adapterkit.Some(v) }

// Null returns an explicit null.
func Null[T any]() Opt[T] { return adapterkit.Null[T]() }

// The message types.
type (
	DescribeParams = adapterkit.DescribeParams
	DescribeResult = adapterkit.DescribeResult
	NameVersion    = adapterkit.NameVersion
	Target         = adapterkit.Target
	Envelope       = adapterkit.Envelope
	Observations   = adapterkit.Observations
	Capability     = adapterkit.Capability
	Concurrency    = adapterkit.Concurrency
	Requirements   = adapterkit.Requirements
	Timing         = adapterkit.Timing
	Network        = adapterkit.Network
	PrepareParams  = adapterkit.PrepareParams
	PortRange      = adapterkit.PortRange
	Limits         = adapterkit.Limits
	PrepareResult  = adapterkit.PrepareResult
	Build          = adapterkit.Build
	RangeAnswer    = adapterkit.RangeAnswer
	IngestParams   = adapterkit.IngestParams
	Range          = adapterkit.Range
	Input          = adapterkit.Input
	SEP54Schema    = adapterkit.SEP54Schema
	IngestResult   = adapterkit.IngestResult
	Signals        = adapterkit.Signals
	Refusal        = adapterkit.Refusal
	ObserveParams  = adapterkit.ObserveParams
	Observation    = adapterkit.Observation
	KindsSet       = adapterkit.KindsSet
	KindStatus     = adapterkit.KindStatus
	Ledger         = adapterkit.Ledger
	Receipt        = adapterkit.Receipt
	Locator        = adapterkit.Locator
	ObsTransaction = adapterkit.ObsTransaction
	Stored         = adapterkit.Stored
	ObsAccount     = adapterkit.ObsAccount
	ObsParticipant = adapterkit.ObsParticipant
	ObsStateChange = adapterkit.ObsStateChange
	ObsSigner      = adapterkit.ObsSigner
	ObsMovement    = adapterkit.ObsMovement
	ObsRouting     = adapterkit.ObsRouting
	ObsAddress     = adapterkit.ObsAddress
	ObsError       = adapterkit.ObsError
	TeardownParams = adapterkit.TeardownParams
	TeardownResult = adapterkit.TeardownResult
	ErrorBody      = adapterkit.ErrorBody
)

type request struct {
	XDRCHECK string `json:"xcc"`
	ID       int64  `json:"id"`
	Method   string `json:"method"`
	Params   any    `json:"params"`
}

// decodeStrict decodes JSON into v, refusing unknown fields and keeping open numbers as json.Number.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}
