package adapterkit

// The protocol's messages as Go types: one struct per request, result and observation record, with the JSON
// names of corpus/schema/adapter-protocol.schema.json and observation.schema.json.

import (
	"encoding/json"
)

// Protocol is the protocol tag every message carries.
const Protocol = "xcc.adapter/1"

// ObservationSchema is the schema tag of an observation set.
const ObservationSchema = "xcc.observation/v1"

// The five methods, in session order.
const (
	MethodDescribe = "describe"
	MethodPrepare  = "prepare"
	MethodIngest   = "ingest"
	MethodObserve  = "observe"
	MethodTeardown = "teardown"
)

// Observation kinds, in the order the protocol lists them.
const (
	KindReceipts     = "receipts"
	KindTransactions = "transactions"
	KindParticipants = "participants"
	KindStateChanges = "state_changes"
	KindMovements    = "movements"
	KindAddresses    = "addresses"
)

// AllKinds lists the six observation kinds.
var AllKinds = []string{KindReceipts, KindTransactions, KindParticipants, KindStateChanges, KindMovements, KindAddresses}

// Ingest statuses.
const (
	StatusCompleted = "completed"
	StatusHalted    = "halted"
	StatusCrashed   = "crashed"
	StatusRefused   = "refused"
	StatusTimeout   = "timeout"
)

// Opt is an optional value that may also be an explicit JSON null: absent (Set false), null (Set and Null) or a
// value. It keeps the three apart so a message re-encodes exactly as it was read.
type Opt[T any] struct {
	Set  bool
	Null bool
	V    T
}

// Some returns a set, non-null Opt.
func Some[T any](v T) Opt[T] { return Opt[T]{Set: true, V: v} }

// Null returns an explicit null.
func Null[T any]() Opt[T] { return Opt[T]{Set: true, Null: true} }

// Get returns the value and whether there is one (set and not null).
func (o Opt[T]) Get() (T, bool) { return o.V, o.Set && !o.Null }

// IsZero reports absence, for the omitzero tag.
func (o Opt[T]) IsZero() bool { return !o.Set }

func (o Opt[T]) MarshalJSON() ([]byte, error) {
	if o.Null {
		return []byte("null"), nil
	}
	return json.Marshal(o.V)
}

func (o *Opt[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Null = true
		return nil
	}
	return json.Unmarshal(b, &o.V)
}

// ---- describe ----

// DescribeParams is the describe request.
type DescribeParams struct {
	HarnessVersion   string   `json:"harness_version"`
	ProtocolVersions []string `json:"protocol_versions"`
	TargetVersion    string   `json:"target_version,omitzero"`
}

// DescribeResult is what an adapter declares about itself and its indexer.
type DescribeResult struct {
	Adapter         NameVersion   `json:"adapter"`
	Target          Target        `json:"target"`
	ProtocolVersion string        `json:"protocol_version"`
	Inputs          []string      `json:"inputs"`
	Units           []string      `json:"units"`
	Envelope        Envelope      `json:"envelope"`
	Observations    Observations  `json:"observations"`
	Concurrency     *Concurrency  `json:"concurrency,omitzero"`
	Requirements    *Requirements `json:"requirements,omitzero"`
	Timing          *Timing       `json:"timing,omitzero"`
}

// NameVersion names the adapter.
type NameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Target is the indexer under test.
type Target struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitzero"`
	VersionKind string `json:"version_kind,omitzero"` // tag, commit, opaque
}

// Envelope is what the indexer at this version declares it handles.
type Envelope struct {
	MinProtocol                 *int     `json:"min_protocol,omitzero"`
	MaxProtocol                 *int     `json:"max_protocol,omitzero"`
	MinProtocolWithTransactions *int     `json:"min_protocol_with_transactions,omitzero"`
	LedgerCloseMetaVersions     []int    `json:"ledger_close_meta_versions,omitzero"`
	TransactionMetaVersions     []int    `json:"transaction_meta_versions,omitzero"`
	OperationTypes              []string `json:"operation_types,omitzero"`
	Enforcement                 string   `json:"enforcement"` // indexer_gate, sdk_limit, none
	Basis                       string   `json:"basis,omitzero"`
}

// Observations declares, per kind, whether the indexer models it.
type Observations struct {
	Receipts     Capability `json:"receipts"`
	Transactions Capability `json:"transactions"`
	Participants Capability `json:"participants"`
	StateChanges Capability `json:"state_changes"`
	Movements    Capability `json:"movements"`
	Addresses    Capability `json:"addresses"`
}

// Kind returns the capability of one kind by its protocol name, or nil for an unknown name.
func (o *Observations) Kind(name string) *Capability {
	switch name {
	case KindReceipts:
		return &o.Receipts
	case KindTransactions:
		return &o.Transactions
	case KindParticipants:
		return &o.Participants
	case KindStateChanges:
		return &o.StateChanges
	case KindMovements:
		return &o.Movements
	case KindAddresses:
		return &o.Addresses
	}
	return nil
}

// Capability is one kind's declaration. The schema leaves this object open, so properties it does not name are
// kept in Extra and written back unchanged.
type Capability struct {
	Supported       bool     `json:"supported"`
	Reason          string   `json:"reason,omitzero"`
	Subkinds        []string `json:"subkinds,omitzero"` // nil means all
	AddressEncoding string   `json:"address_encoding,omitzero"`
	Modelling       []string `json:"modelling,omitzero"`
	Muxed           string   `json:"muxed,omitzero"` // participants: base_only, base_and_alias

	Extra map[string]json.RawMessage `json:"-"`
}

type capabilityFields Capability

var capabilityKnown = map[string]bool{"supported": true, "reason": true, "subkinds": true, "address_encoding": true, "modelling": true, "muxed": true}

func (c *Capability) UnmarshalJSON(b []byte) error {
	var f capabilityFields
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for k, v := range all {
		if !capabilityKnown[k] {
			if f.Extra == nil {
				f.Extra = map[string]json.RawMessage{}
			}
			f.Extra[k] = v
		}
	}
	*c = Capability(f)
	return nil
}

func (c Capability) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(capabilityFields(c))
	if err != nil || len(c.Extra) == 0 {
		return b, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if _, dup := m[k]; !dup {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Concurrency is how many sessions the harness may run at once, each in its own adapter process.
type Concurrency struct {
	MaxParallelSessions *int `json:"max_parallel_sessions,omitzero"`
}

// Requirements are informational host requirements.
type Requirements struct {
	Network  string   `json:"network,omitzero"`
	Services []string `json:"services,omitzero"`
	Tools    []string `json:"tools,omitzero"`
}

// Timing holds advisory durations for sizing deadlines.
type Timing struct {
	PrepareColdMS     *int64           `json:"prepare_cold_ms,omitzero"`
	IngestPerLedgerMS *int64           `json:"ingest_per_ledger_ms,omitzero"`
	SlowestFailureMS  map[string]int64 `json:"slowest_failure_ms,omitzero"`
}

// ---- prepare ----

// Network is a passphrase family and its passphrase.
type Network struct {
	Name       string `json:"name"` // pubnet, testnet, core-test
	Passphrase string `json:"passphrase"`
}

// PrepareParams is the prepare request.
type PrepareParams struct {
	Session       string     `json:"session"`
	TargetVersion string     `json:"target_version"`
	Network       Network    `json:"network"`
	Workdir       string     `json:"workdir"`
	Cachedir      string     `json:"cachedir,omitzero"`
	PortRange     *PortRange `json:"port_range,omitzero"`
	Limits        *Limits    `json:"limits,omitzero"`
	ResolveRanges []string   `json:"resolve_ranges,omitzero"`
}

// PortRange is the loopback ports reserved for a session.
type PortRange struct {
	First int `json:"first"`
	Count int `json:"count"`
}

// Limits are the harness's limits, passed on for information.
type Limits struct {
	MemoryMaxBytes *int64       `json:"memory_max_bytes,omitzero"`
	CPUMax         *json.Number `json:"cpu_max,omitzero"`
	PidsMax        *int         `json:"pids_max,omitzero"`
}

// PrepareResult says the indexer is ready for the session.
type PrepareResult struct {
	Ready         bool          `json:"ready"`
	TargetVersion string        `json:"target_version"`
	Build         *Build        `json:"build,omitzero"`
	State         string        `json:"state,omitzero"`
	Notes         []string      `json:"notes,omitzero"`
	Ranges        []RangeAnswer `json:"ranges,omitzero"`
}

// Build describes the indexer binary used.
type Build struct {
	Cached         *bool  `json:"cached,omitzero"`
	ArtifactSHA256 string `json:"artifact_sha256,omitzero"`
	WallMS         *int64 `json:"wall_ms,omitzero"`
}

// RangeAnswer says whether the target version lies inside one of prepare's resolve_ranges.
type RangeAnswer struct {
	Range    string `json:"range"`
	Contains bool   `json:"contains"`
}

// ---- ingest ----

// IngestParams is the ingest request.
type IngestParams struct {
	Session    string  `json:"session"`
	Input      Input   `json:"input"`
	Range      Range   `json:"range"`
	Network    Network `json:"network"`
	Unit       string  `json:"unit,omitzero"` // single, chain, stream
	DeadlineMS int64   `json:"deadline_ms"`
}

// Range is an inclusive ledger range.
type Range struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// Input is where the indexer reads ledgers from; which fields apply depends on Kind (the schema checks them).
type Input struct {
	Kind            string       `json:"kind"` // sep54-dir, sep54-s3, sep54-gcs, rpc
	Path            string       `json:"path,omitzero"`
	EndpointURL     string       `json:"endpoint_url,omitzero"`
	EmulatorHost    string       `json:"emulator_host,omitzero"`
	BucketPath      string       `json:"bucket_path,omitzero"`
	Region          string       `json:"region,omitzero"`
	AccessKeyID     string       `json:"access_key_id,omitzero"`
	SecretAccessKey string       `json:"secret_access_key,omitzero"`
	URL             string       `json:"url,omitzero"`
	Schema          *SEP54Schema `json:"schema,omitzero"`
}

// SEP54Schema mirrors the store's .config.json.
type SEP54Schema struct {
	LedgersPerBatch     int    `json:"ledgers_per_batch"`
	BatchesPerPartition int    `json:"batches_per_partition"`
	Compression         string `json:"compression,omitzero"`
}

// IngestResult is what happened, as machine-observable facts.
type IngestResult struct {
	Status     string   `json:"status"`
	LastLedger *int64   `json:"last_ledger"` // required; nil is null
	Signals    Signals  `json:"signals"`
	Refusal    *Refusal `json:"refusal,omitzero"`
}

// Signals are the facts behind an ingest status.
type Signals struct {
	CursorBefore         *int64      `json:"cursor_before"` // required; nil is null
	CursorAfter          *int64      `json:"cursor_after"`  // required; nil is null
	ProcessExited        bool        `json:"process_exited"`
	ExitCode             Opt[int64]  `json:"exit_code,omitzero"`
	TermSignal           Opt[string] `json:"term_signal,omitzero"`
	StoppedByAdapter     *bool       `json:"stopped_by_adapter,omitzero"`
	WallMS               int64       `json:"wall_ms"`
	FailingLedger        Opt[int64]  `json:"failing_ledger,omitzero"`
	Phase                Opt[string] `json:"phase,omitzero"`
	RuntimePanic         Opt[bool]   `json:"runtime_panic,omitzero"`
	RowsForFailingLedger Opt[int64]  `json:"rows_for_failing_ledger,omitzero"`
	Attempts             Opt[int64]  `json:"attempts,omitzero"`
	StderrTail           Opt[string] `json:"stderr_tail,omitzero"` // for the report only; never used for scoring
}

// Refusal is a structured refusal naming a declared envelope gate.
type Refusal struct {
	Gate     string          `json:"gate"`
	Reason   string          `json:"reason"`
	Ledger   int64           `json:"ledger"`
	Observed json.RawMessage `json:"observed,omitzero"` // an integer or a string
}

// ---- observe ----

// ObserveParams is the observe request.
type ObserveParams struct {
	Session  string   `json:"session"`
	Range    Range    `json:"range"`
	Kinds    []string `json:"kinds"`
	TxHashes []string `json:"tx_hashes,omitzero"`
}

// Observation is an observation set (observation.schema.json).
type Observation struct {
	Schema  string     `json:"schema"`
	Range   Range      `json:"range"`
	Kinds   KindsSet   `json:"kinds"`
	Ledgers []Ledger   `json:"ledgers"`
	Errors  []ObsError `json:"errors,omitzero"`
}

// Ledger returns the observed ledger with that sequence, or nil.
func (o *Observation) Ledger(seq int64) *Ledger {
	for i := range o.Ledgers {
		if o.Ledgers[i].LedgerSeq == seq {
			return &o.Ledgers[i]
		}
	}
	return nil
}

// KindsSet says, per kind, whether this response provides it.
type KindsSet struct {
	Receipts     KindStatus `json:"receipts"`
	Transactions KindStatus `json:"transactions"`
	Participants KindStatus `json:"participants"`
	StateChanges KindStatus `json:"state_changes"`
	Movements    KindStatus `json:"movements"`
	Addresses    KindStatus `json:"addresses"`
}

// Kind returns the status of one kind by its protocol name, or nil for an unknown name.
func (k *KindsSet) Kind(name string) *KindStatus {
	switch name {
	case KindReceipts:
		return &k.Receipts
	case KindTransactions:
		return &k.Transactions
	case KindParticipants:
		return &k.Participants
	case KindStateChanges:
		return &k.StateChanges
	case KindMovements:
		return &k.Movements
	case KindAddresses:
		return &k.Addresses
	}
	return nil
}

// KindStatus is provided or not_applicable.
type KindStatus struct {
	Status   string   `json:"status"`
	Reason   string   `json:"reason,omitzero"`
	Subkinds []string `json:"subkinds,omitzero"` // nil means all
}

// Ledger is what the indexer holds for one ledger.
type Ledger struct {
	LedgerSeq    int64            `json:"ledger_seq"`
	LedgerHash   string           `json:"ledger_hash,omitzero"`
	Receipt      *Receipt         `json:"receipt,omitzero"`
	Transactions []ObsTransaction `json:"transactions,omitzero"`
	Participants []ObsParticipant `json:"participants,omitzero"`
	StateChanges []ObsStateChange `json:"state_changes,omitzero"`
	Movements    []ObsMovement    `json:"movements,omitzero"`
	Addresses    []ObsAddress     `json:"addresses,omitzero"`
}

// Receipt holds the counters the indexer accounted for in a ledger.
type Receipt struct {
	Transactions *int64 `json:"transactions,omitzero"`
	Operations   *int64 `json:"operations,omitzero"`
	Events       *int64 `json:"events,omitzero"`
	EntryChanges *int64 `json:"entry_changes,omitzero"`
}

// Locator places a fact in a transaction and operation.
type Locator struct {
	TxHash  string `json:"tx_hash,omitzero"`
	TxIndex *int   `json:"tx_index,omitzero"`
	OpIndex *int   `json:"op_index,omitzero"`
}

// ObsTransaction is one transaction the indexer holds.
type ObsTransaction struct {
	Hash                 string   `json:"hash"`
	Index                *int     `json:"index,omitzero"`
	Successful           *bool    `json:"successful,omitzero"`
	ResultCode           string   `json:"result_code,omitzero"`
	OperationResultCodes []string `json:"operation_result_codes,omitzero"`
	FeeCharged           string   `json:"fee_charged,omitzero"`
	InnerHash            string   `json:"inner_hash,omitzero"`
	InnerSuccessful      *bool    `json:"inner_successful,omitzero"`
	InnerResultCode      string   `json:"inner_result_code,omitzero"`
	NativeLabel          string   `json:"native_label,omitzero"`
}

// Stored is a value exactly as the indexer keeps it.
type Stored struct {
	Encoding string `json:"encoding"` // strkey_text, version_byte_payload_hex, xdr_hex, raw_key_hex
	Value    string `json:"value"`
}

// ObsAccount mirrors the manifest's account object.
type ObsAccount struct {
	Address     string   `json:"address,omitzero"`
	MuxedID     string   `json:"muxed_id,omitzero"`
	OnChainForm string   `json:"on_chain_form,omitzero"`
	Roles       []string `json:"roles,omitzero"`
	AsStored    *Stored  `json:"as_stored,omitzero"`
}

// ObsParticipant is one participant record.
type ObsParticipant struct {
	Locator
	Account ObsAccount `json:"account"`
}

// ObsStateChange is one state-change record.
type ObsStateChange struct {
	Locator
	Kind        string         `json:"kind"`
	Account     *ObsAccount    `json:"account,omitzero"`
	Asset       string         `json:"asset,omitzero"`
	Signer      *ObsSigner     `json:"signer,omitzero"`
	Detail      map[string]any `json:"detail,omitzero"`
	Cause       string         `json:"cause,omitzero"`
	NativeLabel string         `json:"native_label,omitzero"`
}

// ObsSigner is a signer as the indexer holds it.
type ObsSigner struct {
	Type       string  `json:"type,omitzero"`
	Key        string  `json:"key,omitzero"`
	PayloadHex string  `json:"payload_hex,omitzero"`
	Weight     *int    `json:"weight,omitzero"`
	AsStored   *Stored `json:"as_stored,omitzero"`
}

// ObsMovement is one value movement record.
type ObsMovement struct {
	Locator
	Kind           string      `json:"kind"`
	Asset          string      `json:"asset"`
	Amount         string      `json:"amount,omitzero"`
	AmountAsStored *string     `json:"amount_as_stored,omitzero"`
	From           *ObsAccount `json:"from,omitzero"`
	To             *ObsAccount `json:"to,omitzero"`
	Routing        *ObsRouting `json:"routing,omitzero"`
	NativeLabel    string      `json:"native_label,omitzero"`
}

// ObsRouting is a movement's routing ID, typed.
type ObsRouting struct {
	Type  string  `json:"type"` // absent, void, u64, text, bytes
	Value *string `json:"value,omitzero"`
}

// ObsAddress is one address-bearing value exactly as stored.
type ObsAddress struct {
	Locator
	Field    string `json:"field"`
	Type     string `json:"type,omitzero"`
	AsStored Stored `json:"as_stored"`
}

// ObsError is an error the indexer itself recorded.
type ObsError struct {
	LedgerSeq int64  `json:"ledger_seq"`
	TxHash    string `json:"tx_hash,omitzero"`
	Code      string `json:"code,omitzero"`
	Message   string `json:"message"`
}

// ---- teardown ----

// TeardownParams is the teardown request.
type TeardownParams struct {
	Session   string `json:"session"`
	KeepState *bool  `json:"keep_state,omitzero"`
}

// TeardownResult says the session's state is gone (or listed).
type TeardownResult struct {
	OK         bool     `json:"ok"`
	LeftBehind []string `json:"left_behind,omitzero"`
}

// ---- envelopes ----

// ErrorBody is the error member of an error response.
type ErrorBody struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Retryable *bool           `json:"retryable,omitzero"`
	Data      json.RawMessage `json:"data,omitzero"`
}
