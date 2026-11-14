// Package manifest holds the Go types of the corpus: manifest entries (corpus/manifest/<id>.json,
// manifest-entry.schema.json), chain indexes (corpus/chains/<id>.json, chain-index.schema.json) and the corpus
// index (corpus/corpus.json, corpus-index.schema.json), and a loader for a corpus root.
//
// Decoding is strict: a field the types do not know is an error, so a corpus written against a newer schema is
// refused instead of being half-read. The only open objects are the ones the schema leaves open (`derived`,
// `object_metadata`, `api.input`, `settings_overrides`, `run_skeletons`, `expect.values[].equals`,
// `api.expect_value`). The loader does not validate against the JSON Schema; that stays in the repository checks
// and in `xdrcheck-corpus verify`. It does check what a reader of the corpus relies on: the file path equals the
// entry ID, every blob's size and sha256 match its file, variant keys are unique, state-change `detail` keys are
// the fixed keys of their kind, and every `${derived.<path>}` token resolves in every variant.
//
// JSON numbers inside open values are kept as json.Number, so 64-bit values survive.
package manifest

import (
	"encoding/json"
	"fmt"
)

// EntrySchema is the schema ID every manifest entry declares.
const EntrySchema = "xcc.manifest.entry/v1"

// Entry is one manifest entry: one rare-but-valid pattern of ledger data.
type Entry struct {
	Schema        string         `json:"schema"`
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Kind          string         `json:"kind"` // ledger, xdr, api, strkey, spec
	Caps          []int          `json:"caps"`
	CapsNote      string         `json:"caps_note,omitempty"`
	Protocol      ProtocolRange  `json:"protocol"`
	Synthetic     bool           `json:"synthetic"`
	Negative      bool           `json:"negative,omitempty"`
	Validity      string         `json:"validity,omitempty"`
	Flags         []string       `json:"flags,omitempty"`
	Shapes        []string       `json:"shapes,omitempty"`
	Why           string         `json:"why"`
	Fields        *FieldRows     `json:"fields,omitempty"`
	Variants      []*Variant     `json:"variants,omitempty"`
	API           *APIVector     `json:"api,omitempty"`
	Strkey        *StrkeyVector  `json:"strkey,omitempty"`
	Expect        Expect         `json:"expect"`
	Conformance   *Conformance   `json:"conformance,omitempty"`
	Replay        *Replay        `json:"replay,omitempty"`
	Related       []string       `json:"related,omitempty"`
	AddedIn       string         `json:"added_in,omitempty"`
	Notes         string         `json:"notes,omitempty"`
	Reference     string         `json:"reference,omitempty"` // network, protocol-rule, spec
	CoreBehaviour *CoreBehaviour `json:"core_behaviour,omitempty"`
	Mirrors       *Mirrors       `json:"mirrors,omitempty"`
}

// ProtocolRange is the first protocol that can emit the pattern and, optionally, the first that no longer can.
type ProtocolRange struct {
	Introduced int  `json:"introduced"`
	Removed    *int `json:"removed,omitempty"`
}

// FieldRows lists the guide field-table rows (VF-NN) an entry demonstrates, by verdict.
type FieldRows struct {
	Validated          []string `json:"validated,omitempty"`
	PartiallyValidated []string `json:"partially_validated,omitempty"`
	PassedThrough      []string `json:"passed_through,omitempty"`
}

// Variant is the pattern's bytes on one network at one protocol.
type Variant struct {
	Network        string         `json:"network"` // pubnet, testnet, core-test, none
	Passphrase     string         `json:"passphrase"`
	Protocol       int            `json:"protocol"`
	HeaderProtocol *int           `json:"header_protocol,omitempty"`
	LedgerSeq      int64          `json:"ledger_seq,omitempty"`
	XDRType        string         `json:"xdr_type"`
	Validity       string         `json:"validity,omitempty"`
	Container      string         `json:"container,omitempty"`   // spec entries: wasm, xdr-stream
	Framing        string         `json:"framing,omitempty"`     // none (default), record-marked
	FrameIndex     *int           `json:"frame_index,omitempty"` // with record-marked: the record holding the value
	Requires       []string       `json:"requires,omitempty"`    // XDR features the bytes use (verify derives them)
	XDRDefinitions string         `json:"xdr_definitions,omitempty"`
	Blob           Blob           `json:"blob"`
	SliceOf        *SliceOf       `json:"slice_of,omitempty"`
	Decoded        string         `json:"decoded,omitempty"`
	DecodedSHA256  string         `json:"decoded_sha256,omitempty"`
	DecodedBy      string         `json:"decoded_by,omitempty"`
	Source         Source         `json:"source"`
	Focus          *Focus         `json:"focus,omitempty"`
	Meta           *Meta          `json:"meta,omitempty"`
	Derived        map[string]any `json:"derived,omitempty"`
	Notes          string         `json:"notes,omitempty"`
	JSONRoundtrip  *JSONRoundtrip `json:"json_roundtrip,omitempty"`

	// Resolved is the entry's expect block with every ${derived.…} token replaced by this variant's value. The
	// loader fills it; it is never part of the JSON.
	Resolved *Expect `json:"-"`
}

// RecordMarked reports whether the blob is an RFC 5531 record-marked stream (negative entries only).
func (v *Variant) RecordMarked() bool { return v.Framing == "record-marked" }

// FrameOf returns the record a record-marked blob's value is in (default 0).
func (v *Variant) FrameOf() int {
	if v.FrameIndex == nil {
		return 0
	}
	return *v.FrameIndex
}

// JSONRoundtrip declares that SEP-51 JSON of the bytes does not reproduce them; the byte round trip still holds.
type JSONRoundtrip struct {
	Skip   bool   `json:"skip"`
	Reason string `json:"reason"`
}

// Blob is the content-addressed raw XDR of one value. Path is relative to the corpus root and empty for
// bulk-tier entries fetched by hash.
type Blob struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Path   string `json:"path,omitempty"`
}

// SliceOf says where an xdr entry cut out of a ledger entry sits in its parent.
type SliceOf struct {
	Entry      string `json:"entry"`
	Path       string `json:"path"`
	ByteOffset *int64 `json:"byte_offset,omitempty"`
}

// Focus is where in a ledger the pattern is. TxIndex is in apply order.
type Focus struct {
	TxIndex *int   `json:"tx_index,omitempty"`
	TxHash  string `json:"tx_hash,omitempty"`
	OpIndex *int   `json:"op_index,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Meta records which meta versions and which stellar-core meta flag profile produced a ledger blob.
type Meta struct {
	LedgerCloseMetaVersion *int        `json:"ledger_close_meta_version,omitempty"`
	TransactionMetaVersion *int        `json:"transaction_meta_version,omitempty"`
	CoreMetaFlags          []string    `json:"core_meta_flags,omitempty"`
	Profile                string      `json:"profile,omitempty"` // lake, golden-test, custom
	GoldenTest             *GoldenTest `json:"golden_test,omitempty"`
}

// GoldenTest names the stellar-core golden test whose meta flags a blob or chain was produced with.
type GoldenTest struct {
	CoreTag     string `json:"core_tag"`
	TestName    string `json:"test_name"`
	FlagsSource string `json:"flags_source"`
}

// Conformance lists the levels that apply and the readers known to diverge.
type Conformance struct {
	Levels           []string          `json:"levels,omitempty"`
	KnownDivergences []KnownDivergence `json:"known_divergences,omitempty"`
}

// KnownDivergence is a reader known to get the entry wrong in a version range (manifest.md §7).
type KnownDivergence struct {
	Target    string `json:"target"`
	Versions  string `json:"versions"`
	Level     string `json:"level,omitempty"` // L0..L4, replay
	Outcome   string `json:"outcome"`         // reject, crash, wrong_value, accepts_invalid, dropped, halt, hang
	Detail    string `json:"detail,omitempty"`
	Reference string `json:"reference"` // URI
	FixedIn   string `json:"fixed_in,omitempty"`
	Status    string `json:"status,omitempty"`   // fixed, fixed_unreleased, open, wont_fix, unreported
	Observed  string `json:"observed,omitempty"` // executed, source-reading, reported
	Evidence  string `json:"evidence,omitempty"`
	Qualifier string `json:"qualifier,omitempty"` // replay class qualifier
	Profile   string `json:"profile,omitempty"`
	Finding   string `json:"finding,omitempty"`
	// Match states details the observed cell must also show for the divergence to count as observed, beyond
	// the outcome class.
	Match *DivergenceMatch `json:"match,omitempty"`
}

// DivergenceMatch is the declared detail of a conformance known divergence. Every field is optional; a stated
// field must equal the driver's report.
type DivergenceMatch struct {
	Reason          string `json:"reason,omitempty"`            // the driver's reason code
	EnvelopesParsed *int   `json:"envelopes_parsed,omitempty"`  // L1 on a ledger: envelopes the SDK parsed
	RejectedTxIndex *int   `json:"rejected_tx_index,omitempty"` // L1 on a ledger: an envelope (apply order) that must be among the rejected
}

// Replay says how the harness serves the entry.
type Replay struct {
	Unit               string `json:"unit,omitempty"` // single, chain
	Chain              string `json:"chain,omitempty"`
	IndexerScope       string `json:"indexer_scope,omitempty"` // all (default), sdk-only
	RequiresPriorState *bool  `json:"requires_prior_state,omitempty"`
}

// APIVector is an SDK-neutral call. ExpectValue is kept raw so that an explicit null is told apart from absence.
type APIVector struct {
	Op           string          `json:"op"`
	Input        map[string]any  `json:"input"`
	ExpectXDRHex string          `json:"expect_xdr_hex,omitempty"`
	ExpectValue  json.RawMessage `json:"expect_value,omitempty"`
	ExpectReject bool            `json:"expect_reject,omitempty"`
}

// StrkeyVector is a text address vector.
type StrkeyVector struct {
	Text       string `json:"text"`
	Type       string `json:"type,omitempty"`
	PayloadHex string `json:"payload_hex,omitempty"`
	Origin     string `json:"origin,omitempty"`
}

// CoreBehaviour records what stellar-core itself does with a negative input.
type CoreBehaviour struct {
	Accepts  bool   `json:"accepts"`
	Value    string `json:"value,omitempty"`
	Observed string `json:"observed"` // executed, source-reading
	Evidence string `json:"evidence,omitempty"`
}

// Mirrors is the golden-mirror record (check AG-4).
type Mirrors struct {
	CoreGolden        MirrorGolden      `json:"core_golden"`
	Flags             []string          `json:"flags"`
	FlagsSource       string            `json:"flags_source"`
	SettingsOverrides map[string]any    `json:"settings_overrides,omitempty"`
	Scenario          string            `json:"scenario,omitempty"`
	SkeletonSHA256    string            `json:"skeleton_sha256,omitempty"`
	RunSkeletons      map[string]string `json:"run_skeletons,omitempty"`
	State             string            `json:"state"` // executed, planned
	Evidence          string            `json:"evidence,omitempty"`
}

// MirrorGolden names the golden ledger and transaction a mirror is compared with.
type MirrorGolden struct {
	CoreTag    string `json:"core_tag"`
	File       string `json:"file"`
	FileSHA256 string `json:"file_sha256"`
	TestName   string `json:"test_name"`
	FrameIndex int    `json:"frame_index"`
	TxIndex    int    `json:"tx_index"`
}

// VariantKey returns the report's variant key for v (report.schema.json row.variant): the network, or
// network@protocol when the entry's variants span several protocols.
func (e *Entry) VariantKey(v *Variant) string {
	for _, o := range e.Variants {
		if o.Protocol != v.Protocol {
			return fmt.Sprintf("%s@%d", v.Network, v.Protocol)
		}
	}
	return v.Network
}

// IndexerScope returns the entry's replay.indexer_scope, defaulting to "all".
func (e *Entry) IndexerScope() string {
	if e.Replay == nil || e.Replay.IndexerScope == "" {
		return "all"
	}
	return e.Replay.IndexerScope
}

// RequiresPriorState returns replay.requires_prior_state, defaulting to false.
func (e *Entry) RequiresPriorState() bool {
	return e.Replay != nil && e.Replay.RequiresPriorState != nil && *e.Replay.RequiresPriorState
}
