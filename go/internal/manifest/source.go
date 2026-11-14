package manifest

import (
	"encoding/json"
	"fmt"
)

// Source kinds (docs/manifest.md §4.4).
const (
	SourceCoreGolden     = "core-golden"
	SourceLocalCore      = "local-core"
	SourceHistory        = "history"
	SourceHistoryArchive = "history-archive"
	SourceSynthetic      = "synthetic"
	SourceContractCode   = "contract-code"
)

// Source is a variant's provenance: exactly one of the kind-specific records is set, matching Kind. Each record
// is decoded strictly against its own field set, so a field of another kind is an error.
type Source struct {
	Kind           string
	CoreGolden     *CoreGoldenSource
	LocalCore      *LocalCoreSource
	History        *HistorySource
	HistoryArchive *HistoryArchiveSource
	Synthetic      *SyntheticSource
	ContractCode   *ContractCodeSource
}

// ContractCodeSource is contract code read from a network's ledger: the CONTRACT_CODE entry whose hash is the
// blob's sha256.
type ContractCodeSource struct {
	Kind         string `json:"kind"`
	Network      string `json:"network"`
	WasmHash     string `json:"wasm_hash"`
	UploadLedger int64  `json:"upload_ledger"`
	FetchedVia   string `json:"fetched_via"`
	CapturedAt   string `json:"captured_at"`
	Perishable   bool   `json:"perishable,omitempty"`
}

// CoreGoldenSource is a ledger taken from a stellar-core golden file.
type CoreGoldenSource struct {
	Kind       string `json:"kind"`
	CoreTag    string `json:"core_tag"`
	CoreCommit string `json:"core_commit"`
	Tier       string `json:"tier"` // current, next
	File       string `json:"file"`
	FileSHA256 string `json:"file_sha256"`
	FrameIndex int    `json:"frame_index"`
	TestName   string `json:"test_name"`
	RNGSeed    *int64 `json:"rng_seed,omitempty"`
}

// LocalCoreSource is a ledger emitted by a local stellar-core run of a scenario.
type LocalCoreSource struct {
	Kind             string       `json:"kind"`
	CoreVersion      string       `json:"core_version"`
	CoreCommit       string       `json:"core_commit"`
	CoreImageDigest  string       `json:"core_image_digest,omitempty"`
	Scenario         string       `json:"scenario"`
	ScenarioSHA256   string       `json:"scenario_sha256,omitempty"`
	Step             string       `json:"step"`
	ConfigSHA256     string       `json:"config_sha256"`
	CloseTime        string       `json:"close_time,omitempty"`
	Regenerate       string       `json:"regenerate,omitempty"`
	Reproducibility  string       `json:"reproducibility"` // byte-identical, normalised-identical
	CorePackage      *CorePackage `json:"core_package,omitempty"`
	CoreBinarySHA256 string       `json:"core_binary_sha256,omitempty"`
	StreamSHA256     string       `json:"stream_sha256,omitempty"`
	FrameIndex       *int         `json:"frame_index,omitempty"`
	GeneratedBy      string       `json:"generated_by,omitempty"`
	SorobanResources string       `json:"soroban_resources,omitempty"` // not-applicable, declared, simulated
	Inputs           []RunInput   `json:"inputs,omitempty"`
	Submission       *Submission  `json:"submission,omitempty"`
	CoreRole         string       `json:"core_role,omitempty"` // release, buildtests, vnext, old-core; empty: release
}

// Submission marks a local-core variant whose bytes are stellar-core's answer to a submission: the refused
// TransactionResult its /tx endpoint returned for the envelope stored as EnvelopeEntry.
type Submission struct {
	Endpoint      string `json:"endpoint"` // tx
	Status        string `json:"status"`
	EnvelopeEntry string `json:"envelope_entry"`
}

// CorePackage is the official release package a stellar-core binary came from.
type CorePackage struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// RunInput is another pinned input of a local-core run.
type RunInput struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Origin string `json:"origin,omitempty"`
}

// HistorySource is a ledger captured from a public SEP-54 store.
type HistorySource struct {
	Kind               string            `json:"kind"`
	Store              string            `json:"store"`
	Key                string            `json:"key"`
	ObjectSHA256       string            `json:"object_sha256"`
	BatchIndex         *int              `json:"batch_index,omitempty"`
	CapturedAt         string            `json:"captured_at"`
	WrittenBy          string            `json:"written_by"`
	Refetch            string            `json:"refetch,omitempty"`
	Perishable         bool              `json:"perishable,omitempty"`
	ObjectBytes        *int64            `json:"object_bytes,omitempty"`
	DecompressedSHA256 string            `json:"decompressed_sha256,omitempty"`
	DecompressedBytes  *int64            `json:"decompressed_bytes,omitempty"`
	BlobOffset         *int64            `json:"blob_offset,omitempty"`
	ObjectMetadata     map[string]string `json:"object_metadata,omitempty"`
	Regenerated        bool              `json:"regenerated"`
	ObjectPath         string            `json:"object_path,omitempty"`
	SelectedBy         *SelectedBy       `json:"selected_by,omitempty"`
}

// SelectedBy names the census query that chose a captured ledger.
type SelectedBy struct {
	Census  string `json:"census"`
	QueryID string `json:"query_id"`
}

// HistoryArchiveSource is a record cut out of a history-archive object.
type HistoryArchiveSource struct {
	Kind         string `json:"kind"`
	Store        string `json:"store"`
	Object       string `json:"object"`
	ObjectSHA256 string `json:"object_sha256"`
	ByteOffset   int64  `json:"byte_offset"`
	Refetch      string `json:"refetch,omitempty"`
	Perishable   bool   `json:"perishable,omitempty"`
	FileKind     string `json:"file_kind,omitempty"` // bucket, scp; empty: bucket
}

// SyntheticSource is bytes built by a recipe.
type SyntheticSource struct {
	Kind      string `json:"kind"`
	Recipe    string `json:"recipe"`
	BaseEntry string `json:"base_entry,omitempty"`
	Reason    string `json:"reason"`
}

// UnmarshalJSON reads the kind and decodes the object strictly into that kind's record.
func (s *Source) UnmarshalJSON(data []byte) error {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	*s = Source{Kind: head.Kind}
	var target any
	switch head.Kind {
	case SourceCoreGolden:
		s.CoreGolden = &CoreGoldenSource{}
		target = s.CoreGolden
	case SourceLocalCore:
		s.LocalCore = &LocalCoreSource{}
		target = s.LocalCore
	case SourceHistory:
		s.History = &HistorySource{}
		target = s.History
	case SourceHistoryArchive:
		s.HistoryArchive = &HistoryArchiveSource{}
		target = s.HistoryArchive
	case SourceSynthetic:
		s.Synthetic = &SyntheticSource{}
		target = s.Synthetic
	case SourceContractCode:
		s.ContractCode = &ContractCodeSource{}
		target = s.ContractCode
	default:
		return fmt.Errorf("source: unknown kind %q", head.Kind)
	}
	if err := decodeStrict(data, target); err != nil {
		return fmt.Errorf("source (%s): %w", head.Kind, err)
	}
	return nil
}

// MarshalJSON writes the kind's record.
func (s Source) MarshalJSON() ([]byte, error) {
	switch {
	case s.CoreGolden != nil:
		return json.Marshal(s.CoreGolden)
	case s.LocalCore != nil:
		return json.Marshal(s.LocalCore)
	case s.History != nil:
		return json.Marshal(s.History)
	case s.HistoryArchive != nil:
		return json.Marshal(s.HistoryArchive)
	case s.Synthetic != nil:
		return json.Marshal(s.Synthetic)
	case s.ContractCode != nil:
		return json.Marshal(s.ContractCode)
	}
	return nil, fmt.Errorf("source: no record set (kind %q)", s.Kind)
}
