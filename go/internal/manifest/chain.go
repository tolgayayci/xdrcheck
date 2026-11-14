package manifest

// ChainSchema is the schema ID of a chain index.
const ChainSchema = "xcc.chain.index/v1"

// ChainIndex is one kept local-core scenario run (corpus/chains/<id>.json): one scenario on one passphrase at one
// protocol under one meta flag profile, with every ledger in sequence order.
type ChainIndex struct {
	Schema          string        `json:"schema"`
	ID              string        `json:"id"`
	Scenario        string        `json:"scenario"`
	ScenarioSHA256  string        `json:"scenario_sha256"`
	Network         string        `json:"network"` // pubnet, testnet, core-test
	Passphrase      string        `json:"passphrase"`
	Protocol        int           `json:"protocol"`
	Profile         string        `json:"profile"` // lake, golden-test, custom
	CoreMetaFlags   []string      `json:"core_meta_flags,omitempty"`
	Core            ChainCore     `json:"core"`
	Settings        ChainSettings `json:"settings"`
	Stream          *ChainStream  `json:"stream,omitempty"`
	FirstLedger     int64         `json:"first_ledger,omitempty"`
	LastLedger      int64         `json:"last_ledger,omitempty"`
	Ledgers         []ChainLedger `json:"ledgers"`
	Regenerate      string        `json:"regenerate,omitempty"`
	Reproducibility string        `json:"reproducibility,omitempty"`
	Notes           string        `json:"notes,omitempty"`
	GoldenTest      *GoldenTest   `json:"golden_test,omitempty"`
	// Orders records, per ordered ledger group (by its first step ID), the ${order_nonce} the generator chose.
	Orders map[string]ChainOrder `json:"orders,omitempty"`
}

// ChainOrder is the apply-order search result of one ledger group: the nonce and the transaction-set shape the
// search used (default or learned).
type ChainOrder struct {
	Nonce int64  `json:"nonce"`
	Shape string `json:"shape"`
}

// ChainCore is the stellar-core build that ran the chain.
type ChainCore struct {
	Version      string       `json:"version"`
	Commit       string       `json:"commit"`
	BinarySHA256 string       `json:"binary_sha256,omitempty"`
	ImageDigest  string       `json:"image_digest,omitempty"`
	Package      *CorePackage `json:"package,omitempty"`
	ConfigSHA256 string       `json:"config_sha256,omitempty"`
}

// ChainSettings is the Soroban settings upgrade applied to the chain.
type ChainSettings struct {
	Source         string         `json:"source"`
	SourceProtocol *int           `json:"source_protocol,omitempty"`
	Files          []SettingsFile `json:"files"`
	SaltRule       string         `json:"salt_rule"`
	Note           string         `json:"note,omitempty"`
}

// SettingsFile is one settings-upgrade file, by name and hash.
type SettingsFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// ChainStream is the run's record-marked meta stream, if kept. Path is relative to the corpus root
// (chains/<id>.meta.xdr.zst, zstd-compressed, for generated chains) or to the repository root (evidence/…,
// raw); SHA256 is always of the uncompressed stream.
type ChainStream struct {
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Records int    `json:"records,omitempty"`
}

// ChainLedger is one ledger of a chain. Only ledgers that are some entry's blob are vendored in corpus/blobs.
type ChainLedger struct {
	Seq                    int64    `json:"seq"`
	BlobSHA256             string   `json:"blob_sha256"`
	Bytes                  int64    `json:"bytes,omitempty"`
	HeaderHash             string   `json:"header_hash"`
	PreviousHeaderHash     string   `json:"previous_header_hash,omitempty"`
	CloseTime              string   `json:"close_time,omitempty"`
	LedgerCloseMetaVersion *int     `json:"ledger_close_meta_version,omitempty"`
	Step                   string   `json:"step,omitempty"`
	Entries                []string `json:"entries,omitempty"`
}

// CorpusIndexSchema is the schema ID of corpus.json.
const CorpusIndexSchema = "xcc.corpus/v1"

// CorpusIndex is corpus/corpus.json: versions, the fail-closed gate, pins, tiers and checksum files.
type CorpusIndex struct {
	Schema                    string          `json:"schema"`
	CorpusVersion             string          `json:"corpus_version"`
	EntrySchema               string          `json:"entry_schema"`
	MaxProtocol               int             `json:"max_protocol"`
	MaxLedgerCloseMetaVersion int             `json:"max_ledger_close_meta_version"`
	Pins                      CorpusPins      `json:"pins"`
	Tiers                     CorpusTiers     `json:"tiers"`
	Checksums                 CorpusChecksums `json:"checksums"`
	GeneratedAt               string          `json:"generated_at,omitempty"`
}

// CorpusPins are the versions against which "decoded" and "core-emitted" are defined.
type CorpusPins struct {
	StellarCore struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"stellar_core"`
	XDRDefinitions struct {
		Tag    string `json:"tag"`
		Commit string `json:"commit"`
	} `json:"xdr_definitions"`
	Oracle struct {
		Crate   string `json:"crate"`
		Version string `json:"version"`
		Commit  string `json:"commit,omitempty"`
	} `json:"oracle"`
}

// CorpusTiers describes the in-repository tier, the fetched bulk tier and the mainnet tier.
type CorpusTiers struct {
	Curated struct {
		InRepository bool  `json:"in_repository"`
		Entries      int   `json:"entries"`
		Blobs        int   `json:"blobs"`
		Bytes        int64 `json:"bytes"`
	} `json:"curated"`
	Bulk    *BulkTier    `json:"bulk,omitempty"`
	Mainnet *MainnetTier `json:"mainnet,omitempty"`
}

// MainnetTier is the mainnet tier (corpus/mainnet/README.md): pubnet transactions located in their public-lake
// objects, which hold the bytes; Header names the tier's header file, whose counts these repeat.
type MainnetTier struct {
	InRepository bool   `json:"in_repository"`
	Description  string `json:"description,omitempty"`
	Header       string `json:"header"`
	Transactions int    `json:"transactions"`
	Ledgers      int    `json:"ledgers"`
	Tokens       int    `json:"tokens"`
}

// BulkTier is the golden set fetched by pinned ref.
type BulkTier struct {
	InRepository bool   `json:"in_repository"`
	Description  string `json:"description,omitempty"`
	Source       string `json:"source"`
	Ref          string `json:"ref"`
	Path         string `json:"path"`
	Files        int    `json:"files"`
	Ledgers      int    `json:"ledgers"`
	Bytes        int64  `json:"bytes"`
	FileIndex    string `json:"file_index"`
}

// CorpusChecksums names the checksum files.
type CorpusChecksums struct {
	Algorithm string `json:"algorithm"`
	Manifest  string `json:"manifest"`
	Blobs     string `json:"blobs,omitempty"`
	Decoded   string `json:"decoded,omitempty"`
}
