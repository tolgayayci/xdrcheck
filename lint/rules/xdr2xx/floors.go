package xdr2xx

// The floors XDR207 compares compile-time bounds with: what stellar-core
// admits into a ledger, per structure, in the unit of an application-level
// walk (nesting levels), or decoder units for the decoder's own depth.
// The configuration key `floors` (structure → integer) overrides or extends
// a row; a structure with no row has no established floor, and a constant
// bound on it is reported as info.
//
// A row has two numbers. Below `levels` a bound is a warning on every path
// fed from ledger meta. Between `levels` and `upper` (when upper is set) no
// floor is established for every part of the meta: the bound is info,
// except when every value the walk starts from was written by the host
// (contract events, contract data, return values), where `levels` is the
// established limit and the bound is silent. At or above `upper` it is
// silent.

type floor struct {
	levels int
	unit   string
	source string
	// upper is the bound at or above which nothing is reported; 0 = levels.
	upper int
	// band is the info message's reason for bounds in [levels, upper).
	band string
}

// The ScVal group. The host refuses values nested deeper than
// DEFAULT_HOST_DEPTH_LIMIT = 100 when it converts, compares or clones them
// (soroban-env-host v30.0.0, src/budget/limits.rs:41), so a value the host
// wrote into an event, contract data or a return value is at most 100 levels
// deep. A value in the envelope of a failed transaction never reached the
// host's limit; its bound is stellar-core's decoder: a bare ScVal decodes at
// 499 nested vector levels and fails at 500 (stellar-core v30.0.0 release
// binary, evidence/core-print-xdr). What core's envelope admission allows
// between the two is not yet measured.
var scValFloor = floor{
	levels: 100,
	unit:   "nested levels",
	source: "the host's value depth limit, DEFAULT_HOST_DEPTH_LIMIT = 100 (soroban-env-host v30.0.0 src/budget/limits.rs:41)",
	upper:  499,
	band:   "envelope limit not established; 499 is the decoder upper bound (stellar-core v30.0.0 decodes a bare ScVal at 499 nested vector levels, evidence/core-print-xdr); a value in a failed transaction's envelope is not held to the host's 100",
}

// structure names are the xdr type names a walk recurses over; every
// member of a recursive group carries the group's floor.
var shippedFloors = map[string]floor{
	"ScVal":              scValFloor,
	"ScVec":              scValFloor,
	"ScMap":              scValFloor,
	"ScMapEntry":         scValFloor,
	"ScContractInstance": scValFloor,
	// CreateClaimableBalance validation fails when the predicate depth
	// exceeds 4 (stellar-core v30.0.0, CreateClaimableBalanceOpFrame.cpp:76-81).
	"ClaimPredicate": {levels: 4, unit: "nested levels", source: "stellar-core rejects claim predicates deeper than 4 levels (code, CreateClaimableBalanceOpFrame.cpp:76-81 at v30.0.0)"},
	// SorobanAuthorizedInvocation, SorobanDelegateSignature, ScSpecTypeDef and
	// ScpQuorumSet: no floor established; the cost per level is not measured.
}

// decoderDepthFloor is the floor for xdr3.DecodeOptions.MaxDepth on ledger
// meta, in go-xdr units (two per nested vector level): the go-xdr default of
// 1500 admits 749 nested vector levels (measured), which covers the 499
// levels core admits for a bare value plus the wrapper levels of a
// LedgerCloseMeta. A lower cap is not proven safe.
const decoderDepthFloor = 1500

// floorFor returns the floor of a structure. A configured floor replaces the
// shipped row entirely: the project then owns the number and nothing at or
// above it is reported.
func (s *state) floorFor(structure string) (floor, bool) {
	if n, ok := s.cfgFloors[structure]; ok {
		return floor{levels: n, unit: "nested levels", source: "configuration (floors)"}, true
	}
	f, ok := shippedFloors[structure]
	return f, ok
}

func (s *state) decodeFloor() floor {
	if n, ok := s.cfgFloors["DecodeOptions.MaxDepth"]; ok {
		return floor{levels: n, unit: "go-xdr depth units", source: "configuration (floors)"}
	}
	return floor{levels: decoderDepthFloor, unit: "go-xdr depth units", source: "go-xdr default 1500 units = 749 nested vector levels (measured); stellar-core admits 499 for a bare value plus wrapper levels"}
}
