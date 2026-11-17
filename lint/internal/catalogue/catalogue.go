// Package catalogue is xdrlint's vocabulary: the go-stellar-sdk (and a few
// standard-library) names the rules treat as sources, sinks, sanitisers,
// gates and recursive types, as data.
//
// Every entry is keyed by a fully qualified name:
//
//	<import path>.<Name>               type, function, constant, variable
//	<import path>.<Type>.<Member>      field or method (pointer or value receiver)
//
// for example "github.com/stellar/go-stellar-sdk/xdr.MuxedAccount.Address".
// The names were collected for the rule set and are verified against go-stellar-sdk v0.9.0 by
// TestCatalogueResolves, which loads the real module with go/packages and
// fails on any name that does not exist or has a different kind. When the SDK
// pin moves, that test is the first thing to run.
//
// Rules look entries up by the name of a types.Object (Name, SelectionName)
// or list them by role (ByRole). Package aliases (the pre-split
// github.com/stellar/go module, or a configured fork) are mapped onto the
// canonical path by Canonical.
//
// Known gap: go-stellar-sdk (since v0.8.0) also has a read-only view API over the
// same data (xdr_views_generated.go: PaymentOpView.MustDestination,
// TransactionResultView.Successful, …, and ingest's transaction views). None
// of it is catalogued yet, so a reader that uses the views passes the rules'
// sources and gates unseen; the view accessors are to be added as sources.
package catalogue

// SDK and its pinned version (pins.toml [go] go_stellar_sdk).
const (
	SDKModule  = "github.com/stellar/go-stellar-sdk"
	SDKVersion = "v0.9.0"

	XDR           = SDKModule + "/xdr"
	Ingest        = SDKModule + "/ingest"
	Strkey        = SDKModule + "/strkey"
	TokenTransfer = SDKModule + "/processors/token_transfer"
	// GoXDR is the go-xdr package the SDK's decoder options come from
	// (go-stellar-sdk v0.9.0 requires go-xdr v0.0.0-20260806060815-dc590f17552a).
	GoXDR = "github.com/stellar/go-xdr/xdr3"

	// PreSplitModule is the old monorepo path of the same packages.
	PreSplitModule = "github.com/stellar/go"
)

// Kind of a catalogued name.
type Kind string

const (
	KindType   Kind = "type"
	KindField  Kind = "field"
	KindMethod Kind = "method"
	KindFunc   Kind = "func"
	KindConst  Kind = "const"
	KindVar    Kind = "var"
)

// Role is what a name means to the rules.
type Role string

const (
	// XDR101 — address built from a memo.
	MemoSource       Role = "memo-source"       // a value derived from the transaction memo
	MemoArmUnsafe    Role = "memo-arm-unsafe"   // MuxedInfo oneof arms that are not a routing ID (text, hash)
	MemoArmID        Role = "memo-arm-id"       // the one arm that is an ID
	MuxedConstructor Role = "muxed-constructor" // sink: building a muxed address from an ID
	MuxedEncode      Role = "muxed-encode"      // completes or renders a muxed strkey (with a muxed constructor)

	// XDR102 — unnormalised address used as identity.
	AddressSource     Role = "address-source"     // a string that can be an M…, W…, P…, B… or L… address
	AddressCarrier    Role = "address-carrier"    // a value that can hold a muxed or non-account kind
	AddressNormaliser Role = "address-normaliser" // reduces to the base account
	AddressKind       Role = "address-kind"       // discriminant and arms checked by a kind switch
	MetaWrittenAddr   Role = "meta-written-address"
	// AddressKindGuard: a re-parse of a ledger entry whose ok result is true
	// only when the address it holds is of a base kind (a contract). A sink
	// on its passing branch, fed from the same entry, is kind-checked.
	AddressKindGuard Role = "address-kind-guard"

	// XDR103 — unvalidated bytes or string into text storage.
	TextSource    Role = "text-source"
	TextValidated Role = "text-validated" // core validates it as printable ASCII: not a source
	SymbolInfo    Role = "symbol-info"    // host-restricted character set: info only
	TextSink      Role = "text-sink"
	TextSanitiser Role = "text-sanitiser"

	// XDR2xx — caps.
	RecursiveType   Role = "recursive-type"   // member of the computed recursive-type set
	RecursiveEdge   Role = "recursive-edge"   // a field leading to children of a recursive type
	DecodeEntry     Role = "decode-entry"     // decoder entry points (XDR205)
	DecodeLimit     Role = "decode-limit"     // decoder options and their defaults
	DecodeUnlimited Role = "decode-unlimited" // disables a decoder limit (XDR205 a)

	// XDR3xx — participants.
	AuthSource          Role = "auth-source"          // authorisation tree and invocation arguments (XDR301)
	AuthKind            Role = "auth-kind"            // credential kinds
	EnvelopeParticipant Role = "envelope-participant" // operation source and body accounts: participants only on success (XDR302)
	EnvelopeAccount     Role = "envelope-account"     // transaction and fee-bump source: always participants
	EnvelopeRead        Role = "envelope-read"        // other envelope reads (XDR303 "never reads meta")
	SuccessGate         Role = "success-gate"         // dominating check that the transaction succeeded
	MetaSource          Role = "meta-source"          // reads ledger meta (XDR303, XDR207)
	EventSource         Role = "event-source"         // contract event topics and data (XDR304)
	EventContractID     Role = "event-contract-id"    // the emitting contract, filled in by the host
	EventVerifier       Role = "event-verifier"       // derives the contract ID an event must come from
	AssetConstructor    Role = "asset-constructor"    // XDR304 sink: an asset built from event data
)

// Entry is one catalogued name.
type Entry struct {
	Name  string   // fully qualified name
	Kind  Kind     // what it must resolve to
	Roles []Role   // what the rules make of it
	Rules []string // rules that use it
	Ref   string   // file:line at go-stellar-sdk v0.8.0, where one is cited
	Note  string
}

func e(name string, kind Kind, roles []Role, rules []string, ref, note string) Entry {
	return Entry{Name: name, Kind: kind, Roles: roles, Rules: rules, Ref: ref, Note: note}
}

func r(rs ...Role) []Role       { return rs }
func ids(xs ...string) []string { return xs }

var (
	x   = XDR + "."
	ing = Ingest + "."
	sk  = Strkey + "."
	tt  = TokenTransfer + "."
	gx  = GoXDR + "."
)

// Entries is the catalogue.
var Entries = []Entry{
	// ---- Memo (XDR101 sources; text arm also XDR103) ----
	e(x+"Memo", KindType, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.Type", KindField, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.Id", KindField, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.Text", KindField, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "", "no content check in core (VF-19)"),
	e(x+"Memo.Hash", KindField, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.RetHash", KindField, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.GetId", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.MustId", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.GetText", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "", ""),
	e(x+"Memo.MustText", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "", ""),
	e(x+"Memo.GetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.MustHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.GetRetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"Memo.MustRetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"TransactionEnvelope.Memo", KindMethod, r(MemoSource, EnvelopeRead), ids("XDR101", "XDR303"), "xdr/transaction_envelope.go:242", ""),
	e(x+"Transaction.Memo", KindField, r(MemoSource, EnvelopeRead), ids("XDR101", "XDR303"), "", ""),
	e(x+"TransactionV0.Memo", KindField, r(MemoSource, EnvelopeRead), ids("XDR101", "XDR303"), "", ""),
	e(ing+"LedgerTransaction.Memo", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "ingest/ledger_transaction.go:353", "returns a Go string built with MustText() for text memos"),
	e(tt+"MuxedInfo", KindType, r(MemoSource), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo.Content", KindField, r(MemoSource), ids("XDR101"), "", "oneof: MuxedInfo_Text, MuxedInfo_Id, MuxedInfo_Hash"),
	e(tt+"MuxedInfo.GetContent", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo.GetId", KindMethod, r(MemoSource), ids("XDR101"), "", "returns 0 for the text and hash arms"),
	e(tt+"MuxedInfo.GetText", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "", ""),
	e(tt+"MuxedInfo.GetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo_Text", KindType, r(MemoArmUnsafe), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo_Hash", KindType, r(MemoArmUnsafe), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo_Hash.Hash", KindField, r(MemoSource), ids("XDR101"), "", ""),
	e(tt+"MuxedInfo_Id", KindType, r(MemoArmID), ids("XDR101"), "", "the only arm that is a routing ID"),
	e(tt+"MuxedInfo_Id.Id", KindField, r(MemoSource), ids("XDR101"), "", ""),

	// ---- Muxed-address construction (XDR101 sinks) ----
	e(x+"MuxedAccountMed25519", KindType, r(AddressCarrier), ids("XDR101", "XDR102"), "", ""),
	e(x+"MuxedAccountMed25519.Id", KindField, r(MuxedConstructor), ids("XDR101"), "", "composite literal field"),
	e(x+"MuxedAccountMed25519.Ed25519", KindField, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"MuxedEd25519Account", KindType, r(AddressCarrier), ids("XDR101", "XDR102"), "", ""),
	e(x+"MuxedEd25519Account.Id", KindField, r(MuxedConstructor), ids("XDR101"), "", "composite literal field"),
	e(x+"MuxedContract", KindType, r(AddressCarrier), ids("XDR101", "XDR102"), "", ""),
	e(x+"MuxedContract.Id", KindField, r(MuxedConstructor), ids("XDR101"), "", "composite literal field"),
	e(x+"NewMuxedAccount", KindFunc, r(MuxedConstructor), ids("XDR101"), "xdr/xdr_generated.go:26734", "with CryptoKeyTypeKeyTypeMuxedEd25519"),
	e(x+"CryptoKeyTypeKeyTypeMuxedEd25519", KindConst, r(MuxedConstructor), ids("XDR101"), "", ""),
	e(x+"MuxedAccountFromAccountId", KindFunc, r(MuxedConstructor), ids("XDR101"), "xdr/muxed_account.go:24", "(added): second argument is the ID"),
	e(x+"AddressToMuxedAccount", KindFunc, r(MuxedEncode), ids("XDR101"), "xdr/muxed_account.go:93", ""),
	e(sk+"MuxedAccount", KindType, r(AddressCarrier), ids("XDR101"), "", ""),
	e(sk+"MuxedAccount.SetID", KindMethod, r(MuxedConstructor), ids("XDR101"), "strkey/muxed_account.go:17", ""),
	e(sk+"MuxedAccount.SetAccountID", KindMethod, r(MuxedEncode), ids("XDR101"), "", ""),
	e(sk+"MuxedAccount.Address", KindMethod, r(MuxedEncode), ids("XDR101"), "", ""),
	e(sk+"MuxedContract", KindType, r(AddressCarrier), ids("XDR101"), "", ""),
	e(sk+"MuxedContract.SetID", KindMethod, r(MuxedConstructor), ids("XDR101"), "strkey/muxed_contract.go:15", ""),
	e(sk+"MuxedContract.SetContractID", KindMethod, r(MuxedEncode), ids("XDR101"), "", ""),
	e(sk+"MuxedContract.Address", KindMethod, r(MuxedEncode), ids("XDR101"), "", ""),
	e(sk+"Encode", KindFunc, r(MuxedConstructor), ids("XDR101"), "strkey/main.go:210", "a sink with VersionByteMuxedAccount or VersionByteMuxedContract"),
	e(sk+"VersionByteMuxedAccount", KindConst, r(MuxedConstructor), ids("XDR101"), "", ""),
	e(sk+"VersionByteMuxedContract", KindConst, r(MuxedConstructor), ids("XDR101"), "", ""),

	// ---- Muxed accounts and addresses (XDR102) ----
	e(x+"MuxedAccount", KindType, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"MuxedAccount.Type", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"MuxedAccount.Ed25519", KindField, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"MuxedAccount.Med25519", KindField, r(AddressCarrier, AddressKind), ids("XDR102"), "", ""),
	e(x+"MuxedAccount.Address", KindMethod, r(AddressSource), ids("XDR102"), "xdr/muxed_account.go:104", ""),
	e(x+"MuxedAccount.GetAddress", KindMethod, r(AddressSource), ids("XDR102"), "xdr/muxed_account.go:116", ""),
	e(x+"MuxedAccount.GetId", KindMethod, r(AddressCarrier), ids("XDR102"), "xdr/muxed_account.go:150", ""),
	e(x+"MuxedAccount.ToAccountId", KindMethod, r(AddressNormaliser), ids("XDR102"), "xdr/muxed_account.go:173", ""),
	e(ing+"LedgerTransaction.AccountMuxed", KindMethod, r(AddressSource, EnvelopeAccount), ids("XDR102", "XDR302"), "ingest/ledger_transaction.go:719", "(added): returns the M… form"),
	e(ing+"LedgerTransaction.FeeAccountAddress", KindMethod, r(AddressSource, EnvelopeAccount), ids("XDR102", "XDR302"), "ingest/ledger_transaction.go:509", "(added): .Address() without ToAccountId(), an M… string when muxed"),
	e(ing+"LedgerTransaction.Account", KindMethod, r(EnvelopeAccount), ids("XDR302"), "ingest/ledger_transaction.go:319", "already reduced with ToAccountId(): not an XDR102 source"),
	e(ing+"LedgerTransaction.FeeAccount", KindMethod, r(AddressCarrier, EnvelopeAccount), ids("XDR102", "XDR302"), "ingest/ledger_transaction.go:44", "returns xdr.MuxedAccount"),
	e(x+"ScAddress", KindType, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"ScAddress.Type", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.AccountId", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.ContractId", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.MuxedAccount", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.ClaimableBalanceId", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.LiquidityPoolId", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.MuxedContract", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddress.String", KindMethod, r(AddressSource), ids("XDR102"), "xdr/scval.go:14", "returns M…/W…/B…/L… for those arms"),
	e(x+"ScAddressTypeScAddressTypeAccount", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddressTypeScAddressTypeContract", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddressTypeScAddressTypeMuxedAccount", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddressTypeScAddressTypeClaimableBalance", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddressTypeScAddressTypeLiquidityPool", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"ScAddressTypeScAddressTypeMuxedContract", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"SignerKey", KindType, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"SignerKey.Ed25519SignedPayload", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"SignerKeyEd25519SignedPayload", KindType, r(AddressCarrier), ids("XDR102"), "", ""),
	e(x+"SignerKey.Address", KindMethod, r(AddressSource), ids("XDR102"), "xdr/signer_key.go:13", "P… for a signed payload"),
	e(x+"SignerKey.GetAddress", KindMethod, r(AddressSource), ids("XDR102"), "xdr/signer_key.go:23", ""),
	e(x+"AccountEntry.SignerSummary", KindMethod, r(AddressSource), ids("XDR102"), "xdr/account_entry.go:3", "the map keys are signer addresses"),
	e(x+"ContractDataEntry.Contract", KindField, r(MetaWrittenAddr), ids("XDR102"), "", "host-written: never a muxed kind (exemption)"),
	e(x+"LedgerEntryData.ContractData", KindField, r(MetaWrittenAddr), ids("XDR102"), "", ""),
	e(Ingest+"/sac.ContractBalanceFromContractData", KindFunc, r(AddressKindGuard), ids("XDR102"), "ingest/sac/contract_data.go:203",
		"ok (result 2) only when the balance key's holder is a contract: GetContractId on the key's address"),

	// ---- Text (XDR103) ----
	e(x+"ScVal.Str", KindField, r(TextSource), ids("XDR103"), "", "ScString is arbitrary bytes"),
	e(x+"ScVal.GetStr", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScVal.MustStr", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScVal.Bytes", KindField, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScVal.GetBytes", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScVal.MustBytes", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScVal.ExecutableTag", KindField, r(TextSource), ids("XDR103"), "xdr/xdr_generated.go:60842", "(added): Protocol 28 arm, ScValTypeScvExecutableTag = 22"),
	e(x+"ScValTypeScvExecutableTag", KindConst, r(TextSource), ids("XDR103"), "xdr/xdr_generated.go:58324", "(added)"),
	e(x+"ContractExecutableExternalRef.Tag", KindField, r(TextSource), ids("XDR103"), "xdr/xdr_generated.go:60143", "(corrected type name)"),
	e(x+"ScString", KindType, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScBytes", KindType, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ManageDataOp.DataValue", KindField, r(TextSource), ids("XDR103"), "", ""),
	e(x+"DataEntry.DataValue", KindField, r(TextSource), ids("XDR103"), "", ""),
	e(x+"SetOptionsOp.HomeDomain", KindField, r(TextValidated), ids("XDR103"), "", "core validates it (VF-28): not a source"),
	e(x+"ManageDataOp.DataName", KindField, r(TextValidated), ids("XDR103"), "", "core validates it (VF-31): not a source"),
	e(x+"ScVal.Sym", KindField, r(SymbolInfo), ids("XDR103"), "", "host-restricted character set"),
	e(x+"ScSymbol", KindType, r(SymbolInfo), ids("XDR103"), "", ""),
	e("database/sql.DB.Exec", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.DB.ExecContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.DB.Query", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.DB.QueryContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.DB.QueryRow", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.DB.QueryRowContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.Exec", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.ExecContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.Query", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.QueryContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.QueryRow", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Tx.QueryRowContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Conn.ExecContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Conn.QueryContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Conn.QueryRowContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.Exec", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.ExecContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.Query", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.QueryContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.QueryRow", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("database/sql.Stmt.QueryRowContext", KindMethod, r(TextSink), ids("XDR103"), "", ""),
	e("unicode/utf8.ValidString", KindFunc, r(TextSanitiser), ids("XDR103"), "", "with a NUL check"),
	e("unicode/utf8.Valid", KindFunc, r(TextSanitiser), ids("XDR103"), "", "with a NUL check"),
	e("strings.ToValidUTF8", KindFunc, r(TextSanitiser), ids("XDR103"), "", "with NUL stripping"),
	e("strings.IndexByte", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check: IndexByte(x, 0) < 0"),
	e("strings.Contains", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check: Contains(x, \"\\x00\")"),
	e("strings.ContainsRune", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("encoding/base64.Encoding.EncodeToString", KindMethod, r(TextSanitiser), ids("XDR103"), "", "encoding before the sink"),
	e("encoding/hex.EncodeToString", KindFunc, r(TextSanitiser), ids("XDR103"), "", "encoding before the sink"),

	// ---- Recursive types and the fields that lead to children (XDR2xx) ----
	// The set itself is computed by RecursiveTypes; these rows are what the
	// computation must find at v0.9.0 (TestRecursiveTypes compares them).
	e(x+"ClaimPredicate", KindType, r(RecursiveType), ids("XDR201", "XDR202", "XDR207"), "", "core bounds the depth at 4"),
	e(x+"ScContractInstance", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScMap", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScMapEntry", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeDef", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", "from contract WASM: attacker-authored"),
	e(x+"ScSpecTypeMap", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeOption", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeResult", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeTuple", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeVec", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal", KindType, r(RecursiveType), ids("XDR201", "XDR202", "XDR207"), "", ""),
	e(x+"ScVec", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", ""),
	e(x+"SorobanAuthorizedInvocation", KindType, r(RecursiveType), ids("XDR201", "XDR202", "XDR207"), "", ""),
	e(x+"SorobanDelegateSignature", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "", "new at v0.8.0"),
	e(x+"ScpQuorumSet", KindType, r(RecursiveType), ids("XDR201", "XDR202"), "xdr/xdr_generated.go:1327", "(added): InnerSets []ScpQuorumSet; SCP data, not transaction meta"),
	e(x+"ScpQuorumSet.InnerSets", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal.Vec", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", "**ScVec"),
	e(x+"ScVal.Map", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", "**ScMap"),
	e(x+"ScVal.Instance", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal.GetVec", KindMethod, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal.MustVec", KindMethod, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal.GetMap", KindMethod, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScVal.MustMap", KindMethod, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScContractInstance.Storage", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScMapEntry.Key", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScMapEntry.Val", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"SorobanAuthorizedInvocation.SubInvocations", KindField, r(RecursiveEdge, AuthSource), ids("XDR201", "XDR202", "XDR301"), "", "no xdrmaxsize"),
	e(x+"SorobanDelegateSignature.NestedDelegates", KindField, r(RecursiveEdge, AuthSource), ids("XDR201", "XDR202", "XDR301"), "", ""),
	e(x+"ClaimPredicate.AndPredicates", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ClaimPredicate.OrPredicates", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ClaimPredicate.NotPredicate", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeOption.ValueType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeVec.ElementType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeMap.KeyType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeMap.ValueType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeTuple.ValueTypes", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeResult.OkType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),
	e(x+"ScSpecTypeResult.ErrorType", KindField, r(RecursiveEdge), ids("XDR201", "XDR202"), "", ""),

	// ---- Decoding (XDR205, XDR207) ----
	e(x+"SafeUnmarshal", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/main.go:94", "defaults: depth 1500, input length known"),
	e(x+"SafeUnmarshalBase64", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/main.go:60", ""),
	e(x+"SafeUnmarshalBase64WithOptions", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/main.go:68", ""),
	e(x+"SafeUnmarshalHex", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/main.go:86", ""),
	e(x+"Unmarshal", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/xdr_generated.go:61", "on an io.Reader"),
	e(x+"UnmarshalWithOptions", KindFunc, r(DecodeEntry), ids("XDR205"), "xdr/xdr_generated.go:66", ""),
	e(x+"DecoderFrom.DecodeFrom", KindMethod, r(DecodeEntry), ids("XDR205"), "xdr/main.go:109", "implemented by every generated type"),
	e(x+"BytesDecoder.DecodeBytes", KindMethod, r(DecodeEntry), ids("XDR205"), "xdr/main.go:130", ""),
	e(x+"DecodeOptions", KindType, r(DecodeLimit), ids("XDR205", "XDR207"), "xdr/main.go:39", "alias of go-xdr's DecodeOptions"),
	e(gx+"DecodeOptions", KindType, r(DecodeLimit), ids("XDR205", "XDR207"), "", ""),
	e(gx+"DecodeOptions.MaxDepth", KindField, r(DecodeLimit), ids("XDR205", "XDR207"), "", ""),
	e(gx+"DecodeOptions.MaxInputLen", KindField, r(DecodeLimit), ids("XDR205"), "", ""),
	e(gx+"DecodeOptions.MaxMemoryBytes", KindField, r(DecodeLimit), ids("XDR205"), "", "default 0: unbounded"),
	e(gx+"DecodeDefaultMaxDepth", KindConst, r(DecodeLimit), ids("XDR205", "XDR207"), "", "1500"),
	e(gx+"DefaultDecodeOptions", KindVar, r(DecodeLimit), ids("XDR205"), "", ""),
	e(gx+"MaxPrealloc", KindConst, r(DecodeLimit), ids("XDR203"), "", "256"),
	e(gx+"DecodeUnlimitedDepth", KindConst, r(DecodeUnlimited), ids("XDR205"), "", "(corrected): lives in go-xdr xdr3, not in the SDK's xdr package"),

	// ---- Authorisation entries and invocation arguments (XDR301) ----
	e(x+"InvokeHostFunctionOp.HostFunction", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"InvokeHostFunctionOp.Auth", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizationEntry.Credentials", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizationEntry.RootInvocation", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.Type", KindField, r(AuthKind), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.Address", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.AddressV2", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.AddressWithDelegates", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.GetAddress", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.MustAddress", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.GetAddressV2", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.MustAddressV2", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.GetAddressWithDelegates", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentials.MustAddressWithDelegates", KindMethod, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanCredentialsTypeSorobanCredentialsSourceAccount", KindConst, r(AuthKind), ids("XDR301"), "", "= 0"),
	e(x+"SorobanCredentialsTypeSorobanCredentialsAddress", KindConst, r(AuthKind), ids("XDR301"), "", "= 1"),
	e(x+"SorobanCredentialsTypeSorobanCredentialsAddressV2", KindConst, r(AuthKind), ids("XDR301"), "", "= 2"),
	e(x+"SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates", KindConst, r(AuthKind), ids("XDR301"), "", "= 3"),
	e(x+"SorobanAddressCredentials.Address", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAddressCredentialsWithDelegates.AddressCredentials", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAddressCredentialsWithDelegates.Delegates", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanDelegateSignature.Address", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizedInvocation.Function", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizedFunction.ContractFn", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizedFunction.CreateContractHostFn", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"SorobanAuthorizedFunction.CreateContractV2HostFn", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"InvokeContractArgs.ContractAddress", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"InvokeContractArgs.Args", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"CreateContractArgs.ContractIdPreimage", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"CreateContractArgsV2.ContractIdPreimage", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"ContractIdPreimage.FromAddress", KindField, r(AuthSource), ids("XDR301"), "", ""),
	e(x+"ContractIdPreimageFromAddress.Address", KindField, r(AuthSource), ids("XDR301"), "", ""),

	// ---- Envelope (XDR302, XDR303) ----
	e(x+"TransactionEnvelope.SourceAccount", KindMethod, r(EnvelopeAccount, AddressCarrier), ids("XDR102", "XDR302"), "xdr/transaction_envelope.go:26", ""),
	e(x+"TransactionEnvelope.FeeBumpAccount", KindMethod, r(EnvelopeAccount, AddressCarrier), ids("XDR102", "XDR302"), "xdr/transaction_envelope.go:9", ""),
	e(x+"TransactionEnvelope.IsFeeBump", KindMethod, r(EnvelopeRead), ids("XDR303"), "xdr/transaction_envelope.go:4", ""),
	e(x+"TransactionEnvelope.Operations", KindMethod, r(EnvelopeRead), ids("XDR303"), "xdr/transaction_envelope.go:226", ""),
	e(x+"Transaction.SourceAccount", KindField, r(EnvelopeAccount, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"Transaction.Operations", KindField, r(EnvelopeRead), ids("XDR303"), "", ""),
	e(x+"TransactionV0.SourceAccountEd25519", KindField, r(EnvelopeAccount), ids("XDR302"), "", ""),
	e(x+"FeeBumpTransaction.FeeSource", KindField, r(EnvelopeAccount, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"Operation.SourceAccount", KindField, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"Operation.Body", KindField, r(EnvelopeRead), ids("XDR303"), "", ""),
	e(x+"OperationBody.MustDestination", KindMethod, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "xdr/xdr_generated.go:33018", "account merge"),
	e(x+"PaymentOp.Destination", KindField, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"PathPaymentStrictReceiveOp.Destination", KindField, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"PathPaymentStrictSendOp.Destination", KindField, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"CreateAccountOp.Destination", KindField, r(EnvelopeParticipant), ids("XDR302"), "", "AccountId"),
	e(x+"ClaimantV0.Destination", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(x+"AllowTrustOp.Trustor", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(x+"SetTrustLineFlagsOp.Trustor", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(x+"ClawbackOp.From", KindField, r(EnvelopeParticipant, AddressCarrier), ids("XDR102", "XDR302"), "", ""),
	e(x+"BeginSponsoringFutureReservesOp.SponsoredId", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(x+"RevokeSponsorshipOp.LedgerKey", KindField, r(EnvelopeParticipant), ids("XDR302"), "", "key owner"),
	e(x+"RevokeSponsorshipOp.Signer", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(x+"RevokeSponsorshipOpSigner.AccountId", KindField, r(EnvelopeParticipant), ids("XDR302"), "", ""),
	e(ing+"LedgerTransaction.Envelope", KindField, r(EnvelopeRead), ids("XDR303"), "", ""),
	e(ing+"LedgerTransaction.Successful", KindMethod, r(SuccessGate), ids("XDR302"), "ingest/ledger_transaction.go:747", ""),
	e(x+"TransactionResultPair.Successful", KindMethod, r(SuccessGate), ids("XDR302"), "xdr/transaction_result.go:21", ""),
	e(x+"TransactionResult.Successful", KindMethod, r(SuccessGate), ids("XDR302"), "xdr/transaction_result.go:6", ""),
	e(ing+"LedgerTransaction.Result", KindField, r(SuccessGate), ids("XDR302"), "", "Result.Successful()"),

	// ---- Meta (XDR303, XDR207) ----
	e(ing+"LedgerTransaction.FeeChanges", KindField, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(ing+"LedgerTransaction.UnsafeMeta", KindField, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(ing+"LedgerTransaction.PostTxApplyFeeChanges", KindField, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(ing+"LedgerTransaction.GetChanges", KindMethod, r(MetaSource), ids("XDR303", "XDR207"), "ingest/ledger_transaction.go:86", ""),
	e(ing+"LedgerTransaction.GetFeeChanges", KindMethod, r(MetaSource), ids("XDR303", "XDR207"), "ingest/ledger_transaction.go:50", ""),
	e(ing+"LedgerTransaction.GetPostApplyFeeChanges", KindMethod, r(MetaSource), ids("XDR303", "XDR207"), "ingest/ledger_transaction.go:62", ""),
	e(ing+"LedgerTransaction.GetOperationChanges", KindMethod, r(MetaSource), ids("XDR303", "XDR207"), "ingest/ledger_transaction.go:178", ""),
	e(ing+"LedgerTransaction.GetContractEvents", KindMethod, r(MetaSource, EventSource), ids("XDR303", "XDR207", "XDR304"), "ingest/ledger_transaction.go:253", ""),
	e(ing+"LedgerTransaction.GetContractEventsForOperation", KindMethod, r(MetaSource, EventSource), ids("XDR303", "XDR207", "XDR304"), "ingest/ledger_transaction.go:245", ""),
	e(ing+"LedgerTransaction.GetTransactionEvents", KindMethod, r(MetaSource, EventSource), ids("XDR303", "XDR207", "XDR304"), "ingest/ledger_transaction.go:278", ""),
	e(ing+"LedgerTransaction.GetDiagnosticEvents", KindMethod, r(MetaSource), ids("XDR303", "XDR207"), "ingest/ledger_transaction.go:264", ""),
	e(ing+"Change", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"TransactionMeta", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"TransactionMetaV1", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"TransactionMetaV2", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"TransactionMetaV3", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"TransactionMetaV4", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"LedgerEntryChange", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),
	e(x+"LedgerEntryChanges", KindType, r(MetaSource), ids("XDR303", "XDR207"), "", ""),

	// ---- Contract events (XDR304) ----
	e(x+"ContractEvent", KindType, r(EventSource), ids("XDR304"), "", ""),
	e(x+"ContractEvent.Body", KindField, r(EventSource), ids("XDR304"), "", ""),
	e(x+"ContractEventBody.V0", KindField, r(EventSource), ids("XDR304"), "", ""),
	e(x+"ContractEventV0.Topics", KindField, r(EventSource), ids("XDR304"), "", ""),
	e(x+"ContractEventV0.Data", KindField, r(EventSource), ids("XDR304"), "", ""),
	e(x+"ContractEvent.ContractId", KindField, r(EventContractID), ids("XDR304"), "", "filled in by the host from the executing contract"),
	e(x+"Asset.ContractID", KindMethod, r(EventVerifier), ids("XDR304"), "xdr/asset.go:467", "compare with the event's ContractId"),
	e(x+"BuildAsset", KindFunc, r(AssetConstructor), ids("XDR304"), "xdr/asset.go:100", ""),
	e(x+"MustNewCreditAsset", KindFunc, r(AssetConstructor), ids("XDR304"), "xdr/asset.go:41", ""),
}
