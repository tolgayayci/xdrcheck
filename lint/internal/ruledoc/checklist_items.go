package ruledoc

// The self-audit checklist: every item, in page order. This table and the
// rule registry are the single source of the checklist page
// (guide/checklist.mdx) and of the table it shares with the linter
// (guide/generated/checklist-table.mdx).
//
// Which linter rule checks an item is not written here: it comes from the
// registry (Rule.Checklist), together with the rule's guide anchor, its
// corpus entry and whether it is opt-in. An item that no rule names must
// carry Manual: why it cannot be checked mechanically and how to check it by
// hand. Guide and Corpus add sections and entries to the ones the rule
// already names. Search hints locate code to review in SDKs other than Go;
// they do not prove a violation. They were checked against js-stellar-sdk
// v17.4.0 (src/base), rs-stellar-xdr v30.0.0, py-stellar-base 17.0.1 and
// java-stellar-sdk 6.0.0; an item without hints has no useful search term
// and is checked as its Manual text or its rule says.
var checklistItems = []item{
	{
		ID:     "HC-101",
		Check:  "No address is ever built from a memo; a memo ID is stored as an ID.",
		Guide:  []string{"passed-through", "muxed-accounts"},
		Corpus: []string{"cap-0067/to-muxed-id-text-non-utf8-memo"},
		Hints: hints{
			JS:     []string{"`encodeMuxedAccountToAddress`, `new MuxedAccount(` near `memo`"},
			Rust:   []string{"`MuxedAccountMed25519 { id:`, `Strkey::MuxedAccountEd25519` near `Memo::`"},
			Python: []string{"`MuxedAccount(` with `account_muxed_id=` near `memo_id` or `memo_text`"},
			Java:   []string{"`new MuxedAccount(` near `Memo`"},
		},
	},
	{
		ID:     "HC-102",
		Check:  "Muxed accounts and muxed contracts are reduced to the base address before they are used as an identity; claimable-balance, liquidity-pool and signed-payload kinds are handled explicitly.",
		Guide:  []string{"muxed-accounts", "muxed-contracts"},
		Corpus: []string{"cap-0084/sac-transfer-to-muxed-contract"},
		Hints:  addressHints,
	},
	{
		ID:     "HC-103",
		Check:  "Memo text, contract strings and data values are treated as bytes: validated before they go into text storage, or stored as bytes.",
		Guide:  []string{"passed-through", "decoder-strictness"},
		Corpus: []string{"cap-0067/to-muxed-id-text-non-utf8-memo", "classic/api-memo-text-non-utf8-roundtrip"},
		Hints: hints{
			JS:     []string{"`scValToNative` results, `memo.value`, `.dataValue`"},
			Rust:   []string{"`StringM`, `ScString`, `to_utf8_string` (refuses invalid UTF-8)"},
			Python: []string{"`memo_text` (bytes), `scval.to_native`"},
			Java:   []string{"`MemoText.getText()` (a decoded string; read the bytes accessor instead), `XdrString`, `getDataValue()`"},
		},
	},
	{
		ID:    "HC-104",
		Check: "The event routing ID `to_muxed_id` is type-switched over all five forms: u64, text, bytes, void and absent.",
		Manual: &manual{
			Why: "Whether every form is handled depends on what the code does with the value afterwards, and a switch with a missing arm compiles.",
			How: "find every read of `to_muxed_id` and confirm that each form has a branch and that none builds an address.",
		},
		Guide: []string{"shorthand", "event-routing-id"},
		Corpus: []string{
			"cap-0067/to-muxed-id-absent",
			"cap-0067/to-muxed-id-void-custom-token",
			"cap-0067/to-muxed-id-text-from-memo",
			"cap-0067/to-muxed-id-bytes-from-memo-hash",
			"cap-0067/to-muxed-id-u64-from-muxed-destination-over-memo",
		},
		Hints: eventHints,
	},
	{
		ID:    "HC-105",
		Check: "Fees are taken from results and meta, never from the fee bid in the envelope.",
		Manual: &manual{
			Why: "Reading the bid is correct in an export of what was submitted, so a rule would flag legitimate code.",
			How: "trace each stored fee to `feeCharged` in the result or to the fee changes in meta.",
		},
		Guide:  []string{"passed-through"},
		Corpus: []string{"cap-0015/fee-bump-soroban-inner-fee-zero-from-p25", "cap-0005/fee-charged-below-bid"},
	},
	{
		ID:    "HC-106",
		Check: "Signature hints are never used as signer identity.",
		Manual: &manual{
			Why: "No pattern in the code separates using the hint as an identity from displaying it.",
			How: "search for uses of the hint outside signature matching.",
		},
		Guide:  []string{"passed-through"},
		Corpus: []string{"cap-0040/tx-authorised-by-signed-payload-signature"},
	},
	{
		ID:     "HC-107",
		Check:  "A union arm is read only after its discriminant was checked.",
		Guide:  []string{"shorthand"},
		Corpus: nil,
	},
	{
		ID:     "HC-108",
		Check:  "No error or ok result of a parse, an encoding or a conversion of ledger data is discarded on a value that is then stored.",
		Guide:  []string{"validated-fields"},
		Corpus: nil,
	},
	{
		ID:     "HC-201",
		Check:  "Every recursive walk over authorization trees, delegate chains and nested values has a bound.",
		Guide:  nil,
		Corpus: nil,
		Hints: hints{
			JS:     []string{"`subInvocations`, `walkInvocationTree`, `buildInvocationTree`, `scValToNative`"},
			Rust:   []string{"`sub_invocations`, `nested_delegates`, `Limits { depth`"},
			Python: []string{"`sub_invocations`, `scval.to_native`"},
			Java:   []string{"`getSubInvocations()`"},
		},
	},
	{
		ID:    "HC-202",
		Check: "Iterative walkers bound their stack and their node count.",
		Hints: hints{
			JS:     []string{"`push(…subInvocations`"},
			Rust:   []string{"`extend(…sub_invocations`"},
			Python: []string{"`extend(…sub_invocations`"},
			Java:   []string{"`addAll(…getSubInvocations`"},
		},
	},
	{
		ID:     "HC-203",
		Check:  "No decoded integer is used as an allocation size or a loop bound without a cap.",
		Guide:  []string{"decoder-strictness"},
		Corpus: nil,
		Hints: hints{
			JS:     []string{"`new Array(n)`, `Buffer.alloc(n)`"},
			Rust:   []string{"`Vec::with_capacity(n as usize)`"},
			Python: []string{"`bytearray(n)`, `[None] * n`"},
			Java:   []string{"`new byte[n]`"},
		},
	},
	{
		ID:     "HC-204",
		Check:  "XDR is decoded with explicit depth and length limits: at or above what stellar-core admits for ledger meta, and documented when tighter for untrusted input.",
		Guide:  []string{"caps-untrusted"},
		Corpus: []string{"cap-0046/scval-nested-vec-99-in-event"},
		Hints:  limitHints,
	},
	{
		ID:     "HC-205",
		Check:  "When a bound is reached the reader does what the project declared: stop at the ledger with a typed error that raises an alert, or skip the field, flag the record as incomplete and keep the raw XDR. Never an undeclared panic or exit.",
		Guide:  []string{"caps-meta-readers"},
		Corpus: nil,
		Hints: hints{
			JS:     []string{"review the `throw` at the bound"},
			Rust:   []string{"review `panic!` and `?` at the bound"},
			Python: []string{"review the `raise` at the bound"},
			Java:   []string{"review the `throw` at the bound"},
		},
	},
	{
		ID:    "HC-206",
		Check: "A meta reader's bounds are not below what stellar-core admits into a ledger.",
		Guide: []string{"caps-meta-readers", "sdk-defaults"},
		Hints: limitHints,
	},
	{
		ID:    "HC-207",
		Check: "Votable network settings are not used as decode limits.",
		Manual: &manual{
			Why: "The settings are read at run time from ledger entries; no pattern in the code identifies them.",
			How: "check where each size or depth limit comes from.",
		},
		Guide:   []string{"caps-meta-readers"},
		NoEntry: "none: no corpus entry yet exceeds a current network setting.",
	},
	{
		ID:    "HC-208",
		Check: "Memory does not grow with the number of ledgers processed.",
		Manual: &manual{
			Why: "It is a run-time property, not a pattern in the code.",
			How: "replay a long range of ledgers under a memory limit and watch the resident size; it must level off.",
		},
		Guide:   []string{"caps-meta-readers"},
		NoEntry: "none: a stream replay of many ledgers under a memory limit checks it, not a single entry.",
	},
	{
		ID:     "HC-209",
		Check:  "A recursive value is not persisted in serialised form without a size check.",
		Guide:  nil,
		Corpus: nil,
	},
	{
		ID:     "HC-301",
		Check:  "Participants never come from the authorization tree or invocation arguments; authorizers come from the nonce entries in meta.",
		Guide:  []string{"participant-algorithm", "shorthand"},
		Corpus: nil,
		Hints: hints{
			JS:     []string{"`.auth`, `rootInvocation`, `subInvocations` feeding an account set"},
			Rust:   []string{"`auth`, `root_invocation`, `contract_address`"},
			Python: []string{"`.auth`, `root_invocation`"},
			Java:   []string{"`getAuth()`, `getRootInvocation()`"},
		},
	},
	{
		ID:     "HC-302",
		Check:  "For a failed transaction only the fee payer and the transaction source are attributed.",
		Guide:  []string{"participant-algorithm", "failed-transactions"},
		Corpus: []string{"cap-0015/fee-bump-muxed-fee-source-inner-failed"},
		Hints: hints{
			JS:     []string{"`successful`, `.destination`"},
			Rust:   []string{"`TransactionResultResult::TxSuccess`, `destination`"},
			Python: []string{"`successful`, `destination`"},
			Java:   []string{"`TransactionResponse.getSuccessful()`, `getDestination()`"},
		},
	},
	{
		ID:     "HC-303",
		Check:  "Every participant set incorporates meta: fee changes, operation changes and events.",
		Guide:  []string{"participant-algorithm"},
		Corpus: nil,
		Hints:  metaHints,
	},
	{
		ID:    "HC-304",
		Check: "Trustline and balance state comes from ledger-entry changes, not from classic operations or events alone.",
		Manual: &manual{
			Why: "It is a property of the state model as a whole; no local pattern in the code shows its absence.",
			How: "confirm that the state writer consumes ledger-entry changes for trustlines and accounts, and replay ledgers that create trustlines without a `ChangeTrust` operation.",
		},
		Guide:  []string{"shorthand", "envelope-versus-meta"},
		Corpus: []string{"cap-0073/sac-trust-creates-trustline"},
		Hints:  metaHints,
	},
	{
		ID:     "HC-305",
		Check:  "A token-shaped contract event counts as a movement of an asset only when the emitting contract is that asset's own contract; no participant is added because an arbitrary contract's event names it.",
		Guide:  []string{"event-routing-id", "passed-through"},
		Corpus: []string{"cap-0067/to-muxed-id-void-custom-token"},
		Hints:  eventHints,
	},
	{
		ID:     "HC-306",
		Check:  "Contract event topics and data are read only after their count and each value's type are checked, or after the emitting contract is known.",
		Guide:  []string{"fields-events", "passed-through"},
		Corpus: []string{"cap-0067/forged-token-event-from-unrelated-contract"},
		Hints:  eventHints,
	},
	{
		ID:     "HC-307",
		Check:  "Rows are built from diagnostic events only for successful transactions, and an operation's rows only from that operation's own changes.",
		Guide:  []string{"failed-transactions", "envelope-versus-meta"},
		Corpus: []string{"cap-0046/failed-soroban-tx-diagnostics-only-golden"},
		Hints:  metaHints,
	},
	{
		ID:    "HC-401",
		Check: "Address storage holds 165 characters, or the base key plus the ID plus a signer table; nothing assumes 56 characters or 32 bytes.",
		Manual: &manual{
			Why: "Column widths live in database migrations, outside what a code analyzer sees.",
			How: "check every address column and every binary key type against the widest form of each kind.",
		},
		Guide:  []string{"storage-widths", "strkey-forms"},
		Corpus: []string{"cap-0040/signed-payload-signer-added", "strkey/truncated-muxed-address-56-chars"},
		Hints:  addressHints,
	},
	{
		ID:    "HC-402",
		Check: "64-bit IDs are carried as strings or big integers from end to end.",
		Manual: &manual{
			Why: "Decoding is exact; the loss happens in JSON encoders, database column types and native conversions in other languages.",
			How: "follow one ID above 2^63 from decoding to the API response.",
		},
		Guide:  []string{"64-bit-ids", "muxed-accounts"},
		Corpus: []string{"cap-0027/muxed-source-id-above-2-pow-63"},
	},
	{
		ID:    "HC-403",
		Check: "Strkeys are decoded by the SDK's strict decoder, with a length check per address kind.",
		Manual: &manual{
			Why: "Whether a decoder is strict depends on the SDK and its version, not on the shape of the code.",
			How: "run the published SEP-23 test vectors through the decoder the code calls.",
		},
		Guide:  []string{"decoding-addresses"},
		Corpus: []string{"strkey/sep-0023-v1.4.0-vectors", "strkey/synthetic-gap-vectors"},
	},
	{
		ID:     "HC-404",
		Check:  "u64, i128 and u128 values are never narrowed (to int64, int32, int16, float64 or a fixed-decimal float) without a range check before they are stored.",
		Guide:  []string{"storage-widths"},
		Corpus: []string{"classic/amount-above-2-pow-53-stroops"},
	},
	{
		ID:    "HC-501",
		Check: "The raw XDR is stored beside every derived value.",
		Manual: &manual{
			Why: "It is a property of the storage design.",
			How: "check that each table of derived rows keeps, or can be joined to, the XDR it was derived from.",
		},
		Guide:   []string{"keep-raw-xdr"},
		NoEntry: "none: a design property, which no single entry can show.",
	},
	{
		ID:    "HC-502",
		Check: "A highest reviewed protocol version and meta version is declared; above them the indexer stops with a typed error and an alert.",
		Manual: &manual{
			Why: "It is project policy.",
			How: "find the declared versions and the check that compares each ledger against them, then feed the reader a ledger above them.",
		},
		Guide:  []string{"protocol-boundaries"},
		Corpus: []string{"cap-0088/first-ledger-with-signed-ms"},
	},
	{
		ID:    "HC-503",
		Check: "The parser is not chosen from the protocol version in the ledger header alone.",
		Manual: &manual{
			Why: "No pattern in the code shows it.",
			How: "replay the protocol-upgrade ledgers and compare the parsed result with the expected one.",
		},
		Guide:  []string{"protocol-boundaries"},
		Corpus: []string{"protocol-20/upgrade-ledger-lcm-v0-header-20", "protocol-23/upgrade-ledger-lcm-v1-header-23"},
	},
	{
		ID:    "HC-504",
		Check: "Enum and union values are taken from the XDR at a release tag, not from CAP text.",
		Manual: &manual{
			Why: "It is a process rule for people adding support for a new protocol.",
			How: "check that every new enum value or union arm the code handles exists in the XDR at the release tag the SDK was generated from.",
		},
		Guide:   []string{"protocol-boundaries"},
		NoEntry: "none: a process rule, which no single entry can show.",
	},
	{
		ID:    "HC-505",
		Check: "The decoder entry point that rejects trailing bytes and non-canonical input is used, and a value that went through a lossy native conversion is never encoded again.",
		Manual: &manual{
			Why: "Which entry point is strict differs between SDKs and versions.",
			How: "run the negative XDR vectors through the decoder the code calls.",
		},
		Guide:  []string{"decoder-strictness"},
		Corpus: []string{"xdr-strict/api-transaction-parse-trailing-bytes", "xdr-strict/bool-value-2"},
	},
	{
		ID:     "HC-506",
		Check:  "Every TransactionMeta and LedgerCloseMeta version the reader can receive is handled; no arm is read without a version check, and no version check halts on an older version.",
		Guide:  []string{"protocol-boundaries"},
		Corpus: []string{"protocol-20/first-lcm-v1-generalized-tx-set", "protocol-23/first-lcm-v2-parallel-phase"},
	},
	{
		ID:     "HC-507",
		Check:  "A switch over an xdr enum that writes rows has a default that records an unknown value without halting.",
		Guide:  []string{"protocol-boundaries"},
		Corpus: nil,
	},
}

var addressHints = hints{
	JS:     []string{"`decodeAddressToMuxedAccount`, `extractBaseAddress`, `Address.fromScAddress`, `StrKey.isValidMed25519PublicKey`, `StrKey.decodeMuxedContract`"},
	Rust:   []string{"`MuxedEd25519Account`, `MuxedContract`, `ScAddress::` arms, `.to_string()` on addresses"},
	Python: []string{"`account_muxed`, `account_muxed_id`, `Address.from_xdr_sc_address`"},
	Java:   []string{"`getMed25519()`, `Address.fromSCAddress`, `StrKey.encodeMed25519PublicKey`, `SignerKey.fromEd25519SignedPayload`, `StrKey.encodeSignedPayload`"},
}

var eventHints = hints{
	JS:     []string{"`to_muxed_id`, `topics`, `contractId` near `transfer` or `mint`"},
	Rust:   []string{"`to_muxed_id`, `ContractEvent`, `contract_id`"},
	Python: []string{"`to_muxed_id`, `contract_id`"},
	Java:   []string{"`to_muxed_id`, `getContractId()`"},
}

var limitHints = hints{
	JS:     []string{"js-xdr `DEFAULT_MAX_DEPTH` (`@stellar/js-xdr` `src/core/reader.ts`); the SDK does not expose it"},
	Rust:   []string{"`Limits { depth, len }`; never `Limits::none()`"},
	Python: []string{"where the XDR decoder's depth limit is set and what its default is"},
	Java:   []string{"where the XDR decoder's depth limit is set and what its default is"},
}

var metaHints = hints{
	JS:     []string{"`resultMetaXdr`"},
	Rust:   []string{"`TransactionMeta::V4`, `LedgerEntryChange`"},
	Python: []string{"`result_meta_xdr`"},
	Java:   []string{"`getResultMetaXdr()`"},
}
