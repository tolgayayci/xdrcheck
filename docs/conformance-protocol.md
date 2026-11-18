# Conformance driver protocol: vocabulary and evidence

For driver authors and for SDK maintainers who need to know exactly why a cell was judged as it was. This page is the
normative part of the driver protocol `xcc.driver/1` that a JSON schema cannot express: the names of the `api`
operations' arguments and results, the facts an accepted cell must carry, and how the orchestrator judges them. The message shapes are in `corpus/schema/driver-protocol.schema.json`; how drivers are
installed and run is in [`drivers/README.md`](../drivers/README.md); the manifest fields the orchestrator compares
against are in [`manifest.md`](manifest.md). The messages, levels and outcomes are introduced in
[`driver-protocol.md`](driver-protocol.md).

A driver answer that is valid against the schema but breaks a rule on this page is a **protocol error**: the
answer is not trusted, the cell is not judged, the driver process is replaced and `xdrcheck conform run` exits 2. A
missing fact is never read as agreement.

## 1. Outcomes and `n_a`

- An `api` operation the driver lists in `describe.api_ops` never answers `n_a/op_not_supported`. An operation it
  does not list answers exactly that.
- A declared operation may answer `n_a` only with `value_not_representable`, `argument_type_not_accepted` or
  `type_not_generated`:
  - `value_not_representable`: an argument carries a native-type tag (`{"native": …}`) whose value the
    language type the tag maps to cannot hold (an integer wider than the widest integer the SDK's parameter takes).
    An answer with this reason when no argument is tagged is a protocol error. The JavaScript drivers never use it
    for `number`: building the JavaScript number literal, already rounded, is the behaviour under test.
  - `argument_type_not_accepted`: an argument carries a native-type tag whose **kind** (`number`, `string`,
    `bigint`) the SDK parameter it is passed to does not take at all. The rule is precise:
    1. It applies only in a dynamically typed language, where the tag kind is the runtime type the driver passes
       (JavaScript: `number`, `string`, `bigint`; Python: `int` for `number` and `bigint`, `float` for a `number`
       with a fraction, `str` for `string`).
    2. "Does not take" is read from the SDK's own published declaration of that parameter, in the installed
       package, before the call: the TypeScript declaration file for JavaScript (`id: string` takes only a
       string; `offerId?: number | string` takes a number or a string but not a bigint), the type annotation for
       Python (`offer_id: int` takes no string). The driver names the declaration it read.
    3. It is never decided from the SDK's reaction to a value. If the declaration admits the tag's kind, the value
       is passed and whatever the SDK does (accept, refuse, encode another value) is the outcome, judged as usual;
       an invalid value of an accepted kind (`"0x10"` to a string parameter) is never `n_a`.
    4. Statically typed drivers (Go, Java, Rust), whose parameter is one integer type, build that integer from the
       tag's decimal text whatever its kind, as an application converts its input; they never use this reason (a
       value outside the type is `value_not_representable`).
    5. An answer with this reason when no argument is tagged is a protocol error.

    An entry chooses the tag its intent needs (the JavaScript `number` that is rounded before the SDK sees it, the
    decimal string a JavaScript muxed-account ID must be); columns whose SDK cannot take that kind are `n_a`, not
    failures.
  - `type_not_generated`: this SDK version lacks the function or generated type for a sub-case of the operation (for
    example no encoder for one strkey type: `strkey.encode` with a `type` whose version byte the SDK's strkey
    package does not know is `n_a/type_not_generated`, never a refusal of the payload).
- A strkey text (input kind `strkey`) is answered like `strkey.decode`: a driver that declares that op may answer
  it `n_a` only with `type_not_generated`.
- A missing argument, an argument name not in the table below, or a malformed argument (wrong JSON type, bad hex,
  an unknown `type` or `xdr_type` value, an asset not spelled `native` or `CODE:ISSUER`) is answered with a
  `protocol_error` message for that request; the driver keeps serving. There are no aliases.

## 2. `api` vocabulary

Conventions:

- Bytes: `{"hex": "…"}` in lower case, or a plain string under an argument name ending in `_hex`;
  `{"native": "bytes", "hex": "…"}` is the same.
- Numbers and IDs in arguments: `{"native": "number" | "string" | "bigint", "value": "<decimal>"}`; a bare string
  is a native string. The tag says how an application would pass the value; an SDK parameter whose declaration does
  not take the tag's kind answers `n_a/argument_type_not_accepted` (section 1).
- IDs in results: decimal strings. Assets: `native` or `CODE:ISSUER`. Hashes and pool IDs: lower-case hex.
- `self_decode` (`accepted`, `rejected`, `not_checked`) is required whenever the result has `xdr_hex` or a strkey:
  the SDK's own decoder run on what the SDK produced. When it is `rejected` the outcome is
  `diverge/own_output_rejected`.

| op | arguments (required unless in brackets) | `value` | `xdr_hex` |
|---|---|---|---|
| `asset.compare` | `asset_a`, `asset_b` | integer -1, 0 or 1 | — |
| `liquidity_pool.id` | `asset_a`, `asset_b`, [`fee` = 30] | pool ID hex | — |
| `liquidity_pool.asset` | `asset_a`, `asset_b`, [`fee` = 30] | pool ID hex | `ChangeTrustAsset` |
| `muxed_account.encode` | `account` (G…), `id` (tagged) | `M…` strkey | `MuxedAccount` |
| `muxed_account.decode` | `text` (M…) | `{"account": "G…", "id": "<decimal>"}` | — |
| `offer.manage_sell`, `offer.manage_buy` | `offer_id` (tagged), [`selling` = `native`], [`buying` = `USD:GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ`], [`amount` = `"1"`], [`price` = `"1"`] | the offer ID read back from the encoded operation, decimal string | `Operation` |
| `scval.from_native` | `value` (JSON, tagged leaves), [`type`] | for a map, the list of keys `"<arm>:<text>"` in the resulting order; else that single string | `ScVal` |
| `scval.sort_map` | `keys` (list of `"u32:10"`, `"bytes:0a"`, `"symbol:a"`, `"string:b"`, or `{"xdr_hex": …}`) | the keys in the resulting order, same form | `ScVal` |
| `scval.to_native` | `xdr_hex` (`ScVal`) | `{"map_entries": n}` for a map, else the native value as JSON (64-bit and wider as decimal strings, bytes as hex) | — |
| `scval.native_roundtrip` | `xdr_hex` (`ScVal`), [`type`] | boolean: bytes preserved | the `ScVal` produced |
| `strkey.encode` | `type` (the schema's strkey type enum), `payload_hex` | strkey text | — |
| `strkey.decode` | `text`, [`type`] | payload hex | — |
| `transaction.parse` | `xdr_hex` (`TransactionEnvelope`), `passphrase` | `{"tx_hash": "<hex>", "operations": n}` | the re-encoded envelope |
| `transaction.hash` | `xdr_hex`, `passphrase` | hash hex | — |
| `memo.text_roundtrip` | `xdr_hex` (`Memo`) | hex of the native text's bytes as the SDK holds them | the re-encoded `Memo` |
| `address.to_strkey` | `xdr_hex`, [`xdr_type` = `MuxedAccount`, or `AccountId`] | strkey | — |
| `address.from_sc_address` | `xdr_hex` (`ScAddress`) | strkey | — |
| `signer_key.to_strkey` | `xdr_hex` (`SignerKey`) | strkey | — |
| `operation.object_roundtrip` | `xdr_hex` (`Operation`) | boolean: bytes preserved | the rebuilt `Operation` |
| `asset.from_operation` | `xdr_hex` (`Asset`) | `{"type", "code", "issuer"}` | — |
| `xdrjson.decode` | `xdr_type`, `json` | — | the value's XDR |
| `xdr.custom_union_encode` | `switch_on` (the discriminant's XDR type: `int`, `unsigned int`, `hyper`, `unsigned hyper`, `float`, `double` or `bool`), `cases` (list of `{"discriminant", "arm"}`: a tagged discriminant, and `void` or one of the `switch_on` type names), `discriminant` (tagged), [`value` (tagged): the payload when the selected arm is not `void`] | the discriminant as the SDK's own decoder reads it back, as text (`String()` of the native value; 64-bit as decimal) | the encoded union |
| `price.encode` | defined with the first entry that uses it | | |

A strkey entry (input kind `strkey`) is answered like `strkey.decode`: `value` is the payload hex.

`xdr.custom_union_encode` exercises an XDR library's schema-definition path rather than a Stellar type: the driver
defines a union named `U` over `switch_on` with one case per element of `cases` (case names `c0`, `c1`, …; a
non-void arm is a field named `value`), encodes `{discriminant, value}` with it, and decodes the result with the
same schema. A refusal while defining the schema or encoding is `reject`; an encoding its own decoder refuses is
`diverge/own_output_rejected` with `xdr_hex` and `self_decode: rejected`; otherwise `ok`. It is how a union that
accepts a non-integer discriminant (a `float` switch; js-xdr#162) is shown: XDR (RFC 4506 §4.15) allows only
`int`, `unsigned int` or an enum (`bool` is one) as a discriminant, so a `hyper`, `float` or `double` switch is
not XDR and an entry about one expects a refusal.

## 2a. The spec and json levels

**spec.** A `spec` entry's request has `input.kind: "spec"`, the `container` (`wasm` or `xdr-stream`), the blob's
`path` and, for a Wasm module, `sections`: where the corpus's own section reader found each `contractspecv0`
payload (`offset`, `length`). A driver whose SDK has a Wasm reader (`Spec.fromWasm` in JavaScript,
`ContractSpec.from_wasm` in Python, `soroban_spec::read::from_wasm` in Rust) ignores `sections` and gives the SDK
the module. A driver whose SDK decodes entry streams but reads no Wasm (go-stellar-sdk) decodes the one listed
section, and answers `n_a/no_object_layer` when there is none or several: which section to read is then the
application's choice, not the SDK's. An accepted cell reports `actual.spec.entries`, each entry rendered from the
SDK's own objects as `{kind, name, args[{name, type}], outputs}` in the vocabulary of
[manifest.md §9.4](manifest.md); the engine compares them, in order, with `expect.spec.entries`. A Wasm with no spec
section conforms both when the reader returns no entries and when it reports the absence as an error. More than one
section, or a stream that does not end in whole entries, must be refused (`spec_sections`, `trailing_bytes`,
`length_exceeds_input`, `length_exceeds_max`). The cross-SDK comparison fingerprints the entry list.

**json.** Columns whose sets.toml entry lists `levels = ["json"]` are XDR-JSON converters. They get a json cell
for every ledger and xdr variant (and no other level); no other column gets json cells. The request is the xdr
input of L0. An accepted cell reports `actual.json`: `json_sha256`, the sha256 of the converter's JSON in canonical
form (object keys sorted by code point, no whitespace, strings escaping only `"`, `\` and control characters as
`\u00XX`, every other character as UTF-8, numbers as the converter wrote them); `schema` (`valid`, `invalid` with
up to five `schema_errors`, or `not_checked` when the binding publishes no schema); `roundtrip` (`identical`,
`changed` with `roundtrip_sha256`, `refused` with `roundtrip_error`, or `not_supported` when the binding has no JSON
to XDR). The request carries the variant's expected-value pointers as `pinpoints`, as at L2, and the converter
returns its own JSON at each of them (`actual.json.pinpoints`); the orchestrator compares each with the manifest's
`expect.values` exactly as JSON, so a 64-bit integer written as a JSON number where SEP-51 and the manifest state a
string is a wrong value (a mismatch makes the cell `diverge`). The ways a converter can be wrong are verdicts and lists in `cross-sdk.md`: `schema_invalid` (its JSON
breaks its own schema), `roundtrip_changed` (its JSON comes back to other bytes), `roundtrip_refused` (it refuses
the JSON it wrote) and cross-binding-different (accepting converters whose canonical JSON differs: a cross-SDK split
of the json level). A known divergence of outcome `wrong_value` at level `json` matches `schema_invalid` and
`roundtrip_changed`, one of outcome `reject` matches `roundtrip_refused` (and a refusal of the bytes), and the list
cites its reference instead of marking the cell new.

### The JavaScript SDK's own XDR-JSON

Planned: this section is written with the change that builds it.

## 3. Evidence an accepted cell carries

| Level and input | Required on `ok` |
|---|---|
| L0, any value | `actual.reencoded_sha256`, `actual.consumed_bytes`; the stellar-core column (kind `core`), which decodes and prints but never re-encodes, carries `consumed_bytes` alone, and it must equal the input's length |
| L1, a ledger (`LedgerCloseMeta`) | `object.transactions`, `envelopes_parsed` (equal to `transactions`), `operations`, `tx_hashes` (one per parsed envelope); `object.focus` when the request's focus names a transaction (`tx_index`), with `focus.rebuild` when the driver declares `object_rebuild` |
| L1, a `TransactionEnvelope` | `object.tx_hash` (when the request carries a passphrase), `operation_types`, `operations`, `reencoded_sha256`, `derived`; `rebuild` under a passphrase when the driver declares `object_rebuild` |
| L1, any other value with an object layer | `object.derived` (`{}` when the object yields nothing) |
| L3 | `actual.native` with `type`, `bytes_preserved`, and `map_entries` when the entry states a map's entry count; `native.error` for an `scvError` value (the native error fact) |
| L4 | `actual.api` with `value` and `xdr_hex` as the table in section 2 defines them, and `self_decode` as above |

An L1 `reject` on a ledger whose envelopes were reached carries `object.transactions`, `envelopes_parsed`,
`tx_hashes` and a non-empty `envelopes_rejected`, with `envelopes_parsed` + rejected = `transactions`. A ledger
that does not decode at all (an undeclared union arm, a depth or length refusal) is refused with that reason and no
object.

### Canonical L1 keys

Ledger inputs:

| key | shape | required on | compared with |
|---|---|---|---|
| `transactions` | integer: envelopes in the transaction set | ok, reject | `expect.ledger.transactions` |
| `envelopes_parsed` | integer | ok, reject | on ok, equal to `transactions` |
| `operations` | integer: operations of every parsed envelope (a fee bump counts its inner transaction's) | ok | `expect.ledger.operations` |
| `tx_hashes` | lower-case hex, the SDK's hash of each parsed envelope in apply order (the order of the ledger's transaction processing list); a rejected envelope is left out; `[]` when there is none | ok, reject | on ok, equal as an ordered list to `variants[].derived.tx_hashes` |
| `envelopes_rejected` | `{tx_index, tx_hash, code, message}`: apply-order index, the hash the ledger records for it, the reason code | reject | a known divergence's declared detail |
| `focus` | `{tx_hash, operation_types[], derived{}}` for the transaction at the request's `focus.tx_index` (apply order); `derived` describes the operation at `focus.op_index` | ok, when the request names a focus transaction | `tx_hash` with `variants[].derived.tx_hash`; `derived` as below |

Other inputs: `tx_hash` (envelopes), `operation_types`, `operations`, `reencoded_sha256` (when the SDK object
re-serialises; compared with the blob's hash), `derived`.

`operation_types` and `derived.operation_type` are XDR-JSON operation arms in snake case (`change_trust`,
`path_payment_strict_receive`, `invoke_host_function`).

`derived` keys are a closed list; every value is a string. A key outside the list is a protocol error. Each key is
compared only with `variants[].derived.l1.<key>`, and a key the manifest states there must be reported.

| key | value |
|---|---|
| `operation_type` | the operation's XDR-JSON arm |
| `operation_source` | the operation's own source account, when it has one (not the transaction's), as a strkey (`M…` when muxed) |
| `pool_id` | the liquidity pool ID (a change-trust to a pool share; a pool deposit or withdrawal), lower-case hex |
| `asset` | `native` or `CODE:ISSUER`: the line of a change-trust to an asset; the asset of a payment, set-trust-line-flags, clawback or create-claimable-balance; the destination asset of a path payment |
| `address` | the counterpart, as a strkey: the destination of create-account, payment, path payments and account-merge; the trustor of allow-trust and set-trust-line-flags; the `from` of clawback; the sponsored account of begin-sponsoring-future-reserves |
| `muxed_id` | the decimal ID of a muxed `address`, else of a muxed `operation_source` |
| `offer_id` | the offer ID of a manage-offer operation, decimal |
| `memo_type` | `none`, `text`, `id`, `hash` or `return`, of the focus transaction (a fee bump's inner transaction) |

The ledger's focus reports `memo_type` whenever the request names a focus transaction, and the operation keys when
it also names an operation (`focus.op_index`).

### The rebuild fact

Parsing a transaction and re-encoding the stored envelope cannot show a field the SDK's object loses: most SDKs
keep the envelope they parsed and write it back unchanged. The defect appears when an application rebuilds the
transaction from the object (to change the fee, re-sign it, or after simulation), and the rebuilt transaction is
another one: a dropped `SorobanTransactionData`, a lost `minSeqNum`, an ID that comes back different. The rebuild
fact makes that check on every focus transaction of a ledger and on every `TransactionEnvelope` parsed under a
passphrase.

A driver whose SDK can rebuild a parsed transaction declares the entry point in `describe.object_rebuild`, and then
reports `rebuild` in `object.focus` (ledgers) and in `object` (envelopes): the parsed transaction handed to the
SDK's builder, built, and hashed under the request's passphrase.

| field | value |
|---|---|
| `entry_point` | the builder entry point, equal to `describe.object_rebuild` |
| `outcome` | `rebuilt` (with `tx_hash`), `refused` (with `message`: the builder threw on a transaction its declaration can express), or `not_rebuilt` (with `reason`) |
| `reason` | `fee_bump`; `no_time_bounds`; `fee_not_per_operation`; `soroban_memo`; `soroban_muxed_source` |
| `differs` | diagnostic only: the `Transaction` fields whose encoding differs between the parsed and the rebuilt transaction |

`not_rebuilt` is decided before the call, from the builder's published declaration, never from the SDK's reaction
(as `argument_type_not_accepted` in section 1). The fact covers transactions, not a fee bump's outer envelope. A
builder that takes a fee per operation cannot express an inclusion fee (the fee less the Soroban resource fee) that
is not a whole multiple of the operation count. A builder whose declaration requires time bounds cannot express a
transaction without them. `soroban_memo` and `soroban_muxed_source` apply only to an SDK version whose `build()`
declaration says it refuses them.

The orchestrator judges the fact against the manifest only: a `rebuilt` hash must equal the network's transaction
hash (`variants[].derived.tx_hash`, or the focus's `tx_hash`), and a `refused` diverges. `not_rebuilt` is not judged.
A driver that declares `object_rebuild` and leaves the fact out of an accepted cell, or a driver that reports it
without declaring it, is a protocol error.

| SDK | `object_rebuild` | Recipe |
|---|---|---|
| JavaScript (16.x and 17.x) | `TransactionBuilder.cloneFrom` | `cloneFrom(tx)`, then `setSorobanData` with the envelope's `SorobanTransactionData`, because `cloneFrom`'s declaration says it does not clone that data; then `build()` |
| Go | `txnbuild.NewTransaction` | the SDK has no clone API, so the recipe is the driver's. It uses only what the parsed object exposes: source account and sequence number (`IncrementSequenceNum` false), the parsed operations, the memo, and the inclusion fee per operation. The inclusion fee is `MaxFee` less the resource fee the parsed Soroban operation's own `BuildTransactionExt` carries. The parsed transaction has no getter for its preconditions beyond `Timebounds()`, so they are read through the SDK's converter, `Preconditions.FromXDR` on the object's `ToXDR()`; a precondition lost there cannot show here |
| Python | not declared | `TransactionBuilder.from_xdr` returns the parsed envelope, not a builder; the SDK's `Transaction` is the typed model itself, and L1 already re-encodes it from its fields |
| Rust | not declared | no object layer (section 4a) |

Every accepted rebuilt transaction must hash to the network's transaction. A Go column that drops a Soroban
operation's `SorobanTransactionData` while parsing (finding F-0056) diverges on `cap-0066/p22-restore-with-backfilled-restored-changes`
(a mainnet `RestoreFootprint`) and `classic/real-result-codes.testnet-5380224` (a testnet `ExtendFootprintTtl`).

### The native error fact

An `ScError` is a pair, the `ScErrorType` (which host subsystem failed: `storage`, `budget`, `auth`, …) and the
`ScErrorCode` (`exceeded_limit`, `missing_value`, …), or a contract's own `u32` code. stellar-core writes such
values into the diagnostic events of every failed Soroban transaction, where `Error(Storage, ExceededLimit)` (a
footprint too small) and `Error(Budget, ExceededLimit)` (declared resources too low) share the code and differ only
in the type. A native conversion that keeps only the code makes them the same value.

At L3 a driver reports, for an `scvError` input, `native.error`: `type` and `code` as the XDR-JSON names the SDK's
native value carries (`type` `contract` with `code` the decimal contract code for a contract error), each left out
when the native value does not carry it. The driver reads the native value only, never the XDR it came from:

| SDK | `scvError` native value | Read as |
|---|---|---|
| JavaScript (16.x and 17.x) | `scValToNative`: `{type: "contract", code}`, or `{type: "system", code, value}` for every other type | `contract` and its code; otherwise any string property naming an `ScErrorType` (`sceStorage` or `storage`) or an `ScErrorCode` (`scecExceededLimit` or `exceeded_limit`) |
| Python | `scval.to_native` returns the `SCVal` itself | its `SCError`: type and code |
| Go, Rust | no native layer (`n_a/no_native_layer`) | — |

An entry states the expectation as `expect.native.error` (`{"type": "storage", "code": "exceeded_limit"}`); a
native value that lacks the type or the code, or names another, diverges. The fact is left out of the cross-SDK
fingerprint (section 4). `cap-0046/scval-error-storage-exceeded-limit` and `cap-0046/scval-error-budget-exceeded-limit`
are 12-byte slices of such diagnostic events from a testnet and a mainnet ledger; every JavaScript column diverges
on both (finding F-0061).

## 4. How the orchestrator judges

- **Values.** An accepted value is compared with the manifest only. Integers are compared by value only where the
  manifest states an integer (a JSON integer, or a decimal string in canonical form): the driver's value may then
  be a JSON integer or a canonical decimal string, never a string with leading zeros or a sign. Hex is compared
  without regard to case.
- **Exact or refuse.** An `api` entry with `expect_reject` and `expect_value` or `expect_xdr_hex` conforms on a
  refusal, or on an acceptance whose result equals the expected one exactly; any other acceptance diverges.
- **Schema reach.** A variant lists the XDR features its bytes need (`requires`, for example
  `stellar_value_signed_ms`); it is beyond a column's reach only if the column's `describe` reports the probe of a
  required feature as `false` (a feature name is its probe name). A variant without `requires` falls back to its
  protocol against the column's `xdr_schema.protocol`; a column that reports no protocol has nothing beyond reach by protocol. Beyond reach the only expected outcome is a refusal at L0
  (or at a higher level when L0 of the same column was refused; the only level of an `api` or `strkey` entry) for
  `union_arm_undeclared` or `enum_undeclared`, or `strkey_version` for a strkey text (the Rust `stellar-xdr`
  column reports such refusals as `decode_error`, which is accepted for it). That refusal is
  `n_a`; a crash or a refusal for another reason is a failure; an acceptance is judged as usual. Known divergences
  are not evaluated beyond reach, and a negative entry beyond reach is `n_a`.
- **stellar-core's own reading.** A negative entry whose `core_behaviour.accepts` is `true` records that
  stellar-core's decoder accepts the input. The SDK columns must still refuse it, but on the stellar-core column
  (kind `core`) acceptance is the expected outcome: an acceptance that reads the whole input conforms.
- **Level cascade.** When a column's L0 cell for a variant is a known divergence, or a refusal beyond reach, its L1
  and L2 cells for that variant are `n_a` (shown as `n/a (L0)`).
- **Known divergences** match on the outcome class and on their declared detail: a known divergence of an L1
  refusal on a ledger whose variant names a focus transaction is observed only if that transaction is among the
  rejected envelopes; a divergence's `match` block (`reason`, `envelopes_parsed`, `rejected_tx_index`), when it has
  one, must equal the driver's report. Otherwise the cell is `known-changed`.
- **Version ranges** that do not parse stop the run (exit 2) and name the entry.
- **Decode profiles.** A column with a `profile` runs every cell under limits the driver sets, not the SDK. The Rust
  `stellar-xdr` columns, whose library has no default limits, use two: `limits-default` is
  `Limits { depth: 500, len: <input length> }`, the Soroban host's default XDR depth (`DEFAULT_XDR_RW_LIMITS` in
  `soroban-env-host/src/budget/limits.rs`) with the length budget set to the input size; `limits-none` is
  `Limits::none()`, what the crate's CLI uses. A valid input the profile's own limit refuses (a ledger nested
  deeper than 500 levels refused for `depth` under `limits-default`) is not `n_a` and not a library defect: it is
  declared as a known divergence of outcome `reject` with `profile` set to that column profile and `match.reason`
  the refusal's reason, so it is asserted on that profile's columns only and the other profile must still decode
  the input.
- **Profiles.** A known divergence's `profile` is either a column's decode profile (Rust `limits-default`,
  `limits-none`), asserted only on columns of that profile, or an address-space sandbox written
  `address-space cap RLIMIT_AS <n> MiB|GiB`. A memory-stress vector's outcome under the default limits alone can
  depend on how much of a huge allocation the runtime happens to touch, so it is never judged there: every column
  of that divergence's target runs the entry in a fresh process under that `RLIMIT_AS` cap (versions outside the
  divergence's range too, which must then refuse cleanly), the divergence is asserted there, and the cell records
  the sandbox it ran under (`sandbox` in the matrix). Columns of other targets run the entry under the run's limits.
  A divergence that shows only under one decode profile writes it before the cap,
  `<decode profile> under address-space cap RLIMIT_AS <n> MiB|GiB` (for example `limits-none under address-space
  cap RLIMIT_AS 1 GiB`): every column of the target still runs the entry under the cap, and the divergence is
  asserted on that decode profile's columns only; the target's other columns must refuse cleanly.
- **Not exercised.** The matrix lists every known divergence the run did not assert: no selected column inside its
  range, or every cell inside it `n_a`.
- **Cross-SDK comparison.** Accepting columns are grouped by a fingerprint of canonical JSON: L0 the re-encoding
  hash; L1 `{transactions, operations, tx_hashes, focus.tx_hash, focus.derived}` for a ledger and
  `{tx_hash, operations, derived}` otherwise, `derived` reduced to the keys the manifest states; L2 the pinpoints
  sorted by path; L3 `{map_entries, bytes_preserved, reencoded_sha256}`; L4 `{value, xdr_hex}`. A column without an
  object layer (`n_a/no_object_layer`) is not compared; an acceptance without a comparable value (stellar-core at
  L0) agrees with a single valued acceptance.
- **Left out of the cross-SDK comparison.** Only the fingerprint keys above are compared between columns. These
  facts a driver reports are not, so two columns that differ only in them are listed as agreeing
  (`fingerprint` in `go/internal/conform/verdict/matrix.go`): L0 `consumed_bytes`, `reencoded_hex` and
  `lenient_entry_points`; L1 `operation_types`, `focus.operation_types`, `events`, `reencoded_sha256`,
  `envelopes_parsed`, `envelopes_rejected` and `rebuild` (the rebuild fact, which not every SDK can report), and
  every `derived` key the manifest does not state for the
  variant; L3 `native.type`, `native.summary` and `native.error`; L4 `self_decode`. Each column is still judged against the
  manifest on every fact the manifest states (L0 `consumed_bytes` against the blob's length, for one).


## 4a. What the required columns do not show

The required set (`drivers/sets.toml`: `js@17.4.0`, `go@v0.9.0`, `rust@30.0.0:limits-default`,
`rust@30.0.0:limits-none`) has three limits a reader of the matrix should know:

- **The Rust column is the oracle.** The `rust@30.0.0` columns run the `stellar-xdr` crate at 30.0.0, the same
  crate and version that writes and checks the corpus's sidecars, pinpoints and round trips (`pins.toml`
  `[rust] stellar_xdr`). Their agreement with the manifest is the oracle agreeing with itself, not independent
  evidence; what they add is the decode profiles (section 4) and the refusals of negative entries.
- **Rust has no L1.** The crate has no transaction object layer, so every L1 cell of the Rust columns is
  `n_a/no_object_layer` (one per variant the run selects, on both profiles), and the L1 cross-SDK comparison
  holds the JavaScript and Go columns only.
- **No floor on judged cells.** Nothing requires a minimum number of judged cells per required column or level:
  a column whose cells are all `n_a` (out of reach, blocked by L0, no object layer) passes `xdrcheck conform check`
  without having judged anything. How many cells each column judged is read from `matrix.json` (`cells`, each
  with its `column` and `verdict`); no report states it per column. `xdrcheck conform sdk-regression` fails only on its own rows
  whose cell was not judged. A floor is not added here: it needs a count per column and level the matrix does not
  compute yet.

## 5. Checking a run: undeclared and pending divergences

`xdrcheck conform check <matrix.json>` fails on every cell whose check is `undeclared`, `unexpected-conform` or
`known-changed`. An undeclared cell is a divergence no entry declares: a regression, a new defect, or a defect that
is known but not yet reported upstream. A failure on an SDK must map to a finding record before it can be declared
on an entry, and a defect that is not reported upstream is recorded first in a private overlay outside the
repository, so in development mode (the default) an undeclared cell does not fail the check when it is accounted for
as **pending**, and is listed as such (tag `KNOWN`), never passed silently:

| Listed as | When | Where it comes from |
|---|---|---|
| `known divergence, recorded as finding F-NNNN (state) but not yet declared on the entry` | a finding record lists the cell's report row (`conform:<entry>:<variant or ->:<column>:<level>`) in `evidence.report_rows` | `findings/`, and the private overlay with `--overlay DIR` (or `XDRCHECK_OVERLAY`) |
| `known divergence, not yet triaged` | the cell is an item of the pending list | `findings/pending/conformance.json` (or `--pending FILE`): `{"pending": [{"entry", "variant", "column", "level"}]}` with no description, no reason and no finding ID (`variant` is `""` for an entry without variants), for public CI, which never loads the overlay; `xdrcheck findings check` reads the same list |

A cell that is neither is listed as `new divergence: no entry declares it and no finding records it`, with its
report row. An item for which the run has the cell but the cell is no longer undeclared is **stale** and fails the
check, so the list cannot outlive what it acknowledges. The summary line counts the pending cells of each kind.
In `--mode acceptance` pending cells fail like any other undeclared cell: in that mode every divergence must be
declared on its entry.

| Exit | `xdrcheck conform check` |
|---|---|
| 0 | pass |
| 1 | failing or stale cells |
| 2 | the check could not run |

`xdrcheck conform sdk-regression` asserts three known js-stellar-sdk defects (js-stellar-sdk#1766, #1785, #1789) on
`js@17.2.0`, `js@17.2.1` and `js@17.3.0`: each pre-fix cell must be a known divergence observed inside its declared
range, with the facts the assertion names, and each fixed cell must conform. Removing a declared divergence from its
entry fails the assertion.

## 5a. What a run writes, and what to read first

`xdrcheck conform run --report DIR` writes `SUMMARY.md` next to `matrix.json`, `matrix.md`, `cross-sdk.md`,
`report.json`, `cells.ndjson` and `describe.json`, and prints the same summary on stderr before the per-cell lines
(stdout). The summary lists only the rows (entry, variant, level) that need a look, in this order:

| Kind | Rows |
|---|---|
| new | a cell `xdrcheck conform check` fails on: a divergence no entry declares, a declared divergence the cell no longer matches, or a cell that conforms inside a declared range |
| known, not yet triaged | only undeclared cells that the committed pending list names |
| known divergences | every wrong cell is a declared known divergence |
| SDKs disagree | no column is wrong against the corpus, but the latest columns of the SDKs disagree (a value the corpus does not state) |

Each row gives the entry's CAPs, the **expected** value in words, read from the manifest entry and its variant
only (the blob's length and hash at L0, the ledger's counts and hashes at L1, the pinpoints at L2, the native facts
at L3, the `api` expectation at L4, a refusal with its reason for a negative entry; `matrix.json` `expectations`,
keyed `"<entry> <variant> <level>"`), each wrong column's answer with the first difference the engine found, its
known divergence and finding when the entry declares one, the columns that conform or are n/a, and the command that
reruns just that row: `xdrcheck conform run --columns '<wrong columns>' --entries '<entry>' --levels <level>`.
Cells n/a because the variant needs XDR newer than the column's SDK has, refused cleanly (section 4, schema
reach), are counted under the summary, not listed; `matrix.md` shows them as `–`.

`matrix.md` is still the full grid. Under each group's table, the rows where every column conforms or is n/a are
folded into a collapsed block. `cross-sdk.md` lists the cross-SDK disagreements with the CAPs, the expected value,
the columns the corpus says are wrong, their known divergence or finding, and a repro command.

## 5b. Expected-failure lists and the all-read check

Two options of `xdrcheck conform run` are for an SDK's own CI ([use-in-sdk-ci.md §7](use-in-sdk-ci.md)):

- `--write-expected-failures FILE` writes the failing cells of one column (`--columns <id>`) as a list;
  `--expected-failures FILE` then passes only when that column's failing cells are exactly the list. A failing
  cell is one whose verdict is not `conform` and not `n_a`, whether or not the corpus declares it as a known
  divergence. A failing cell the list does not name fails the run (`NEW-FAILURE`); a listed cell that conforms or is
  n/a fails it too (`UNEXPECTED-PASS`: remove the line), and so does a listed cell of a selected entry that the run
  does not have (`NOT-RUN`); a line for an entry the run did not select is ignored. With `--expected-failures` the
  list decides the exit code instead of the corpus's declarations: 0 equal, 1 different, 2 the run could not run.
  The file has one item per line, `<entry> <variant or -> <level or unread>`; `#` starts a comment.
- `--require-all-read` fails the run (exit 1) when a column never read a selected entry variant: no cell of the
  column for it got a driver answer other than `n_a` (a refusal or a crash is a read), because every level answered
  `n_a` or the column's driver declares none of the levels the entry needs. With `--expected-failures`, an item
  the list names with the level `unread` does not fail it (`NEW-UNREAD` is one it does not name), and a listed
  `unread` item the column now reads fails the run whether or not the option is given. Without the option the run
  prints one line per column with such items and lists them in `SUMMARY.md` (`matrix.json` `unread`); it does not
  fail.

## 6. Running with the private overlay

The private overlay ([SECURITY.md](../SECURITY.md), "The private overlay") may hold corpus entries that exist only to
show a withheld defect, under `<overlay>/corpus/` with the public corpus layout: `manifest/<id>.json`,
`blobs/<aa>/<sha256>.xdr`, `decoded/<aa>/<sha256>.json.zst` and `recipes/<id>.json`, plus `plan-rows.json`, the ID
registry rows the public `corpus/plan.json` does not hold: `{"rows": [<plan.json rows>], "members": {"<public row
id>": ["<member>", …]}}`.

`xdrcheck conform run --overlay DIR` loads that corpus together with the public one, in memory: overlay entries are
selected, run and reported like public ones, their blobs and sidecars read from the overlay. `xdrcheck replay --overlay
DIR` does the same for replay (only the flag turns it on there; `XDRCHECK_OVERLAY` is not read). `xdrcheck-corpus verify
--overlay DIR` runs the oracle gate over the merged corpus, with `plan-rows.json` added to `plan.json` for the `ids`
check and the overlay's blobs and sidecars included in the `orphans` check. An entry ID, or a plan row ID, present
in both the public tree and the overlay is an error (exit 2): an entry is public or withheld, never both. A report
made with the overlay is marked as such in its header; `xdrcheck conform run` and `xdrcheck replay` refuse to write it inside
the working tree, and a `verify --report` file of an overlay run belongs outside it too.

