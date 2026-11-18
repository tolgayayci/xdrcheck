# Conformance driver protocol — `xcc.driver/1`

For SDK maintainers who write or debug a driver, or read a conformance cell: the messages between
`xdrcheck conform` and a **driver**, a small program that wraps exactly one SDK at exactly one version. After this
page you can implement `describe` and `run`, choose the right outcome and reason, and know how the orchestrator turns
an answer into a verdict. Three companions complete the protocol:

| Page | Covers |
|---|---|
| `corpus/schema/driver-protocol.schema.json` | The message shapes (JSON Schema 2020-12); worked messages in `corpus/schema/examples/driver-protocol/`. Where this page and the schema disagree, the schema wins |
| [conformance-protocol.md](conformance-protocol.md) | The normative rules a schema cannot express: the `api` operation vocabulary, the facts an accepted cell must carry, `n_a` rules, and how the orchestrator judges cells and checks a run |
| [drivers/README.md](../drivers/README.md) | Driver directories, the `Makefile` contract (`fetch`, `build`, `test`), column sets, how the orchestrator starts and supervises drivers, and the output files |

## 1. Roles

The driver reports what the SDK did; it **never sees expected values** and never reads the manifest. The
orchestrator sends each request, judges the answer against the manifest and the entry's known divergences, and
writes the matrix. A driver therefore cannot pass a cell by agreeing with the expectation, and a missing fact is
never read as agreement.

## 2. Transport

| Rule | Requirement |
|---|---|
| Framing | One JSON object per line (NDJSON) on stdio. Requests on the driver's stdin; exactly one response per request on stdout, echoing the request `id` and the protocol tag `"xcc": "xcc.driver/1"`. stderr is free-form diagnostics, captured and never parsed |
| Start | The orchestrator starts the column's `run` command (by convention `bin/xdrcheck-driver`) in the driver directory, with no network, and sends one request at a time |
| Processes | One long-lived process serves a column's cells serially; columns run in parallel (`--jobs`). Entries built to stress a reader (the `limits/` group, and any entry with a known divergence of outcome `crash` or `hang`) run in a fresh process each |
| Limits | Per driver process: `--timeout` per request (default 20 s, plus as much again per MiB of input), `--memory-max` (default 1 GiB) and an optional address-space cap (`--as-limit`) |
| Death | A driver that dies, or is killed at the timeout or the memory cap, is recorded as `crash` by the orchestrator (reason `process_died`, `timeout` or `out_of_memory`) and replaced |

## 3. Messages

### 3.1 `describe`

Always first. The answer states what the driver can do, read from the installed package at run time:

```json
{"xcc":"xcc.driver/1","id":1,"op":"describe"}
```

| Field | Meaning |
|---|---|
| `driver` | Driver name and version; `adapter` names the API generation it bridges (for example `js-v17`) |
| `sdk` | `ecosystem`, `package`, `version` (must equal the column's pin, or the column is not run and the command exits 2), `integrity` of the installed artefact, and the resolved `dependencies` that decide decoding |
| `runtime` | Language runtime name and version, OS, architecture, decode thread stack size |
| `xdr_schema` | What the SDK's generated XDR can represent, probed from its enums at start-up, not inferred from the version: named `probes` (at least `sc_address_type_muxed_contract` and `stellar_value_signed_ms`), the highest `protocol` whose probes pass (omitted when the SDK declares an enum member beyond the highest protocol the kit knows, so nothing is excused by protocol), and optionally the decodable `types` |
| `levels` | The levels it answers (§4); a level not declared is recorded `n_a` without a request |
| `object_parsers`, `native_converters` | L1 and L3 entry points per XDR type, for example `{"TransactionEnvelope": "TransactionBuilder.fromXdr"}` |
| `api_ops` | The `api` operations it implements ([conformance-protocol.md §2](conformance-protocol.md)) |
| `decode` | The L0 `entry_point`, the SDK's `default_depth`, whether the entry point itself rejects trailing bytes (`checks_consumed_length`), and named decode `profiles` (Rust: `limits-default`, `limits-none`) |

### 3.2 `run`

One cell: one entry, one variant, one level, optionally one decode profile.

```json
{"xcc":"xcc.driver/1","id":7,"op":"run","entry":"cap-0038/pool-issuers-order-by-bytes-not-strkey","variant":"testnet","level":"L1","input":{"kind":"xdr","xdr_type":"LedgerCloseMeta","path":"/corpus/blobs/85/85….xdr","passphrase":"Test SDF Network ; September 2015"}}
```

Inputs, by `input.kind`:

| `kind` | Fields |
|---|---|
| `xdr` | `xdr_type`; the bytes as `path` (absolute, opened read-only) or inline `xdr_hex`; `framing` (`none`, or `record-marked` with `frame_index`); `passphrase` for parsers that compute hashes; `focus` (transaction and operation index); `pinpoints` (L2: JSON Pointers whose values to return) |
| `api` | `api_op`, `args` (the entry's `api.input` verbatim, with native-type tags), `passphrase` |
| `strkey` | `text`, optional `declared_type` |

The response echoes `id`, `entry`, `level` (and `variant`, `profile` when present) and gives an `outcome`, a typed
`reason` unless the outcome is `ok`, and `actual`: what the SDK produced. The same ledger on js-stellar-sdk 17.2.0,
which ordered pool asset issuers by strkey text (js-stellar-sdk#1766), and on 17.2.1, which fixed it:

```json
{"xcc":"xcc.driver/1","id":7,"op":"run","entry":"cap-0038/pool-issuers-order-by-bytes-not-strkey","variant":"testnet","level":"L1","outcome":"reject","reason":{"code":"ordering","message":"Assets are not in lexicographic order","error_class":"Error","entry_point":"TransactionBuilder.fromXdr"},"actual":{"object":{"transactions":19,"envelopes_parsed":18,"tx_hashes":["92203c07…","e63b9ca4…"],"envelopes_rejected":[{"tx_index":2,"tx_hash":"0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f","code":"ordering","message":"Assets are not in lexicographic order"}]}}}
```

```json
{"xcc":"xcc.driver/1","id":8,"op":"run","entry":"cap-0038/pool-issuers-order-by-bytes-not-strkey","variant":"testnet","level":"L1","outcome":"ok","actual":{"object":{"transactions":19,"envelopes_parsed":19,"operations":21,"tx_hashes":["92203c07…","e63b9ca4…","01267480…"],"focus":{"tx_hash":"0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f","operation_types":["change_trust","change_trust","change_trust"],"derived":{"operation_type":"change_trust","pool_id":"c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"}}}}}
```

(Hash lists shortened here; the full messages are `valid-03.json`, `valid-04.json` and `valid-07.json` in the
examples folder.)

### 3.3 `shutdown`

`{"xcc":"xcc.driver/1","id":N,"op":"shutdown"}`; the driver answers `{"ok": true}` and exits.

### 3.4 `protocol_error`

A driver that cannot understand a request (a missing or unknown argument, bad hex, an unknown type name) answers
with a `protocol_error` message for that request and keeps serving. It is never an SDK outcome. Conversely, a
driver answer that breaks the protocol — not JSON, an unknown field, a wrong echo, an accepted cell without the
evidence its level requires — is not trusted: the cell is not judged, the process is replaced and the command
exits 2.

## 4. Levels

| Level | Question | Example failure |
|---|---|---|
| **L0** codec | Decode the bytes as the named type and re-encode: identical, and all bytes consumed? | a Protocol 30 ledger on a pre-Protocol 30 SDK; trailing bytes accepted |
| **L1** object | Does the SDK's high-level layer take it? For a ledger, every envelope in the transaction set goes through the SDK's transaction parser | js-stellar-sdk#1766: the bytes round-trip, `TransactionBuilder.fromXdr` throws |
| **L2** values | Does the SDK's decoded value equal the oracle's at the requested pinpoints? | a 64-bit ID through a float |
| **L3** native | Does the SDK's native conversion keep the value? | js-stellar-sdk#1789: colliding map keys silently merged |
| **L4** API | For `api` and `strkey` entries: does building or encoding produce the expected bytes or the expected refusal? | js-stellar-sdk#1785: an offer ID re-encoded as a different ID |
| **spec** contract interface | For `spec` entries: does the SDK's contract-spec reader return the entries the bytes hold, and refuse a module with several `contractspecv0` sections or a stream that does not end cleanly? | a reader that takes the first of two sections shows half the interface |
| **json** XDR-JSON | On the XDR-JSON columns, for every ledger and xdr variant: does the converter's SEP-51 JSON validate against its own schema and come back to the same bytes, and do converters agree? | a `StringM` escaped beyond its schema's `maxLength` |

Which levels apply to which entry kind is in [manifest.md §10](manifest.md).

## 5. Outcomes and reasons

| `outcome` | Meaning |
|---|---|
| `ok` | The SDK accepted the input and the level's operation completed |
| `diverge` | The SDK accepted the input and the driver itself saw a self-evident mismatch (for example its re-encoding differs, or its own decoder rejects what it just encoded) |
| `reject` | The SDK refused the input through its normal error channel and the process is healthy |
| `crash` | A fault-class error was caught in process; the orchestrator assigns `crash` itself when the process dies. A driver never reports a stack overflow, out-of-memory or panic as `reject` |
| `n_a` | The SDK has no API for this level, type or operation, under the narrow rules of [conformance-protocol.md §1](conformance-protocol.md) |

Reasons are a closed list of codes in the schema, in groups: re-encoding mismatches (`reencode_mismatch`,
`object_reencode_mismatch`, `own_output_rejected`, `native_reencode_mismatch`); decode refusals
(`decode_error`, `union_arm_undeclared`, `enum_undeclared`, `bool_range`, `optional_flag_range`,
`nonzero_padding`, `trailing_bytes`, `length_exceeds_max`, `length_exceeds_input`, `depth`); object and value
refusals (`object_validation`, `value_out_of_range`, `ordering`, `lossy_conversion_refused`,
`unsupported_address_type`); strkey refusals (`strkey_checksum`, `strkey_length`, `strkey_version`,
`strkey_padding`, `strkey_noncanonical`, `strkey_payload`); faults (`stack_overflow`, `out_of_memory`, `panic`,
`internal_error`); not-applicable reasons (`type_not_generated`, `no_object_layer`, `no_native_layer`,
`op_not_supported`, `value_not_representable`, `argument_type_not_accepted`, `schema_too_old`); and `other`. The
SDK's own error text goes in `reason.message` and is never used for classification.

## 6. From outcomes to the matrix

The orchestrator turns each answer into a **verdict** against the manifest — `conform`, `diverge` (accepted, with
bytes or values that differ from the manifest's), `accepts_invalid`, `reject_valid`, `crash` or `n_a` — and a
**check** against the entry's known divergences for the column's target, version and profile: inside a declared
range the declared outcome is `known`, `conform` is `unexpected-conform`, anything else `known-changed`; outside
every range `conform` stays `conform` and anything else is `undeclared`. `xdrcheck conform check` fails on
`undeclared`, `unexpected-conform` and `known-changed`. A cell that differs from the manifest **diverges from the
network** (the manifest's expected values trace to core-emitted bytes); accepting columns whose results differ
**diverge from each other**, which `cross-sdk.md` lists. The exact rules are in
[conformance-protocol.md §4–§5](conformance-protocol.md). Read a run from `SUMMARY.md`: only the rows where a
column is wrong or the SDKs disagree, each with the expected value, every column's answer and a repro command
([conformance-protocol.md §5a](conformance-protocol.md)).

A cell answered `n_a` is not a read. A column whose every cell of an entry variant is `n_a` (or whose `describe`
declares none of the levels the entry needs) never read that entry; `xdrcheck conform run --require-all-read` fails on
it ([conformance-protocol.md §5b](conformance-protocol.md)), so a driver answers `n_a` only under the narrow rules
of [conformance-protocol.md §1](conformance-protocol.md).

`xdrcheck conform sdk-regression` asserts three known js-stellar-sdk defects: on `js@17.2.0`, `js@17.2.1` and `js@17.3.0` each
pre-fix cell of js-stellar-sdk#1766, #1785 and #1789 must be the declared divergence and each fixed cell must
conform.

## 7. Writing a driver

1. Create `drivers/<language>/<version>/` with lock files that pin the SDK version listed in `pins.toml`
   `[conformance.columns]`, and a `Makefile` with `fetch`, `build`, `test` and `clean`
   ([drivers/README.md](../drivers/README.md)).
2. Answer `describe` from the installed package: version, integrity, probes. Never hard-code the SDK version.
3. Implement L0 first: decode by type name with the SDK's strict entry point, re-encode, report
   `reencoded_sha256` and `consumed_bytes`. Report lenient entry points that behave differently under
   `lenient_entry_points`.
4. Add L1, L3 and the `api` operations the SDK can express, reporting exactly the facts
   [conformance-protocol.md §3](conformance-protocol.md) requires.
5. Optionally let the driver build from an SDK checkout, so the SDK's maintainers can run `xdrcheck conform --sdk PATH`
   against an unreleased branch: the `Makefile` reads `XDRCHECK_SDK_SOURCE`, points the build at that directory, and
   leaves `bin/xdrcheck-sdk-source` naming it ([drivers/README.md](../drivers/README.md), "Building from an SDK
   checkout"). `describe` then reports the version the checkout declares.
6. Add the column to its family's file in `drivers/sets.d/` (and to a set in `drivers/sets.toml`, or with
   `[extend]` in the same file), run `xdrcheck conform build --columns '<sdk>@<version>'` and
   `xdrcheck conform run --columns '<sdk>@<version>' --report <dir>`. Every divergence the run shows is declared on its
   entry before the column joins a public set; a defect not yet reported upstream goes through the private process
   in [SECURITY.md](../SECURITY.md) first.

`drivers/stub/` is a driver with canned answers and no SDK, used by the orchestrator's own tests.
