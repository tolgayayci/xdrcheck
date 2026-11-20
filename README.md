# XDRCheck

[![full CI](https://github.com/tolgayayci/xdrcheck/actions/workflows/full.yml/badge.svg)](https://github.com/tolgayayci/xdrcheck/actions/workflows/full.yml)
[![goldens](https://github.com/tolgayayci/xdrcheck/actions/workflows/nightly-goldens.yml/badge.svg)](https://github.com/tolgayayci/xdrcheck/actions/workflows/nightly-goldens.yml)
[![licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![protocol 30](https://img.shields.io/badge/stellar--core-30.0.0-black)](pins.toml)

**A shared test kit for every program that reads the Stellar ledger.** XDRCheck holds rare but valid transaction and
ledger shapes, each emitted by a real stellar-core, tagged with the CAP and protocol that introduced it, and carrying
the values a correct reader must produce. Its tools run those shapes through indexers (wallet-backend, stellar-etl,
Horizon), through the JavaScript, Go, Rust and Python SDKs, and through a linter for Go ingestion code, and name the
exact entry each one gets wrong. It is open source (Apache-2.0) and built against the Protocol 30 stable stack.

Every number on this page comes from a file the kit generates and checks (`evidence/results/`,
`corpus/COVERAGE.md`, `evidence/mainnet-scan/`); every check is a `make` target that runs offline after one fetch,
and a job of the same name in the [full CI](.github/workflows/full.yml).

## At a glance

| | |
|---|---|
| **Corpus** | 446 entries in 36 of 37 CAP rows and 16 protocol-gated or encoding rows ([coverage](corpus/COVERAGE.md)); 138 local-core entries with testnet and pubnet twins, rebuilt byte for byte by `make verify-generate`; stellar-core's goldens and public-lake ledgers imported; hand-made entries flagged `synthetic` |
| **Mainnet, all of it** | a scan of pubnet ledgers 2 to 65,505,999 (10,869,626,939 transactions, 0 gaps) found 3,270,052 transaction-part shapes and 15,884 shape tokens; the [mainnet tier](corpus/mainnet/README.md) holds 6,158 real transactions that together contain **every one of the 15,186 transaction-level tokens**, checked against the public lake by `make verify-mainnet` |
| **Indexers** | wallet-backend built at seven commits, fed by a mock `getLedgers` RPC and by a Galexie (SEP-54) data lake; stellar-etl and Horizon rigs; an independent judge computes from each ledger's own entry changes what the stored rows must be |
| **SDKs** | one divergence matrix over stellar-core 30.0.0 and 17 SDK releases in 20 columns: go-stellar-sdk v0.7.1 to v0.9.0, js-stellar-sdk 16.3.0 to 17.4.0, py-stellar-base 17.0.0 and 17.0.1, rs-stellar-xdr 28.0.0 to 30.0.0 (default and no limits) ([matrix](evidence/results/conformance-matrix.json), [siblings](findings/SIBLINGS.md)) |
| **Linter** | `xdrlint`: the three ingestion mistakes as rules with IDs, 87 seeded-violation fixtures, run on the current wallet-backend and stellar-etl ([rules](lint/docs/README.md)) |
| **Guide** | indexer-hardening guide for developers.stellar.org: 462 claims (407 facts, 55 recommendations), each with its sources: stellar-core source lines, corpus entries and runs ([verification](guide/VERIFICATION.md)) |
| **Findings** | **48 issues filed upstream in 10 projects**: 7 already fixed (3 in rs-stellar-xdr, 3 in py-stellar-base, 1 in java-stellar-sdk), 1 fix awaiting merge in js-stellar-sdk ([details](#found-and-filed-upstream)) |

## Acceptance checks

Each check is one `make` target; [docs/acceptance.md](docs/acceptance.md) gives its full pass condition.

| Check | Condition | Result | Run it | Evidence |
|---|---|---|---|---|
| `roundtrip` | entries round-trip through rs-stellar-xdr | met: 738 round-trip and reject rows | `make verify-corpus` | [manifest schema](corpus/schema/manifest-entry.schema.json), [format](docs/manifest.md) |
| `golden-agreement` | entries agree with the `--check-lcm` goldens | met: imported goldens equal byte for byte; local-core entries compared with the golden transaction of the same shape ([mirrors](corpus/mirrors.json)); stellar-core's own `--check-lcm` accepts the golden tree (`nightly-goldens`) | `make verify-corpus`, `make verify-goldens-nightly` | [golden mirror](evidence/golden-mirror/README.md) |
| `replay-regression` (case `wallet-backend-729`) | wallet-backend#729 reproduced before the fix, passes after | met: halt at `2a0a84ea`, pass at `2c873353` | `make verify-replay` | [evidence](evidence/wallet-backend-replay/README.md) |
| `replay-regression` (case `wallet-backend-731`) | wallet-backend#731 reproduced before the fix, passes after | met: dropped at `764a4f5b`, pass at `c152783c` | `make verify-replay` | [evidence](evidence/wallet-backend-731/README.md) |
| `replay-regression` (case `wallet-backend-716`) | wallet-backend#716 reproduced before the fix, passes after | met: mishandled at `79ea2acd`, pass at `bb0b162b` | `make verify-replay` | [evidence](evidence/wallet-backend-replay/README.md) |
| `lint-fixtures` | the linter flags seeded violations | met: 87 of 87 | `make lint-fixtures` | [rules](lint/docs/README.md) |
| `lint-current` | the linter runs clean on current wallet-backend | met at wallet-backend `f0c00cf5`: its 3 reports are each tied to a finding record and frozen in an expected list | `make lint-wallet-backend` | [lint](lint/README.md) |
| `guide-table` | the guide's field table agrees with the corpus manifest | met: 142 rows | `make verify-guide` | [guide](guide/README.md) |
| `guide-review` | publication gated on review by a core or platform engineer | **not met: the review has not taken place**; publication waits for it | — | [verification report](guide/VERIFICATION.md) |
| `sdk-regression` (cases `js-1766`, `js-1785`, `js-1789`) | js-stellar-sdk#1766, #1785, #1789 reproduced on pre-fix tags | met: 24 assertion rows on js 17.2.0, 17.2.1 and 17.3.0 | `make verify-conformance` | [#1766](evidence/js-1766/README.md), [#1785](evidence/js-1785/README.md), [#1789](evidence/js-1789/README.md) |
| `findings-linked` | every failure maps to a finding record | met: 857 failure rows, each linked to a record that is filed, a duplicate of an upstream item, or not a defect; none pending | `make verify-findings-acceptance` | [findings](findings/README.md) |

The table as the last run wrote it:
[evidence/results/acceptance.json](evidence/results/acceptance.json).

## Check every claim yourself

After `make toolchain && make fetch && make build` (the only networked step), every target runs offline; `OFFLINE=1`
enforces it with a network namespace. Times are the full CI's jobs on a 2-CPU GitHub runner.

| Command | What it proves | Time |
|---|---|---|
| `make verify-corpus OFFLINE=1` | every entry matches the schema, round-trips through rs-stellar-xdr 30.0.0, carries its expected values, and agrees with stellar-core's goldens | 2 min |
| `make verify-generate OFFLINE=1` | every local-core entry is rebuilt from its scenario by a pinned, offline stellar-core 30.0.0 on both the testnet and the mainnet passphrase, with no difference | 1 min |
| `make verify-coverage OFFLINE=1` | the per-CAP coverage manifest is current, and every CAP with no entry says why | under 1 min |
| `make verify-replay OFFLINE=1` | the reference adapter reproduces wallet-backend #729, #731 and #716 on the pre-fix commits and passes on the fixed ones, over both inputs | 14 min |
| `make replay-full OFFLINE=1` | the whole corpus through current wallet-backend: each entry pass, mishandled or dropped, judged from the rows it stored | 21 min |
| `make harness-selftest OFFLINE=1` | indexers with planted bugs land in the result classes their bugs should produce (mishandled, dropped, halt, …), so the harness can tell them apart | 6 min |
| `make verify-memory OFFLINE=1` | the harness replays a full corpus without unbounded memory growth | 10 min |
| `make verify-conformance OFFLINE=1` | the SDK divergence matrix, and js-stellar-sdk #1766, #1785 and #1789 on their pre-fix tags | 22 min |
| `make verify-conformance-public OFFLINE=1` | the same corpus through every pinned SDK release and stellar-core's own decoder | 30 min |
| `make verify-lint OFFLINE=1` | `xdrlint` on its seeded fixtures, on current wallet-backend and stellar-etl, and before and after the upstream fixes it should catch | 18 min |
| `make verify-guide OFFLINE=1` | the guide's field table agrees with the manifest, and every claim has a source that resolves | 4 min |
| `make verify-mainnet OFFLINE=1` | the 6,158 mainnet-tier transactions hash-chain to their lake objects and hold all 15,186 tokens | 11 min |
| `make verify-findings-acceptance` | every failure row of every run maps to a finding record with an upstream link | under 1 min |
| `make verify OFFLINE=1` | all of the above, as the full CI runs it | about 40 min side by side on GitHub |

## Found and filed upstream

Running the corpus found defects in the pipelines and SDKs it targets. Each one has a record in
[`findings/`](findings/README.md) with its severity, affected CAP, component and minimal reproducing entry, and was
reported to the project that owns it. Upstream states below were checked on 2026-11-20.

- **48 issues filed in 10 projects**: wallet-backend 12, go-stellar-sdk 13, js-stellar-sdk 8, rs-stellar-xdr 4,
  Horizon 3, py-stellar-base 3, stellar-etl 2, java-stellar-sdk, stellar-cli and rs-stellar-rpc-client 1 each.
- **7 already fixed upstream.** In rs-stellar-xdr the maintainers merged fixes for three of our issues
  ([#622](https://github.com/stellar/rs-stellar-xdr/issues/622), [#625](https://github.com/stellar/rs-stellar-xdr/issues/625),
  and [#626](https://github.com/stellar/rs-stellar-xdr/issues/626), closed as a duplicate of the maintainers' own issue
  and fixed with it). In py-stellar-base all three are fixed:
  [#1256](https://github.com/StellarCN/py-stellar-base/issues/1256) by the maintainer and
  [#1258](https://github.com/StellarCN/py-stellar-base/issues/1258) by our merged pull request, and
  [#1278](https://github.com/StellarCN/py-stellar-base/issues/1278) by the maintainer. In java-stellar-sdk the maintainers merged a fix
  for [#834](https://github.com/lightsail-network/java-stellar-sdk/issues/834).
- **1 fix awaiting merge**: an SDF developer opened a pull request for js-stellar-sdk
  [#1901](https://github.com/stellar/js-stellar-sdk/issues/1901).
- **Siblings**: when a defect is found in one SDK, the conformance runner checks the same shape in the others, and the
  sibling issue is filed where it reproduces ([sibling matrix](findings/SIBLINGS.md)).

Besides the 48, 34 finding records are duplicates of items already open upstream and 10 were ruled not a defect; the
reports give each one: [pipelines](findings/REPORT-pipelines.md), [SDKs](findings/REPORT-sdks.md).

<details>
<summary>All 48 filed issues, by project</summary>

**wallet-backend** (12)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#804](https://github.com/stellar/wallet-backend/issues/804) | medium | An account created by a native Stellar Asset Contract transfer produces no account_created | open |
| [#805](https://github.com/stellar/wallet-backend/issues/805) | medium | A pre-authorized-transaction signer removed by a failed transaction produces no signer_removed | open |
| [#806](https://github.com/stellar/wallet-backend/issues/806) | low | Contracts deployed by a factory contract get no ACCOUNT CREATE state change | open |
| [#809](https://github.com/stellar/wallet-backend/issues/809) | medium | SEP-41 classifier requires wallet-backend's exact parameter names, so tokens written to the SEP-41 interface are never tracked | open |
| [#811](https://github.com/stellar/wallet-backend/issues/811) | low | AllowTrust that moves a trustline between authorized and authorized-to-maintain-liabilities records no CLEAR of the old flag | open |
| [#824](https://github.com/stellar/wallet-backend/issues/824) | medium | SEP-41 balances are running sums of four event names, so a token that used other event names before a WASM upgrade is served a negative balance | open |
| [#825](https://github.com/stellar/wallet-backend/issues/825) | low | Signer weights above 32,767 wrap when stored as signer_weight_old / signer_weight_new (int16) | open |
| [#831](https://github.com/stellar/wallet-backend/issues/831) | low | A pool-share trustline removed by an AllowTrust or SetTrustLineFlags revocation gets no TRUSTLINE REMOVE state change | open |
| [#829](https://github.com/stellar/wallet-backend/issues/829) | medium | A tracked SEP-41 token that upgrades to a WASM whose transfer takes to: MuxedAddress is no longer indexed, and its old balances keep being served | open |
| [#830](https://github.com/stellar/wallet-backend/issues/830) | medium | operations.successful is true for operations of a failed transaction that stellar-core rolled back | open |
| [#832](https://github.com/stellar/wallet-backend/issues/832) | low | TRUSTLINE, SIGNATURE_THRESHOLD and DATA_ENTRY UPDATE rows are written for operations that leave the entry unchanged | open |
| [#833](https://github.com/stellar/wallet-backend/issues/833) | low | Entry changes made by a ledger upgrade (upgradesProcessing) are never indexed, so a base-reserve increase leaves stale num_subentries and liabilities | open |

**Horizon** (3)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#259](https://github.com/stellar/stellar-horizon/issues/259) | low | Transaction participants from operation meta are never recorded: participantsForMeta reads only the TransactionMeta v0 arm | open |
| [#266](https://github.com/stellar/stellar-horizon/issues/266) | medium | A revocation that redeems pool shares from several liquidity pools gets one liquidity_pool_revoked effect, which can cite another pool's claimable balance | open |
| [#267](https://github.com/stellar/stellar-horizon/issues/267) | low | A pool-share trustline removed by an AllowTrust or SetTrustLineFlags revocation gets no trustline_removed effect | open |

**stellar-etl** (2)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#504](https://github.com/stellar/stellar-etl/issues/504) | low | A text memo is written into the JSON export without a UTF-8 check (invalid bytes become U+FFFD) | open |
| [#511](https://github.com/stellar/stellar-etl/issues/511) | low | export_ledger_transaction drops PostTxApplyFeeChanges, so Soroban fee refunds (P23+) are missing from the row | open |

**go-stellar-sdk** (13)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#6042](https://github.com/stellar/go-stellar-sdk/issues/6042) | medium | strkey.Decode with the claimable-balance version byte accepts an unknown type byte | open |
| [#6043](https://github.com/stellar/go-stellar-sdk/issues/6043) | medium | support/contractevents rejects CAP-67 three-topic SAC mint and clawback events, so consumers such as stellar-etl write no effect for them | open |
| [#6044](https://github.com/stellar/go-stellar-sdk/issues/6044) | medium | The token transfer processor credits the admin, not the recipient, of a legacy custom-token mint event | open |
| [#6045](https://github.com/stellar/go-stellar-sdk/issues/6045) | low | txnbuild: TransactionFromXDR drops SorobanTransactionData from ExtendFootprintTtl and RestoreFootprint operations | open |
| [#6051](https://github.com/stellar/go-stellar-sdk/issues/6051) | low | txnbuild: NewFeeBumpTransaction refuses a parsed Soroban inner transaction unless the base fee also covers its resource fee | open |
| [#6052](https://github.com/stellar/go-stellar-sdk/issues/6052) | low | txnbuild: time bounds above 2^63-1 parse as negative values, so a valid transaction cannot be rebuilt | open |
| [#6053](https://github.com/stellar/go-stellar-sdk/issues/6053) | medium | ingest: Soroban fee accessors and ledger.SorobanFeeWrite1Kb return (0, false) for protocol 23+ meta (only TransactionMeta v3 / LedgerCloseMeta v1 are read) | open |
| [#6054](https://github.com/stellar/go-stellar-sdk/issues/6054) | low | ingest: footprint helpers give up at the first footprint key of another type, and panic on classic transactions | open |
| [#6055](https://github.com/stellar/go-stellar-sdk/issues/6055) | low | ingest: ChangeCompactor writes the merged TTL back into the caller's LedgerCloseMeta when two transactions extend the same TTL entry | open |
| [#6056](https://github.com/stellar/go-stellar-sdk/issues/6056) | low | ingest: SorobanInclusionFeeCharged / InclusionFeeCharged return minus the resource fee when the fee account is a muxed account | open |
| [#6057](https://github.com/stellar/go-stellar-sdk/issues/6057) | low | txnbuild: NewFeeBumpTransaction with a v0 inner transaction returns a fee bump whose inner transaction is nil, so Base64 () and Hash () panic | open |
| [#6058](https://github.com/stellar/go-stellar-sdk/issues/6058) | low | processors/token_transfer: NewEventsProcessor drops the issuer burn when a revocation redeems pool shares and the other asset's amount rounds to 0 | open |
| [#6060](https://github.com/stellar/go-stellar-sdk/issues/6060) | low | ingest: FeesFromTxParts counts a failed Soroban transaction as a classic fee when core runs without EMIT_SOROBAN_TRANSACTION_META_EXT_V1 | open |

**js-stellar-sdk** (8)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#1899](https://github.com/stellar/js-stellar-sdk/issues/1899) | medium | StrKey.encodeSignedPayload encodes a signed payload outside 1 to 64 bytes (empty or 65 bytes) | open |
| [#1901](https://github.com/stellar/js-stellar-sdk/issues/1901) | low | LedgerCloseMetaBatch.fromXDR refuses a valid ledger whose failed transaction carries an authorization tree at the network's maximum depth | fix PR open by an SDF developer, awaiting merge |
| [#1904](https://github.com/stellar/js-stellar-sdk/issues/1904) | medium | Transaction drops an explicit minSeqNum of 0; cloneFrom and assembleTransaction rebuild the transaction without it | open |
| [#1905](https://github.com/stellar/js-stellar-sdk/issues/1905) | low | scValToNative and humanizeEvents drop the ScErrorType of every non-contract error | open |
| [#1911](https://github.com/stellar/js-stellar-sdk/issues/1911) | low | buildFeeBumpTransaction throws "Inner transaction must have time bounds" for a v0 transaction without time bounds | open |
| [#1912](https://github.com/stellar/js-stellar-sdk/issues/1912) | medium | contract.Spec decodes a struct map by entry position instead of by key: a missing Option field shifts values, an extra key throws | open |
| [#1913](https://github.com/stellar/js-stellar-sdk/issues/1913) | low | rpc.Server.getLedgerEntries drops the extXdr field, so the sponsor of an entry cannot be read | open |
| [#1915](https://github.com/stellar/js-stellar-sdk/issues/1915) | low | contract.Spec cannot convert a #[contracterror] argument or a nested soroban_sdk::Error value | open |

**rs-stellar-xdr** (4)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#622](https://github.com/stellar/rs-stellar-xdr/issues/622) | medium | A bool encoded as 2 decodes as false, while stellar-core reads the same bytes as true | fixed (maintainer PR merged) |
| [#623](https://github.com/stellar/rs-stellar-xdr/issues/623) | low | Decoding with Limits::none () allocates the length a prefix claims before reading the body (up to 4 GiB per prefix) | open |
| [#625](https://github.com/stellar/rs-stellar-xdr/issues/625) | low | Top-level Int64 and Uint64 serialize to JSON numbers and reject strings, diverging from SEP-51 | fixed (maintainer PR merged) |
| [#626](https://github.com/stellar/rs-stellar-xdr/issues/626) | low | JSON schema $ref values contain unencoded &lt; and &gt; (#/definitions/StringM&lt;N&gt;), so strict validators reject the schemas | fixed (closed as a duplicate of the maintainers' issue; fix merged) |

**py-stellar-base** (3)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#1256](https://github.com/StellarCN/py-stellar-base/issues/1256) | medium | Signed payload signer: an empty or 65+ byte payload is encoded into a P key that the SDK itself cannot decode | fixed |
| [#1258](https://github.com/StellarCN/py-stellar-base/issues/1258) | medium | StrKey decodes a signed payload key whose padding bytes are not zero | fixed (our PR merged) |
| [#1278](https://github.com/StellarCN/py-stellar-base/issues/1278) | low | SorobanServer.get_ledger_entries drops the extXdr field, so the sponsor of a ledger entry cannot be read | fixed (maintainer PR merged) |

**java-stellar-sdk** (1)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#834](https://github.com/lightsail-network/java-stellar-sdk/issues/834) | low | Sep45Challenge.readChallengeAuthorizationEntries throws IllegalArgumentException instead of InvalidSep45ChallengeException for some malformed input | fixed (maintainer PR merged) |

**stellar-cli** (1)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#2897](https://github.com/stellar/stellar-cli/issues/2897) | low | contract invoke panics with "not yet implemented" on a result holding a soroban_sdk::Error and cannot pass a #[contracterror] argument | open |

**rs-stellar-rpc-client** (1)

| Issue | Severity | What breaks | State |
|---|---|---|---|
| [#124](https://github.com/stellar/rs-stellar-rpc-client/issues/124) | low | get_ledger_entries and get_full_ledger_entries drop the extXdr field, so the sponsor of a ledger entry cannot be read | open |

</details>

## Where things are

[Manifest schema](corpus/schema/manifest-entry.schema.json) ([format](docs/manifest.md)) · sample entries:
[issuer ordering](corpus/manifest/cap-0038/pool-issuers-order-by-bytes-not-strkey.json),
[muxed ID round-trip](corpus/manifest/cap-0027/api-muxed-account-id-encoding.id-hex-string.json),
[colliding map keys](corpus/manifest/cap-0046/scval-map-keys-collide-u32-symbol.json) ·
[the 18 known upstream defects](#known-upstream-defects) · [per-CAP coverage](corpus/COVERAGE.md) ·
[each check and its evidence](docs/acceptance.md)

| Part | Where | Command | Check |
|---|---|---|---|
| Corpus and generator, per-CAP coverage manifest | `corpus/` ([schema](corpus/schema/manifest-entry.schema.json), [coverage](corpus/COVERAGE.md)); generator `crates/xdrcheck-gen` | `make verify-corpus`, `make verify-generate`, `make verify-coverage` | entries round-trip through rs-stellar-xdr and agree with the `--check-lcm` goldens |
| Supporting evidence for the corpus: pubnet history | [evidence/mainnet-scan](evidence/mainnet-scan/README.md): integrity check and component/whole-transaction shape census of pubnet ledgers 2 to 65,505,999 | `sha256sum -c SHA256SUMS` in that folder | none (context for the corpus; the pipelines were not replayed over mainnet) |
| Supporting evidence for the corpus: mainnet tier | [corpus/mainnet](corpus/mainnet/README.md): 6,158 real pubnet transactions, located in their public-lake objects, that together hold every transaction-level shape token of the scan (15,186; [coverage](evidence/results/mainnet-coverage.json)) | `make mainnet-fetch`, `make verify-mainnet` | none (context for the corpus; the tier reports no SDK or pipeline results) |
| Replay harness, adapter interface, reference adapter | `go/` ([harness](docs/replay-harness.md), [adapter protocol](docs/adapter-protocol.md)), `go/adapters/walletbackend` | `make verify-replay`, `make harness-selftest` | reproduces wallet-backend #729, #731, #716 on pre-fix commits, passes on the fixed ones |
| Linter and checklist | `lint/` ([rules](lint/docs/README.md)), [guide checklist](guide/checklist.mdx) | `make lint-fixtures`, `make lint-wallet-backend` | flags seeded violations; clean on current wallet-backend |
| Indexer-hardening guide | [guide/](guide/README.md), [verification report](guide/VERIFICATION.md) | `make verify-guide` | field table agrees with the corpus manifest; review by a core or platform engineer |
| Conformance runner (JS, Go, Rust, Python) | `go/` (`xdrcheck conform`), `drivers/` ([rules](docs/conformance-protocol.md)) | `make verify-conformance` | reproduces js-stellar-sdk #1766, #1785, #1789 on pre-fix tags |
| Findings reports, filed upstream | [pipelines](findings/REPORT-pipelines.md), [SDKs](findings/REPORT-sdks.md), records in `findings/` | `make verify-findings` | every failure maps to a filed issue |
| Test suite and CI | `.github/workflows/`, [timings](docs/ci-timings.md) | `make test`, `make verify-pr`, `make verify` | tests and CI for all tooling |
| Release and maintenance | [CHANGELOG.md](CHANGELOG.md), [release](docs/release.md), [maintenance](docs/maintenance.md) | `make release` | Protocol 30 release; the upgrade procedure for each protocol release |

## What the kit is

Software that reads the Stellar ledger breaks or silently misreads transaction shapes that are rare but valid: a
muxed account, a signed-payload signer, a fee bump around a failed transaction, a deeply nested authorization
tree. The kit has:

- a **corpus** of them, one entry per pattern, each tagged with the CAP and protocol that introduced it (a pattern
  no CAP introduced, such as a pre-CAP operation or an encoding rule, carries a note saying so) and emitted
  by a real stellar-core (hand-made entries are marked synthetic), with the values a correct reader must produce;
- a **generator** that produces entries from a local, offline stellar-core on the testnet and mainnet passphrases,
  and imports stellar-core's goldens and public-lake ledgers;
- a **replay harness** that serves the corpus to an unmodified indexer through a documented adapter interface and
  reports every entry it mishandles or drops, with a reference adapter;
- **service rigs** that run real ledgers through wallet-backend, stellar-etl and Horizon built at any commit, and an
  independent **judge** that computes from each ledger's own entry changes what really happened and compares the
  rows each pipeline stored;
- a **conformance runner** that runs the corpus through the JavaScript, Go, Rust and Python SDKs and reports where
  they disagree with the network or each other, and `xcheck`, which compares SDKs on real transactions;
- a **linter**, `xdrlint`, for the three ingestion mistakes in Go source, and an **indexer-hardening guide** with a
  checklist for every other language;
- **data tools**: a scan of network history gives a shape census, value tags and a lookup index, and the commands
  `find`, `replay`, `repro`, `xcheck`, `data` and `runs` turn them into example mainnet transactions, replays and
  self-contained reproductions.

## Five-minute start

**Offline, from a fresh clone, with Python 3 only.** The corpus is plain files; the Python loader (package
`xdrcheck`, module `xdrcheck`, the name of the corpus release) uses the standard library (and the
`zstd` command for decoded sidecars):

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "packages/python")
import xdrcheck
corpus = xdrcheck.open("corpus")
print(corpus)
e = corpus.entry("cap-0040/signed-payload-signer-added")
print(e.id, e.caps, e.title)
v = e.variants[0]
print(v.network, v.protocol, v.ledger_seq, len(v.blob()), "bytes")
PY
```

```text
Corpus('30.0.0-dev', 'corpus')
cap-0040/signed-payload-signer-added [40] SetOptions adds an ed25519 signed-payload signer to an account
testnet 28 4437357 58256 bytes
```

**After one fetch.** On Linux, with [mise](https://mise.jdx.dev) and [rustup](https://rustup.rs) installed:

```sh
mise install    # the pinned Go, Node, Python and Java; rustup reads rust-toolchain.toml
make toolchain && make fetch-replay && make build && make demo
```

The demo replays the fee-bump and muxed-account entries through a small indexer with one planted bug (it skips
failed transactions). It prints each entry the indexer got wrong, what the ledger holds against what the indexer
stored, and the command that replays that entry alone; the full report is `reports-demo/REPORT.md`. The demo
itself takes seconds; the first fetch and build take a few minutes. No Docker and no network after the fetch.
The replay step ends with one summary line: rows per result class, failures, and harness faults.

`make build` links every tool into `./bin`; run `export PATH="$PWD/bin:$PATH"` or call them as `bin/xdrcheck`.

## Who it's for

**You maintain an indexer written in Go.** Replay the whole corpus through the adapter template, then copy it
into your own module and point it at your indexer:

```sh
bin/xdrcheck replay --adapter bin/minimal --target-version 0.1.0 --input sep54-dir --report reports/minimal
```

`--target-version` names the version of the indexer under test in the report. Next:
[go/adapters/minimal](go/adapters/minimal/README.md), then
[docs/adapter-protocol.md](docs/adapter-protocol.md) §8 and [docs/github-action.md](docs/github-action.md) for CI.

**You maintain an indexer in another language.** The adapter speaks JSON over stdin and stdout, so it can be
written in anything. Start from the TypeScript template:

```sh
(cd examples/adapter-ts && npm ci --ignore-scripts)
bin/xdrcheck replay --adapter "node examples/adapter-ts/adapter.ts" --target-version 0.1.0 --input sep54-dir --report reports/adapter-ts
```

Next: [examples/adapter-ts](examples/adapter-ts/README.md) and [docs/adapter-protocol.md](docs/adapter-protocol.md).

**You maintain a Stellar SDK.** Put every corpus entry through your SDK's decoder in your own CI, with a small
loader for Go, Rust, Python or JavaScript and a committed list of the failures you expect. To run the recipes
here against the pinned SDKs:

```sh
make fetch-sdk && make sdk-ci-examples
```

Next: [docs/use-in-sdk-ci.md](docs/use-in-sdk-ci.md) (loaders, recipes, expected-failure lists, an unreleased
branch), [docs/github-action.md](docs/github-action.md) §3 (`conform` mode) and
[docs/protocol-upgrades-for-sdks.md](docs/protocol-upgrades-for-sdks.md).

**Your team writes Go ingestion code and wants a linter.** `xdrlint` flags trusting fields stellar-core never
validated, walking nested structures with no depth or size cap, and taking participants from the envelope
instead of the meta. From your module's root:

```sh
path/to/this/checkout/bin/xdrlint ./...   # after make build, or: cd lint && go build -o bin/xdrlint ./cmd/xdrlint
```

Next: [lint/README.md](lint/README.md).

**You are adding a CAP or a protocol change.** Add the new shapes as corpus entries and check them (this needs
the full fetch: stellar-core, its goldens and every dependency):

```sh
make fetch && make build && make verify-corpus OFFLINE=1
```

Next: [docs/authoring-entries.md](docs/authoring-entries.md), [docs/manifest.md](docs/manifest.md).

**You maintain this kit.** Run every check at full size, as the full CI on main does (`make verify` took about 15 minutes
on an 8-vCPU machine with warm caches, [docs/ci-timings.md](docs/ci-timings.md)), and follow the upgrade
procedure at each protocol release:

```sh
make fetch && make build && make verify OFFLINE=1
```

Next: [docs/maintenance.md](docs/maintenance.md); `make help` lists every target by kind of user.

## What's inside

| Part | What it does | Path | Doc |
|---|---|---|---|
| Corpus | One entry per rare shape: the bytes stellar-core emitted (hand-made ones are marked synthetic), the CAP and protocol, and the values a correct reader must produce | `corpus/` | [manifest](docs/manifest.md), [coverage](corpus/COVERAGE.md) |
| Generator | Produces entries from a local stellar-core, offline, on the testnet and mainnet passphrases; imports stellar-core's goldens and public-lake ledgers | `crates/` (`xdrcheck-corpus gen`) | [authoring entries](docs/authoring-entries.md) |
| Corpus check | Every entry round-trips through rs-stellar-xdr and agrees with stellar-core's goldens | `crates/` (`xdrcheck-corpus verify`) | [architecture](docs/architecture.md) |
| Replay harness | Serves the corpus to an unmodified indexer as a data lake or a mock `getLedgers`, compares what it stored with the manifest, and classifies each entry pass, mishandled or dropped | `go/` (`xdrcheck replay`) | [harness](docs/replay-harness.md) |
| Adapters | `minimal` (the template), `baseline` (the complete example), wallet-backend, stellar-etl, a TypeScript template | `go/adapters/`, `examples/adapter-ts/` | [adapter protocol](docs/adapter-protocol.md) |
| Conformance runner | Runs the corpus through the JavaScript, Go, Rust and Python SDKs and reports where they disagree with the network or each other | `go/` (`xdrcheck conform`), `drivers/` | [conformance](docs/conformance-protocol.md), [drivers](docs/driver-protocol.md) |
| SDK loaders | Read the corpus from an SDK's own tests | `packages/`, `examples/sdk-ci/` | [SDK CI](docs/use-in-sdk-ci.md) |
| Linter | `xdrlint`: the three ingestion mistakes in Go source | `lint/` | [lint](lint/README.md) |
| Guide | The indexer-hardening guide for developers.stellar.org, with a checklist | `guide/` | [guide](guide/README.md) |
| GitHub Action | Replay, conform or lint in CI from a pinned release | `action.yml` | [action](docs/github-action.md) |
| Service rigs | wallet-backend, stellar-etl and Horizon built at a commit, fed real ledgers from a lake directory, their stored rows exported | `go/adapters/walletbackend/`, `go/adapters/stellaretl/`, `go/adapters/horizon/`, `go/internal/rig/` | [replay](docs/replay.md), [harness §13](docs/replay-harness.md) |
| Judge | `xdrcheck-judge`: facts from each ledger's own entry changes, and verdicts on a pipeline's rows, with a scope file per target | `crates/xdrcheck-judge/` | [judge](crates/xdrcheck-judge/README.md) |
| Real-ledger replay and runs | `xdrcheck replay --target` (SDK sweeps and rigs at any version), `xdrcheck runs`, `xdrcheck repro`, `xdrcheck xcheck` | `go/cmd/xdrcheck/`, `go/internal/hunt/` | [replay](docs/replay.md), [run directory](docs/run-directory.md), [repro](docs/repro.md), [xcheck](docs/xcheck.md) |
| Scan, census and lookup index | `xdrcheck-corpus scan`: shape tokens of every ledger (grammar `xcc.shape/v1`), the census per level, the token census, the locate index | `crates/xdrcheck-corpus/` | [data](docs/data.md) |
| Value tagger | `xdrcheck-tagger`: transactions holding values readers get wrong (integer edges, non-UTF-8 text, duplicate map keys, token events from contracts that are not a SAC) | `crates/xdrcheck-tagger/` | [data](docs/data.md) |
| Dataset and `find` | `xdrcheck data` (the dataset manifest, named sets, ledger fetch) and `xdrcheck find` (from a token, tag, CAP or linter assumption to example transactions) | `go/cmd/xdrcheck/` | [data](docs/data.md), [find](docs/find.md) |

## Requirements

| You want to | OS | Tools | Disk |
|---|---|---|---|
| Run the demo, or replay your indexer | Linux | Go, Rust, Node, Python and Java through mise and rustup (`make toolchain` checks them); Docker only for the `sep54-s3` input | about 1.5 GB of dependencies (`make fetch-replay`) and 2 GB for `target/` |
| Use the corpus in an SDK's CI | any | your SDK's language and a zstd decoder; none of this repository's tools | about 100 MB (the corpus) |
| Run the SDK recipes and the conformance runner here | Linux | as for replay | about 4.4 GB (`make fetch-sdk`) and 2 GB for `target/` |
| Lint a Go module | Linux or macOS | Go 1.26 or later | Go modules; about 2.6 GB with the golangci-lint plugin (`make fetch-lint`) |
| Author entries, or run every check | Linux on x86-64 with cgroup v2 and unprivileged user namespaces (for `OFFLINE=1`) | all of the above and Docker | about 15 to 17 GB (`make fetch`), up to 3.3 GB of container images and 2 GB for `target/` |

Measured times for each step are in [docs/ci-timings.md](docs/ci-timings.md). Every version the kit builds
against or tests is pinned in [`pins.toml`](pins.toml): the Protocol 30 stable stack (stellar-core 30.0.0,
rs-stellar-xdr 30.0.0, go-stellar-sdk, js-stellar-sdk, …). After the fetch, every `make` target runs offline;
`OFFLINE=1` enforces it.

## Repository map

| Path | What |
|---|---|
| `corpus/` | manifest entries, content-addressed blobs, decoded sidecars, chains, vendored lake objects, scenarios, recipes, schemas, the field table source, coverage |
| `crates/` | Rust: `xdrcheck-corpus` (oracle, generator, scan) and its libraries `xdrcheck-xdr`, `xdrcheck-meta`, `xdrcheck-gen`; `xdrcheck-mutate`; `xdrcheck-judge`; `xdrcheck-tagger` |
| `go/` | Go: `xdrcheck` (ledger server, replay harness, conformance orchestrator, target replay, data, find, repro, runs, xcheck, reports, pins), the public `adapterkit` package, the adapters and rigs |
| `lint/` | Go: `xdrlint`, its rules, fixtures and rule pages |
| `drivers/` | conformance drivers, one directory per pinned SDK version |
| `packages/` | corpus loaders for SDK tests: Go, Rust, Python, npm |
| `examples/` | the TypeScript adapter and the SDK CI recipes |
| `guide/` | the indexer-hardening guide (MDX), its checklist and its claim-to-source map |
| `findings/` | public finding records and the findings reports |
| `evidence/` | hand-run reproductions the acceptance checks are built on, the mainnet scan's integrity check and shape census ([mainnet-scan](evidence/mainnet-scan/README.md)), and the generated results data the docs, dashboard and landing page read ([results](evidence/results/README.md)) |
| `schemas/` | JSON Schemas of the run directory, the dataset manifest and the issue table |
| `apps/docs/` | the documentation site (Mintlify): guides, reference, the CAP pages and the results pages, generated from this tree |
| `apps/dashboard/` | a static dashboard of the corpus by CAP, the scan, the SDK matrix, replay and findings ([README](apps/dashboard/README.md)) |
| `apps/landing/` | the static landing page ([README](apps/landing/README.md)) |
| `action.yml`, `action/` | the GitHub Action |
| `contracts/` | Soroban test contracts the generator deploys |
| `scripts/`, `mk/`, `Makefile` | fetch, offline and memory wrappers, repository checks, CI helpers, make targets |
| `bin/` | links to the built tools (`make build`) |

## Known upstream defects

Public defects in which a Stellar reader met a rare shape and handled it wrong, and how the kit covers each one.
"Reproduced" means a `make` target runs the affected project at a pre-fix version and shows the defect, and at the
fixed version and shows it gone; "input" means corpus entries hold the shape behind the defect but no reader of that
project runs them here. The generated data is [evidence/results/known-defects.json](evidence/results/known-defects.json).

| Defect | How the kit covers it | Where |
|---|---|---|
| stellar-core#5435 (`--check-lcm` goldens) | agreement, not a reproduction: imported goldens equal their golden frame byte for byte, and each local-core entry that matches a golden transaction of the same shape is compared with it (only these count as mapped); for an entry that matches none, the operation tier, reported separately and not agreement of the entry, states whether every operation has a golden operation of the same shape | `make verify-corpus`; the `*-golden.*` entries under `corpus/manifest/`; `corpus/mirrors.json` |
| wallet-backend#731 (CAP-73 SAC trustline) | reproduced: pre-fix and fixed commits | `make verify-replay` (`reports/replay-regression/`); `cap-0073/sac-trust-creates-trustline`; [evidence](evidence/wallet-backend-731/README.md) |
| wallet-backend#729 (CAP-40 signed-payload signer) | reproduced: pre-fix and fixed commits | `make verify-replay`; `cap-0040/signed-payload-signer-added`; [evidence](evidence/wallet-backend-replay/README.md) |
| henyey#3941 (bucket-entry parse failure) | input: the bucket entry and the contract-data key it failed on; no henyey reader runs here | `cap-0085/bucket-entry-with-executable-tag`, `cap-0085/contract-data-keyed-by-executable-tag` |
| rs-stellar-xdr#581 (VecM capacity on decode) | input: length prefixes larger than the input | `xdr-strict/length-prefix-exceeds-input.*` |
| stellar-etl#454 (data-quality sweep) | input: entries for members of the sweep | `classic/amount-above-2-pow-53-stroops`, `cap-0038/claim-atoms-pool-and-order-book-mixed`, `cap-0046/failed-soroban-tx-with-sac-transfers-in-diagnostics` |
| stellar-etl#470 (Protocol 28 epic) | input for the epic's XDR themes: CAP-83's `STELLAR_VALUE_EMPTY_TX_SET` and CAP-85's `CONTRACT_EXECUTABLE_EXTERNAL_REF` and `SCV_EXECUTABLE_TAG`; CAP-86 changed no XDR. The ledger entries among them replay through the [stellar-etl adapter](go/adapters/stellaretl/README.md) (its "Build and run" command, with `--entries`) | `cap-0083/stellar-value-empty-tx-set`, `corpus/manifest/cap-0085/` |
| wallet-backend#716 (AddressBytea truncation) | reproduced: pre-fix and fixed commits | `make verify-replay`; `strkey/truncated-muxed-address-56-chars`, `cap-0040/signed-payload-signers-1-byte-and-64-byte`; [evidence](evidence/wallet-backend-replay/README.md) |
| stellar-etl#460 (P23+ event and effect gaps) | run: stellar-etl through the adapter at v2.8.34 and the pinned v2.8.35, entries declare the result | `make replay-etl-known`; `cap-0067/sac-mint-three-topics`; [evidence](evidence/stellar-etl/README.md) |
| wallet-backend#753 (four indexer fixes) | run: the commits before and after the fixes, through the replay harness and the linter | [pipelines report](findings/REPORT-pipelines.md) (fix table); `make lint-before-after` |
| rs-soroban-sdk#2099 (MuxedAddress from a non-address ScVal) | input: a `transfer` event whose `to` topic is a symbol; no soroban-sdk column runs it | `cap-0067/transfer-event-with-non-address-to-topic` |
| rs-stellar-xdr#598 (VecM max on serde) | input | `xdr-json/vector-longer-than-declared-max` |
| js-stellar-sdk#1766 (issuer and map-key order) | reproduced: pre-fix and fixed tags | `make verify-conformance` (`reports/conformance/sdk-regression.json`); `cap-0038/pool-issuers-order-by-bytes-not-strkey`; [evidence](evidence/js-1766/README.md) |
| rs-stellar-xdr#604 (schemas omit feature-gated types) | checked at the pinned 30.0.0, where the gates are gone: the structural walk reads the ledger against that crate's own `LedgerCloseMeta` JSON Schema and fails on an arm the schema lacks (the issue was closed as not planned) | `make verify-corpus`; `cap-0088/signed-ms-local-twins` (`signed_ms`) |
| js-stellar-sdk#1789 (colliding map keys) | reproduced: pre-fix and fixed tags | `make verify-conformance`; `cap-0046/scval-map-keys-collide-u32-symbol`; [evidence](evidence/js-1789/README.md) |
| js-stellar-sdk#1785 (muxed and offer IDs) | reproduced: pre-fix and fixed tags | `make verify-conformance`; `cap-0027/api-muxed-account-id-encoding.*`, `classic/api-offer-id-encoding.*`; [evidence](evidence/js-1785/README.md) |
| js-xdr#165 (XDR validation pass) | input of the same class: float union discriminants, a bool of 2, trailing bytes, undeclared discriminants | `corpus/manifest/xdr-strict/` |
| js-stellar-sdk#1823 (non-UTF-8 string arms) | input | `classic/api-memo-text-non-utf8-roundtrip`, `cap-0067/to-muxed-id-text-non-utf8-memo` |

## Status

The first release is `30.0.0` ([CHANGELOG.md](CHANGELOG.md)). Every acceptance check holds on
the current tree but one: the guide's review by a core or platform engineer has not taken place, and the guide is
not published until it has ([docs/acceptance.md](docs/acceptance.md)). The linter is clean on the pinned current
wallet-backend because each of its three reports there is in a frozen expected list, with a reason and a finding
record. Not built yet: serving the lake layout over a GCS API from `xdrcheck`, and `xdrcheck replay --resume`. The
scan's per-ledger output and the lookup index are too large for this repository; its integrity check and census
summary are in [evidence/mainnet-scan](evidence/mainnet-scan/README.md).

Maintainer: Tolga Yaycı ([@tolgayayci](https://github.com/tolgayayci)). How the kit is kept current across protocol
upgrades: [docs/maintenance.md](docs/maintenance.md).

## Documentation

The documentation site is in [`apps/docs`](apps/docs/README.md) (Mintlify; `pnpm --filter docs dev` previews it).
Its reference pages are generated from [`docs/`](docs/README.md), `lint/docs/` and the corpus; the CAP coverage page
(`apps/docs/caps/overview.mdx`) lists every entry by CAP with its pattern, protocol, origin, source ledger and, where it
can be joined exactly, mainnet prevalence. The results pages (`apps/docs/results/`: the mainnet scan, the SDK matrix,
replay, the known incidents and the findings table) are generated from
[`evidence/results/`](evidence/results/README.md) and [`evidence/mainnet-scan/`](evidence/mainnet-scan/README.md);
`apps/docs/scripts/generate.py --check` (in `make repo-checks`) fails when one is stale or a link or anchor is broken.
The dashboard and the landing page (`apps/dashboard/`, `apps/landing/`) read the same files and are not deployed from
this repository.

## Glossary

| Term | Meaning |
|---|---|
| XDR | The binary format of every Stellar transaction, result and ledger |
| `LedgerCloseMeta` | The XDR record of one closed ledger: its transactions, their results and every state change. Indexers read these |
| CAP | Core Advancement Proposal: a change to the Stellar protocol. Each entry names the CAPs whose shapes it holds |
| Shape | A structural variant of a transaction, operation or ledger entry, such as a signed-payload signer |
| Union arm | One case of an XDR union (an operation type, an address kind, …); coverage is counted by arm |
| Entry | One shape in the corpus: its bytes, its CAPs and protocol, and what a correct reader must derive |
| Variant | The same entry captured on another network or protocol version |
| Golden | A `LedgerCloseMeta` file stellar-core checks in its own CI (`--check-lcm`); corpus entries must agree with them |
| SEP-51 | The XDR-JSON format; each entry's decoded values are stored in it |
| SEP-54 | The data-lake layout of ledger files that Galexie, Stellar's ledger exporter, writes; the harness serves the corpus in it |
| Mishandled, dropped | The replay's two failure classes: the indexer crashed, hung, halted or stored a wrong value; or it stored the shape only in part, or not at all |
| Adapter | A small program you write that starts your indexer for the harness and reports what it stored |
| Driver | A small program that runs the corpus through one SDK version for the conformance runner |
| Expected-failure list | A committed list of the entries your reader is known to fail; CI fails on any new failure, and on a listed one that starts passing |

## More

- [docs/README.md](docs/README.md): every document, by kind of user, and the repository layout
- [docs/acceptance.md](docs/acceptance.md): each acceptance check with its pass condition, `make` target and evidence
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) (report a
  vulnerability privately; how defects found in other projects are handled)

## Keys and networks

Entries generated on a local stellar-core are signed by keys derived from **public labels** (and, for the root
account, from the network passphrase), on a private standalone network. Transactions signed under the mainnet
passphrase are therefore published with keys anyone can derive. They cannot be replayed on the real network
(their sequence numbers can never match a real account's), but **never fund an account whose key is derived from
a label in this repository** on any real network: anyone can take the funds. No secret, funded key or account is
used anywhere in the kit.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for third-party material in the corpus.
