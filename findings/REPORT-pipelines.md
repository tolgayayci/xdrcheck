# Findings report: pipelines

What the kit found when it ran the corpus against two SDF pipelines, **stellar/wallet-backend** and
**stellar/stellar-etl**, through the replay harness and the `xdrlint` static analyser, and where each result stands
upstream. Every failure row of every run below resolves to a finding record under `findings/`; the records are the
source of truth and this page summarises them. State as of 2026-11-20 (upstream states checked on 2026-11-20).

Findings still under coordinated disclosure, if any, are not represented in this report.
Results our runs produced that are not yet reported upstream are pending finding review: the public tree lists only
which rows they account for (`findings/pending/`, `lint/expected/*/*.pending.json`) and describes nothing about them
(`findings/README.md`).

## How to reproduce

```sh
make fetch                                  # the only networked step
make build
make verify-replay       OFFLINE=1          # wallet-backend: three fixes before and after, and the current commit
make lint-wallet-backend OFFLINE=1          # xdrlint at the pinned current wallet-backend commit
make lint-before-after   OFFLINE=1          # xdrlint over the before/after table of upstream fixes
make lint-stellar-etl    OFFLINE=1          # xdrlint at the pinned stellar-etl commit (its own Go toolchain)
make replay-etl-known    OFFLINE=1          # stellar-etl: the entries that declare a stellar-etl divergence
make verify-findings     OFFLINE=1          # every failure row carries a finding ID that resolves to a record
```

The stellar-etl replay half is in [`evidence/stellar-etl/`](../evidence/stellar-etl/), recorded at v2.8.34
(`2b24ec89`); its `reproduce.sh` needs the network once, to build stellar-etl at that commit and install the storage
emulator, and writes its transcripts to a scratch folder. `make replay-etl-known` replays the same entries at the
pinned v2.8.35.

## Targets

| Pipeline | Pinned | How it was run |
|---|---|---|
| stellar/wallet-backend | current `f0c00cf5`; for the fix table, the pre- and post-fix commits of PRs #693, #729, #739, #745, #753, #756 and issues #716, #731 | Replay harness with the wallet-backend adapter over the RPC and the SEP-54 lake inputs (`docs/replay-harness.md`); `xdrlint -profile wallet-backend` with frozen expected lists (`lint/expected/wallet-backend/`) |
| stellar/stellar-etl | v2.8.35 (`7e3fc9af`) | Replay harness with the stellar-etl adapter, the unmodified binary reading captured pubnet ledgers from a GCS emulator (`evidence/stellar-etl/`); `xdrlint -profile default`, built with Go 1.27.3 as stellar-etl's `go.mod` requires (`lint/expected/stellar-etl/`) |

The pins moved from wallet-backend `e967ce8b` to `3e22515a` and from stellar-etl v2.8.34 (`2b24ec89`) to v2.8.35
(`7e3fc9af`). Every corpus entry that declares a divergence at the current commit of either pipeline was executed
again at the new pin on 2026-11-18 with the same result as at the old one, on both inputs for wallet-backend (the entries'
known divergences in `corpus/manifest/`). From v2.8.34 to v2.8.35 only `go.mod`, `go.sum` and workflows changed, so
every stellar-etl linter site is the same code at the same line
(`lint/expected/stellar-etl/7e3fc9af95359dad6ba939fa88791f49cdf531ae.suppressions.yml`). On 2026-11-19 the wallet-backend
pin moved again, from `3e22515a` to `18db88f4`, its next commit on main, which changes ingest configuration only
(`internal/indexer/` is unchanged): every replay row of `make verify-replay` and `make replay-full` has the same result
on both inputs, and every linter site is the same code at the same line
(`lint/expected/wallet-backend/18db88f4ba481c49a782d157be42177700c4385e.suppressions.yml`). On 2026-11-20 it moved
again, from `18db88f4` to `f0c00cf5`, its next commit on main, which adds GraphQL usage metrics to the server only
(`internal/serve/`, `internal/metrics/`; `internal/indexer/` is unchanged): every replay row of `make verify-replay` and
`make replay-full` has the same result on both inputs, and every linter site is the same code at the same line
(`lint/expected/wallet-backend/f0c00cf5242048d0438d07151cc1ef1a4b98d7c7.suppressions.yml`).

## Results by run (development mode)

| Run | Rows | Failure rows | With a finding | Pending finding review |
|---|---|---|---|---|
| `make verify-replay` (7 commits × 2 inputs) | 104 | 20 | 20 | 0 |
| `make lint-wallet-backend` | 3 | 3 | 3 | 0 |
| `make lint-before-after` (11 commits) | 231 | 231 | 231 | 0 |
| `make lint-stellar-etl` | 10 | 10 | 10 | 0 |

A linter report on third-party code is a failure row whether or not it is suppressed: a suppression hides it from
the exit code, not from the findings map. The linter counts are the frozen lists in `lint/expected/` (the `count` of
each expected report plus the pending sites); the replay counts are those of `make verify-findings` over the run's
reports at the current pins. The pre-fix replay rows fail on purpose; each post-fix commit passes.

## Findings

38 finding records cover the pipelines: 13 `duplicate-of`, 18 `filed` and 7 `not-a-defect`.

### Reproduced defects, already public upstream

| Record | Pipeline | What the run shows | Severity | Upstream | State |
|---|---|---|---|---|---|
| F-0012 | wallet-backend | Ingestion halts on a SetOptions that adds a signed-payload signer: replay `mishandled · halt` at `2a0a84ea` on `cap-0040/signed-payload-signer-added`, both inputs; `pass` at the fix `2c873353` | critical | [PR #729](https://github.com/stellar/wallet-backend/pull/729), fixed | `duplicate-of` |
| F-0013 | wallet-backend | A signed-payload signer stored truncated to an account key: `mishandled · wrong_value` at `79ea2acd`; `pass` at `bb0b162b` | high | [issue #716](https://github.com/stellar/wallet-backend/issues/716), fixed | `duplicate-of` |
| F-0014 | wallet-backend | A trustline created by a Stellar Asset Contract call produces no trustline state change: `dropped · partial` at `764a4f5b` on `cap-0073/sac-trust-creates-trustline`; `pass` at `c152783c` | high | [issue #731](https://github.com/stellar/wallet-backend/issues/731), fixed | `duplicate-of` |
| F-0004 | wallet-backend | Soroban participants taken from the declared authorization tree (XDR301, XDR102 and XDR201 at `666a64d4`; at `9538b3ca` the rows of the before/after table fall to their recorded counts) | high | [PR #739](https://github.com/stellar/wallet-backend/pull/739), fixed | `duplicate-of` |
| F-0005 | wallet-backend | Operation participants recorded before the success check (XDR302) | high | [PR #739](https://github.com/stellar/wallet-backend/pull/739), fixed | `duplicate-of` |
| F-0006 | wallet-backend | A nested deploy declared in the authorization tree recorded without meta showing it (XDR303 at `9538b3ca`, silent at `80121f3a`) | medium | [issue #746](https://github.com/stellar/wallet-backend/issues/746), **open**; the fix landed as `80121f3a` inside PR #739 without closing it | `duplicate-of` |
| F-0007 | wallet-backend | A Soroban operation's source stored in its muxed `M…` form (XDR102) | high | [PR #753](https://github.com/stellar/wallet-backend/pull/753), fixed | `duplicate-of` |
| F-0008 | wallet-backend | Claimable-balance and pool address kinds reach an account column in SEP-41 and SAC event processing (XDR102) | medium | [PR #756](https://github.com/stellar/wallet-backend/pull/756), fixed | `duplicate-of` |
| F-0009 | wallet-backend | A muxed address reaches an account column in SEP-41 processing (XDR102) | high | [PR #693](https://github.com/stellar/wallet-backend/pull/693), fixed | `duplicate-of` |
| F-0010 | wallet-backend | A deployer address of a kind the account column cannot store is recorded (XDR102) | medium | [PR #745](https://github.com/stellar/wallet-backend/pull/745), fixed | `duplicate-of` |
| F-0015 | stellar-etl | `export_token_transfer` turns a text or hash memo into a muxed destination with ID 0: replay `mishandled · wrong_value` at v2.8.34 and again at v2.8.35 on four pubnet entries (`cap-0067/to-muxed-id-*`); XDR101 at the two `SetID` calls in `internal/transform/token_transfer.go` | high | [issue #450](https://github.com/stellar/stellar-etl/issues/450), **open**; upstream keeps the behaviour on purpose and pins it in a test | `duplicate-of` |
| F-0086 | stellar-etl | `asset_balance_changes` are built from a transaction's diagnostic events with no check that the transaction succeeded, so a failed Soroban transaction gets balance-change rows for transfers that were rolled back: XDR405 at `internal/transform/operation.go:1889` and `:1924` at v2.8.35, suppressed with this record; the corpus entry `cap-0046/failed-soroban-tx-with-sac-transfers-in-diagnostics` holds such a transaction, no replay compares this field | medium | [issue #488](https://github.com/stellar/stellar-etl/issues/488) (opened by a stellar-etl maintainer), **open** | `duplicate-of` |
| F-0087 | stellar-etl | `export_token_transfer` parses each amount with `strconv.ParseFloat` into a float64 and scales it by 0.0000001, so `amount` is inexact (`amount_raw` keeps the exact value): XDR402 (warning) at `internal/transform/token_transfer.go:57`, `:62`, `:67`, `:72` and `:77` at v2.8.35, suppressed with this record | low | [issue #454](https://github.com/stellar/stellar-etl/issues/454) (opened by a stellar-etl maintainer), **open** | `duplicate-of` |

The before/after table of `make lint-before-after` (12 rows; `reports/lint-before-after.md` prints it) shows each
linter rule firing at a fix's pre-fix commit and falling silent, or to the recorded count, at the fixed one. That
table and the replay pairs above are the regression tests the fixes leave behind: a later commit that brings a
defect back turns the run red.

### Defects found by these runs and reported upstream (`filed`)

Reported by the maintainers of this kit; each record cites its public issue.

| Record | Pipeline | What the run shows | Severity | Upstream | State |
|---|---|---|---|---|---|
| F-0066 | wallet-backend | SEP-41 balances are running sums of transfer, mint, burn and clawback events with no starting value from contract storage, so a token whose balance changes were published under other event names (here: before a WASM upgrade) is stored and served a wrong balance, negative after its first standard transfer out; executed by hand at `3e22515a` on mainnet ledgers 65,293,184 to 65,293,433, no run compares it | medium | [issue #824](https://github.com/stellar/wallet-backend/issues/824), **open** | `filed` |
| F-0070 | wallet-backend | The SEP-41 check accepts a `MuxedAddress` recipient in `transfer` only when the parameter is named `to_muxed`, so a tracked token that upgrades to the standard `transfer(from: Address, to: MuxedAddress, amount: i128)` is no longer indexed and its `sep41_balances` rows keep being served as at the upgrade (29 pubnet contracts); executed by hand at `18db88f4`, no run compares it | medium | [issue #829](https://github.com/stellar/wallet-backend/issues/829), **open** | `filed` |
| F-0071 | wallet-backend | `operations.successful` comes from the operation's own result code, so operations coded `op_success` in a failed transaction are stored as successful (195 of 868 operations of pubnet ledger 65484612); executed by hand at `18db88f4`, no run compares it | medium | [issue #830](https://github.com/stellar/wallet-backend/issues/830), **open** | `filed` |
| F-0072 | wallet-backend | A `change_trust`, `set_options` or `manage_data` that leaves the entry unchanged still writes a `TRUSTLINE`, `SIGNATURE_THRESHOLD` or `DATA_ENTRY` `UPDATE` row; executed by hand at `18db88f4` on three pubnet ledgers, no run compares it | low | [issue #832](https://github.com/stellar/wallet-backend/issues/832), **open** | `filed` |
| F-0073 | wallet-backend | Entry changes in `upgradesProcessing` are never indexed, so a base-reserve increase leaves stale `num_subentries`, `minimum_balance` and liabilities (latent); executed by hand at `18db88f4` on a local stellar-core 30.0.0 upgrade ledger, no corpus entry holds one | low | [issue #833](https://github.com/stellar/wallet-backend/issues/833), **open** | `filed` |
| F-0039 | wallet-backend | An account created by a native Stellar Asset Contract transfer (CAP-73) produces no `account_created`: replay `dropped · partial` at `e967ce8b` and again at `3e22515a`, `18db88f4` and `f0c00cf5` on the four variants of `cap-0073/native-sac-transfer-creates-account-local-twins` and on the stellar-core golden `cap-0073/native-sac-transfer-creates-account`, both inputs | medium | [issue #804](https://github.com/stellar/wallet-backend/issues/804), **open** | `filed` |
| F-0040 | wallet-backend | A pre-auth-tx signer removed by a failed transaction (CAP-28) produces no `signer_removed`: replay `dropped · partial` at `e967ce8b` and again at `3e22515a`, `18db88f4` and `f0c00cf5` on the four variants of `cap-0028/pre-auth-signer-removed-on-failed-tx`, both inputs | medium | [issue #805](https://github.com/stellar/wallet-backend/issues/805), **open** | `filed` |
| F-0069 | wallet-backend | A pool-share trustline that stellar-core removes when an AllowTrust or SetTrustLineFlags revocation redeems the holder's pool shares (CAP-38) gets no `TRUSTLINE` `REMOVE`: replay `dropped · partial` at `3e22515a` and again at `18db88f4` and `f0c00cf5` on the four variants of `cap-0038/auth-revocation-redeems-pool-shares`, both inputs; by hand at `18db88f4` on pubnet ledger 50914934 (AllowTrust) | low | [issue #831](https://github.com/stellar/wallet-backend/issues/831), **open** | `filed` |
| F-0042 | wallet-backend | A contract deployed by a factory contract gets no deploy state change: replay `dropped · partial` at `e967ce8b` and again at `3e22515a`, `18db88f4` and `f0c00cf5` on `cap-0085/instance-with-external-ref-executable.testnet-4372196`, both inputs | low | [issue #806](https://github.com/stellar/wallet-backend/issues/806), **open** | `filed` |
| F-0044 | stellar-etl | A text memo is exported without a UTF-8 check, so invalid bytes become U+FFFD (XDR103 at `internal/transform/transaction.go:247`, suppressed with this record) | low | [issue #504](https://github.com/stellar/stellar-etl/issues/504), **open** | `filed` |
| F-0052 | wallet-backend | The SEP-41 classifier requires wallet-backend's exact parameter names, so tokens written to the SEP-41 interface (for example the corpus's testnet wasm `df3524d3…`) are never classified; executed by hand at `3e22515a`, no run compares it | medium | [issue #809](https://github.com/stellar/wallet-backend/issues/809), **open** | `filed` |
| F-0057 | wallet-backend | An AllowTrust between AUTHORIZED and AUTHORIZED_TO_MAINTAIN_LIABILITIES records a SET for the new flag and no CLEAR for the old one; the replay of `cap-0018/allow-trust-maintain-liabilities` passes because the entry states only the final flags; executed by hand (unit test) at `3e22515a` | low | [issue #811](https://github.com/stellar/wallet-backend/issues/811), **open** | `filed` |
| F-0067 | wallet-backend | A signer weight is narrowed to int16 with no range check before it is stored as `signer_weight_old` / `signer_weight_new`, so a weight above 32,767 (only a signer added before protocol 10 can hold one) is written wrapped: XDR402 at `internal/indexer/processors/effects.go:598` (`EffectsProcessor.parseSigners`) at `3e22515a`, `18db88f4` and `f0c00cf5`, suppressed with this record; the wrap was confirmed by reading the source, not by ingesting such a signer | low | [issue #825](https://github.com/stellar/wallet-backend/issues/825), **open** | `filed` |
| F-0055 | stellar-etl | `export_ledger_transaction` drops `PostTxApplyFeeChanges`, so Soroban fee refunds are missing from the row; executed by hand at v2.8.34 on pubnet ledger 59501299, no run compares this export's balance changes | low | [issue #511](https://github.com/stellar/stellar-etl/issues/511), **open** | `filed` |
| F-0054 | Horizon | `participantsForMeta` reads only the TransactionMeta v0 arm, so accounts changed only in operation meta are never transaction participants; executed by hand at v30.0.1 on pubnet ledger 59501299 (Horizon has no replay adapter in this kit) | low | [stellar-horizon#259](https://github.com/stellar/stellar-horizon/issues/259), **open** | `filed` |
| F-0074 | Horizon | A revocation that redeems pool shares from several liquidity pools (CAP-38) gets one `liquidity_pool_revoked` effect per operation, and that effect can cite another pool's claimable balance; executed by hand at v30.0.1 on pubnet ledger 55568683 (Horizon has no replay adapter in this kit) | medium | [stellar-horizon#266](https://github.com/stellar/stellar-horizon/issues/266), **open** | `filed` |
| F-0088 | Horizon | A pool-share trustline removed by an AllowTrust or SetTrustLineFlags revocation (CAP-38) gets no `trustline_removed` effect, the Horizon sibling of F-0069; executed by hand on pubnet ledgers 50914934 (AllowTrust, at v30.0.1 and main `01ba44a`) and 55568683, and on the four variants of `cap-0038/auth-revocation-redeems-pool-shares` (SetTrustLineFlags) (Horizon has no replay adapter in this kit) | low | [stellar-horizon#267](https://github.com/stellar/stellar-horizon/issues/267), **open** | `filed` |
| F-0038 | stellar-etl (cause in go-stellar-sdk) | `support/contractevents` parses only the four-topic SAC mint and clawback, so the CAP-67 three-topic mint gets no effect: replay `dropped · partial` at v2.8.34 (`evidence/stellar-etl/`) and again at v2.8.35 on `cap-0067/sac-mint-three-topics` | medium | [go-stellar-sdk#6043](https://github.com/stellar/go-stellar-sdk/issues/6043), **open** | `filed` |

### Replay rows reviewed as expected behaviour (`not-a-defect`)

| Record | Rows | Why it is not a defect |
|---|---|---|
| F-0062 | `cap-0015/fee-bump-inner-apply-time-failures.bad-seq` and `.no-account`, every variant, both inputs: one extra participant, the inner transaction's source | wallet-backend attributes every transaction, failed or not, to its envelope source (the inner source for a fee bump) so the submitter sees its own failed transaction; the corpus's stricter rule counts only a source whose sequence number moved. Declared `wont_fix` on both entries |
| F-0065 | `cap-0023/claimants-max-10`, `claim-predicate-depth-4`, `relative-predicate-stored-absolute`, `balance-id-from-muxed-source` and `cap-0035/claimable-balance-clawback-flag-ext-v1`, every variant, both inputs: claimants with no ledger change are participants | wallet-backend's own participant table counts accounts named in a successful operation's body, claimants among them; the corpus's stricter rule counts only accounts the meta shows affected. Declared `wont_fix` on the five entries |

### Linter reports reviewed as accepted sites (`not-a-defect`)

| Record | Site | Why it is not a defect |
|---|---|---|
| F-0001 | `contract_deploy.go`, top-level CreateContract (XDR301) | The deploy only succeeds with the deployer's authorization, so the deployer and contract ID are corroborated by the result |
| F-0002 | `sep41/processor.go` (XDR304) | The state change is keyed by the contract that emitted the event; the report was a linter false positive, fixed in the rule (XDR304 now follows builder chains), so the site is no longer reported |
| F-0003 | invoked contract of a successful transaction (XDR301) | Corroborated by the successful invocation |
| F-0011 | SAC metadata enrichment at `79ea2acd` and `6e5a5910` (XDR103) | Reachable at those commits, but best-effort: a failed write is logged and the rows keep their defaults, so it cannot halt ingestion; PR #695 made it unreachable and PR #723 removed it |
| F-0068 | `contract_deploy.go`, `walkInvocation` over authorization sub-invocations, at every commit of the before/after table (XDR201, a warning) | A hardening note: the walk has no explicit depth bound, but the go-xdr decoder stops at 1500 depth units, stellar-core admits an envelope only within its own decoder depth and Go stacks grow, and no level merges its children's results. The warning stays as advice to add an explicit cap and is not counted as a pipeline failure |

### Drafts

None for the pipelines: every pipeline finding above is already recorded upstream, and our rows add no reproduction
the open items (#746, #450, #488, #454) lack. [`findings/drafts/README.md`](drafts/README.md) lists every public draft.

## Status against the acceptance check

`make verify-findings` (development mode) passes with `make replay-full` and `make replay-etl-known` among the
checked runs: every failure row of these runs resolves to a record or to a pending entry. `make replay-etl-known`
replays the entries that declare a stellar-etl divergence at the pinned commit, so the stellar-etl rows F-0015 and
F-0038 rest on are in a required report. `make verify-findings-acceptance` passes only when every row resolves to a record in a terminal
state. At the current pins no row is pending finding review (every pending list is empty), so it passes; a row
that becomes pending turns it red again, because reporting a defect upstream needs a maintainer's approval of each draft.
