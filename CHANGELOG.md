# Changelog

All notable changes to the kit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning ([docs/maintenance.md](docs/maintenance.md)): the **corpus** is versioned `MAJOR.MINOR.PATCH`, where
MAJOR is the highest protocol it covers (30.x.y covers Protocol 30), MINOR adds entries or variants, and PATCH
corrects expectations or metadata. The manifest schema, the adapter protocol and the driver protocol carry their
own versions (`xcc.manifest.entry/v1`, `xcc.adapter/1`, `xcc.driver/1`). The bytes of a released entry never
change and a released entry is never removed; each release lists new entries, superseded entries, pin changes and
known-divergence changes.

## [Unreleased]

The first release, `30.0.0`: Protocol 30 coverage, built against the Protocol 30 stable stack pinned in
`pins.toml` (stellar-core 30.0.0, rs-stellar-xdr 30.0.0). The tag is not cut yet.

### Added

- **Corpus.** One entry per rare XDR shape, tagged with its CAPs and protocol: the bytes, the values a correct
  reader must produce, and where they came from. The manifest specification and JSON Schemas
  (`corpus/schema/`, entry schema `xcc.manifest.entry/v1`, with `validity` and bug-class `flags` per entry and
  variant), the entry-ID registry (`corpus/plan.json`), content-addressed blobs, decoded SEP-51 sidecars stored once
  per blob, chain indexes for multi-ledger scenarios, vendored public-lake objects and a history-archive bucket,
  and the flat entry index `corpus/index.json` (`xcc.index/v1`). Sources: local stellar-core scenarios on the
  testnet and mainnet passphrases, stellar-core's own goldens, public testnet and pubnet history, and flagged
  synthetic recipes (XDR strictness, depth, colliding map keys, SEP-23 strkey vectors, `api` vectors, contract
  specs). The CAP inventory (`corpus/caps.toml`) and the generated coverage report (`corpus/coverage.json`,
  `corpus/COVERAGE.md`) by CAP, by pattern and by XDR union arm, with every gap explained.
- **Generator.** `xdrcheck-corpus gen`: a pinned stellar-core release run offline with deterministic,
  label-derived keys; a scenario interpreter for classic and Soroban transactions (Stellar Asset Contract calls,
  custom contracts with offline simulation, fixed-salt settings upgrades, controlled apply order); `gen --check`
  regeneration compared with stellar-core's golden-comparison normalisation; the Soroban test contracts in
  `contracts/` (shape emitter, token shapes, custom accounts).
- **Oracle and intake.** `xdrcheck-corpus verify`: schema, IDs, hashes, byte and XDR-JSON round trip,
  negative-entry refusal, sidecars, pinpoints, golden import (AG-1), decoder consistency (AG-3), golden mirror
  (AG-4, in two tiers: a golden transaction of the same shape, or a golden operation for each operation), the reference extractor and orphan checks. Intake and tooling: `capture`, `mine`, `refetch`,
  `fetch-goldens`, `import-golden`, `synth`, `slice`, `render`, `extract`, `normalise`, `skeleton`,
  `chain-index`, `coverage`, `index`, `guide-table`, `guide-claims`.
- **Replay harness.** `xdrcheck serve` and `xdrcheck replay`: the corpus served to an unmodified indexer as a
  SEP-54 data lake (on disk or behind a logged S3-compatible store) or a mock stellar-rpc `getLedgers`; single,
  chain and stream units; the expectation matcher (with an adapter's declared out-of-scope facts), the
  pass/mishandled/dropped classifier, known-divergence assertions and windowed observation for bounded memory.
  The adapter protocol `xcc.adapter/1` with `--selftest`, and the public Go package `adapterkit`.
- **Adapters.** wallet-backend (the reference adapter: builds the indexer at any commit and reproduces
  wallet-backend#729, #731 and #716 on the pre-fix commits), stellar-etl (through a GCS emulator), the baseline
  indexer (the complete example, every observation kind), the `minimal` Go template and its TypeScript twin
  (`examples/adapter-ts`), the `demo` adapter, and the seeded-bug indexers behind `make harness-selftest`.
- **Service rigs and real-ledger replay.** wallet-backend, stellar-etl and Horizon built at a commit and fed real
  ledgers from a lake directory, with their stored rows exported; `xdrcheck replay --target` for SDK sweeps and
  rigs at any version; `xdrcheck runs`, `xdrcheck repro` (self-contained result bundles) and `xdrcheck xcheck`
  (the same transactions through two or more targets or versions).
- **Judge.** `xdrcheck-judge`: indexer-neutral facts computed from each ledger's own entry changes, with a
  conservation self-check, and verdicts on a pipeline's exported rows with a scope file per target.
- **Conformance runner.** `xdrcheck conform` with the driver protocol `xcc.driver/1`, the verdict engine, the
  divergence matrix, sibling grouping across SDKs, `conform diff` between two runs, and bulk-tier runs. Driver
  columns, one per pinned version: js-stellar-sdk 16.3.0 to 17.4.0, go-stellar-sdk v0.7.1 to v0.9.0 (and their
  view paths), rs-stellar-xdr 28.0.0 to 30.0.0 under two decode profiles, the XDR-JSON converter, the Soroban
  contract-spec readers, Python stellar-sdk 17.0.x, and stellar-core's own decoder as the reference column.
  The rebuild fact (L1: the parsed transaction rebuilt through the SDK's own builder), the native error fact (L3:
  an `scvError` value converted to native) and XDR-JSON converter values compared with the manifest exactly as JSON.
  The sibling matrix (`findings/SIBLINGS.md`): each SDK defect class against every SDK line the runner drives.
  `xdrcheck mutate`: structure-aware mutants of corpus values through every reader.
- **SDK loaders.** Corpus readers for an SDK's own tests in Go, Rust, Python and npm (`packages/`), with
  expected-failure lists, and the SDK CI recipes in `examples/sdk-ci/`.
- **Linter.** `xdrlint` for Go ingestion code: rules XDR000, XDR101 to XDR103, XDR105, XDR201 to XDR207, XDR301 to
  XDR304 and XDR401 to XDR406; suppressions with reasons, profiles, SARIF and `xcc.report/v1` output, a
  golangci-lint module plugin, generated rule pages, expected lists frozen per pinned commit, the before/after
  table over the public wallet-backend fixes, and a clean-run check on pinned wallet-backend and stellar-etl
  commits.
- **Guide.** The indexer-hardening guide for developers.stellar.org (`guide/`) with its checklist, a
  field-by-field table generated from the corpus, and a claim-to-source map for every normative sentence, checked
  against the documentation repository's own checks. The review package for a core or platform engineer
  (`guide/review/`: the claims as a table with links to every cited line, the highest-risk claims, what rests on
  code reading alone, and the review request).
- **Findings.** Finding records (`xcc.finding/v1`) for defects filed upstream, duplicates of public upstream
  items and reviewed non-defects, with the reports `findings/REPORT-pipelines.md` and `findings/REPORT-sdks.md`;
  `xdrcheck findings` (`check`, `new`, `issue`, `list`) in development and acceptance modes; committed pending
  lists that hold row keys only, with `since` dates and age limits; the required run set
  (`findings/required-runs.d/`); and the private-overlay mechanism for defects not yet reported
  ([SECURITY.md](SECURITY.md)).
- **Acceptance checks.** `make verify-replay` over the pinned wallet-backend commits for #729, #731 and #716;
  `make verify-memory` with its negative control; `xdrcheck conform sdk-regression` for js-stellar-sdk #1766, #1785 and
  #1789; `make replay-full`, the whole corpus against wallet-backend at its pinned current commit on both inputs.
- **Reports and acceptance.** `xdrcheck report` (`acceptance`, `redact`, `diff`), the acceptance table with one row
  per check read from that check's own verdict artefact, and the hand-run reproductions under `evidence/`.
- **Data and lookup.** `xdrcheck-corpus scan` (shape tokens of every ledger, grammar `xcc.shape/v1`, census and
  locate index), `xdrcheck-tagger` (transactions holding values readers get wrong), `xdrcheck data`,
  `xdrcheck find` and `xdrcheck entry` (list entries by CAP or ID glob, or show one with its decoded values).
- **Results data and sites.** `evidence/mainnet-scan/`: the pubnet scan's integrity check and shape census summary,
  with each entry's mainnet prevalence. `evidence/results/`: generated results files (findings, known upstream defects,
  conformance matrix, sibling matrix, replay summary) with `make results` and `make results-check`. The
  documentation site's results pages, a static dashboard (`apps/dashboard/`) and a landing page (`apps/landing/`),
  all read from those files.
- **XDR watch.** `xdrcheck xdr`: diff XDR definition sets, watch upstream, generate driver ceilings and candidate
  rows; `xdrcheck pins check` and the latest-version canary.
- **Distribution.** The GitHub Action (`action.yml`: replay, conform or lint from a pinned release); `make release`
  (the corpus release archive, built twice and verified offline, and the npm package), per-platform binaries,
  `SHA256SUMS`, provenance and a container image, through `release.yml`.
- **Infrastructure and CI.** `pins.toml` as the single list of versions; `make fetch` as the only networked step,
  `OFFLINE=1` and memory wrappers; CI in two tiers, the pull-request workflow (`pr.yml`, the fast forms
  of the slow checks) and the full CI on main (`full.yml`, every check at full size; on a release tag, the acceptance
  run), each job one `make` target, with `make verify-pr`, `make verify` and `make ci-local` (jobs run as on a cold
  hosted runner) to run them locally; hand-dispatched nightly, watch and next-protocol workflows, read-only by default (a job may write
  only the scopes `.github/write-jobs.toml` grants it) and checked by `scripts/ci/check-workflows.sh`; repository
  checks for schemas, IDs, fields, guide claims, public-tree hygiene and hard-coded repository names.
- **Documentation.** README, the documentation site (`apps/docs`, generated reference pages from `docs/`),
  architecture overview, adapter, driver and conformance protocols, replay harness, command-line reference
  generated from the tools' help, the maintenance and upgrade plan (maintainer, period, protocol-upgrade
  procedure), threat model, infrastructure and decentralisation statements, contribution guide and security
  policy.
