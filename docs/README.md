# Documentation

Start with the [README](../README.md): what XDRCheck is, the demo, and the first command for each kind of user.
This page lists every document, grouped by who needs it.

## Indexer authors

| Page | Contents |
|---|---|
| [go/adapters/minimal](../go/adapters/minimal/README.md) | The adapter template for Go indexers: run it, copy it, fill in the marked places |
| [examples/adapter-ts](../examples/adapter-ts/README.md) | The same template in TypeScript, for indexers in any other language |
| [adapter-protocol.md](adapter-protocol.md) | The adapter interface `xcc.adapter/1`; §8 is the step-by-step for writing an adapter |
| [replay-harness.md](replay-harness.md) | How the harness serves ledgers, judges what the indexer stored, and classifies each entry |
| [go/adapters/baseline](../go/adapters/baseline/README.md) | The complete example adapter: a separate indexer process with every observation kind |
| [github-action.md](github-action.md) | Running replay, conform or lint in GitHub Actions from a pinned release, with expected-failure lists |
| [lint/README.md](../lint/README.md), [lint/docs/](../lint/docs/README.md) | `xdrlint` for Go indexers: install, run, read a diagnostic, suppress with a reason; one page per rule |
| [guide/](../guide/README.md) | The indexer-hardening guide: which fields stellar-core validates, depth and size caps, participants from meta, muxed and signed-payload addresses, a checklist |

## SDK maintainers

| Page | Contents |
|---|---|
| [use-in-sdk-ci.md](use-in-sdk-ci.md) | The corpus in an SDK's own CI: loaders for Go, Rust, Python and npm, recipes, expected-failure lists, testing an unreleased branch |
| [protocol-upgrades-for-sdks.md](protocol-upgrades-for-sdks.md) | Testing a new protocol's shapes before the SDK release |
| [conformance-protocol.md](conformance-protocol.md) | The conformance runner's vocabulary, levels and judging rules |
| [driver-protocol.md](driver-protocol.md), [drivers/README.md](../drivers/README.md) | Writing a driver that runs the corpus through one SDK version; the driver directories |
| [release.md](release.md) | The release archive: layout, checksums, provenance, reproducibility, prebuilt binaries |

## Replaying real ledgers (any target, any version)

| Page | Contents |
|---|---|
| [replay.md](replay.md) | `xdrcheck replay --target`: an SDK or pipeline at any version against ledgers, transactions, a set, a CAP or a known issue |
| [run-directory.md](run-directory.md) | The run directory every replay writes (`manifest.json`, `verdicts.jsonl`, `clusters.json`, `summary.json`), dispositions, `xdrcheck runs` |
| [repro.md](repro.md) | `xdrcheck repro`: a bundle that reproduces one result on a clean machine with one command, and the stellar-core check of its input |
| [find.md](find.md) | `xdrcheck find`: from a token, class, value tag, CAP, linter assumption or operation type to example transactions |
| [data.md](data.md) | `xdrcheck data`: the dataset manifest, named sets, ledger downloads, keeping the data current |
| [xcheck.md](xcheck.md) | `xdrcheck xcheck`: the same transactions through two or more targets, with the normalisation rules |
| [ci-replay.md](ci-replay.md) | A CI job that pins a dataset version and replays its control set through an SDK branch |

## Corpus authors and protocol engineers

| Page | Contents |
|---|---|
| [authoring-entries.md](authoring-entries.md) | Adding or changing an entry: sources, expected values, scenarios, the review checklist |
| [manifest.md](manifest.md) | The corpus manifest specification |
| [entry-ids.md](entry-ids.md) | Entry IDs and the registry |
| [mutation.md](mutation.md) | `xdrcheck mutate`: new inputs made by mutating corpus values, run through every reader |
| [corpus/COVERAGE.md](../corpus/COVERAGE.md) | Coverage by CAP and by XDR union arm |

## Kit maintainers and reviewers

| Page | Contents |
|---|---|
| [maintenance.md](maintenance.md) | Versioning, releases, the protocol-upgrade procedure, who maintains the kit and for how long |
| [architecture.md](architecture.md) | Components, data flow, diagrams, languages and layout |
| [cli.md](cli.md) | Every command and `make` target |
| [ci-isolation.md](ci-isolation.md) | How "offline" and "bounded memory" are enforced |
| [ci-timings.md](ci-timings.md) | Measured run time and disk use of every `make` target |
| [acceptance.md](acceptance.md) | Every acceptance check, its pass condition, its `make` target and its evidence |
| [evidence/mainnet-scan](../evidence/mainnet-scan/README.md) | The scan of pubnet history: what was checked on every ledger and the result, the shape census, per-entry prevalence, what is not claimed |
| [evidence/results](../evidence/results/README.md) | The generated results data: SDK conformance matrix, sibling matrix of SDK defect classes, replay summary, findings, known upstream defects |
| [findings/REPORT-pipelines.md](../findings/REPORT-pipelines.md), [findings/REPORT-sdks.md](../findings/REPORT-sdks.md) | The findings reports, one entry per finding |
| [threat-model.md](threat-model.md) | Threat model and monitoring plan |
| [statements.md](statements.md) | Infrastructure, user tracking and decentralisation |
| [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), [CHANGELOG.md](../CHANGELOG.md) | Contributing; reporting a vulnerability; changes |

## Repository layout

| Path | What |
|---|---|
| `corpus/` | manifest entries, content-addressed blobs, decoded sidecars, chain indexes, vendored lake objects, scenarios, recipes, schemas, the field table source, coverage |
| `crates/` | Rust: `xdrcheck-corpus` and its libraries (`xdrcheck-xdr`, `xdrcheck-meta`, `xdrcheck-gen`), `xdrcheck-mutate`, the judge (`xdrcheck-judge`) and the value tagger (`xdrcheck-tagger`) |
| `go/` | Go: `xdrcheck` (ledger server, replay harness, target and rig replays, run directories, dataset, conformance orchestrator, findings, reports, pins), the public `adapterkit` package and the adapters |
| `lint/` | Go: `xdrlint`, its rules, fixtures and rule pages |
| `drivers/` | conformance drivers, one directory per pinned SDK version |
| `packages/` | corpus loaders for SDK tests: Go, Rust, Python, npm |
| `examples/` | the TypeScript adapter and the SDK CI recipes |
| `action/`, `action.yml` | the GitHub Action |
| `contracts/` | Soroban test contracts the generator deploys, built reproducibly from source |
| `guide/` | the indexer-hardening guide (MDX) and its claim-to-source map |
| `findings/` | finding records and issue drafts |
| `evidence/` | hand-run reproductions the acceptance checks are built on, with scripts and transcripts; the mainnet scan's integrity check and component and whole-transaction shape census (`evidence/mainnet-scan/`); the generated results data (`evidence/results/`) |
| `apps/` | the documentation site (`apps/docs`, Mintlify, its results pages generated from `evidence/`), the dashboard (`apps/dashboard`) and the landing page (`apps/landing`), static and not deployed from here |
| `scripts/` | fetch, offline and memory wrappers, repository checks, CI helpers |
| `bin/` | links to the built tools (`make build`) |
