# Threat model and monitoring plan

For SDK maintainers and indexer operators who run the corpus or the tools in their own CI. It lists what could go
wrong with the kit's data and code, which control covers each threat and where that control lives, what risk is
left, and what is watched after a release.

## Scope

The kit is an offline test kit: command-line tools, data files and CI workflows. It runs no service, holds no
user data and touches no funds. What needs protecting:

1. **The integrity of the corpus and its expected values.** A wrong byte or a wrong expectation makes a correct
   reader fail or lets a buggy one pass.
2. **The integrity of what downstream CI executes.** Other projects run the corpus, and some run the tools, in
   their own CI.
3. **The confidentiality of unreported security defects** the kit finds in other projects, until those projects
   have been told.

## Threats and mitigations (STRIDE)

Each mitigation names where it is implemented or checked. Residual risk is stated plainly.

| Category | Threat | Mitigation (where) | Residual risk |
|---|---|---|---|
| Spoofing | A look-alike repository or package distributes a tampered corpus | Every blob is named by its sha256 and the manifest records `sha256` and `byte_length` per variant; release archives carry checksums (`corpus.json` `checksums`); `xdrcheck-corpus verify --checks hashes` re-checks every blob | A consumer who skips verification |
| Tampering | A contribution changes bytes or expectations so that a real bug passes or a correct reader fails | Released bytes are immutable ([maintenance.md §9](maintenance.md)); every pull request re-hashes every blob, sidecar and vendored object (`make repo-checks`, `make verify-corpus`); golden entries must equal the named frame of the file at the pinned stellar-core tag (`ag1`); `local-core` entries must regenerate (`make verify-generate`); expectations must agree with the reference extractor (`extractor` check); a reviewer who did not write the entry answers the review checklist ([authoring-entries.md §6](authoring-entries.md)) | **Expectations are the weak point.** Bytes are protected by hashes; a wrong hand-curated expectation on a history entry is checked only by the reference extractor and a reviewer. Partial mitigations: pinpoints written independently of the extractor, and the fact that a wrong expectation shows up as the same divergence in every SDK column at once |
| Tampering | Supply chain: a pinned SDK, image, package or download is replaced upstream | Every version in `pins.toml`, images by digest, downloads by sha256, lock files with integrity hashes; `xdrcheck pins check` fails on any version named elsewhere; npm installs run with `--ignore-scripts`; third-party CI actions pinned by commit; `make fetch` verifies hashes before anything is used | A compromised upstream release that is then pinned on purpose; every pin move carries a differential report for review |
| Repudiation | Dispute over what a run observed | Reports (`xcc.report/v1`) record tool versions, pins, entry hashes and the observed values next to the expected ones; CI uploads them as artefacts | — |
| Information disclosure | A security-relevant defect in another project leaks before that project can fix it — through a draft, a corpus entry, an annotation, or because public CI would have to either list the divergence or go red | The report-before-release rule and the private overlay ([SECURITY.md](../SECURITY.md)): withheld material lives outside the repository and is merged in memory only with `--overlay`; public CI never loads it; public pending lists carry row keys only; overlay finding IDs come from a separate range; pin moves and new linter rules are tried privately first; scheduled jobs that track unpinned upstream releases never gate and publish counts only | Misjudging severity (the default is to embargo when unsure); a defect anyone can find by running the already-public corpus against a new upstream release, which no embargo of ours can hide — only prompt reporting helps |
| Information disclosure | Secrets in the repository or CI | No secret is needed by any job; workflows run with `permissions: contents: read` and `persist-credentials: false`; `scripts/py/check_public.py` (in `make repo-checks`) rejects machine paths, private names and internal references | — |
| Denial of service | The corpus contains, on purpose, inputs built to stress readers (deep nesting, large length prefixes, very large ledgers). Run in another project's CI they can exhaust memory, stack or time | The manifest flags negative entries with a reason class; release archives keep stress entries in a separate directory, out of the default run ([release.md](release.md)); the kit's own runs decode with explicit limits and run every driver and adapter under memory and time limits ([ci-isolation.md](ci-isolation.md), `xdrcheck conform run --memory-max`, `xdrcheck replay --memory-max`); stress entries run in a fresh driver process each | A consumer who opts in to the stress entries and decodes them without limits — which is the failure the corpus exists to expose |
| Elevation of privilege | Code execution in CI through a contribution | Scenario files and recipes are declarative data validated against schemas. Three things that run are code: the test contracts' wasm (executed by stellar-core on a local chain), the adapters and the drivers; third-party SDKs and the pipelines under test are code too. Controls: contracts are built reproducibly from reviewed source and the build fails if the wasm hash differs (`contracts/build.sh`); drivers and adapters change only through reviewed pull requests; pull requests from forks get no secrets or write token; every run step executes offline (`OFFLINE=1`) under resource limits | A reviewed-in malicious change; a compromised pinned package executing inside the sandbox, where it can reach only the checkout |
| Misuse | The corpus publishes transaction envelopes signed under the public network passphrase with keys anyone can derive; they could be mistaken for real transactions or replayed | They come from a private standalone network and are labelled as `local-core` in the manifest. They cannot be replayed on the public network because of sequence numbers: an account created on the local chain at ledger L has a sequence number near `L << 32`, while every account on the public network today was created tens of millions of ledgers later and its sequence number only rises, so the envelopes fail with a bad sequence number. The README warns never to fund a label-derived account | (1) The root account's key derives from the network passphrase, so on the real networks it is the genesis account; scenarios use root only for initial funding. (2) After a testnet reset sequence numbers start again, so testnet-passphrase envelopes may become valid on the new testnet for a while; only test funds are involved. (3) Anyone who funds a label-derived account on a real network can lose those funds to anyone else |
| Licence | Vendored third-party bytes and code are redistributed | Lake objects and SEP vectors are public data; stellar-core goldens and settings are Apache-2.0; each source is listed in `NOTICE` and its provenance recorded per entry | — |

## Monitoring plan

There is no production system to monitor: no uptime, no user metrics. What is monitored is the corpus's integrity,
upstream drift and the state of findings. "In place" means the job or check exists and runs today.

A nightly failure turns the scheduled run red, writes the failed job and the command to rerun it to the run's job
summary, and GitHub notifies the workflow's owner. No secret or external service is involved. Opening an issue from
a failure is a maintainer's step.

| What | How | Response | Status |
|---|---|---|---|
| Corpus integrity | Every pull request: hashes, round trip, golden import, extractor agreement (`make verify-static`, `make verify-corpus`) | A mismatch blocks the merge | In place |
| Reproducibility | Every pull request: the scenario subset in `corpus/scenarios/pr.list` (`make verify-generate`); nightly (job N1, `nightly-goldens.yml`): every scenario (`make nightly-regenerate`) | A regeneration difference blocks the merge or turns the nightly run red | In place |
| Pinned downloads still available | Nightly: `make fetch` from cold caches, every artefact verified by hash (job N8, `nightly-goldens.yml`) | A missing or changed artefact turns the nightly run red | In place |
| Golden agreement with stellar-core's own test binary | Nightly: `make verify-goldens-nightly` (jobs N2 and N3 in `nightly-goldens.yml`, `scripts/nightly/goldens.sh`) | A failure turns the nightly run red | In place |
| History sources | `xdrcheck-corpus refetch`: every vendored lake object fetched again and compared; nightly in job N8 (`make nightly-refetch`, `nightly-goldens.yml`) | Perishable objects reported, others fail | In place |
| Upstream drift | Early-warning decode of stellar-core's next-protocol goldens (N6, `make nightly-early-warning`, `nightly-goldens.yml`); the watch list ([maintenance.md §6](maintenance.md)) | A watch-log entry; a pin-move pull request | In place |
| Findings | Each filed issue or private report tracked to closure; when a fix ships, the known-divergence range is closed and the next run asserts the fix | A status update (public findings only) | In place (`xdrcheck findings list`) |
| Embargoes | Each embargoed finding has a report date and an end date; the private run lists those within 14 days of their end | The maintainers extend at the affected maintainer's request, or lift and publish | Process in place; private run kept outside this repository |
