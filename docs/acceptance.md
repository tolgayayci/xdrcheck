# Acceptance checks

This page is the reference for the kit's acceptance checks: the checks that show the kit itself works. Each part of
the kit has one or more checks; each check is one `make` target that exits 0 when the check holds and non-zero when
it does not, and the files it writes are the evidence. To use the kit you do not need this page: start from the
[README](../README.md).

## Before you run them

Requirements are in the README ([Requirements](../README.md#requirements), the full-kit row). Then:

```sh
mise install            # Go, Node, Python and Java at the versions in mise.toml; rustup reads rust-toolchain.toml
make toolchain          # check them against pins.toml
make fetch              # the only networked step: every dependency, pinned and hash-verified
make build              # every tool, linked into ./bin
make repo-checks        # schemas, corpus data, entry IDs, the public-tree scan (needs no build)
```

Every version the kit builds against or tests is in [`pins.toml`](../pins.toml). Any `make` target runs without
the network once `make fetch` has run; add `OFFLINE=1` to enforce it (the run step then executes in a network
namespace with loopback only; [ci-isolation.md](ci-isolation.md)). [ci-timings.md](ci-timings.md) gives the
measured time of each target.

## The checks

Each row is one command. It exits 0 when the check holds and non-zero when it does not; the files it writes are
the evidence. The check IDs (`roundtrip`, `golden-agreement`, …) are the ones the acceptance table uses. Two checks
hold one case per known upstream defect, and the acceptance table may give each case its own row
(`replay-regression/wallet-backend-729`): `replay-regression` and `sdk-regression`.

| Part | Check | Command | Passes when | Evidence written |
|---|---|---|---|---|
| Corpus and generator | `roundtrip`: entries round-trip through rs-stellar-xdr | `make verify-corpus OFFLINE=1` | every positive entry decodes with explicit limits and re-encodes byte-exactly, XDR-JSON included; every negative entry is refused for its declared reason; sidecars, pinpoints and the reference extractor agree with the manifest | `reports/corpus-verify.json` |
| | `golden-agreement`: entries agree with stellar-core's `--check-lcm` goldens | `make verify-corpus OFFLINE=1` (pinned import, decoder consistency, and the golden mirror AG-4 against the cached goldens from `make fetch`); `make verify-goldens-nightly` (stellar-core's own test binary accepts the goldens; whole golden set) | every golden entry equals the named frame of the named golden file at the pinned tag; each local-core entry that `corpus/mirrors.json` maps matches a golden transaction on its own bytes (the transaction tier: the same structural skeleton and shape tokens), and only these count as mapped; for an unmapped entry where every operation has a golden operation of the same shape (the operation tier, listed under `operations`), that is checked and reported separately and is not agreement of the entry; every unmapped entry is listed there with the reason it matches no golden transaction | `reports/corpus-verify.json`, `reports/corpus-verify-ag4.json`, `reports-nightly/` |
| | Generation is reproducible on both passphrases, offline | `make verify-generate` | regenerated ledgers have the same header and transaction hashes and the same bytes after stellar-core's golden normalisation | command output |
| | Per-CAP coverage manifest | `make verify-coverage OFFLINE=1` | the committed coverage report is current and every reader-visible CAP has entries or a stated reason | [`corpus/COVERAGE.md`](../corpus/COVERAGE.md) |
| Replay harness and reference adapter | `replay-regression` (cases `wallet-backend-729`, `wallet-backend-731`, `wallet-backend-716`): the reference adapter reproduces wallet-backend#729, #731 and #716 on pre-fix commits and passes on the fixed ones | `make verify-replay OFFLINE=1` | each pre-fix commit gives exactly the declared class (halt; partial drop; wrong value) and every fixed commit and the current commit pass | `reports/replay-regression/` |
| | Every result class is reachable and correct | `make harness-selftest OFFLINE=1` | each seeded-bug indexer lands in its documented class; the correct baseline passes everything | `reports/selftest/` |
| | No unbounded memory growth on a full corpus | `make verify-memory OFFLINE=1` | the four memory tests pass and the negative control fails | `reports/memory/` |
| Linter | `lint-fixtures`: flags seeded violations | `make lint-fixtures OFFLINE=1` | every rule's fixtures report exactly the seeded violations | `reports/lint-fixtures.jsonl` (`go test -json`) |
| | `lint-current`: runs clean on current wallet-backend | `make lint-wallet-backend OFFLINE=1` (also `make lint-before-after`, `make lint-selftest`) | the summary's `clean` is true and its `clean_statement` says why or why not: clean means xdrlint exits 0 with the shipped profile after the suppressions, with no unsuppressed error left (a report pending finding review is not excused if it is an error; a pending warning does not make the run unclean and still counts in `findings-linked`); the run also checks that every report is accounted for by the frozen lists (compared by count) and every suppression names its line or anchor, a reason and a finding record | `reports/lint-wallet-backend/`, `reports/lint-wallet-backend.summary.json` (`clean`, `clean_statement`), `reports/lint-wallet-backend.verdict.json` (the outcome without sites, which CI uploads) |
| Guide | `guide-table`: the field-by-field table agrees with the manifest | `make verify-guide OFFLINE=1` | the committed table equals the one generated from `corpus/fields.yaml` and the manifest; every normative sentence has a sourced claim record | `reports/guide-table.json` (one row per entry that cites the table), command output |
| | `guide-review`: publication gated on review by a core or platform engineer | `make acceptance-report` (row `guide-review`) | every claim in [`guide/claims.yaml`](../guide/claims.yaml) is `confirmed` or `corrected` by the reviewer | `reports/acceptance.md` |
| Conformance runner | `sdk-regression` (cases `js-1766`, `js-1785`, `js-1789`): reproduces js-stellar-sdk#1766, #1785 and #1789 on pre-fix tags | `make verify-conformance OFFLINE=1` | each pre-fix release shows its declared divergence and the next release conforms; every divergence in the JS, Go, Rust and Python matrix is declared on its entry (cells pending finding review are listed and counted, and fail in acceptance mode) | `reports/conformance/` (`matrix.md`, `cross-sdk.md`, `sdk-regression.json`) |
| Findings | `findings-linked`: every failure maps to a finding record | `make verify-findings-acceptance` (after the checks above, over `reports/`, including `make replay-full`, `make replay-etl-known` and `make verify-conformance-public`) | every failure row carries a finding ID, every record is `filed`, `duplicate-of` or `not-a-defect`, and no record is orphaned (the exemptions of [findings/README.md](../findings/README.md#records-no-run-can-refer-to) are listed in the row) | [`findings/`](../findings/README.md); `reports/<lint target>.tally.json` (what the check takes from each linter report, without sites, which CI uploads when it withholds the report) |
| Test suite and CI | unit tests of every component | `make test OFFLINE=1` | all pass | [`.github/workflows/`](../.github/workflows/) |

The `golden-agreement` row names the golden checks AG-1 to AG-4; [architecture.md](architecture.md) defines each one.

Everything at once:

```sh
make verify OFFLINE=1        # every check at full size, then reports/acceptance.md
make verify-pr OFFLINE=1     # the pull-request CI's fast forms, then its acceptance table
make verify-acceptance       # the same with the findings check in acceptance mode
```

The full CI (`.github/workflows/full.yml`, run by hand and on release tags) runs every target of
`make verify-acceptance`, one job each; its run-summary job runs `make acceptance-report` over all of their
reports and uploads the table with the run's reports (the job summary shows only each job's result and key
numbers), so `findings-linked` is computed there. Its findings-check-strict job runs `make verify-findings-acceptance`: on a
release tag it fails while any row awaits finding review, so a release cannot be cut while `findings-linked` is not met; on main
and by hand it runs with `PENDING_OK=1` (`xdrcheck findings check --pending-ok`), which passes with the warning
"N failure rows have no linked issue" when those rows are the only failure, and fails on anything else. `findings-linked` itself and the acceptance table are the same either way. `make results-acceptance` turns a local run's table
into [`evidence/results/acceptance.json`](../evidence/results/README.md#acceptancejson).

## The acceptance table

`make acceptance-report` (part of both) writes `reports/acceptance.md`: one row per check with its status and the
artefact that shows it. `make help` lists every target; [cli.md](cli.md) documents every command.

Each row of the table is read from that check's own verdict artefact (the evidence column above; `lint-current` from
the pinned current wallet-backend commit's lint summary, `sdk-regression` from `sdk-regression.json`, `findings-linked` from the acceptance-mode
findings check itself). A status is one of:

| Status | Meaning |
|---|---|
| `met` | the artefact shows the check holds |
| `not met` | anything is open, including what waits on people outside the build; the row names that action (rows pending finding review: filing waits on the maintainers' approval of each draft; `guide-review`: the guide's external review) and keeps it apart from what the build must fix |
| `missing` | a report the check needs is not under `reports/` |
| `not recorded` | the check's make target was not run against these reports |
| `proven in full CI` | only in the pull-request CI's table (`make acceptance-report-pr`): what that run checked holds, and the check's other runs are made only by the full CI (`.github/workflows/full.yml`), whose table is the check's verdict; a row that fails or lacks a report of its own pull-request run stays `not met` or `missing` |

A row that a committed, description-free pending list names (`findings/pending/*.json`,
`lint/expected/*/*.pending.json`) is marked `pending` in its report by the tool that wrote it, not `unexpected`.
Pending is not passing: such rows keep their check `not met` (for `lint-current` only a pending error does; a
pending warning does not make the run unclean and still counts in `findings-linked`), and the table says they wait on the maintainers'
approval of each draft. A pending entry whose row no longer fails is stale and fails the findings check.

Two checks depend on people outside the build, and the acceptance table says so instead of hiding it: `guide-review`
needs the guide's reviewer, and `findings-linked` in acceptance mode needs each finding draft to be approved and filed by a
person. Linter errors pending finding review at the pinned current commit keep `lint-current` open for the same reason.
`make verify-findings` (development mode) is the per-pull-request form and allows drafts.

## Other parts and where they are

| Part | Where |
|---|---|
| Documented adapter interface | [adapter-protocol.md](adapter-protocol.md), [replay-harness.md](replay-harness.md) |
| Indexer-hardening guide and its checklist | [`guide/`](../guide/README.md) |
| Findings reports | [`findings/`](../findings/README.md) |
| Test suite and CI configuration | `make test`, [`.github/workflows/`](../.github/workflows/), [ci-isolation.md](ci-isolation.md) |
| Release | [release.md](release.md), [github-action.md](github-action.md), [use-in-sdk-ci.md](use-in-sdk-ci.md) |
| Maintenance across protocol upgrades | [maintenance.md](maintenance.md) |
| Infrastructure and user tracking | [statements.md](statements.md), [threat-model.md](threat-model.md) |

## Not built yet

Not built as of release `30.0.0` ([CHANGELOG.md](../CHANGELOG.md)):
serving the lake layout over a GCS API from `xdrcheck` (the stellar-etl adapter runs its own emulator) and `xdrcheck replay
--resume`. `make verify-goldens-nightly`
needs the stellar-core test image and runs by hand only (`.github/workflows/nightly-goldens.yml`): its golden emission
(AG-2) alone took 20 minutes on 8 CPUs, too long for the full CI on 2-CPU runners.
