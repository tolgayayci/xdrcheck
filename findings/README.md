# Findings

One directory per finding: `findings/<id>/finding.json` (schema `xcc.finding/v1`,
[`corpus/schema/finding-record.schema.json`](../corpus/schema/finding-record.schema.json)) and, once drafted,
the issue body next to it (`issue-<project>.md`). A finding is one defect in one target project; the same defect
in several projects is several records that share a `defect_group` and list each other in `siblings`.

The records here describe defects that are already public upstream, and the linter's accepted sites:
`duplicate-of` records for the known divergences of the corpus that reference a public issue, pull request or
advisory (each divergence names its record in its `finding` field), and for the pre-fix side of the public
wallet-backend fixes in the linter's before/after table; `not-a-defect` records for the linter reports that were
reviewed as accepted sites or as the linter's own limitation, and for the conformance refusals that come from the
kit's own decode profile rather than from the library, that match stellar-core's own reading, or that follow
the XDR definitions older than v30 a version was built on, and for replay rows where a pipeline does by design what
the corpus's stricter rule does not expect (F-0062, F-0065); and `filed` records
for the defects this project's runs found and the maintainers reported upstream (F-0034,
F-0036 to F-0040, F-0042 to F-0046, F-0052 to F-0061, F-0063, F-0064, F-0066, F-0067, F-0069 to F-0085, F-0088 to F-0093), each citing its public issue in `upstream`. `xdrcheck findings list` prints them.

## Reports and drafts

- [`REPORT-pipelines.md`](REPORT-pipelines.md): what the corpus found in wallet-backend and stellar-etl (replay and
  linter), and where each finding stands upstream.
- [`REPORT-sdks.md`](REPORT-sdks.md): the SDK and XDR-library divergences of the conformance runner, with the
  same defect side by side across SDKs.
- [`drafts/README.md`](drafts/README.md): every draft issue or comment in this tree and the command that would send
  it (printed, never run).

## IDs

Public records are numbered `F-0001`, `F-0002`, … in order. IDs are never reused, so a gap left by a record
removed from the public tree is not filled (F-0031 is one). Records created in the private overlay take IDs
above `F-5000` (`xdrcheck findings new --overlay` picks the next one), so creating one never consumes a public
ID and the public sequence says nothing about withheld work; the check reports an overlay record with a
public-range ID. When an overlay finding becomes public, it gets a new public record with the next public ID,
written from the public upstream item; the overlay record keeps its own ID.

## Lifecycle

`candidate` → `draft` → `approved` → one of the terminal states `filed`, `duplicate-of` or `not-a-defect`. A
record leaves `candidate` only with an independent reproduction, an upstream search and evidence; `draft` and
`approved` carry the issue text; `approved` and `filed` carry the user's approval. Records name roles, never
people.

Nothing in this repository files, comments on or reports anything upstream. The tools write drafts and print the
command a person would run after the user has approved that exact draft and channel.

## Commands

| Command | Does |
|---|---|
| `xdrcheck findings new --from <report> --row <row_id> [--sibling-of ID]` | Create a `candidate` from a failure row of an `xcc.report/v1` report |
| `xdrcheck findings issue <id>` | Write the draft issue body next to the record and print the command that would file it — never runs it |
| `xdrcheck findings list [--state S] [--target T]` | List records |
| `xdrcheck findings check --mode development <reports-dir>` (`make verify-findings`) | Every failure row on an `sdk`, `pipeline` or `core` target carries a finding ID that resolves to a record; every record validates; no record is orphaned. Not acceptance evidence |
| `xdrcheck findings check --mode acceptance <reports-dir>` (`make verify-findings-acceptance`) | The same, and every record is `filed`, `duplicate-of` or `not-a-defect` |

A row gets its finding ID from the manifest's known divergence or the linter suppression it matched: after
`xdrcheck findings new`, add the new ID there.

### Records no run can refer to

The orphan rule (a record no checked report row refers to fails the acceptance mode) has three exemptions, all
listed in the check's output and in the acceptance table's findings-linked row, never applied silently:

- **Rows from the private overlay only.** A record whose every `evidence.report_rows` entry comes from a column
  `drivers/sets.toml` does not define (only an overlay's sets file adds it): a public run cannot produce those rows.
- **Source reading on a target without a driver.** A record that says so itself, with `evidence.observed:
  "source-reading"` (read from the source, never executed) and no `evidence.report_rows`, whose `target.package`
  (and `target.ecosystem`) no column in `drivers/sets.toml` drives. No run of the kit can produce a row for it.
  F-0032 (stellar-dotnet-sdk, the same defect as the open upstream issue
  Beans-BV/dotnet-stellar-sdk#257) is the one such record; its evidence comment stays a draft and nothing is
  posted.
- **Rows only in the private acceptance run.** A record that says so itself, with `evidence.observed:
  "private-run"` (executed in the maintainer's private acceptance run, outside the public repository) and no
  `evidence.report_rows`: no public report holds its rows. F-0045, F-0046, F-0052 to F-0061, F-0066, F-0070 to F-0085 and F-0088 to F-0093 are such records
  (executed by hand, on ledgers or code paths no corpus run drives or compares).

A record observed by source reading only records its reproduction the same way: `reproduction.result:
"source-reading"` says the defect was confirmed by reading the source again, not by running it (F-0032).

## Pending finding review

A defect our own runs found that is not yet reported upstream stays a `candidate` in the private overlay until a
maintainer approves it, together with whatever describes it (for the linter: its suppression, site and reason). The
public tree records only which report rows it accounts for, in committed pending lists that hold row keys and
nothing else: no reason, no finding ID, no description.

| List | Keys |
|---|---|
| `findings/pending/<source>.json` (generic; for example `conformance.json`) | the keys the source's rows are identified by: for conformance `entry`, `variant`, `column`, `level` |
| `lint/expected/<target>/<commit>.pending.json` (the linter, next to its frozen expected lists) | `rule`, `file`, `line`, with the list's top-level `commit` |

Each file is `{"pending": [{<key>: <value>, …}, …]}`, optionally with a top-level `commit`, `target`, `tool` and
`since` that every entry inherits. Allowed keys: `target`, `commit` (the row's target version), `tool`, `column`, `entry`, `variant`,
`level`, `rule`, `file`, `line`, `function`. An entry matches a row when every key it names equals the row's value;
it must name at least one of `entry`, `rule` or `file`. Any other key fails the check, so a description cannot slip
in.

Pending work is counted in two units: an *entry* is one line of a pending list, and a *row* is one failure row of a
run's report that an entry matches; one entry can match several rows (every variant and input of a corpus entry, or a
linter site of the pinned commit, which both `make lint-wallet-backend` and `make lint-before-after` lint), so the
rows the findings check counts are at least as many as the entries the lists hold.

`xdrcheck findings check` reads every list. In development mode (`make verify-findings`) a failure row with no
finding ID passes when a pending entry matches it, and the output counts it as pending finding review. In
acceptance mode (`make verify-findings-acceptance`) every such row fails ("pending finding review: rows that need
an approved finding"), as a draft record does. The tools that produce the rows apply the same lists and give a
listed row the expectation `pending` in their reports instead of `unexpected` (`xdrlint -pending`, `xdrcheck conform run`,
`xdrcheck replay`): the public lint run accepts a listed report as pending and counts it, and a run with the overlay
resolves it to the overlay's record and suppression. When a maintainer approves a finding, its record and suppression
move to the public tree and its entries leave the pending list.

CI artifacts say no more than the lists do. Before each upload, the workflows run
[`scripts/ci/withhold-pending.py`](../scripts/ci/withhold-pending.py) on the reports directory: a linter report
that holds a pending row (it names the file, line and message in clear) is withheld with its SARIF and text
companions, and so is any other file that names such a site; replay and conformance rows awaiting review lose
their `evidence`, and their sections in a rendered `REPORT.md` are dropped. The upload runs only when that step
succeeded. The findings check downstream then lists a withheld linter run as not checked; the linter job has
already accounted for every row of it. The linter job also writes `<name>.verdict.json` next to its summary: the
run's outcome with no site in it (report counts per rule and severity, pending counts, clean), which is uploaded and
from which the acceptance table's lint-current row reads a withheld run. Local runs keep the full reports.

### Governance of the pending lists

- **Required runs.** [`required-runs.d/`](required-runs.d) names the make targets whose reports the check
  must read, one file per area read in name order; `xdrcheck findings check` expands them into report paths from `pins.toml` (for example
  `replay-full/wallet-backend-sep54-s3/report.json`, the whole corpus against wallet-backend at the pinned current
  commit). In acceptance mode a required report that is absent fails the check as missing; in development mode
  it is listed.
- **Stale entries.** An entry that accounts for no failure row of the required runs that could hold its rows (the
  same `tool`, and the same `target` and `commit` where both are named) fails the check in both modes, once all
  of those runs are among the checked reports. An entry no required run can hold is stale outright. Remove a
  stale entry from its list.
- **Age.** Each entry carries `since`, the date it was listed (`YYYY-MM-DD`; on the entry, or at the top level
  for every entry of the file). An entry older than 90 days, or one without a date, fails the acceptance mode; a
  date in the future fails both. `since` is not a row key.
- **Acceptance assertions are never pending.** A list that names a cell `xdrcheck conform sdk-regression` asserts (the same
  entry, and the same column and level where the entry names them) does not load.

## Embargo

Pending review and embargo use the same overlay; an embargo is the stricter case. A defect that may halt, crash or exhaust a production reader, or let a submitter corrupt balances,
participants or authorisation, is not recorded here until it has been disclosed to the affected project through its security policy and the embargo has
ended. Such records live in a private overlay outside this working tree (`--overlay DIR` or `XDRCHECK_OVERLAY`), with
the same layout: `<overlay>/findings/<id>/finding.json`. `xdrcheck findings new` refuses to write a candidate that may
be security-relevant to this directory unless the row matched a public upstream item, and the check fails on an
embargoed record found here. When in doubt, embargo.
