# xdrlint rules

For authors of Go indexers and pipelines built on the go-stellar-sdk ingest stack (the `xdr`, `ingest`,
`processors/token_transfer` and `strkey` packages): what each `xdrlint` rule reports, how to run the linter, and how
to configure it or accept a report.

| Family | Mistake |
|---|---|
| XDR1xx | trusting fields stellar-core never validated |
| XDR2xx | walking self-referential structures with no depth or size bound |
| XDR3xx | deriving participants from the envelope instead of the meta |
| XDR4xx | assumptions about the ledger's form, ranges and outcomes |
| XDR000 | suppression hygiene: a suppression with no reason, an unknown rule, or one that suppresses nothing |

Each rule has a page with what it reports, why, a reported and a compliant example taken from the linter's own
fixtures, and its limits. The guide sections are in [guide/indexer-hardening.mdx](../../guide/indexer-hardening.mdx).

<!-- rules -->

## Running it

| Mode | How |
|---|---|
| Standalone | `go install github.com/tolgayayci/xdrcheck/lint/cmd/xdrlint@<version>`, then `xdrlint ./...` in your module |
| `go vet` tool | `go vet -vettool=$(which xdrlint) ./...`; configuration from `.xdrlint.yml` or `XDRLINT_PROFILE`, `XDRLINT_CONFIG` |
| golangci-lint module plugin | a `.custom-gcl.yml` naming `github.com/tolgayayci/xdrcheck/lint/plugin`, built with `golangci-lint custom` at the golangci-lint version that uses the same `golang.org/x/tools` (v2.15.0 for this release); settings under `linters.settings.custom.xdrlint.settings`: `profile`, `config`, or any configuration key inline. See the package documentation of `lint/plugin` |

Building `xdrlint` needs Go 1.26 or later; the code it checks may declare an older Go version.

A five-minute walk-through (install, run, read a diagnostic, suppress with a reason, run in CI) is in
[lint/README.md](../README.md).

Output:

| Flag | Output |
|---|---|
| (none) | text: `file:line:col: XDR201 (warning): message`, then a `fix:` line with the usual fix and a `docs:` line with the rule's page; on stderr a closing summary of what was found, whether the run fails and how to accept a report. Page links start at `-docs-base` (or `XDRLINT_DOCS_BASE`; default `lint/docs`; a base containing `{rule}` is a template) |
| `-json` | the `go/analysis` diagnostic tree with each report's rule, severity, function, guide anchor, corpus entry, fix and page link |
| `-sarif FILE` | SARIF 2.1.0, every rule linked to its page, suppressed reports marked as such |
| `-report FILE` | every report, suppressed ones included, as `xcc.report/v1` rows |
| `-expect FILE` | a comparison with a frozen expected list that fails on any difference in either direction. The list is compared by count: each entry (rule, file, function, suppressed) stands for `count` reports (default 1), so one report more than it counts is a difference |
| `-pending FILE` | names the reports pending finding review (`xdrlint.pending/v1`: rule, file and line only, one entry per report; a list for another commit is refused); they are marked `pending` in the `-report` rows instead of unexpected |

| Exit | When |
|---|---|
| 0 | no unsuppressed report at or above `-fail-on`, and no `-expect` difference |
| 1 | an unsuppressed report that no `-pending` list names is at or above `-fail-on` (default `error`), or, with `-expect`, any difference |
| 2 | a usage, configuration or loading error; or no recognised source package is loaded (none of the packages, nor anything they import, is go-stellar-sdk's `xdr` package or an alias of it), since the rules then analyse nothing |

## Configuration

`.xdrlint.yml` in the module (or a file named with `-config`), over a shipped profile named with `-profile`
(`default`, `wallet-backend`, or a path). Keys are flat and lower-case so that golangci-lint can pass them through:

| Key | Meaning |
|---|---|
| `rules` | enabled rule IDs (default: every rule not marked opt-in) |
| `severity` | map of rule ID to `error`, `warning` or `info` |
| `xdrpackagealiases` | extra import paths treated as the SDK's `xdr` package |
| `participantnameregex` | names of participant sets (default `(?i)participant`) |
| `sinksparticipant`, `sinksaccountkey`, `sinkstext`, `sinksmovement` | extra sinks, as `pkg.Func`, `pkg.Type.Method` or `pkg.Type.Field` |
| `sanitizersaddress`, `sanitizerstext`, `sanitizersevent` | functions accepted as normalisers or verifiers |
| `budgetmethods` | methods accepted as a depth budget check (XDR201) |
| `overflowpolicy`, `overflowflags`, `haltingfuncs`, `ingestentrypoints` | what the project does at a bound (XDR206) |
| `floors` | map of structure to the minimum bound (XDR207) |
| `suppressions` | an external suppression file |

A configured name that does not exist in a loaded package stops the run, so a misspelt sink cannot silently check
nothing.

A private overlay layer (`-overlay DIR`, or `XDRLINT_OVERLAY`) merges `DIR/xdrlint.yml` over both; this project keeps
its overlay layer outside the repository, at `$XDRCHECK_OVERLAY/lint/xdrlint.yml`, and public runs never load it.

<h2 id="linter-suppressions">Configuring and suppressing</h2>

Every report can be accepted with a reason:

- **Inline**, on the reported line or on the enclosing function's doc comment:
  `//xdrlint:ignore XDR201 linear walk over a tree the decoder bounded`. Under golangci-lint,
  `//nolint:xdrlint // <reason>` works too (enable `nolintlint` with `require-explanation` and
  `require-specific`).
- **An external suppression file**, for code you cannot edit: a YAML list of entries with `rule`, `file`
  (module-relative), one or more of `function` (`F` or `Type.Method`), `anchor` (a substring of the reported line),
  `line` (the reported line) and `message` (the report's message), and `reason`; optionally `finding`, `issue`,
  `commit`, `reviewer` and `date`. Every key given must match. An entry with a function only survives line drift
  but also accepts any new report of its rule in that function; an anchor or a line narrows it to one site, which
  is what a list frozen against one commit should use. `function` with `message` is the baseline key that
  survives code moving within the file: the message is compared without the line numbers it names
  (`line 28`, `events.go:12`), so it names one report without naming a line.

Expected lists (`-expect`) and pending lists (`-pending`) take the same key: an entry with a `message` accounts for
reports of its rule, file and function with that message only; a pending entry may name `function` and
`message` instead of a `line`, or give `site2`, the hex SHA-256 of
`xdrlint.site/v2:<rule>:<file>:<function>:<message without line numbers>`.

A suppression without a reason, one naming an unknown rule, and one that suppresses nothing are reported as
XDR000, which cannot itself be suppressed.

Every diagnostic names, in `assumption` (JSON, SARIF result properties and `-report` rows), the assumption about
the ledger the reported code makes, as a stable key such as `meta-version:v4-only` or `narrowing:u64->int64`.
[assumptions.md](assumptions.md) lists every key with the input that violates it. Suppressed reports are not printed, but `-report`, `-json` and `-sarif`
keep them, marked as suppressed.

## The wallet-backend check

`make lint-wallet-backend` runs the shipped `wallet-backend` profile over the pinned wallet-backend commit and
compares the reports with the frozen expected list and suppression file of that commit in
[lint/expected/wallet-backend](../expected/wallet-backend); `make lint-before-after` does the same for each commit
of a before/after table, where each rule fires at the commit before a known upstream fix and is silent after it.
Every suppression there names a finding record under [findings](../../findings). A report our run found that is
not yet reported upstream is listed in `<commit>.pending.json` as (rule, file, line) only; the run counts it as
pending finding review until its record is approved (see [findings](../../findings/README.md)).

The lists are compared by count, and every suppression names its line or an anchor, so a new report inside a
suppressed function is not accepted with the old one. A suppression is for a reviewed, accepted site or one with
an upstream item; a false positive of the linter is fixed in the rule instead. The pinned commit runs clean when
`xdrlint` exits 0 with the shipped profile after the suppressions. While a pending report is an unsuppressed
error it does not: the run's accounting can still pass, and its first line and
`reports/lint-wallet-backend.summary.json` (`clean`, `clean_statement`) say so and why; a pending warning does not
make the run unclean. `reports/lint-wallet-backend.verdict.json` states the same outcome with no site in it.
`make lint-selftest` shows that each of these checks can fail.
