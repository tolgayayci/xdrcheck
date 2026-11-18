# Results data

Small JSON files, generated from runs of the kit and from the public finding records, for pages that show the
kit's results (the dashboard, the docs, the README). Nothing here is written by hand: each file has one command
that makes it and a `--check` that fails when the committed file no longer matches its sources.

| File | What it holds | Made by | Checked by |
|---|---|---|---|
| `conformance-matrix.json` | per corpus entry × SDK column: agrees, diverges (with the finding), pending, not run | `make results-conformance` | `make results-check` (cheap, in `make repo-checks`); `make results-conformance RESULTS_CHECK=1` (against a fresh run) |
| `replay-summary.json` | per corpus entry × pipeline version × input: pass, mishandled, dropped, halt, refused, not run | `make results-replay` | the same two |
| `findings.json` | one row per public finding record under `findings/` | `make results-findings` | `make results-check` |
| `known-defects.json` | how the kit covers each known upstream reader defect (the README's "Known upstream defects" table) | `make results-known-defects` | `make results-check` |
| `sibling-matrix.json` | each SDK defect class against each SDK family (rendered as `findings/SIBLINGS.md`) | `make results-siblings` | `make results-siblings-check` (in `make repo-checks`); `make results-siblings RESULTS_CHECK=1` (against a fresh run) |
| `acceptance.json` | per acceptance check (`roundtrip` … `findings-linked`): the area and check it answers, its make target, its status and why | `make results-acceptance` after `make verify-acceptance` | `make results-check` (cheap: against `docs/acceptance.md` and the tree); `make results-acceptance RESULTS_CHECK=1` (against a fresh run) |
| `mainnet-coverage.json` | of the mainnet scan's transaction-level shape tokens, how many the mainnet tier (`corpus/mainnet/`) holds and how many the curated corpus holds | `make results-mainnet` | `make results-mainnet-check` (in `make verify-coverage`); the tier half also by `make mainnet-tier-check` (in `make repo-checks`) |
| `../mainnet-scan/entry-prevalence.json` | per corpus entry, how common its rarest shape token is on mainnet | `make results-prevalence TOKEN_TABLE=…` | `make results-check` |

## Common rules

- Every file is one JSON object with `schema` (`xdrcheck.results.<name>/v1`) and `generated_by` (the command that
  makes it). Keys are stable; objects are written with sorted keys and two-space indentation, so a regeneration
  from the same sources gives the same bytes. No timestamps, no run times, no machine paths.
- Only public sources go in: the tracked corpus, the tracked finding records (`visibility: public`), the tracked
  pins and column sets, and runs of the public column sets and pinned pipelines. A cell or row that waits on a
  finding review says `"pending"` and nothing more.
- Finding IDs (`F-NNNN`) refer to `findings/F-NNNN/finding.json`; `findings.json` has the row for each.
- Upstream references: `findings.json` gives the URL only of an issue this kit filed (`state: filed`).

## conformance-matrix.json

```json
{
  "schema": "xdrcheck.results.conformance-matrix/v1",
  "generated_by": "make results-conformance",
  "corpus": {"version": "30.0.0-dev", "manifest_sha256": "…"},
  "sets": {"pr": ["go@v0.7.1", "…"], "public": ["…"]},
  "columns": {
    "js@17.4.0": {"sdk": "js", "package": "@stellar/stellar-sdk", "version": "17.4.0", "profile": null,
                  "role": "required", "release_date": null}
  },
  "classes": ["agrees", "diverges", "pending", "not-run"],
  "entries": {
    "cap-0038/pool-issuers-order-by-bytes-not-strkey": {
      "js@17.2.0": {"class": "diverges", "findings": ["F-0016"]},
      "js@17.4.0": {"class": "agrees"},
      "rust@30.0.0:limits-none": {"class": "not-run"}
    }
  },
  "totals": {"js@17.4.0": {"agrees": 0, "diverges": 0, "pending": 0, "not-run": 0}}
}
```

- A column ID is `<sdk>@<version>` or `<sdk>@<version>:<profile>`, as in `drivers/sets.toml`. `sets.pr` and
  `sets.public` list the column IDs of each set (`public` contains `pr`). Every column of `public` has a cell for
  every entry.
- One cell per entry × column, folded over the entry's variants and levels (L0…L4, spec, json): `diverges` if any
  of them diverges, else `pending` if any is pending, else `agrees` if any agrees, else `not-run`.
  - `agrees`: the column's result is the expected one (`conform`).
  - `diverges`: a declared divergence; `findings` lists the finding IDs the declarations name (sorted; may be
    empty when a declaration names no finding record).
  - `pending`: a divergence waiting on finding review (the tracked `findings/pending/conformance.json`). No detail.
  - `not-run`: every variant and level was not applicable to the column (outside its protocol, a level it does not
    run, or blocked because L0 did not decode).
- `release_date` is `null`: the repository does not record SDK release dates.
- `totals` counts the cells of each column by class.

## replay-summary.json

```json
{
  "schema": "xdrcheck.results.replay-summary/v1",
  "generated_by": "make results-replay",
  "pipelines": {
    "wallet-backend@f0c00cf52420": {"pipeline": "wallet-backend", "commit": "f0c00cf5242048d0438d07151cc1ef1a4b98d7c7",
                                    "role": "current", "pair": null, "scope": "corpus"},
    "wallet-backend@2a0a84ea1252": {"pipeline": "wallet-backend", "commit": "…", "role": "prefix", "pair": 1,
                                    "scope": "known-divergences"},
    "stellar-etl@7e3fc9af9535": {"pipeline": "stellar-etl", "commit": "…", "tag": "v2.8.35", "role": "current",
                                 "pair": null, "scope": "known-divergences"}
  },
  "inputs": ["rpc", "sep54-dir", "sep54-s3"],
  "classes": ["pass", "mishandled", "dropped", "halt", "refused", "pending", "not-run", "error"],
  "entries": {
    "cap-0073/sac-trust-creates-trustline": {
      "wallet-backend@764a4f5bcbff": {"sep54-s3": {"class": "mishandled", "findings": []},
                                      "rpc": {"class": "mishandled", "findings": []}}
    }
  },
  "totals": {"wallet-backend@f0c00cf52420": {"sep54-s3": {"pass": 0}}}
}
```

- A pipeline key is `<pipeline>@<first 12 hex of the commit>`, or `baseline@<version>` for the kit's own reference
  indexer (`go/adapters/baseline`, unmodified, from `make harness-selftest`). `role` is `current` (the pinned
  current commit), `prefix` or `fixed` (the acceptance pairs of `pins.toml` `[pipelines.wallet_backend]
  acceptance`; `pair` is the pair's 1-based position there), or `reference` (the baseline). `scope` is `corpus`
  when the whole corpus ran, `known-divergences` when only the entries declaring a known divergence for that
  pipeline ran (entries absent from such a run have no cell for it).
- `inputs`: `sep54-s3` is the Galexie (SEP-54) layout served from an object store, `sep54-dir` the same layout as
  a plain directory, `rpc` the mock `getLedgers` endpoint. wallet-backend runs on `sep54-s3` and `rpc`;
  stellar-etl and the baseline on `sep54-dir`.
- One cell per entry × pipeline × input, folded over the entry's variants: the worst class wins in the order
  `error`, `halt`, `refused`, `mishandled`, `dropped`, `pending`, `pass`, `not-run`.
  - `halt` and `refused` are the harness's `halt` and `refused` qualifiers (the pipeline stopped; the pipeline's
    own gate turned the input away); `mishandled` and `dropped` are the remaining qualifiers of those classes.
  - `not-run`: the harness planned the variant out (outside the pipeline's declared envelope, not reached).
  - `error`: a harness fault; a published file has none (the generator refuses such a run).
  - `pending`: the row waits on finding review, or a pipeline's failing row names no public finding record; no
    detail. (The baseline's rows keep their class.)
  - `findings` (on `halt`, `refused`, `mishandled`, `dropped`): finding IDs of public records that the failing
    rows name, sorted; empty when none does (the baseline's refusals are its documented behaviour). A finding's
    state (`filed`, `duplicate-of`, `not-a-defect`) is in `findings.json`.
- Horizon has no column: its rig (`go/adapters/horizon`) runs lake ledgers, not corpus entries, and has no make
  target for the corpus.

## findings.json

```json
{
  "schema": "xdrcheck.results.findings/v1",
  "generated_by": "make results-findings",
  "findings": [
    {"id": "F-0066", "title": "…", "state": "filed", "component": "pipeline", "target": "stellar/wallet-backend",
     "severity": "medium", "class": "wrong_value", "caps": [], "entries": ["…"],
     "versions_affected": "…", "fixed_in": null, "upstream": "https://github.com/stellar/wallet-backend/issues/824"}
  ],
  "totals": {"state": {"filed": 0}, "severity": {"medium": 0}, "component": {"pipeline": 0}}
}
```

- `state`: `filed` (this kit opened the upstream issue), `duplicate-of` (the defect was already known upstream),
  `not-a-defect`. `upstream` is the issue URL for `filed`, the string `"known upstream"` for `duplicate-of`, and
  `null` for `not-a-defect`.
- `entries` are corpus entry IDs (`none` dropped); `caps` are CAP numbers taken from those entries' manifests.
- `fixed_in` is the record's fixed version or commit when it has one, else `null`.

## known-defects.json

```json
{
  "schema": "xdrcheck.results.known-defects/v1",
  "generated_by": "make results-known-defects",
  "readme_anchor": "known-upstream-defects",
  "defects": [
    {"id": "kd-01", "project": "stellar-core", "topic": "…", "coverage": "reproduced",
     "how": "…", "entries": ["…"], "make_targets": ["make verify-replay"], "evidence": ["evidence/…/README.md"]}
  ],
  "totals": {"reproduced": 0, "run": 0, "checked": 0, "input": 0, "agreement": 0}
}
```

- One row per row of the README's "Known upstream defects" table, in table order; `id` is `kd-NN` by position.
  No upstream issue number or URL is repeated here; the README table is the source.
- `coverage`: `reproduced` (a make target runs the affected project before and after its fix and shows the defect
  and its absence), `run` (a make target runs the project; the entries declare its result), `checked` (a make
  target checks the shape), `agreement` (compared with a reference, not a reproduction), `input` (corpus entries
  hold the shape; no reader of that project runs them here).

## acceptance.json

```json
{
  "schema": "xdrcheck.results.acceptance/v1",
  "generated_by": "make results-acceptance (after make verify-acceptance)",
  "run": {"kind": "local", "commit": "<40 hex>", "modified": false},
  "statuses": ["met", "not met", "missing", "not recorded", "proven in full CI"],
  "rows": [
    {"id": "roundtrip", "area": "Corpus and generator", "check": "entries round-trip through rs-stellar-xdr",
     "make": "make verify-corpus", "status": "met", "reason": "round-trip and reject checks: all … rows passed"}
  ],
  "totals": {"met": 0, "not met": 0, "missing": 0, "not recorded": 0, "proven in full CI": 0}
}
```

- One row per row of the acceptance table `xdrcheck report acceptance` writes (`acceptance.json` beside
  `acceptance.md` in the reports directory), in the order of `docs/acceptance.md`'s check table, which defines
  the checks: `area`, `check` and `make` are that table's first column, its Check column without the ID, and the
  first make target of its Command column. A check the page writes with cases (`replay-regression` (cases
  `wallet-backend-729`, …)) has one row per case, `<id>/<case>`, when the acceptance table has one.
- `status` and `reason` are the acceptance table's status and "what was checked" text, as published: no count of
  rows pending finding review, no clause about runs that only the private acceptance run makes, no upstream issue
  number, no machine path. The status is never set by hand: the file is generated from a local
  `make verify-acceptance` (public column sets only, no overlay) and changes only when that run is made again.
- `run` says which run made the table: `kind` `github-actions` with the workflow run's `id` and its `commit`, or
  `local` with the checked-out `commit` and `modified` (true when tracked files differed from that commit). The
  generator reads it from the tree it runs in, so run `make results-acceptance` where `make verify-acceptance`
  ran. `RESULTS_CHECK=1` compares the rows, not the run; a file made before the field existed has no `run`.
- The cheap check holds the file to its definitions and to what the tree shows without a run: every check of
  `docs/acceptance.md` has a row and nothing else does; each make target is a documented one; `guide-review` is not
  `met` while `guide/claims.yaml` has a claim that is not confirmed or corrected; `findings-linked` is not `met` while a pending list
  has an entry or a public record is not filed, a duplicate or not a defect.

## ../mainnet-scan/entry-prevalence.json

```json
{
  "schema": "xdrcheck.results.entry-prevalence/v1",
  "generated_by": "make results-prevalence TOKEN_TABLE=<the scan's token table>",
  "scan": {"first_ledger": 2, "last_ledger": 65505999, "grammar": "xcc.shape/v1", "distinct_tokens": 15884},
  "entries": {
    "cap-0063/parallel-phase-single-cluster": {
      "walked": true, "variant": "pubnet@28", "rarest_occurrences": 2, "never_seen_on_mainnet": false,
      "rarest_tokens": [{"token": "L|len|lcm.v2.txProcessing#len=1", "occurrences": 2,
                         "first_ledger": 59508408, "last_ledger": 61199447}],
      "rarest_tokens_total": 1, "tokens": 37, "tokens_unseen_on_mainnet": 0,
      "variants": {"pubnet@28": 2, "pubnet@30": 0, "testnet@28": 2, "testnet@30": 0}
    },
    "cap-0046/scval-map-keys-collide-u32-symbol": {"walked": false}
  },
  "totals": {"entries": 0, "walked": 0, "not_walked": 0, "never_seen_on_mainnet": 0,
             "distinct_entry_tokens": 0, "distinct_entry_tokens_seen_on_mainnet": 0,
             "mainnet_variants_checked_against_the_scan": 0}
}
```

- Prevalence is per token: an entry's count is that of the rarest token its focus transaction (or ledger) holds,
  in the variant where that count is highest. It bounds how often the entry's whole shape can occur; it is not a
  count of transactions with that whole shape. `evidence/mainnet-scan/README.md` has the method.
- `never_seen_on_mainnet` is true when `rarest_occurrences` is 0: the shape is not on mainnet in the scanned
  range, and the entry exists because a local stellar-core produced it. `first_ledger` and `last_ledger` are
  `null` for a token with no occurrence.
- `walked: false`: the entry has no `LedgerCloseMeta` variant (an SDK-level value such as an `ScVal`, or no
  variant at all); no count.
- A mainnet count says where a shape occurs; it says nothing about what any pipeline did with it.
- `mainnet_variants_checked_against_the_scan`: the variants taken from a scanned pubnet ledger; the generator
  refuses to write the file unless every token of each is in the token table at that ledger, which shows the walk
  emits what the scan emitted.
