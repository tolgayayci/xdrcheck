# Contributing

Thank you for helping. The kit is useful only if its corpus is right and its checks are honest, so most of this
page is about evidence: where bytes come from, where expected values come from, and which command proves a change.

Questions and proposals go to the repository's issue tracker. A security problem in this kit, or a defect with
security impact that you found in another project by running the kit, does **not** go into a public issue: see
[SECURITY.md](SECURITY.md).

## Set up

```sh
mise install && make toolchain   # pinned Go, Node, Python, Java; Rust from rust-toolchain.toml
make fetch                       # the only networked step
make build
make repo-checks                 # needs no build; run it before every commit
make test
```

[docs/acceptance.md](docs/acceptance.md) lists every acceptance check and its `make` target; [docs/cli.md](docs/cli.md) lists every command.
Before opening a pull request, run `make repo-checks`, `make test` and the `verify-*` targets of the parts you
changed (`make verify-pr` runs what the pull-request CI runs). CI runs one job per target, with the same commands,
offline, in two tiers: every pull request and branch push runs the fast forms
([.github/workflows/pr.yml](.github/workflows/pr.yml)), and the full tier runs every check at full size
([.github/workflows/full.yml](.github/workflows/full.yml)) by hand and on release tags; its run
on a given commit is the acceptance evidence. `make ci-local TIER=pr` (or `TIER=full`, or one job with
`JOB=<id>`) runs those jobs on your machine as on a cold hosted runner.

## Rules every change follows

1. **Versions only from [`pins.toml`](pins.toml).** No floating versions, no version named in a workflow, script
   or lock file that `pins.toml` does not list; `xdrcheck pins check` enforces it. Moving a pin is its own pull request
   and carries the differential run that shows what changed ([docs/maintenance.md](docs/maintenance.md)).
2. **Never derive an expected value from a reader under test.** Expected values come from the bytes (the oracle's
   decoding), a scenario's stated intent, the reference extractor, or a primary source (stellar-core code at a
   pinned tag, a CAP or SEP clause). Not from an SDK's output, and not from an indexer's.
3. **Never edit corpus bytes.** A blob is exactly what stellar-core emitted or the public lake served. A smaller
   value is a slice with a pointer to its parent; a corrected pattern is a new entry.
4. **Offline and keyless.** Tools read inputs from disk; anything fetched is pinned by hash and fetched only by
   `make fetch`. No secrets, no funded keys: generated transactions are signed by keys derived from public labels.
5. **Public-tree hygiene.** No machine-local paths, no private names, no references to files outside the
   repository, and no internal planning labels (work-item and requirement IDs of the planning process, build or
   worktree names); `scripts/py/check_public.py` (part of `make repo-checks`) enforces it. Say what the code does,
   and cite `docs/`, `evidence/` or a public upstream permalink instead.
6. **Tests with everything.** A change comes with the test or `make` target that proves it. Tests derive counts
   from the corpus instead of hard-coding them, because the corpus grows.
7. **Commits**: one logical change per commit; a one-line, imperative message of at most 72 characters
   (`add muxed-source entry for CAP-27`, `fix strkey padding check`), no body.

## Adding a corpus entry

The workflow and the review checklist are in [docs/authoring-entries.md](docs/authoring-entries.md); the fields in
[docs/manifest.md](docs/manifest.md); IDs in [docs/entry-ids.md](docs/entry-ids.md). In short:

| Step | What is needed |
|---|---|
| Propose | An issue naming the pattern, its CAP and protocol, why it trips readers, and how it can be sourced |
| Register | A row in `corpus/plan.json` for the new ID, in its own reviewed change |
| Source | In order of preference: a scenario file (`corpus/scenarios/`, anyone can regenerate it on both passphrases); a stellar-core golden by tag and test name (`xdrcheck-corpus import-golden`); a public-lake ledger (`xdrcheck-corpus capture`); a synthetic recipe with the reason stellar-core cannot emit the bytes (`xdrcheck-corpus synth`) |
| Expect | Facts a correct reader must derive, from the scenario's intent or the decoded bytes, checked against the reference extractor (`xdrcheck-corpus extract`); must-not facts where the pattern is a trap |
| Check | `make repo-checks`, `make verify-corpus`, `make verify-generate` for scenarios, `make verify-coverage` (and `xdrcheck-corpus coverage` to regenerate), `make verify-guide` if the entry cites a field-table row |
| Review | A reviewer who did not write the entry answers the checklist in [docs/authoring-entries.md §6](docs/authoring-entries.md) |

Contributed bytes are untrusted input. The static checks validate size, schema and hashes before anything decodes
them, and every decoder runs with explicit limits under resource caps. Negative (deliberately invalid) entries are
accepted only as synthetic, with a reason class from the schema.

## Adding an adapter, a driver or a linter rule

- **Adapter** for another indexer: follow [docs/adapter-protocol.md §8](docs/adapter-protocol.md) and copy
  `go/adapters/baseline`. It must pass `xdrcheck replay --selftest`. An adapter for a private indexer can live in its own
  repository; nothing in the protocol needs the indexer's source.
- **Driver** for another SDK version: follow [docs/driver-protocol.md §7](docs/driver-protocol.md) and the
  directory contract in [drivers/README.md](drivers/README.md). The SDK version goes into `pins.toml`
  `[conformance.columns]` first.
- **Linter rule**: rules live in `lint/rules/` with fixtures under `lint/testdata/`; each needs reported and
  compliant fixtures, a page generated into `lint/docs/` (`make lint-docs`), and a checklist item in the guide. A
  new rule is run privately over every pinned target before it is merged (see [SECURITY.md](SECURITY.md)), and the
  frozen expected lists under `lint/expected/` are updated in the same change.

## Changing the guide

Every normative sentence in `guide/indexer-hardening.mdx` carries a claim tag that resolves to a record in
`guide/claims.yaml` with its source; the field table is generated, never edited by hand. The writing rules and
checks are in [guide/README.md](guide/README.md).

## Findings

A defect the kit finds becomes a finding record (`xdrcheck findings new`), never a direct upstream issue. Records are
reproduced by someone other than their author, searched against the upstream tracker, and drafted with
`xdrcheck findings issue`; a draft is filed only after the maintainers approve it. Process: [findings/README.md](findings/README.md).

## Licence

The project is Apache-2.0 ([LICENSE](LICENSE)). By contributing you agree that your contribution is licensed under
the same terms. Third-party material vendored into the corpus is listed in [NOTICE](NOTICE) with its source and
licence; add an entry there when you vendor something new.
