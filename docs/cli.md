# Command-line reference

For SDK maintainers and indexer operators who run the kit by hand or from CI. It lists every tool and command,
the conventions they share, and each command's own `--help`, so you can find the flag you need and tell from an
exit code whether your reader or the kit failed.

The kit has three main command-line tools, two helper tools (the judge, which the target form of `xdrcheck replay`
calls, and the value tagger), and a `Makefile` that runs them:

| Tool | Language | Built to (linked into `bin/` by `make build`) | What it does |
|---|---|---|---|
| `xdrcheck-corpus` | Rust | `target/release/xdrcheck-corpus` | The corpus toolchain: the oracle (`verify`), the generator (`gen`), intake from the public lake, stellar-core goldens and recipes, decoded sidecars, the reference extractor, the coverage report and the guide's generated table |
| `xdrcheck` | Go | `go/bin/xdrcheck` | The ledger server (`serve`), the replay harness and the target and rig replays (`replay`), the conformance orchestrator (`conform`), the dataset (`data`), example lookup (`find`), run directories (`runs`), reproduction bundles (`repro`), cross-target diffs (`xcheck`), finding records (`findings`), reports (`report`), XDR diffs (`xdr`), the overlay audit (`overlay`) and the pins check (`pins`) |
| `xdrlint` | Go | `lint/bin/xdrlint` | The linter for Go indexer source |
| `xdrcheck-judge` | Rust | `target/release/xdrcheck-judge` (not linked into `bin/`) | The judge of pipeline replays: facts computed from a ledger's own entry changes (`facts`) and verdicts on a pipeline's exported rows (`verdict`); `xdrcheck replay --target` finds it through `$XDRCHECK_JUDGE` or `PATH` ([replay.md](replay.md), `crates/xdrcheck-judge/README.md`) |
| `xdrcheck-tagger` | Rust | `target/release/xdrcheck-tagger` (not linked into `bin/`) | The value tagger: one streaming pass over a lake-layout directory that tags values the shape grammar does not record (wide integers, bytes in text fields, map key order and similar), per partition (`run`), then joined (`merge`) |

`make build` builds all five, the replay adapters (`baseline`, `wallet-backend-adapter`, `stellaretl`) and
`xdrcheck-mutate`, and links each into `./bin` (Rust binaries always go to `./target`, whatever `CARGO_TARGET_DIR` the
shell exports). It ends by printing the line that puts them on your `PATH`:

```sh
export PATH="$PWD/bin:$PATH"
```

The examples on this page write bare `xdrcheck`, `xdrcheck-corpus` and `xdrlint` for those binaries. Each section
below has a short summary written by hand and then the tool's own `--help` output, copied verbatim. The help blocks are generated: `scripts/py/check_cli_reference.py` compares them
with the built binaries and fails when they drift (`--write` regenerates them), and it also checks that the table
of `make` targets at the end lists exactly what `make help` prints.

## Conventions shared by every tool

- **Exit codes.** `0`: the command did what it was asked and every check passed. `1`: a check failed (an
  unexpected result, a mismatch, a missing finding). `2`: the tool itself could not run (bad arguments, missing
  input, an integrity mismatch, an adapter or driver that broke its protocol). So `1` means the reader under test failed and `2`
  means the kit did.
- **Network.** Only these commands use the network, and only to fetch pinned, hash-checked inputs:
  `xdrcheck-corpus capture`, `xdrcheck-corpus refetch`, `xdrcheck-corpus fetch-goldens` and `xdrcheck conform fetch` (all reached
  through `make fetch` or run by hand when adding entries). Everything else runs offline; `make <target>
  OFFLINE=1` runs it inside a network namespace with loopback only ([ci-isolation.md](ci-isolation.md)).
- **Nothing is filed upstream.** No command files, comments on or reports anything to another project.
  `xdrcheck findings issue` writes a draft and prints the command a person would run.
- **Pins.** `--pins FILE` (default `pins.toml`) is the single file of external versions. No tool reads a version
  from anywhere else, and `xdrcheck pins check` fails on any version named elsewhere.
- **Reports.** `--report` writes results in the shared format `xcc.report/v1`
  (`corpus/schema/report.schema.json`), the only format `xdrcheck findings check` and `xdrcheck report` read.
- **Private overlay.** `--overlay DIR` (or `XDRCHECK_OVERLAY`) merges a private directory of withheld finding records,
  known divergences and suppressions over the public tree in memory. Public CI never uses it. See
  [SECURITY.md](../SECURITY.md) and [findings/README.md](../findings/README.md).

## Cookbook: replay anything against anything

Each line below was run from the repository root after `make fetch && make build`, with `export PATH="$PWD/bin:$PATH"`
(the `--set public` line as `make verify-conformance-public`, the run `evidence/results/` is made from). After the
fetch all run offline, except `conform fetch --sdk`, which fetches the checkout's own dependencies. An entry ID glob's `*` crosses `/`; `--entries` works the same in `replay` and
`conform run`. `--caps` is `replay`'s alone: in `conform run`, select a CAP's row with `--entries 'cap-0040/*'`. `--input` defaults to the first input the adapter declares, so it is needed only to pick another one.

| To | Run |
|---|---|
| list the entries of a CAP | `xdrcheck entry --cap 40` |
| list entries by ID | `xdrcheck entry --list 'cap-0067/*'` |
| show one entry: tags, variants, expected values, declared divergences, how common it is on mainnet | `xdrcheck entry cap-0040/signed-payload-signer-added` |
| print one variant decoded (SEP-51 JSON) | `xdrcheck entry --decoded testnet cap-0040/signed-payload-signer-added` |
| replay one entry through the baseline adapter | `xdrcheck replay --adapter bin/baseline --target-version dev --entries cap-0040/signed-payload-signer-added` |
| the same through the mock `getLedgers` endpoint, or an S3 store in the lake layout | add `--input rpc`, or `--input sep54-s3` |
| replay one CAP through your own adapter (the Go template; it reads the Galexie layout, `sep54-dir`) | `xdrcheck replay --adapter bin/minimal --target-version 0.1.0 --caps 40` |
| replay the whole corpus, with a report | `xdrcheck replay --adapter bin/baseline --target-version dev --parallel 4 --report reports/baseline` |
| replay through wallet-backend at its pinned commit (needs Docker) | `xdrcheck replay --adapter bin/wallet-backend-adapter --target-version "$(python3 -c 'import tomllib; print(tomllib.load(open("pins.toml","rb"))["pipelines"]["wallet_backend"]["current"])')" --input rpc --entries cap-0040/signed-payload-signer-added` |
| replay through stellar-etl at its pinned commit, from the cache `make fetch` filled | `xdrcheck replay --adapter "bin/stellaretl --offline" --target-version "$(python3 -c 'import tomllib; print(tomllib.load(open("pins.toml","rb"))["pipelines"]["stellar_etl"]["commit"])')" --network testnet --entries 'cap-0040/*'` |
| serve the corpus to any indexer by hand (one mock `getLedgers` URL per replay unit, printed as JSON lines) | `xdrcheck serve --network testnet --rpc 127.0.0.1:8000` |
| run one entry through one SDK column | `xdrcheck conform run --columns 'js@17.4.0' --entries cap-0038/pool-issuers-order-by-bytes-not-strkey` |
| run one entry through every SDK column of the `pr` set (the default) | `xdrcheck conform run --entries cap-0038/pool-issuers-order-by-bytes-not-strkey` |
| run the whole corpus through the widest public set | `xdrcheck conform run --set public --report reports/conformance-public` |
| run an SDK checkout instead of its release (Go, Rust, Python columns) | `xdrcheck conform fetch --columns 'go@v0.9.0' --sdk ../go-stellar-sdk`, then `build` and `run` with the same flags; add `--expected-failures FILE --require-all-read` to `run` to fail only on a new divergence ([use-in-sdk-ci.md](use-in-sdk-ci.md) §8) |
| look for one finding's defect in the other SDKs (read-only plan) | `xdrcheck conform siblings --finding F-0017 --offline --plan` |
| every SDK defect class against every SDK family | [`findings/SIBLINGS.md`](../findings/SIBLINGS.md) (`make results-siblings`) |

The `--sdk` copy of a driver is built outside the repository, where a version manager's per-directory toolchain does
not apply: put the pinned Go first on `PATH` (`export PATH="$(go env GOROOT)/bin:$PATH"`, run in the repository)
when your default `go` is older. `--target-version` names the indexer version in the report and, for the pipeline adapters, selects the commit to
build; the baseline and template adapters run one fixed version and record the name you give.

## `xdrcheck-corpus`

| Command | Does | Used for |
|---|---|---|
| `verify [--tier curated\|bulk] [--checks LIST] [--entries GLOB] [--report FILE] [--overlay DIR]` | The oracle gate. Checks `schema`, `ids`, `hashes`, `roundtrip`, `reject`, `sidecar`, `pinpoints`, `ag1`, `ag3`, `ag4`, `extractor`, `orphans`; the default is every check that applies to the tier except `ag4`, which needs the golden cache. `--overlay DIR` verifies the public corpus merged with the overlay's `corpus/` ([conformance-protocol.md](conformance-protocol.md) §6) | Corpus check: round trip through rs-stellar-xdr, agreement with stellar-core's goldens |
| `gen <scenario>… [--network testnet\|pubnet\|core-test\|both] [--protocol N,…] [--profile P]` | Run scenarios on a local stellar-core (offline, standalone, manual close) and write blobs, manifest variants and chain indexes | Generator |
| `gen --check (<scenario>… \| --list FILE \| --all)` | Regenerate and require equal ledger header hashes, transaction hashes and results, and equal bytes after stellar-core's own golden-comparison normalisation | Reproducible generation on both passphrases |
| `capture <network> <ledger> [--tx HASH] [--entry ID]` | Fetch one object from the public SEP-54 data lake verbatim and record its provenance (network) | History entries |
| `mine --network N --range A..B --want PREDICATES [--first K] [--pick smallest\|first] [--except MINED.json] [--max-bytes N] [--step S] [--lake DIR] [--out DIR]` | Stream public-lake objects (anonymous, read-only; `Retry-After` honoured) or a local store directory, walk each ledger, and keep, per wanted predicate (an arm or optional state, an enum value, a result code, a value class, an `SCVal` depth, `uncovered`, `any`), the K smallest matching objects of the range (`--pick first`: the first K); `--except` drops predicates an earlier run satisfied (mine testnet first, then pubnet with `--except`); kept objects are written verbatim with `mined.json` (header and transaction hashes recomputed) (network) | History entries for coverage gaps |
| `refetch [--network N]` | Re-fetch every history entry's object and compare hashes; testnet objects from a reset epoch are reported, not failed (network) | Provenance |
| `fetch-goldens <tag>` | Fetch stellar-core's golden `LedgerCloseMeta` tree at a tag into the cache and verify it against the bulk-tier hash index (network) | Golden agreement, bulk tier |
| `import-golden <tag> <test name> [--frame N] [--entry ID]` | Import one golden ledger as a `core-golden` variant | Golden agreement |
| `synth <recipe>…` | Build synthetic, `api` or `strkey` entries from recipe files | Synthetic and negative entries |
| `slice <entry> <path> --id ID --type XDR_TYPE` | Cut an `xdr` entry out of a ledger entry | One entry per pattern |
| `render [<entry>… \| --all] [--check] [--print ENTRY]` | Write (or check, or print) the SEP-51 decoded sidecars | Expected decoded values |
| `extract <entry>…` | Run the reference extractor: participants, state changes and movements derived from ledger-entry changes and events only | Expected values from an independent source |
| `normalise <file>` | Apply stellar-core's golden-comparison normalisation to a ledger or a record-marked stream | Reproducibility |
| `skeleton <entry> [--scope tx\|ledger]` | Print the structural skeleton (union arms and lengths, leaves masked) and its hash | Golden mirror |
| `chain-index <run dir>` | Write the chain index of a run kept by `gen --keep` | Replay units |
| `coverage [--check]` | Generate `corpus/coverage.json` and `corpus/COVERAGE.md`; with `--check`, fail on drift or on a CAP row with neither an entry nor a stated reason | Per-CAP coverage manifest |
| `coverage --arms [--bulk] [--mined DIR] [--fail-on-regression \| --write-baseline] [--report FILE]` | Per-arm coverage: every union arm and optional state reachable from `LedgerCloseMetaBatch`, with hit counts per tier (curated, bulk, mined), the best source (real, local-core, synthetic) and the arm's class from `corpus/arms.toml`; a `validation-only` or `never-built` class without indexer evidence is reported as unverified and still counted uncovered; `--fail-on-regression` fails when an arm of the baseline (`--baseline FILE`, else `$XDRCHECK_OVERLAY/arms-baseline.txt`) is no longer covered, and skips with a message when there is none | Coverage drift |
| `index [--check]` | Generate `corpus/index.json`, one row per entry (CAPs, validity, variants, blobs, hashes); with `--check`, fail on drift | Flat corpus index |
| `guide-table [--check]` | Generate the guide's field-by-field table from `corpus/fields.yaml` joined with the manifest; with `--check`, fail on drift | Guide table agrees with the manifest |
| `guide-claims --check` | Check every normative sentence of the guide against its claim record and source | Guide claims match their sources |
| `mainnet fetch [--cache DIR] [--jobs N] [--from DIR]` | Fetch the mainnet tier's public-lake objects ([corpus/mainnet](../corpus/mainnet/README.md)) into `<cache>/mainnet/objects/`: plain HTTPS GETs, each object kept only with the sha256 and size `tier.jsonl` names, one already cached not fetched again (a full cache makes no request); an object the lake now serves with other bytes is kept as `<key>.drift` and fails the run (network) | Mainnet tier |
| `mainnet check [--cache DIR] [--jobs N] [--out TSV]` | The mainnet tier from the cache only: each object's hash, decompression and batch split, each part's bytes and sha256 at its offset, its rs-stellar-xdr round trip, the transaction cut again as `scan cut-slices` cuts it, then the scan's emitter over every ledger: each line's tokens are the transaction's tokens no earlier line holds, and the union is the header's count | Mainnet tier: every transaction-level shape token of the scan, in a real transaction |
| `mainnet coverage [--check]` | Write `evidence/results/mainnet-coverage.json`: of the tier's tokens, how many the tier holds and how many a curated entry's focus transaction holds (walked as `scan entry-tokens` walks it); with `--check`, fail on drift | Coverage statement |
| `mainnet build --cover FILE --token-table FILE [--objects DIR]` | Write `corpus/mainnet/tier.jsonl` and `tier.json` from the scan's rare-first token cover and token table (neither is in the repository) and the lake objects; fails unless every row's new-token count and rarest occurrence are the cover's | How the tier was made |

The global `--corpus DIR` (default `corpus`) selects the corpus root.

<!-- BEGIN GENERATED: help xdrcheck-corpus -->

#### `xdrcheck-corpus --help`

```text
Corpus toolchain: oracle, generator, intake, coverage

Usage: xdrcheck-corpus [OPTIONS] <COMMAND>

Commands:
  verify         The oracle gate: schema, ids, hashes, roundtrip, reject, sidecar, pinpoints, ag1, ag3, ag4, extractor
  render         Write SEP-51 decoded sidecars
  extract        Reference extractor: participants, state changes, movements
  normalise      stellar-core golden-comparison normalisation
  skeleton       Structural skeleton and hash
  gen            Run scenarios on a local stellar-core; --check regenerates and compares
  gen-lake       Run exploratory scenarios on a local stellar-core and write the ledgers as a lake
  chain-index    Write a chain index for a kept scenario run
  capture        Fetch one public-lake object verbatim with provenance
  mine           Stream public-lake objects and keep only ledgers with wanted shapes
  refetch        Re-fetch every history entry and compare hashes
  fetch-goldens  Fetch the golden tree at a stellar-core tag
  import-golden  Import one golden ledger as a core-golden variant
  synth          Build synthetic, api or strkey entries from a recipe
  slice          Cut an xdr entry out of a ledger entry
  coverage       Generate coverage.json and COVERAGE.md; --check fails on unexplained gaps
  index          Generate corpus/index.json, one row per entry; --check fails on drift
  guide-table    Generate the guide's field table; --check fails on drift
  guide-claims   Check the guide's claim-to-source map
  mainnet        The mainnet tier: fetch its lake objects, check it, build it from the scan
  scan           Mainnet scan pilot: shape records and the offline tools over them
  help           Print this message or the help of the given subcommand(s)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
  -V, --version          Print version
```

#### `xdrcheck-corpus verify --help`

```text
The oracle gate: schema, ids, hashes, roundtrip, reject, sidecar, pinpoints, ag1, ag3, ag4, extractor

Usage: xdrcheck-corpus verify [OPTIONS]

Options:
      --corpus <CORPUS>
          Corpus root (directory holding corpus.json, manifest/, blobs/)

          [default: corpus]

      --tier <TIER>
          Tier to verify

          Possible values:
          - curated:   The in-repository corpus (`manifest/`, `blobs/`, `decoded/`)
          - bulk:      The golden set listed in `corpus.json` `tiers.bulk`, read from the golden cache
          - bulk-next: The next-protocol golden set listed in `corpus.json` `tiers.bulk-next`, read from the golden cache under the protocol gate `--max-protocol` lifts it to

          [default: curated]

      --checks <CHECKS>
          Comma-separated checks: schema, hashes, ids, roundtrip, reject, sidecar, pinpoints, ag1, ag3, ag4, extractor, orphans, spec. Default: every check that applies to the tier except ag4

      --entries <ENTRIES>
          Only entries whose ID matches this glob (`*` and `?`); on the bulk tier, golden file paths

      --report <REPORT>
          Write an `xcc.report/v1` report to this file

      --pins <PINS>
          The pins file (only read for the report header)

          [default: pins.toml]

      --goldens <GOLDENS>
          Golden cache root (default `$XDRCHECK_GOLDENS`, else `$HOME/.cache/xdrcheck/goldens`)

      --write-mirrors
          With `ag4` on a whole-corpus run: search the golden set again and rewrite `<corpus>/mirrors.json` (the local-core entries' golden counterparts) before checking

      --overlay <OVERLAY>
          Private overlay directory: verify the public corpus merged with `DIR/corpus` (manifests, blobs, sidecars; `DIR/corpus/plan-rows.json` adds to `plan.json`). Curated tier only

      --max-protocol <N>
          With --tier bulk-next (and only with it, where it is required): the protocol of the next-protocol goldens. The oracle's protocol gate is raised to N for this run only, to see what the pinned definitions fail on; corpus.json can never raise it

  -h, --help
          Print help (see a summary with '-h')
```

#### `xdrcheck-corpus render --help`

```text
Write SEP-51 decoded sidecars

Usage: xdrcheck-corpus render [OPTIONS] [ENTRIES]...

Arguments:
  [ENTRIES]...  Entry IDs to render

Options:
      --all                Render every manifest entry
      --corpus <CORPUS>    Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --check              Report drift without writing anything
      --print <ENTRY>      Print the decoded JSON of this entry's variant to stdout instead of rendering
      --variant <VARIANT>  With --print: the variant (`network` or `network@protocol`); default: the first
      --pretty             With --print: indent the JSON
  -h, --help               Print help
```

#### `xdrcheck-corpus extract --help`

```text
Reference extractor: participants, state changes, movements

Usage: xdrcheck-corpus extract [OPTIONS] <ENTRIES>...

Arguments:
  <ENTRIES>...  Entry IDs (`<group>/<slug>`)

Options:
      --corpus <CORPUS>    Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --variant <VARIANT>  Only this variant: `testnet`, `pubnet`, `testnet.p28`, …
  -h, --help               Print help
```

#### `xdrcheck-corpus normalise --help`

```text
stellar-core golden-comparison normalisation

Usage: xdrcheck-corpus normalise [OPTIONS] <FILE>

Arguments:
  <FILE>  A `LedgerCloseMeta` blob or a record-marked meta stream (golden file, core meta stream)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --out <OUT>        Write the normalised bytes here instead of stdout
  -h, --help             Print help
```

#### `xdrcheck-corpus skeleton --help`

```text
Structural skeleton and hash

Usage: xdrcheck-corpus skeleton [OPTIONS] <ENTRY>

Arguments:
  <ENTRY>
          Entry ID (`<group>/<slug>`)

Options:
      --corpus <CORPUS>
          Corpus root (directory holding corpus.json, manifest/, blobs/)

          [default: corpus]

      --variant <VARIANT>
          Only this variant: `testnet`, `pubnet`, `testnet.p28`, …

      --scope <SCOPE>
          Scope of the skeleton

          Possible values:
          - tx:     The variant's focus transaction
          - ledger: The whole ledger

          [default: tx]

  -h, --help
          Print help (see a summary with '-h')
```

#### `xdrcheck-corpus gen --help`

```text
Run scenarios on a local stellar-core; --check regenerates and compares

Usage: xdrcheck-corpus gen [OPTIONS] [SCENARIOS]...

Arguments:
  [SCENARIOS]...  Scenario files (paths, or relative to the corpus root)

Options:
      --corpus <CORPUS>      Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --network <NETWORK>    testnet, pubnet, core-test, or both (testnet and pubnet) [default: both]
      --protocol <PROTOCOL>  Protocols to run (default: the scenario's)
      --profile <PROFILE>    Meta flag profile (default: the scenario's)
      --check                Regenerate and compare with the committed chains instead of writing
      --list <LIST>          File listing scenario paths, one per line (with --check)
      --all                  Every scenario under <corpus>/scenarios (with --check)
      --runs <RUNS>          Directory for run directories [default: target/xdrcheck-runs]
      --keep                 Keep the run directories
  -h, --help                 Print help
```

#### `xdrcheck-corpus gen-lake --help`

```text
Run exploratory scenarios on a local stellar-core and write the ledgers as a lake

Usage: xdrcheck-corpus gen-lake [OPTIONS] --out <OUT> [SCENARIOS]...

Arguments:
  [SCENARIOS]...  Scenario files (paths, or relative to the corpus root)

Options:
      --corpus <CORPUS>            Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --out <OUT>                  Output directory; each scenario writes `<out>/<scenario>/`
      --network <NETWORK>          testnet, pubnet or core-test [default: testnet]
      --protocol <PROTOCOL>        Protocol to run (default: the scenario's first)
      --annotations <ANNOTATIONS>  Directory of `<scenario>.json` objects copied into `scenario.json` as `annotations`
      --stream <STREAM>            Export this meta stream instead of running scenarios (needs --name and --passphrase)
      --name <NAME>                Scenario name for --stream
      --passphrase <PASSPHRASE>    Network passphrase of the node that wrote --stream
      --steps <STEPS>              With --stream: a JSON array of the driver's steps (`id`, `property`, `tx_hash`, `submit`: core's answer to the submission); each is placed by its hash
  -h, --help                       Print help
```

#### `xdrcheck-corpus chain-index --help`

```text
Write a chain index for a kept scenario run

Usage: xdrcheck-corpus chain-index [OPTIONS] <RUN_DIR>

Arguments:
  <RUN_DIR>  A run directory kept by `gen --keep` (holds run.json and meta.xdr)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --out <OUT>        Write here instead of the corpus's chains/ directory
  -h, --help             Print help
```

#### `xdrcheck-corpus capture --help`

```text
Fetch one public-lake object verbatim with provenance

Usage: xdrcheck-corpus capture [OPTIONS] <NETWORK> <LEDGER>

Arguments:
  <NETWORK>  `pubnet` or `testnet` (the current testnet epoch pinned in pins.toml)
  <LEDGER>   Ledger sequence

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --tx <TX>          Focus transaction (hash, hex); must be in the ledger
      --entry <ENTRY>    Manifest entry ID whose history variant to add or update
  -h, --help             Print help
```

#### `xdrcheck-corpus mine --help`

```text
Stream public-lake objects and keep only ledgers with wanted shapes

Usage: xdrcheck-corpus mine [OPTIONS] --network <NETWORK> --range <RANGE> --want <WANT>

Options:
      --corpus <CORPUS>        Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --network <NETWORK>      `pubnet` or `testnet` (the current testnet epoch pinned in pins.toml)
      --range <RANGE>          Inclusive ledger range `A..B`
      --want <WANT>            Wanted predicates, comma-separated (see the module documentation)
      --first <FIRST>          Ledgers kept per predicate [default: 1]
      --pick <PICK>            `smallest`: keep the K smallest matching objects per predicate over the whole range; `first`: keep the first K matching ledgers and stop once every predicate has them [default: smallest]
      --except <EXCEPT>        `mined.json` of an earlier run: drop the predicates it already satisfied (repeatable)
      --max-bytes <MAX_BYTES>  Stop keeping once this many object bytes are kept [default: 67108864]
      --step <STEP>            Look at every STEP-th ledger of the range only [default: 1]
      --jobs <JOBS>            Objects fetched at once [default: 8]
      --lake <LAKE>            Read objects from a local directory laid out like a store instead of the lake
      --out <OUT>              Output directory (default `<cache>/mined`)
  -h, --help                   Print help
```

#### `xdrcheck-corpus refetch --help`

```text
Re-fetch every history entry and compare hashes

Usage: xdrcheck-corpus refetch [OPTIONS]

Options:
      --corpus <CORPUS>    Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --network <NETWORK>  Only this network (`testnet` or `pubnet`)
  -h, --help               Print help
```

#### `xdrcheck-corpus fetch-goldens --help`

```text
Fetch the golden tree at a stellar-core tag

Usage: xdrcheck-corpus fetch-goldens [OPTIONS] <TAG>

Arguments:
  <TAG>  stellar-core tag, e.g. v30.0.0

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
```

#### `xdrcheck-corpus import-golden --help`

```text
Import one golden ledger as a core-golden variant

Usage: xdrcheck-corpus import-golden [OPTIONS] <TAG> <TEST_NAME>

Arguments:
  <TAG>        stellar-core tag of the fetched tree, e.g. v30.0.0
  <TEST_NAME>  Human test name from index.json, e.g. "Trustline stellar asset contract|protocol version 30"

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --frame <FRAME>    Ledger of the test to import (0-based record index in the golden file)
      --entry <ENTRY>    Manifest entry ID whose core-golden variant to add or update
  -h, --help             Print help
```

#### `xdrcheck-corpus synth --help`

```text
Build synthetic, api or strkey entries from a recipe

Usage: xdrcheck-corpus synth [OPTIONS] <RECIPES>...

Arguments:
  <RECIPES>...  Recipe files (JSON, `recipe.schema.json`)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
```

#### `xdrcheck-corpus slice --help`

```text
Cut an xdr entry out of a ledger entry

Usage: xdrcheck-corpus slice [OPTIONS] --id <ID> --type <XDR_TYPE> <ENTRY> <PATH>

Arguments:
  <ENTRY>  Parent entry ID (a `ledger` or `xdr` entry)
  <PATH>   JSON Pointer into the parent's decoded form

Options:
      --corpus <CORPUS>    Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --id <ID>            ID of the new `xdr` entry (must exist in `plan.json`)
      --type <XDR_TYPE>    XDR type of the value at the pointer, e.g. `TransactionEnvelope`
      --variant <VARIANT>  Parent variant (`network` or `network@protocol`); default: the first
      --offset <OFFSET>    Byte offset of the slice in the parent blob, when the bytes occur more than once
  -h, --help               Print help
```

#### `xdrcheck-corpus coverage --help`

```text
Generate coverage.json and COVERAGE.md; --check fails on unexplained gaps

Usage: xdrcheck-corpus coverage [OPTIONS]

Options:
      --check                Compare with the committed files and check every row instead of writing
      --corpus <CORPUS>      Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --arms                 Per-arm and per-optional-state coverage instead of the per-CAP table
      --fail-on-regression   With --arms: fail when an arm or state of the baseline is no longer covered
      --write-baseline       With --arms: rewrite the baseline from the current corpus
      --baseline <BASELINE>  With --arms: the baseline file (default `$XDRCHECK_OVERLAY/arms-baseline.txt`)
      --bulk                 With --arms: also walk the cached golden tree (bulk tier)
      --mined <MINED>        With --arms: also walk ledgers kept by `xdrcheck-corpus mine` under this directory
      --report <REPORT>      With --arms: write the full table as JSON
      --universe <UNIVERSE>  With --arms: the root type whose arms are counted: LedgerCloseMetaBatch (ledger data), or SCSpecEntry (the entries of every `spec` entry's contract interface) [default: LedgerCloseMetaBatch]
  -h, --help                 Print help
```

#### `xdrcheck-corpus index --help`

```text
Generate corpus/index.json, one row per entry; --check fails on drift

Usage: xdrcheck-corpus index [OPTIONS]

Options:
      --check            Compare with the committed corpus/index.json instead of writing it
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --plan             Merge the plan fragments corpus/plan.d/*.json into corpus/plan.json instead (with --check: fail when a fragment row is not in plan.json yet)
  -h, --help             Print help
```

#### `xdrcheck-corpus guide-table --help`

```text
Generate the guide's field table; --check fails on drift

Usage: xdrcheck-corpus guide-table [OPTIONS]

Options:
      --check            Compare the committed blocks with the generated ones instead of rewriting them
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
      --report <FILE>    Also write the result as an xcc.report/v1 file (one row per citing entry)
  -h, --help             Print help
```

#### `xdrcheck-corpus guide-claims --help`

```text
Check the guide's claim-to-source map

Usage: xdrcheck-corpus guide-claims [OPTIONS]

Options:
      --check            Check the page against the claim map (the command only checks; the flag is accepted for the documented spelling `guide-claims --check`)
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
```

#### `xdrcheck-corpus mainnet --help`

```text
The mainnet tier: fetch its lake objects, check it, build it from the scan

Usage: xdrcheck-corpus mainnet [OPTIONS] <COMMAND>

Commands:
  fetch     Fill the cache with the tier's lake objects (network step; offline when the cache is full)
  check     Check the tier from the cache: hash chain, cut, round trip, tokens
  build     Write tier.jsonl and tier.json from the scan's token cover and token table
  coverage  Write the token coverage statement (evidence/results/mainnet-coverage.json); --check compares
  help      Print this message or the help of the given subcommand(s)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
```

#### `xdrcheck-corpus scan --help`

```text
Mainnet scan pilot: shape records and the offline tools over them

Usage: xdrcheck-corpus scan [OPTIONS] <COMMAND>

Commands:
  run             Scan ledgers into shape records
  ablate          Distinct components and transaction shapes at G0–G3, and the ablation table
  cover           Kept-example cover at each level (components and whole transactions)
  saturation      Saturation curves per era on the held-out set
  vocab           Most common event symbols and data-map keys outside the closed vocabularies
  size            Record and dictionary bytes per ledger and per transaction, per era
  format          Per writer era: what the lake serves
  ledgers         Ledgers holding a component (via the transaction shapes that contain it)
  refusals        Refusals of a run: stage, class, error, classification notes
  grep            Components whose tokens contain a text (id, kind, op type, matching tokens)
  ledger-sep      Ledger components: for each ledger, how many run ledgers within a window share its `L` id
  slice-cover     Transaction-slice cover: one transaction per not yet covered component (ledgers ascending), as `seq<TAB>tx_index`
  fetch-bench     Reader throughput: GET every listed ledger from the lake with N parallel requests, keep nothing
  plan-ranges     Cut [first, tip] into a range plan balanced by bytes plus a fixed per-ledger cost
  verify          Prove that run directories hold every ledger of a range plan exactly once
  merge           Merge workers' run directories into one
  cut-slices      Cut transaction slices out of captured overlay ledger entries
  supervise       Run N scan workers of a range plan: restart on throttle or crash, heartbeat, watchdog
  list-lake       List lake partitions (anonymous ListObjectsV2) into per-partition size files
  diff            Compare two runs file by file
  recall          Known-trigger recall with independent predicates
  heldout         Held-out recall: pinpointed transactions of corpus entries
  census-extract  Census phase 1: one sorted run file per unit (ids at G0–G3 with counts), unit by unit
  census-merge    Census phase 2: bounded k-way merge of the run files into per-level shape lists and a summary
  cover-stream    Greedy example covers (transactions, whole ledgers; ascending and rarest-first) per level, streaming unit by unit
  token-census    Per token and per token class: carrying components, occurrences, ledger range; projection-step attribution of the O components
  chain-check     Header-hash chain, sequence gaps and invariant bits over every ledger, in ledger order
  locate-build    Build the locate index: token, G3 component and G3 tx shape -> (ledger, transaction) postings
  locate          Where a token, token class, G3 component or G3 tx shape occurs (TSV)
  locate-check    Check the locate index against the token census and the pilot index
  entry-tokens    The shape tokens of every corpus entry's focus transaction (or ledger), walked as `scan run` walks a mainnet ledger
  help            Print this message or the help of the given subcommand(s)

Options:
      --corpus <CORPUS>  Corpus root (directory holding corpus.json, manifest/, blobs/) [default: corpus]
  -h, --help             Print help
```

<!-- END GENERATED -->

## `xdrcheck`

| Command | Does | Used for |
|---|---|---|
| `entry --cap N`, `entry --list GLOB`, `entry ID [--decoded VARIANT]` | List corpus entries by CAP or ID glob; show one entry (tags, variants, expected values, declared divergences, mainnet prevalence, the commands that run it) or print a variant decoded | Corpus |
| `serve --network N (--sep54-dir OUT \| --s3 ADDR \| --rpc ADDR)…` | Serve corpus ledgers as a SEP-54 layout on disk, through an S3-compatible store, or as a mock stellar-rpc `getLedgers`, until interrupted; useful for pointing any indexer at the corpus by hand | Ledger delivery |
| `replay --adapter "CMD" --target-version V [--assert-known] [--report DIR] …` | Replay corpus entries through an adapter and classify each one `pass`, `mishandled` or `dropped` (see [replay-harness.md](replay-harness.md)) | Replay harness |
| `replay --selftest` | Check an adapter's protocol conformance without scoring its indexer | Adapter interface |
| `conform fetch` / `build` | Fill each driver directory's package cache from its lock files (network), then build the drivers offline | Conformance runner |
| `conform run [--set NAME \| --columns GLOB] [--report DIR]` | Run entries through the SDK drivers and write the divergence matrix (`matrix.json`, `matrix.md`, `cross-sdk.md`, `report.json`) | Divergence matrix |
| `conform check <matrix.json>` | Fail on any cell that is undeclared, conforms where a divergence is declared, or diverges differently, and on a required column that judged no cell | Regression test across SDKs |
| `conform sdk-regression` | The regression assertions for js-stellar-sdk#1766, #1785 and #1789 on their pre-fix and fixed releases | Conformance check |
| `conform diff <a> <b>`, `conform readiness [--protocol N] [--report DIR]` | Cells that changed between two runs; which pinned SDK versions decode each protocol's and CAP's shapes (`full`, `partial n of m`, `refuses new arms`, `not run`), as `readiness.md` and `readiness.json` | Upgrade review |
| `conform scoreboard --report DIR [--replay FILE]…` | `scoreboard.html`, one self-contained page: per implementation (SDK columns, replayed indexers) the cells that pass, fail as known or fail unexpectedly, failures by bug class, and the findings filed upstream | Sharing a run's results |
| `conform siblings` | For a public finding, run the same entries on sibling SDKs and look up their trackers read-only; writes drafts and prints the commands that would file them | Findings process |
| `findings check --mode development\|acceptance <reports-dir>` | Every failure row maps to a finding record; in acceptance mode every record is `filed`, `duplicate-of` or `not-a-defect` | Findings check |
| `findings new`, `issue`, `list` | Create a candidate record from a report row; write a draft issue and print the command that would file it; list records | Findings process |
| `report acceptance <reports-dir>` | The acceptance table: one row per check with its status (`met`, `not met`, `missing`, `not recorded`, and with `--full-ci` `proven in full CI`), read from that check's own verdict artefact; statuses in [acceptance.md](acceptance.md) | Run summary |
| `report redact <report>`, `report diff <a> <b>` | A copy of a report with evidence strings removed, safe to share; rows that changed between two reports | Third-party runs; upgrade review |
| `pins check` | Every toolchain file, lock file, image and download agrees with `pins.toml` | Pinned, reproducible builds |
| `pins check --today D`, `pins check --network` | The `pins.toml` `[[schedule]]` events (mainnet votes, testnet resets) read against a date; with `--network`, the Horizon roots of mainnet and testnet and the status page against the pins ([maintenance.md §5.5](maintenance.md)) | Dated upgrades and resets do not pass unnoticed |
| `pins latest [--list]` | Each pin with a `# renovate:` annotation against the newest stable upstream release (`--list`: the annotated pins only, offline) | Pin moves ([maintenance.md §5.3](maintenance.md)) |
| `xdr diff <base> <head>` | Structural diff of two XDR definition sets (a `.x` directory, a definitions JSON, `pinned`, or any stellar-xdr git ref): types, enum members, struct fields, union arms with numeric cases, optionality and size bounds; each change with its `#ifdef` gate, the CAP that gate names, and whether `LedgerCloseMetaBatch` or `TransactionEnvelope` reaches it; JSON and Markdown | Upgrade review |
| `xdr watch --out DIR` | Diff every source of unreleased XDR (main, branches, pull requests, pending CAP documents, standing items) against the pins; `watch-log.jsonl`, a digest per upcoming protocol, per-source diffs | Upgrade watch |
| `xdr candidates <diff.json>…` | Candidate `caps.toml`, `arms.toml` and `plan.json` rows for the new shapes of diffs, each marked for review; `--write` edits the files | Upgrade review |
| `xdr ceilings --check\|--write` | The conformance drivers' sentinel-enum ceilings against the pinned XDR definitions | Driver upkeep |

<!-- BEGIN GENERATED: help xdrcheck -->

#### `xdrcheck --help`

```text
usage: xdrcheck <command> [arguments]

commands:
  conform   run the corpus through SDK conformance drivers
  data      the dataset: status, named ledger sets, ledger fetch, manifest, top-up plan
  entry     list corpus entries by CAP or glob; show one entry, its expected values, decoded XDR and mainnet prevalence
  find      example transactions for a token, class, value tag, CAP, assumption or operation type
  findings  check, create and render finding records
  mutate    structure-aware mutants of corpus values through every reader
  overlay   audit the working tree against the private overlay before a push
  pins      check that every version used matches pins.toml
  replay    replay the corpus through an indexer's adapter, or ledgers through a target or a rig
  report    build, redact and diff reports
  repro     pack a run's result into a self-contained bundle, run a bundle, verify its input
  runs      validate run directories and compare two runs by cluster
  serve     serve corpus ledgers as a SEP-54 layout, an object store, or a mock getLedgers
  xcheck    the same transactions through two or more targets or versions; diff the fields both compute
  xdr       diff XDR definition sets, watch upstream, generate driver ceilings and candidate rows
```

#### `xdrcheck conform --help`

```text
usage: xdrcheck conform fetch|build|run|describe|check|sdk-regression|diff|readiness|scoreboard|siblings [flags]
```

#### `xdrcheck conform fetch --help`

```text
Usage of xdrcheck conform fetch:
  -column value
    	one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable
  -columns string
    	comma-separated column globs, for example 'js@17.*,go@*'
  -overlay string
    	private overlay directory (only xdrcheck conform run and xdrcheck conform check read one)
  -pins string
    	pins file (default pins.toml at the repository root)
  -sdk string
    	build and run the selected columns from this SDK checkout instead of their pinned package (one SDK's columns, for example --column go --sdk ../go-stellar-sdk); fetch, build and run all need it
  -set string
    	named column set from drivers/sets.toml (default pr)
```

#### `xdrcheck conform build --help`

```text
Usage of xdrcheck conform build:
  -column value
    	one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable
  -columns string
    	comma-separated column globs, for example 'js@17.*,go@*'
  -overlay string
    	private overlay directory (only xdrcheck conform run and xdrcheck conform check read one)
  -pins string
    	pins file (default pins.toml at the repository root)
  -sdk string
    	build and run the selected columns from this SDK checkout instead of their pinned package (one SDK's columns, for example --column go --sdk ../go-stellar-sdk); fetch, build and run all need it
  -set string
    	named column set from drivers/sets.toml (default pr)
```

#### `xdrcheck conform run --help`

```text
Usage of xdrcheck conform run:
  -as-limit value
    	address-space cap (RLIMIT_AS) per driver process (0 = none)
  -column value
    	one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable
  -columns string
    	comma-separated column globs, for example 'js@17.*,go@*'
  -entries string
    	comma-separated entry ID globs ('*' crosses '/')
  -expected-failures string
    	the column's expected-failure list: the run passes only when its failing cells are exactly the list (a new failure or a listed cell that passes fails it); needs one column
  -goldens string
    	golden cache root for --tier bulk (default $XDRCHECK_GOLDENS, else ~/.cache/xdrcheck/goldens)
  -jobs int
    	columns run in parallel (default the number of CPUs)
  -kind string
    	only entries of this kind (ledger, xdr, api, strkey, spec); --kind spec with neither --set nor --columns selects the spec set
  -level string
    	the same as --levels; --level json with neither --set nor --columns selects the json set
  -levels string
    	comma-separated levels, for example L0,L1 or spec or json (default every applicable level)
  -memory-max value
    	memory cap per driver process, for example 1G or 512M (0 = none) (default 1073741824)
  -overlay string
    	private overlay directory, required to run a column of its sets file (default $XDRCHECK_OVERLAY for those); its corpus/ (manifests, blobs, sidecars) is merged with the public corpus, and the report must be written outside the working tree
  -pins string
    	pins file (default pins.toml at the repository root)
  -report string
    	directory for matrix.json, matrix.md, cross-sdk.md, report.json, cells.ndjson and describe.json
  -require-all-read
    	fail the run when a column never read a selected entry variant (every level n/a, or no level its driver answers)
  -sdk string
    	build and run the selected columns from this SDK checkout instead of their pinned package (one SDK's columns, for example --column go --sdk ../go-stellar-sdk); fetch, build and run all need it
  -set string
    	named column set from drivers/sets.toml (default pr)
  -tier string
    	corpus tier: curated or bulk (default "curated")
  -timeout duration
    	per-request base timeout; a request gets it once more per MiB of input (default 20s)
  -write-expected-failures string
    	write the column's failing cells to this file as an expected-failure list; needs one column
```

#### `xdrcheck conform describe --help`

```text
Usage of xdrcheck conform describe:
  -column value
    	one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable
  -columns string
    	comma-separated column globs, for example 'js@17.*,go@*'
  -overlay string
    	private overlay directory (only xdrcheck conform run and xdrcheck conform check read one)
  -pins string
    	pins file (default pins.toml at the repository root)
  -sdk string
    	build and run the selected columns from this SDK checkout instead of their pinned package (one SDK's columns, for example --column go --sdk ../go-stellar-sdk); fetch, build and run all need it
```

#### `xdrcheck conform check --help`

```text
Usage of xdrcheck conform check:
  -min-judged int
    	judged (not n_a) cells every required column must have (default 1)
  -mode string
    	development (pending cells are reported and pass) or acceptance (they fail) (default "development")
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
  -pending string
    	pending list (default findings/pending/conformance.json at the repository root, when it exists)
```

#### `xdrcheck conform sdk-regression --help`

```text
Usage of xdrcheck conform sdk-regression:
  -column value
    	one SDK's columns by name, for example soroban-spec (every version and profile of it); repeatable
  -columns string
    	comma-separated column globs, for example 'js@17.*,go@*'
  -memory-max value
    	memory cap per driver process (0 = none) (default 1073741824)
  -overlay string
    	private overlay directory (only xdrcheck conform run and xdrcheck conform check read one)
  -pins string
    	pins file (default pins.toml at the repository root)
  -report string
    	directory for sdk-regression.json
  -timeout duration
    	per-request base timeout (default 20s)
```

#### `xdrcheck conform diff --help`

```text
usage: xdrcheck conform diff <matrix-a> <matrix-b>
```

#### `xdrcheck conform readiness --help`

```text
Usage of xdrcheck conform readiness:
  -protocol int
    	only the entries introduced at this protocol (default every protocol)
  -report string
    	the run's report directory: read its matrix.json (unless one is named) and write readiness.md and readiness.json into it
```

#### `xdrcheck conform scoreboard --help`

```text
Usage of xdrcheck conform scoreboard:
  -findings string
    	public finding records directory (default findings/ at the repository root); only public, filed records with an upstream URL are listed
  -matrix string
    	the conformance matrix (default <report>/matrix.json; optional when --replay is given)
  -replay value
    	an indexer replay report (report.json of xdrcheck replay --report); repeatable
  -report string
    	directory to write scoreboard.html and scoreboard.json into (required); its matrix.json is read unless --matrix names one
```

#### `xdrcheck conform siblings --help`

```text
Usage of xdrcheck conform siblings:
  -confirm value
    	an issue or pull request URL a person confirmed describes this defect (repeatable)
  -date string
    	date to record, YYYY-MM-DD (default today, UTC)
  -divergence string
    	start from a known divergence: the upstream reference the matrix cells cite
  -finding string
    	the finding record the defect was found in
  -github-api string
    	GitHub REST API base URL, read with unauthenticated GET only (default "https://api.github.com")
  -manual value
    	manual evidence file for an SDK without a driver (repeatable)
  -matrix string
    	conformance matrix (default reports/conformance/matrix.json)
  -offline
    	do not query the tracker; use the upstream states already recorded
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
  -plan
    	print the plan and write nothing
  -query value
    	tracker search terms (repeatable; default: the first words of each draft's title)
  -templates string
    	draft templates (default findings/templates)
```

#### `xdrcheck data --help`

```text
usage: xdrcheck data <subcommand> [flags]

subcommands:
  status    the dataset present: version, tip ledger, tables and sets with their files (--verify: sha256)
  sets      the named ledger sets shipped with the dataset
  fetch     download ledgers from the public lake into the local ledger cache (size and MD5 checked)
  manifest  write a dataset manifest for derived data under named roots
  update    print the plan of an append-only top-up from the dataset's tip (does not scan)
  export    copy named sets (and small tables) with a manifest into a portable dataset directory, for CI
```

#### `xdrcheck entry --help`

```text
usage: xdrcheck entry [--corpus DIR] (--cap N | --list [GLOB])
       xdrcheck entry [--corpus DIR] [--json] [--decoded [VARIANT]] ENTRY

List corpus entries by CAP or ID glob ('*' crosses '/'), or show one entry. VARIANT is a variant key
(testnet, pubnet@30, none) or its position from 1; --decoded alone takes the first variant.
  -cap int
    	list the entries tagged with this CAP number
  -corpus string
    	corpus root (the directory holding index.json) (default "corpus")
  -decoded string
    	print a variant's decoded SEP-51 JSON (the variant key or position; - for the first)
  -json
    	print the entry's manifest as JSON instead of the summary
  -list
    	list the entries whose ID matches GLOB (default every entry)
```

#### `xdrcheck find --help`

```text
Usage of xdrcheck find:
  -assumption string
    	a linter assumption key (for example text-to-db:memo); --list-assumptions shows the mapped keys
  -cap int
    	the corpus examples of a CAP, and the dataset's cap-N set
  -class string
    	every token of a class, K|class (for example V|u64band)
  -corpus string
    	corpus root (for --cap) (default "corpus")
  -dataset string
    	dataset directory (default $XDRCHECK_DATASET, else the per-user data directory)
  -format string
    	tsv, json or ledgers (one ledger per line, for --ledgers @FILE) (default "tsv")
  -limit int
    	examples to print (default 20)
  -list-assumptions
    	print the assumption keys find can map to ledgers
  -op string
    	an operation type (for example PATH_PAYMENT_STRICT_SEND)
  -order string
    	first, last, rarest (by census occurrences of the matched token) or random (default "first")
  -seed uint
    	seed of --order random (default 1)
  -set string
    	a named set of the dataset
  -source string
    	auto (locate index, else the kept-ledger index), locate or kept (default "auto")
  -tag string
    	a value tag (for example u64>=2^63); a trailing * matches a prefix
  -token string
    	a token, as its text (K|class|path) or its 32-hex id
  -token-contains string
    	every token whose text contains this string (kept-ledger index only)
```

#### `xdrcheck findings --help`

```text
usage: xdrcheck findings check|new|issue|list|tally [flags]
```

#### `xdrcheck findings check --help`

```text
Usage of xdrcheck findings check:
  -mode string
    	development or acceptance (required)
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
  -pending-ok
    	acceptance mode: exit 0 when the only failure is rows awaiting finding review (findings-linked stays not met; printed, and noted in a GitHub job summary and annotation)
```

#### `xdrcheck findings new --help`

```text
Usage of xdrcheck findings new:
  -from string
    	report file (required)
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
  -row string
    	row_id of the failure row (required)
  -sibling-of string
    	finding ID this candidate is a sibling of
```

#### `xdrcheck findings issue --help`

```text
Usage of xdrcheck findings issue:
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
```

#### `xdrcheck findings list --help`

```text
Usage of xdrcheck findings list:
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
  -state string
    	only records in this state
  -target string
    	only records whose project or package contains this text
```

#### `xdrcheck findings tally --help`

```text
Usage of xdrcheck findings tally:
  -make string
    	the make target whose required runs' reports to tally (required)
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY)
```

#### `xdrcheck mutate --help`

```text
usage: xdrcheck mutate run|replay|minimise|promote [flags]
```

#### `xdrcheck mutate run --help`

```text
Usage of xdrcheck mutate run:
  -adapter-deadline duration
    	ingest deadline per replay unit (default: sized from the adapter's describe)
  -adapter-memory-max value
    	memory cap for an adapter's process group (default 4294967296)
  -adapter-parallel int
    	replay units run at once per adapter (default 4)
  -adapters string
    	replay adapters: all, none, or wallet-backend,stellar-etl,baseline (default "all")
  -all-variants
    	every variant of an entry, not only the first
  -as-limit value
    	address-space cap (RLIMIT_AS) per driver process: SIZE for every column, or GLOB=SIZE,… per column (0 = none)
  -budget int
    	mutants to build (default 2000)
  -classes string
    	mutator classes (default "valid,metamorphic,wire-invalid")
  -columns string
    	conformance columns: all, none, or comma-separated column globs (default "all")
  -entries string
    	source entry ID globs, comma-separated
  -jobs int
    	conformance columns run in parallel (default the number of CPUs)
  -max-bytes int
    	largest corpus value used as a source (default 262144)
  -memory-max value
    	memory cap per driver process (0 = none) (default 1073741824)
  -minimise int
    	candidates minimised at most (each costs a run of its readers per mutation) (default 400)
  -mutate-bin string
    	the xdrcheck-mutate binary (default $XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate)
  -mutators string
    	mutator IDs (default every mutator of the classes)
  -no-cut
    	do not cut envelopes and SCVals out of ledgers as sources
  -no-suppress
    	report signatures that match existing findings too
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY, else ~/.local/share/xdrcheck/overlay)
  -pins string
    	pins file (default pins.toml at the repository root)
  -report string
    	report directory (default <work>/report)
  -seed uint
    	seed (default 1)
  -set string
    	named column set (with --columns other than all or none)
  -stale-hashes
    	leave ledger hashes stale after a valid-preserving mutation
  -timeout duration
    	per-request base timeout of a driver (default 20s)
  -work string
    	work directory for the mutant corpus and the runners' reports (outside the repository)
```

#### `xdrcheck mutate replay --help`

```text
Usage of xdrcheck mutate replay:
  -adapter-deadline duration
    	ingest deadline per replay unit (default: sized from the adapter's describe)
  -adapter-memory-max value
    	memory cap for an adapter's process group (default 4294967296)
  -adapter-parallel int
    	replay units run at once per adapter (default 4)
  -as-limit value
    	address-space cap (RLIMIT_AS) per driver process: SIZE for every column, or GLOB=SIZE,… per column (0 = none)
  -entry string
    	the mutant's source: an entry ID, or <entry>#<path> for a value cut from a ledger
  -jobs int
    	conformance columns run in parallel (default the number of CPUs)
  -memory-max value
    	memory cap per driver process (0 = none) (default 1073741824)
  -mutate-bin string
    	the xdrcheck-mutate binary (default $XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate)
  -mutation string
    	mutation IDs, comma-separated, in order
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY, else ~/.local/share/xdrcheck/overlay)
  -pins string
    	pins file (default pins.toml at the repository root)
  -print string
    	print only this reader's verdict line
  -readers string
    	readers: column IDs and adapters (name or name@version), 'columns' or 'all' (default "all")
  -seed uint
    	seed (default 1)
  -stale-hashes
    	leave ledger hashes stale after a valid-preserving mutation
  -timeout duration
    	per-request base timeout of a driver (default 20s)
  -variant int
    	the source's variant index
  -work string
    	work directory for the mutant corpus and the runners' reports (outside the repository)
```

#### `xdrcheck mutate minimise --help`

```text
Usage of xdrcheck mutate minimise:
  -adapter-deadline duration
    	ingest deadline per replay unit (default: sized from the adapter's describe)
  -adapter-memory-max value
    	memory cap for an adapter's process group (default 4294967296)
  -adapter-parallel int
    	replay units run at once per adapter (default 4)
  -as-limit value
    	address-space cap (RLIMIT_AS) per driver process: SIZE for every column, or GLOB=SIZE,… per column (0 = none)
  -entry string
    	the mutant's source: an entry ID, or <entry>#<path> for a value cut from a ledger
  -jobs int
    	conformance columns run in parallel (default the number of CPUs)
  -memory-max value
    	memory cap per driver process (0 = none) (default 1073741824)
  -mutate-bin string
    	the xdrcheck-mutate binary (default $XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate)
  -mutation string
    	mutation IDs, comma-separated, in order
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY, else ~/.local/share/xdrcheck/overlay)
  -pins string
    	pins file (default pins.toml at the repository root)
  -reader string
    	the reader whose verdict is kept
  -readers string
    	readers to judge with (default the reader and the stellar-core column; a split needs the run's columns)
  -seed uint
    	seed (default 1)
  -stale-hashes
    	leave ledger hashes stale after a valid-preserving mutation
  -timeout duration
    	per-request base timeout of a driver (default 20s)
  -variant int
    	the source's variant index
  -work string
    	work directory for the mutant corpus and the runners' reports (outside the repository)
```

#### `xdrcheck mutate promote --help`

```text
Usage of xdrcheck mutate promote:
  -adapter-deadline duration
    	ingest deadline per replay unit (default: sized from the adapter's describe)
  -adapter-memory-max value
    	memory cap for an adapter's process group (default 4294967296)
  -adapter-parallel int
    	replay units run at once per adapter (default 4)
  -as-limit value
    	address-space cap (RLIMIT_AS) per driver process: SIZE for every column, or GLOB=SIZE,… per column (0 = none)
  -entry string
    	the mutant's source: an entry ID, or <entry>#<path> for a value cut from a ledger
  -id string
    	the new entry's ID
  -into string
    	corpus root to write into (default <overlay>/corpus)
  -jobs int
    	conformance columns run in parallel (default the number of CPUs)
  -memory-max value
    	memory cap per driver process (0 = none) (default 1073741824)
  -mutate-bin string
    	the xdrcheck-mutate binary (default $XDRCHECK_MUTATE_BIN, else target/release/xdrcheck-mutate)
  -mutation string
    	mutation IDs, comma-separated, in order
  -overlay string
    	private overlay directory (default $XDRCHECK_OVERLAY, else ~/.local/share/xdrcheck/overlay)
  -pins string
    	pins file (default pins.toml at the repository root)
  -public
    	allow writing into the repository's corpus (the ID must then be in corpus/plan.json)
  -seed uint
    	seed (default 1)
  -stale-hashes
    	leave ledger hashes stale after a valid-preserving mutation
  -timeout duration
    	per-request base timeout of a driver (default 20s)
  -variant int
    	the source's variant index
  -work string
    	work directory for the mutant corpus and the runners' reports (outside the repository)
```

#### `xdrcheck overlay --help`

```text
usage: xdrcheck overlay audit [flags]
```

#### `xdrcheck pins --help`

```text
usage: xdrcheck pins check [--pins FILE] [--today YYYY-MM-DD] [--network]
       xdrcheck pins latest [--pins FILE] [--json FILE] [--list]
```

#### `xdrcheck replay --help`

```text
usage: xdrcheck replay --adapter "COMMAND" --target-version V [flags]
         replay the corpus through an indexer's adapter (the flags below)
       xdrcheck replay --target T --version V (--ledgers L | --tx T | --set S | --cap N | --issue I | --ledger-file F) [flags]
         run an SDK or pipeline target over ledgers and write a run directory (xdrcheck replay --target T --help)
       xdrcheck replay --rig wallet-backend|stellar-etl|horizon --ledgers L --commit C --lake DIR --out DIR [flags]
         run a service rig directly: raw rig output, not a run directory (xdrcheck replay --rig R --help)

Flags of the corpus form:
  -adapter string
    	the adapter's command line (required)
  -assert-known
    	run only entries with a known divergence for this target; fail on any other result than the declared one
  -caps string
    	comma-separated CAP numbers
  -confirm int
    	re-run a unit with a non-pass result K more times; differing results are flaky
  -corpus string
    	corpus root (default "corpus")
  -deadline duration
    	ingest deadline per unit (default: sized from describe.timing)
  -entries string
    	comma-separated entry ID globs
  -findings string
    	after the run, apply the development-mode findings check to this run's report against the records in this directory
  -input string
    	sep54-s3, sep54-gcs, sep54-dir or rpc (default: the first the adapter declares)
  -keep-going
    	continue after a harness fault
  -keep-state
    	keep each session's state and directories
  -memory-max value
    	memory cap for the adapter's group, for example 1G
  -network string
    	all, testnet, pubnet or core-test (default "all")
  -out-of-envelope string
    	probe or skip: out-of-envelope entries of an indexer_gate adapter (default "probe")
  -overlay string
    	private overlay directory: merge its corpus/ with the public corpus (the report must then be written outside the working tree)
  -parallel int
    	units run at once, each with its own adapter process (default 1)
  -pids-max int
    	process cap for the adapter's group
  -pins string
    	pins file (default pins.toml beside the corpus)
  -repeat int
    	stream: repeat the pass's ledgers K times (default 1)
  -report string
    	write report.json, describe.json, REPORT.md and logs/ here
  -resume
    	skip entries already in the report (not built)
  -selftest
    	check the adapter's protocol conformance without scoring the indexer
  -target-version string
    	version or full commit of the indexer under test (required)
  -unit string
    	auto, single, chain or stream (default "auto")
```

#### `xdrcheck report --help`

```text
usage: xdrcheck report acceptance|redact|diff [flags] <args>
```

#### `xdrcheck report acceptance --help`

```text
Usage of xdrcheck report acceptance:
  -full-ci targets
    	comma-separated targets: make targets only the full CI runs; a check met here whose other runs are theirs is "proven in full CI"
  -out string
    	output file (default <reports-dir>/acceptance.md)
```

#### `xdrcheck report redact --help`

```text
Usage of xdrcheck report redact:
  -out string
    	output file (default standard output)
```

#### `xdrcheck report diff --help`

```text
Usage of xdrcheck report diff:
```

#### `xdrcheck repro --help`

```text
usage: xdrcheck repro pack RUN_DIR --cluster KEY [--tx LEDGER:INDEX] [--out DIR]
       xdrcheck repro run BUNDLE [--version V] [--out DIR]
       xdrcheck repro verify BUNDLE
```

#### `xdrcheck runs --help`

```text
usage: xdrcheck runs validate DIR...
       xdrcheck runs compare DIR_A DIR_B
```

#### `xdrcheck serve --help`

```text
Usage of xdrcheck serve:
  -chain string
    	serve this chain run as one chain unit
  -corpus string
    	corpus root (default "corpus")
  -delivery-log string
    	append one JSON line per request to this file
  -entries string
    	entry ID glob
  -gcs string
    	GCS endpoint (not built)
  -ledgers string
    	S..E: only ledgers in this range
  -network string
    	pass to serve: testnet, pubnet or core-test (required)
  -overlay string
    	private overlay (not supported by serve yet)
  -pins string
    	pins file (for the object-store image) (default "pins.toml")
  -proxy-to string
    	log and forward to an external emulator (not built)
  -rpc string
    	serve the mock getLedgers here
  -s3 string
    	serve the layouts from an S3 store whose logging proxy listens here
  -sep54-dir string
    	write each unit's SEP-54 layout under this directory
  -stream-base uint
    	first sequence of a stream unit (default 1000)
  -unit string
    	single, chain or stream (default: what each entry needs)
```

#### `xdrcheck xcheck --help`

```text
Usage of xdrcheck xcheck:
  -corpus string
    	corpus root (for --cap, --issue and corpus ledgers) (default "corpus")
  -dataset string
    	dataset directory (default $XDRCHECK_DATASET, else the per-user data directory)
  -lake string
    	ledger cache in lake layout (default $XDRCHECK_LAKE, else <dataset>/lake)
  -lake-url string
    	lake URL to fetch missing ledgers from (default: the public pubnet lake)
  -ledger-file value
    	a ledger object file; repeatable
  -ledgers string
    	ledgers: comma-separated sequences and ranges a-b, or @FILE
  -max-ledgers int
    	refuse selections larger than this (default 2000)
  -network string
    	pubnet or testnet (default: pubnet, or the network of the issue or corpus entry)
  -offline
    	never use the network: no ledger download, no target fetch
  -out string
    	output directory (default xcheck/<time>)
  -parallel int
    	downloads in flight (at most 256) (default 64)
  -rate float
    	download requests per second, 0 for no cap (default 200)
  -rules
    	print the normalisation rules and exit
  -set string
    	a named set of the dataset
  -target value
    	TARGET@VERSION (go, js, python or rust); give two or more; repeatable
  -tx value
    	a transaction LEDGER:INDEX; repeatable
```

#### `xdrcheck xdr --help`

```text
usage: xdrcheck xdr diff|ceilings|candidates|watch [flags]
```

#### `xdrcheck xdr diff --help`

```text
usage: xdrcheck xdr diff [flags] <base> <head>

base and head: a directory of .x files, a definitions .json(.zst), `pinned`, or a stellar-xdr git ref.
  -base-features string
    	features enabled in the base: none, all, or a comma-separated list (default "none")
  -cap string
    	attribute every change to this CAP (CAP-NNNN), e.g. for a CAP document's own diff
  -exit-code
    	exit 1 when the sets differ
  -format string
    	what to print: md or json (default "md")
  -head-features string
    	features enabled in the head: none, all, or a comma-separated list (default "all")
  -json string
    	also write the JSON report to this file
  -md string
    	also write the Markdown report to this file
  -repo string
    	git repository git refs are read from (default "https://github.com/stellar/stellar-xdr.git")
  -roots string
    	types whose reachability marks a change as reader-visible (default "LedgerCloseMetaBatch,TransactionEnvelope")
```

#### `xdrcheck xdr ceilings --help`

```text
Usage of xdrcheck xdr ceilings:
  -check
    	fail (exit 1) when a block differs from the definitions; write nothing
  -defs string
    	the definitions: a .x directory, a definitions .json(.zst) or a stellar-xdr git ref (default: the vendored pinned definitions, crates/xdrcheck-corpus/data/xdr-definitions-v30.0.0.json.zst)
  -dir string
    	directory searched for ceiling blocks (default "drivers")
  -label string
    	the definitions' label written on each block's BEGIN line (default: stellar-xdr <pinned tag>)
  -repo string
    	git repository a git ref is read from (default "https://github.com/stellar/stellar-xdr.git")
  -write
    	rewrite every block from the definitions
```

#### `xdrcheck xdr candidates --help`

```text
usage: xdrcheck xdr candidates [flags] (--from candidates.txt | <diff.json>...)
  -caps-info xdrcheck xdr watch
    	CAP preambles as xdrcheck xdr watch writes them (caps.json)
  -corpus string
    	corpus directory holding caps.toml, arms.toml and plan.json (default "corpus")
  -from string
    	a file listing diff reports, one per line, relative to its own directory (candidates.txt of a watch run)
  -next-protocol int
    	protocol for rows no CAP names (default: pins.toml max_supported + 1)
  -write
    	rewrite the three files in place (default: write nothing, list the rows)
```

#### `xdrcheck xdr watch --help`

```text
Usage of xdrcheck xdr watch:
  -api string
    	GitHub API base URL (read-only; GH_TOKEN or GITHUB_TOKEN is sent when set) (default "https://api.github.com")
  -github-repo string
    	the same repository as owner/name, for listing open pull requests (default "stellar/stellar-xdr")
  -next-protocol int
    	the next protocol (default: pins.toml max_supported + 1)
  -out string
    	output directory (required)
  -previous string
    	the previous run's watch-log.jsonl, carried over and used to mark what is new
  -protocol-repo string
    	the CAP repository (default "https://github.com/stellar/stellar-protocol.git")
  -repo string
    	the XDR definitions repository (default "https://github.com/stellar/stellar-xdr.git")
  -skip string
    	parts not to run, comma-separated: main, branches, prs, caps
  -standing string
    	stellar-xdr branches always reported, comma-separated (default "lcm_v3")
```

<!-- END GENERATED -->

## `xdrlint`

`xdrlint` runs the rules over Go packages and prints findings with rule IDs; it exits 1 when an unsuppressed
finding at or above `-fail-on` exists, and 2 (with a warning) when none of the packages it loaded, nor anything
they import, is go-stellar-sdk's `xdr` package, since its rules then have nothing to analyse. The same analyzers
run as a `go vet` tool (`go vet -vettool=$(which xdrlint) ./...`) and inside golangci-lint as a module plugin
(`make lint-plugin`). Each rule has its own page under [`lint/docs/`](../lint/docs/README.md).

<!-- BEGIN GENERATED: help xdrlint -->

#### `xdrlint -h`

```text
usage: xdrlint [flags] <packages>
       go vet -vettool=$(which xdrlint) <packages>

flags:
  -config FILE
    	project configuration FILE (default: .xdrlint.yml found from the working directory up to the module root)
  -docs-base BASE
    	where diagnostics link the rule pages: BASE/XDR103.md, or a URL template with {rule} (env XDRLINT_DOCS_BASE) (default "lint/docs")
  -expect FILE
    	compare (rule, file, function, suppressed) of the reports with the expected list in FILE; exit 1 on any difference
  -fail-on string
    	lowest severity that fails the run: error, warning or info (default "error")
  -json
    	print diagnostics as JSON
  -overlay DIR
    	private overlay DIR (loads DIR/xdrlint.yml)
  -pending FILE
    	reports pending finding review, as (rule, file, line) in FILE (xdrlint.pending/v1); they are marked pending in -report and do not fail the run
  -profile NAME
    	shipped profile NAME or profile file PATH
  -report FILE
    	write every diagnostic, suppressed ones included, as xcc.report/v1 to FILE
  -sarif FILE
    	write SARIF 2.1.0 to FILE

shipped profiles: default, fixtures, wallet-backend

rules in this build:
  XDR000 (error) suppression without a reason, naming an unknown rule, or suppressing nothing
  XDR101 (error) address built from a memo
  XDR102 (error) unnormalised address used as an identity key
  XDR103 (error) unvalidated bytes or string into text storage
  XDR105 (warning, opt-in) Must<Arm>() on a multi-arm union without a dominating discriminant check
  XDR201 (warning) recursion over a self-referential xdr type with no depth bound
  XDR202 (warning) iterative walker with an unbounded worklist
  XDR203 (warning) decoded integer used as an allocation size or loop bound
  XDR204 (info, opt-in) persisted serialisation of a recursive value with no length check
  XDR205 (error) decoder with limits disabled
  XDR206 (warning) behaviour at a bound differs from the declared overflow policy
  XDR207 (warning) bound below what stellar-core admits, on a path fed from ledger meta
  XDR301 (error) participants harvested from the authorization tree or invocation arguments
  XDR302 (error) envelope operation fields used as participants without a success gate
  XDR303 (warning) participant builder that never reads meta
  XDR304 (error) token-shaped contract event trusted without checking the emitting contract
  XDR401 (error) one meta version assumed: an arm read without a version check, or a version check that halts on the others
  XDR402 (error) wide integer narrowed without a range check and stored
  XDR403 (warning) error or ok result discarded on a value that is then stored
  XDR404 (error) contract event topics or data trusted by position or kind without a shape or emitter check
  XDR405 (error) rows from diagnostic events without a success gate, or from transaction-level changes in operation scope
  XDR406 (warning, opt-in) closed switch over an xdr enum that writes rows, with no default or a panicking default
```

<!-- END GENERATED -->

## `make` targets

Each target runs the same command locally and in CI. A row that says "network" reaches the network; every check
also runs with it unreachable under `OFFLINE=1` (below).

| Target | Runs |
|---|---|
| `make toolchain` | Check the installed toolchains against `pins.toml` |
| `make fetch` | Network: everything every target needs: crates, Go modules, Python packages, the stellar-core package and goldens, container images, driver packages and pipeline sources, all pinned and hash-verified (`scripts/fetch.sh all`). `FETCH_ONLY="PART..."` fetches only the named parts (`scripts/fetch.sh` lists them: `deps`, `core`, `conform-pr`, `drivers`, `driver:DIR`, `wallet-backend`, `lint-sources`, `lint-sources-wb`, `docs`, ...); each CI job names the parts its target needs |
| `make demo` | The one-minute demo: replays an indexer with one planted bug (`go/adapters/demo`) from a plain directory and prints its failures with repro commands; exits 0 when the bug is found |
| `make fetch-replay` | Network, for indexer authors: the build dependencies (Python packages, crates, Go modules) and the pinned SeaweedFS image the replay harness serves the `sep54-s3` input from |
| `make fetch-sdk` | Network, for SDK maintainers: the build dependencies and every public conformance column's driver packages, stellar-core's own decoder among them (`xdrcheck conform fetch --set public`) |
| `make fetch-lint` | Network, for `xdrlint` users: the build dependencies (xdrlint's Go modules among them) and golangci-lint at the pinned version with the xdrlint module plugin |
| `make build` | Build `xdrcheck-corpus`, `xdrcheck-mutate`, `xdrcheck`, the adapters and `xdrlint`, link them into `./bin`, and print the `export PATH=…` line |
| `make release` | `scripts/release.sh all`: build the release archive twice and compare, verify it offline from an empty directory, check the stable/`-next` channel split, pack and check the npm package, and write `dist/SHA256SUMS` and the release provenance ([release.md](release.md)); `VERSION=<MAJOR+1>.0.0-rc.N` builds the `-next` channel (refused while the corpus has no next-protocol entry) |
| `make repo-checks` | Repository checks that need no build: schemas and their examples, corpus data, entry IDs, the field table source and guide claims, the public-tree scan and its history self-test, the documentation site's generated pages (`apps/docs/scripts/generate.py --check`), workflow rules, the results data (`results-check`), the corpus entries the guide cites (`check_guide_entries.py`), the mainnet tier's files (`mainnet-tier-check`), and, when `xdrcheck-corpus` is built, the guide's field table, the coverage report with the golden mirror listing and the corpus index (`--check` of each) |
| `make ci-local` | `scripts/ci/run-local.sh`: the jobs of `.github/workflows/pr.yml` (`TIER=pr`) or `full.yml` (`TIER=full`), or one job and the jobs it needs (`JOB=<id>`), run as on a cold hosted runner: a fresh clone of `SHA` (default `HEAD`) per job, an empty home with only the job's declared fetch parts and artifacts, 2 CPUs and 7 GiB per step, the workflow's run lines as written; writes `summary.md` (result, wall time, fetch time, peak disk per job) under `CI_LOCAL_OUT` (network for the fetch steps) |
| `make overlay-audit` | The pre-push gate of `SECURITY.md`: `xdrcheck overlay audit` against `$XDRCHECK_OVERLAY` (skipped when it is not set) |
| `make verify-static` | `repo-checks`, then `xdrcheck-corpus verify --checks schema,hashes,ids` and `xdrcheck pins check` |
| `make verify-corpus` | `xdrcheck-corpus verify --tier curated --report reports/corpus-verify.json` |
| `make verify-generate` | `xdrcheck-corpus gen --check --list corpus/scenarios/pr.list`, always without network |
| `make test` | Unit tests of every component: `test-rust`, `test-go`, `test-drivers` and `test-cli`; the full CI's unit jobs |
| `make test-rust` | `cargo test --locked --workspace` |
| `make test-go` | `go test` in `go/` and `lint/` |
| `make test-cli` | `scripts/py/check_cli_reference.py`: this page against the built tools' help and `make help` |
| `make test-drivers` | Each driver directory's `make test` (and, with `XDRCHECK_OVERLAY` set, each overlay driver's), several directories at once (`scripts/test-drivers.sh`), each one's versions in turn; `DRIVERS=js,go@v0.9.0` runs only those directories or `DIR@VERSION` items (the CI splits them over several jobs, and `scripts/ci/check-workflows.sh` checks that the jobs cover every directory and version) |
| `make test-fast` | The pull-request unit tier: `test-rust-fast`, `test-go-fast`, `test-drivers` and `test-cli` |
| `make test-rust-fast` | Every test `test-rust` runs, the test binaries side by side (`scripts/cargo-test-parallel.sh`): the same build, every binary from its package directory, the documentation tests through `cargo test --doc`; nothing skipped or filtered |
| `make test-go-fast` | `test-go` with `go test -short`: a test that checks `testing.Short()` skips (today only `TestTemplateBuildsInItsOwnModule`, which builds the minimal adapter's template as a module of its own) |
| `make check-adapter-ts` | The TypeScript minimal adapter (`examples/adapter-ts`): installs its pinned dependency, runs its selftest and a full replay |
| `make harness-selftest` | Every seeded-bug indexer is replayed and must land in its documented class |
| `make verify-memory` | The replay harness's memory-bound tests and their negative control |
| `make verify-replay` | The reference adapter on every pinned pre-fix and fixed wallet-backend commit, and on the current one |
| `make verify-replay-pr` | The pull-request CI's form of `verify-replay`: the same script and row-by-row assertions on one input, `REPLAY_PR_INPUT` (default `rpc`, the cheaper one); the full CI runs both inputs |
| `make replay-full` | `scripts/replay-full.sh`: the whole curated corpus against wallet-backend at the pinned current commit, on the `sep54-s3` and `rpc` inputs, into `reports/replay-full/wallet-backend-<input>/`; fails on a harness fault, an entry without a row or anything left behind (its unexpected rows are judged by the findings check); not part of `verify`, about 8 minutes |
| `make replay-etl-known` | `scripts/replay-etl-known.sh`: the corpus entries that declare a stellar-etl replay divergence, against stellar-etl at its pinned commit (`pins.toml`), with `--assert-known`, into `reports/replay-etl-known/stellar-etl-<commit>/`; fails when the run cannot be made, a row is not of the pinned commit or an entry does not show its declared result; a run of the findings check's required set, not part of `verify` |
| `make verify-conformance` | `xdrcheck conform build`, `sdk-regression`, `run` and `check` on the per-pull-request column set |
| `make verify-conformance-js` | The pull-request CI's form of the `conform sdk-regression` assertions: `xdrcheck conform build` of the three JavaScript columns the assertions use, then `xdrcheck conform sdk-regression`, into `reports/conformance/sdk-regression.json`; the `pr`-set matrix around it runs in the full CI (`verify-conformance`) |
| `make verify-conformance-public` | `xdrcheck conform build`, `run` and `check` on the `public` column set into `reports/conformance-public/`; not part of `verify`; `verify-acceptance` runs it before `verify-findings-acceptance` |
| `make sdk-loaders` | The corpus loaders an SDK's own tests use (`packages/go`, `packages/rust`, `packages/python`, `packages/npm`), each tested against this corpus ([use-in-sdk-ci.md](use-in-sdk-ci.md) §1) |
| `make sdk-ci-examples` | The Go, Rust and Python SDK CI recipes (`examples/sdk-ci/<lang>`) against the pinned go-stellar-sdk, stellar-xdr and stellar-sdk, offline from the caches `make fetch-sdk` fills; each must equal its committed expected-failure list ([use-in-sdk-ci.md](use-in-sdk-ci.md) §2) |
| `make sdk-ci-recipes` | `examples/sdk-ci/check_recipes.py`: each SDK CI recipe (Go, Rust, Python, JavaScript) end to end as an SDK maintainer uses it: a scratch SDK repository holding the pinned SDK's tree and the recipe wired to it, the workflow's own test step, offline; each must pass as committed and fail on a new divergence (`SDKCI_LANGS="go js"` selects languages; [use-in-sdk-ci.md](use-in-sdk-ci.md) §2) |
| `make sdk-readiness` | Over the run `make verify-conformance-public` wrote: the readiness table (`readiness.md`, `readiness.json`: which pinned SDK versions decode each protocol's and CAP's shapes) and the scoreboard page (`scoreboard.html`), into the same report directory |
| `make results` | `results-findings`, `results-known-defects`, `results-conformance`, `results-replay` and `results-acceptance`: every file under `evidence/results/` (formats in `evidence/results/README.md`); `RESULTS_CHECK=1` compares each with its sources instead of writing it |
| `make results-conformance` | `scripts/py/results.py conformance`: `evidence/results/conformance-matrix.json` from the runs `make verify-conformance` and `make verify-conformance-public` wrote under `REPORTS` |
| `make results-replay` | `scripts/py/results.py replay`: `evidence/results/replay-summary.json` from the runs of `make replay-full`, `verify-replay`, `replay-etl-known` and `harness-selftest` under `REPORTS` |
| `make results-acceptance` | `scripts/py/results.py acceptance`: `evidence/results/acceptance.json`, one row per acceptance check of `docs/acceptance.md` with the status and reason of the acceptance table `make verify-acceptance` wrote under `REPORTS` (`acceptance.json` beside `acceptance.md`) |
| `make results-findings` | `scripts/py/results.py findings`: `evidence/results/findings.json` from the public finding records |
| `make results-known-defects` | `scripts/py/results.py known-defects`: `evidence/results/known-defects.json` from the README's known upstream defects table |
| `make results-prevalence` | `xdrcheck-corpus scan entry-tokens`, then `scripts/py/results.py prevalence`: `evidence/mainnet-scan/entry-prevalence.json`, each corpus entry's rarest shape token and how often it occurs on mainnet, from the scan's token table (`TOKEN_TABLE`, not in the repository) |
| `make results-check` | `scripts/py/results.py check`, part of `repo-checks`: `findings.json` and `known-defects.json` equal a fresh generation; the run summaries are consistent with `corpus/index.json`, `findings/` and `findings/pending/` |
| `make results-siblings` | `scripts/py/sibling_matrix.py generate`: `evidence/results/sibling-matrix.json` and [`findings/SIBLINGS.md`](../findings/SIBLINGS.md), each SDK defect class against each SDK family, from the level-resolved runs of `make verify-conformance` and the public set under `REPORTS`; `RESULTS_CHECK=1` compares instead of writing |
| `make results-siblings-refresh` | `scripts/py/sibling_matrix.py refresh`: the sibling matrix's record states and its page from `findings/`, without a run (after a record changes state) |
| `make results-mainnet` | `xdrcheck-corpus mainnet coverage`: `evidence/results/mainnet-coverage.json`, the tier's transaction-level tokens held by the mainnet tier and by the curated corpus; `RESULTS_CHECK=1` compares instead of writing |
| `make results-mainnet-check` | `xdrcheck-corpus mainnet coverage --check`, part of `verify-coverage`: the statement is current with `corpus/mainnet/` and the curated corpus (it moves when an entry adds a token) |
| `make results-siblings-check` | `scripts/py/sibling_matrix.py check` and its tests, part of `repo-checks`: the sibling matrix is consistent with `conformance-matrix.json` and `findings/`, and `findings/SIBLINGS.md` is its rendering |
| `make lint-fixtures` | The linter's seeded-violation fixtures (`go test -json` in `lint/`, into `reports/lint-fixtures.jsonl`) |
| `make lint-wallet-backend` | `xdrlint` on wallet-backend at the pinned current commit, compared by count with a frozen expected list; every suppression names its line or anchor, xdrlint's exit status must agree with its report, and the first line and `lint-wallet-backend.summary.json` (`clean`, `clean_statement`) say whether the commit runs clean (xdrlint exits 0 with the shipped profile after the suppressions) or what keeps it from it; `XDRCHECK_LINT_REQUIRE_CLEAN=1` fails a run that is not clean; reports on the commit's pending list are marked `pending` (they do not change xdrlint's exit status) but still keep the commit from being clean |
| `make lint-before-after` | Each rule fires before its upstream fix and is silent after |
| `make lint-stellar-etl` | `xdrlint`, built with the Go toolchain stellar-etl requires (`pins.toml` `[pipelines.stellar_etl] go_toolchain`), on stellar-etl at the pinned commit, compared by count with the frozen lists in `lint/expected/stellar-etl/`; the summary says whether it runs clean, as for `lint-wallet-backend` |
| `make lint-selftest` | Shows the pinned-commit check can fail: an added violation, a second report in a suppressed function (with the suppression at its line, and widened to the function), a function-wide suppression, a stale suppression and a stale pending entry each turn it red |
| `make lint-docs` | The rule pages under `lint/docs/` match the rule registry and fixtures |
| `make lint-plugin` | The golangci-lint module plugin loads under the pinned golangci-lint |
| `make verify-lint` | `lint-fixtures`, `lint-wallet-backend`, `lint-before-after`, `lint-stellar-etl`, `lint-selftest` |
| `make verify-lint-pr` | The pull-request CI's form of `verify-lint`: `lint-fixtures` and `lint-wallet-backend`; the before/after pairs, stellar-etl and the self-test run in the full CI |
| `make verify-guide` | `xdrcheck-corpus guide-table --check --report reports/guide-table.json` and `guide-claims --check`; with the network (`DOCS=1`, the default when not offline), the documentation site's own checks |
| `make verify-coverage` | `xdrcheck-corpus coverage --check`, and `results-mainnet-check` |
| `make mainnet-fetch` | `xdrcheck-corpus mainnet fetch` (network): the mainnet tier's 6,150 public-lake objects, about 1 GB, into `$XDRCHECK_CACHE/mainnet/`, hash-checked and resumable; a full cache makes no request (also `make fetch FETCH_ONLY=mainnet`; not part of `make fetch`) |
| `make verify-mainnet` | `xdrcheck-corpus mainnet check` from the cache `make mainnet-fetch` filled, offline under `OFFLINE=1`: every part's hash chain to its lake object, its round trip and its cut, and the tier's 15,186 transaction-level tokens recomputed with the scan's emitter ([corpus/mainnet](../corpus/mainnet/README.md)); writes `reports/mainnet-check.tsv`; the full CI's P18 |
| `make mainnet-tier-check` | `scripts/py/check_mainnet_tier.py`, part of `repo-checks`: `corpus/mainnet/tier.json` and every line of `tier.jsonl` against their schemas, the header's sha256 and counts, one line per transaction and each token on one line, the lake keys and the cover order, without the lake objects |
| `make verify-findings` | `xdrcheck findings check --mode development reports` (drafts allowed); a stale pending entry fails it once every required run that could hold its rows is among the reports |
| `make verify-findings-acceptance` | `xdrcheck findings check --mode acceptance reports`: also fails on a missing run of the required set (`findings/required-runs.d/`), on any pending row, and on a pending entry older than 90 days or without a `since` date; with `PENDING_OK=1` (`--pending-ok`, the full CI on main) rows awaiting finding review alone exit 0 with the note "findings-linked not met: N rows await finding review; this blocks a release tag, not main" (and, in GitHub Actions, a warning annotation and a job summary line), every other failure still fails |
| `make acceptance-report` | `xdrcheck report acceptance reports`: writes `reports/acceptance.md` |
| `make acceptance-report-pr` | `xdrcheck report acceptance reports --full-ci <targets>`: the pull-request CI's table, where a check met on that run whose other runs only the full CI makes (`verify-replay`, `verify-conformance`, `lint-before-after`, `lint-stellar-etl`) is `proven in full CI` |
| `make dist-bin` | `scripts/dist.sh bin`: `dist/xdrcheck-<version>-<os>-<arch>.tar.gz` with `xdrcheck`, `xdrcheck-corpus`, `xdrlint` and the template adapters (Linux) or `xdrlint` (macOS), for each platform of `DIST_PLATFORMS` that builds completely on this machine, then `SHA256SUMS`; `DIST_STRICT=1` fails on one that does not ([release.md §9](release.md#9-release-assets-prebuilt-binaries-and-the-pin-helper)) |
| `make dist-image` | `scripts/dist.sh image`: the container image `xdrcheck-dist:<version>` from the release assets in `dist/`, built with the network off and smoke-tested offline (each tool starts, the bundled corpus verifies, the demo replay finds its bug, the minimal adapter passes), then removed unless `KEEP_IMAGE=1` ([release.md §10](release.md#10-container-image)) |
| `make release-assets` | `scripts/dist.sh assemble`: `SHA256SUMS` and `xdrcheck-<version>.provenance.json` over every asset of the version in `dist/`, each asset checked against them, then the `dist-image` smoke test; what the release workflow runs last |
| `make action-selftest` | `action/selftest.sh`: the GitHub Action (`action.yml`) run step by step against the release in `dist/`, every mode and failure path, and the workflow examples of [github-action.md](github-action.md) through actionlint |
| `make verify` | Every check at full size, then the run summary table (`acceptance-report`): what the full CI runs besides `make test` |
| `make verify-pr` | What the pull-request CI runs: `verify-static`, `verify-corpus`, `verify-generate`, `test-fast`, `verify-replay-pr`, `verify-conformance-js`, `verify-lint-pr`, `verify-guide`, `verify-coverage`, `verify-findings`, then `acceptance-report-pr` |
| `make verify-acceptance` | `verify` plus `replay-full`, `replay-etl-known` and `verify-conformance-public`, with the acceptance-mode findings check |
| `make fetch-nightly` | Network: what only the nightly jobs need — the public columns' driver packages (`xdrcheck conform fetch --set public`) and the stellar-core test image by digest |
| `make nightly-regenerate` | Nightly: `xdrcheck-corpus gen --check --all`, every scenario, without network |
| `make verify-goldens-nightly` | Nightly: golden agreement with stellar-core's own test binary and the bulk tier across drivers |
| `make nightly-differential` | By hand: the curated corpus through every public column (`all` with the overlay), `xdrcheck conform check`, the readiness view, and `xdrcheck conform diff` against `XDRCHECK_DIFF_BASE` when given |
| `make mutate-sensitivity` | By hand: `TestMutateSensitivity` with `XDRCHECK_MUTATE_REQUIRE=1`, so `xdrcheck mutate` must re-find the known public findings it is tested on and cannot skip for a missing driver |
| `make nightly-early-warning` | Nightly (N6): stellar-core's `test-lcm-next` goldens at `master` (fetched; network) round-tripped in the oracle; the summary separates `fetch` (network), `layout` (stellar-core moved or renamed its goldens) and `decode` failures, and its `arms` line names the arms stellar-core's XDR submodule has that the pinned definitions lack (`xdrcheck xdr diff`) |
| `make nightly-xdr-watch` | By hand, network: `xdrcheck xdr watch` over stellar-xdr main (every `#ifdef` on), its other branches and open pull requests, the standing `lcm_v3` item and the XDR diffs of pending CAP documents, then `xdrcheck xdr candidates` as a patch; writes `reports-nightly/xdr-watch/` (digests per upcoming protocol, `watch-log.jsonl`, per-source diffs, `candidates.patch`). Findings never fail it |
| `make xdr-ceilings` | `xdrcheck xdr ceilings --write`: rewrite the drivers' sentinel-enum ceilings from the pinned XDR definitions; `make test` fails when they drift |
| `make nightly-refetch` | Nightly, network: `make fetch` into an empty cache, then `xdrcheck pins check`, the golden tree's hashes and `xdrcheck-corpus refetch` |
| `make watch-network` | Nightly, network: `xdrcheck pins check --network`, the Horizon roots of mainnet and testnet and the status page's scheduled maintenances against `pins.toml` ([maintenance.md §5.5](maintenance.md)) |
| `make nightly-canary` | Nightly, network: `xdrcheck pins latest` (pins behind the newest upstream release) and canary columns for SDK releases not yet pinned, diffed against the pinned columns; reports drift, fails only when it cannot run ([maintenance.md §5.3](maintenance.md)) |
| `make vnext-core` | By hand, network and docker: stellar-core master built with the next-protocol flag, cached by commit; `VNEXT_PLAN=1` prints the plan ([maintenance.md §5.4](maintenance.md)) |
| `make maint-selftest` | Offline: `renovate.json`, the canary and the next-protocol build scripts against fixtures |
| `make push-gate` | Before every push, `RANGE=<last-pushed>..main`: `xdrcheck overlay audit --revs`, `check_public.py --revs` and `--messages` at every commit of the range, then the ref checks (the range ends at `main`; with `COMMIT_MAP=FILE`, no rewritten-away commit is reachable). Needs `XDRCHECK_OVERLAY` and fails without it ([SECURITY.md](../SECURITY.md)) |
| `make history-audit` | The same scans as `push-gate` over `RANGE` (default `main`, else `HEAD`), without the ref checks; needs `XDRCHECK_OVERLAY` |
| `make history-selftest` | The history scans find a planted private name, internal label, commit message and overlay blob in a throwaway repository |

`make <target> OFFLINE=1` wraps each run step in `scripts/offline-run.sh`. A target that runs `xdrcheck`,
`xdrcheck-corpus` or `xdrcheck-mutate` first brings it up to date (`go build`, `cargo build`; they rebuild only what
changed), so a binary older than its sources never judges a run. A tool given on the command line
(`make verify-findings XDRCHECK=/path/to/xdrcheck`) is used as it is, and a missing one fails with a message naming it;
nothing passes silently. `make help` prints the same targets grouped by who runs them.
