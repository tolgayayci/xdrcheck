# Mainnet scan: integrity check and shape census

The aggregate results of one scan of Stellar pubnet history, as the scan's own subcommands wrote them. The files
are copied unchanged (only renamed); `SHA256SUMS` holds their hashes (`sha256sum -c SHA256SUMS` in this folder).

## What was scanned

- **Ledgers 2 to 65,505,999** of pubnet, every one, read from the public data lake (the SEP-54 layout that
  `xdrcheck-corpus scan run --http` reads over HTTPS). The upper end was fixed before the run; it lies before the
  protocol 30 upgrade, so the scanned headers carry protocol versions 1 to 29 (pubnet has no protocol 14 ledger).
- **Run on 2026-11-16**, as 32,753 units of at most 2,000 consecutive ledgers.
- **65,505,998 ledgers and 10,869,626,939 transactions** (`chain-summary.txt`; `census-facts.tsv` sums to the
  same two numbers).

## What was checked on every ledger, and the result

`scan run` decodes each ledger object and refuses the ledger, recording why, when any of these fails: the zstd
frame, the decode of the `LedgerCloseMetaBatch` and its byte-exact re-encode, the walk of every byte against the
pinned XDR definitions, the header's stored hash against the SHA-256 of the header, and the join of every
transaction result to an envelope under the pubnet passphrase. It also records, per ledger, whether the header's
transaction-set hash and result-set hash match the hashes of the transaction set and results it carries, whether
the lake object's metadata (`protocol-version`, `start-ledger`) matches the header, and whether the object's MD5
equals its ETag. `scan chain-check` then reads every ledger in sequence order and checks that each header's
previous-ledger hash equals the hash of the ledger before it, across unit boundaries too.

| Check | Failures | Source |
|---|---|---|
| Ledgers refused by any of the per-ledger checks above | 0 | `chain-summary.txt`, `refusals` |
| Header hash chain: 65,505,997 links checked (32,752 of them between units) | 0 mismatches | `hash_links_checked`, `hash_mismatches` |
| Missing ledgers, gaps, duplicates or out-of-order ledgers | 0, 0, 0 | `missing_ledgers`, `gaps`, `duplicates_or_out_of_order` |
| Transaction-set hash | 0 | `chain-groups.tsv`, `tx_set_hash_fail`, every row |
| Result-set hash | 0 | `chain-groups.tsv`, `result_hash_fail`, every row |
| Lake object metadata against the header, where the object carries it | 0 | `chain-groups.tsv`, `meta_mismatch`, every row |
| Object MD5 against its ETag; objects without an ETag | 0; 0 | `chain-groups.tsv`, `md5_etag_fail`, `no_etag` |

The chain is open at its first end: ledger 2's previous-ledger hash names ledger 1, which is not in the run.
`chain-groups.tsv` splits the same ledgers by the `core-version` metadata of the lake object (the stellar-core
that wrote it), the protocol the ledger's transactions were applied under, and the `LedgerCloseMeta` arm (40
rows).

## What the census counts

The scan cuts every transaction into **components** and walks each against the pinned definitions, turning it
into a set of **tokens**. Grammar `xcc.shape/v1`, implemented in `crates/xdrcheck-corpus/src/cmd/scan/shape.rs`:

- A **token** is one string `<kind>|<class>|<body>` from a finite grammar: a union arm, optional or enum value
  at a type or at a field path, a length class, a value class, a summary of a recursive value (`SCVal` and the
  like), an event signature, a ledger-entry change, or what an operation asked for against what the meta shows.
  No token holds bytes taken from the ledger (keys, addresses, amounts, contract ids), apart from two closed
  vocabularies of event names and data-map keys.
- A **component** is one part of a transaction: `E` the envelope without its operations, `A` its authorization
  entries, `O` one operation with its result and its meta, `R` the result without the operation results, `F` the
  fee processing, `M` the transaction meta frame; plus `L`, the ledger-level part (header, upgrades, transaction
  set structure), one per ledger.
- A **component shape** is the hash of a component's sorted token set. A **whole-transaction shape** is the hash
  of the transaction's E, R, F and M component shapes, its A shape if it has one, the set of its distinct O
  shapes each with a class of how often it repeats, and a class of its operation count. The order of operations
  is not part of it, and their exact repetition only as a class.
- Four **levels** keep more token kinds each: G0 keeps the type-level tokens (union arms, optional states and
  enum values, wherever they occur), G1 adds where each arm, optional and enum value sits, G2 adds value
  classes, length classes, recursive-value summaries, the first arm and arm set of union vectors, and event
  signatures, and G3 adds ledger-entry changes and operation-versus-effect relations. G3 is the finest; the coarser levels are
  projections of the same tokens.

Distinct shapes at G3, the finest level (`census-summary.tsv`, column `distinct`):

| What | Distinct | Rows |
|---|---|---|
| Transaction-level component shapes (kinds A, E, F, M, O, R) | 3,270,052 | A 2,186 + E 18,544 + F 679 + M 11,964 + O 3,236,582 + R 97 |
| Ledger-level component shapes (kind L) | 33,705 | L |
| All component shapes | 3,303,757 | the sum of the two lines above; `cover-summary.tsv`, `ids_all` |
| Whole-transaction shapes | 26,418,998 | `tx`; 18,066,711 of them occur in exactly one transaction |
| Distinct tokens | 15,884 | `token-classes.tsv`, row `all`; 15,186 occur in transaction-level components (`cover-summary.tsv`, `TOK`, `ids_tx`) |

The two shape counts measure different things: 3,270,052 counts the parts transactions are made of, and
26,418,998 counts the distinct combinations of those parts.

## The files

| File | Rows | One row is | Written by |
|---|---|---|---|
| `chain-summary.txt` | 17 | one total of the chain check (key, tab, value) | `scan chain-check` (`chain-summary.txt`) |
| `chain-groups.tsv` | 40 | one (writer core, protocol applied, `LedgerCloseMeta` arm): ledgers, transactions, ledger range, failures per check | `scan chain-check` (`chain-groups.tsv`) |
| `census-facts.tsv` | 30 | one (header protocol version, `LedgerCloseMeta` arm): ledgers, transactions, ledger range, units | `scan census-merge` (`facts.tsv`) |
| `census-summary.tsv` | 32 | one (level, component kind or `tx`): distinct shapes; how many occur once, at most 10 times, in one unit; occurrence total and quantiles; shapes first seen per 5 M ledgers and per protocol | `scan census-merge` (`summary.tsv`) |
| `token-classes.tsv` | 27 | one token (kind, class): distinct tokens, the components that carry one, per component kind | `scan token-census` (`token-classes.tsv`) |
| `token-steps.tsv` | 28 | for `O` components, one step between levels and one token class: distinct shapes with that class added alone or dropped alone | `scan token-census` (`token-steps.tsv`) |
| `cover-summary.tsv` | 10 | one (level or `TOK`, order): how many transactions, and how many whole ledgers, it takes to hold every distinct shape (or token) at least once | `scan cover-stream` (`cover-summary.tsv`) |
| `cover-eras.tsv` | 30 | the same covers, split per 5 M ledgers | `scan cover-stream` (`cover-eras.tsv`) |

Rows are data rows (the header line is not counted). Occurrences of a component shape count the transactions
that hold it (ledgers for `L`); occurrences of a whole-transaction shape count transactions. The two protocol
tables group the same ledgers differently: `census-facts.tsv` by the header's protocol version, `chain-groups.tsv`
by the protocol the transactions were applied under. On an upgrade ledger the header already carries the new
version while its transactions apply under the old one, so per-protocol counts differ slightly between the two;
the totals are equal. A cover is greedy: `asc` takes the first carrier in ledger order, `rare` starts from the
rarest shapes. At G3 the ascending cover holds every transaction-level component shape in 3,229,456
transactions from 2,718,654 ledgers, and every component shape in 2,748,376 whole ledgers.

## Reproducing it

Every step is a subcommand of `xdrcheck-corpus scan` in this tree (`docs/cli.md` lists them; `--help` gives every
option). The files here were written by earlier development builds of the same subcommands; the commands below
describe the procedure, not a promise of byte-identical output from today's tree. The whole-run steps stream
unit by unit and keep memory bounded.

```sh
LAKE=https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/pubnet
B=target/release/xdrcheck-corpus

# 1. list the lake and cut the range into units of at most 2,000 ledgers
$B scan list-lake --first 2 --tip 65505999 --out listing
$B scan plan-ranges --first 2 --tip 65505999 --listing listing --max-unit-ledgers 2000 --out plan.tsv

# 2. scan: N workers share the plan (or run `scan run --ranges plan.tsv --workers N --worker I --http $LAKE --out run/wI` per worker)
$B scan supervise --ranges plan.tsv --workers N --http $LAKE --out run -- --tip 65505999

# 3. prove every planned ledger is there exactly once, then merge the workers' directories
$B scan verify --ranges plan.tsv --run run/w0 ... --run run/wN-1
$B scan merge --ranges plan.tsv --run run/w0 ... --run run/wN-1 --into merged

# 4. the files in this folder
$B scan chain-check    --run merged --out chain                    # chain-summary.txt, chain-groups.tsv
$B scan census-extract --run merged --out census/runs
$B scan census-merge   --runs census/runs --out census              # facts.tsv, summary.tsv
$B scan token-census   --run merged --census census --out tokens    # token-classes.tsv, token-steps.tsv
$B scan cover-stream   --run merged --census census --token-occ tokens/tokens.tsv.zst \
                       --levels G0,G1,G2,G3,TOK --out cover          # cover-summary.tsv, cover-eras.tsv
```

## What is not claimed

- **The pipelines were not replayed over all of mainnet.** The scan computes shapes, tokens and the checks above;
  it does not run wallet-backend, stellar-etl, Horizon or any SDK. Those ran on the corpus and on selected
  ledgers only.
- **Shapes are those of the lake as it is served today.** The lake's older ledgers were regenerated by a recent
  stellar-core (see the `core` column of `chain-groups.tsv`), so their transaction meta is a recent version: a meta
  arm that only older stellar-core versions emitted is absent from the census even where the network once
  produced it.
- **The per-ledger output is not in this repository.** The scan's per-ledger records and the census's per-shape
  lists are tens of gigabytes; only the aggregate files above are kept here. The lists of individual example
  transactions (the covers themselves) and the locate index are not here either.
- **An entry's mainnet count is that of its rarest token, not of the entry.** `entry-prevalence.json` (below)
  says how often the rarest part of an entry's shape occurs on mainnet; it does not say that a transaction with
  the entry's whole shape occurred, nor anything about what a pipeline did with such a transaction.

## Per-entry prevalence (`entry-prevalence.json`)

How common each corpus entry's distinguishing shape is on mainnet, counted per token. It is generated, not
copied, so it is not in `SHA256SUMS`; `make results-prevalence TOKEN_TABLE=…` writes it and `make results-check`
(part of `make repo-checks`) checks that it is consistent with the corpus.

1. `xdrcheck-corpus scan entry-tokens` walks every `LedgerCloseMeta` variant of `corpus/index.json` with the
   scan's own emitter and rules (`scan run`'s cut into components, grammar `xcc.shape/v1`) and lists the tokens of
   the variant's focus transaction (its E, A, R, F, M and O components), or of the ledger component L when the
   focus is the ledger itself. Variants of other XDR types are not walked (`walked: false`): the scan has no
   component of that type.
2. Each token is looked up in the scan's token table (`scan token-census`: per token, its occurrences, first and
   last ledger; not in this repository, see "What is not claimed"). A token the table does not hold occurs
   nowhere in the scanned range: 0.
3. Per variant, the rarest token is the one with the fewest occurrences. Per entry, the variant whose rarest
   token is the most common is kept (the form of the entry closest to what mainnet carries; a protocol 30 variant
   of an entry that also has a protocol 28 one is not held against it, since the scan ends before protocol 30).
   `rarest_tokens` lists that variant's rarest tokens (up to five; `rarest_tokens_total` says how many share the
   count) with occurrences, first and last ledger; `variants` gives every walked variant's rarest count.
4. The walk is checked against the scan itself: for every variant taken from a scanned pubnet ledger, each of its
   tokens must be in the token table with that ledger inside the token's first..last range, or nothing is written
   (`totals.mainnet_variants_checked_against_the_scan`).
5. `never_seen_on_mainnet: true` means even the best variant holds a token that never occurs in the scanned range:
   a shape mainnet has not produced, which is what generating ledgers on a local stellar-core is for.

`occurrences` is the token table's count: the sum, over the distinct components that carry the token, of the
transactions holding each component (ledgers for L), so a transaction with two different components carrying
the same token counts twice. The file holds only these aggregates per token; it lists no transactions.
