# Run directory: the data contract of a run

Every `xdrcheck replay --target` run writes one directory. It is what the dashboard, `xdrcheck repro pack`, `xdrcheck runs`
and a CI job read; nothing else of a run is a contract. The JSON Schemas are in [`schemas/`](../schemas/), and the
`xdrcheck` binary carries a copy, so `xdrcheck runs validate DIR` checks a directory without a checkout.

| File | Schema | Content |
|---|---|---|
| `manifest.json` | `run-manifest.schema.json` (`xcc.run/v1`) | tool and version; the dataset version (and the manifest's sha256) the selection went through, or `null`; target; version asked for, version built and where from; network; the selection; every input ledger with its object key and sha256; the command line; host (operating system, architecture, CPUs; the host name only with `XDRCHECK_REPORT_HOST=1`); start and finish |
| `verdicts.jsonl` | `run-verdict.schema.json` (one object per line) | one row per result that is not a pass: `ledger`, `tx` (0-based apply order; `null` for a ledger-level row), `tx_hash`, `op` (`null` when the row is about the whole transaction), `op_type`, `check`, `class`, `verdict` (`fail`, `error`, `unavailable`), `evidence` (`detail`: the message, values stripped from the class only) |
| `clusters.json` | `run-clusters.schema.json` (`xcc.run.clusters/v1`) | rows grouped by `check|class`: counts of rows, transactions and ledgers, first and last ledger, operation types, rows per dataset stratum, up to five examples, `disposition`, `note`, `finding` |
| `summary.json` | `run-summary.schema.json` (`xcc.run.summary/v1`) | `status` (`complete`, `partial`, `unavailable`, `failed`) and `message`; rows per verdict; per check how often it ran and how often it did not pass; clusters per disposition; cost (wall, CPU, build seconds, ledgers, transactions) |
| `work/` | none | the target's raw output, build and run logs, the input list, the reference cut; useful for debugging, not stable |

Passes are not rows: a check that ran a million times and failed twice gives two rows and `tested: 1000000` in
the summary. With `--tx`, rows are limited to the selected transactions while the tested counts still cover the
whole ledgers (the summary's message says so).

## Cluster keys and dispositions

The key is `check|class` and leaves out the version, so the same defect has the same key at every version of the
target: `xdrcheck runs compare A B` lists the keys a fix removed (`-`) or a change brought (`+`). The class is the
target's message with values removed (strkeys, hex, numbers, quoted strings), or a structured difference such as
`rebuild-differs:cond:v2>v2`.

A disposition says what a cluster is:

| Disposition | Meaning |
|---|---|
| `candidate` | nothing explains it: look at it |
| `known` | a recorded finding (only a private overlay says this) |
| `by-design`, `builder-default`, `dialect`, `expected-refusal`, `recipe-artefact`, `harness` | noise that the target's own documentation or design explains |

The public table (`go/internal/hunt/rundir/dispositions.tsv`) holds noise rules only and never names a finding.
A private overlay table in the same format, given by `--dispositions FILE` or `$XDRCHECK_DISPOSITIONS`, is read first
and is the only place a rule may name a finding (a sixth column); keep it outside the tree.

## `xdrcheck runs`

```
$ xdrcheck runs validate runs/1766-prefix runs/1766-fixed
valid runs/1766-prefix
valid runs/1766-fixed
$ xdrcheck runs compare runs/1766-prefix runs/1766-fixed
A js@17.2.0
B js@17.2.1
-      1      0  op-decode|Error:Assets are not in lexicographic order
+      0      1  tx-rebuild|rebuild-throws:TimeBounds has to be set or you must call setTimeout(TimeoutInfinite).
-      1      0  tx-parse|Error:Assets are not in lexicographic order
```

`validate` checks each file against its schema and that `verdicts.jsonl`, `clusters.json` and `summary.json` count
the same rows (exit 1 on any problem). `compare` exits 1 when the two runs differ in their keys.

## Example rows

```
{"ledger":5521432,"tx":2,"tx_hash":"0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f","op":null,"op_type":"changeTrust","check":"tx-parse","class":"Error:Assets are not in lexicographic order","verdict":"fail","evidence":{"detail":"Error: Assets are not in lexicographic order"}}
{"ledger":5521432,"tx":2,"tx_hash":"0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f","op":2,"op_type":"changeTrust","check":"op-decode","class":"Error:Assets are not in lexicographic order","verdict":"fail","evidence":{"detail":"Error: Assets are not in lexicographic order"}}
```
