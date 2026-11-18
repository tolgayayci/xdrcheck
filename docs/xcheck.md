# `xdrcheck xcheck`: the same transactions through two or more targets

For SDK maintainers who want to know whether their SDK reads real transactions the same way another SDK, or another
version of their own, does. `xdrcheck xcheck` runs the same transactions through two or more SDK targets or versions
and compares only the fields both computed. Each target parses every envelope with its own builder API and writes one
row of fields per transaction; a field only one side produces is not compared.

```
xdrcheck xcheck --target TARGET@VERSION --target TARGET@VERSION [...]  (--ledgers L | --tx L:I | --set NAME | --ledger-file F)
           [--out DIR] [--network pubnet|testnet] [--rules]
```

Targets: `go`, `js`, `python`, `rust` (built and cached as in [replay.md](replay.md)). The reference cut (which bytes
are which transaction, in apply order) comes from `xdrcheck` itself, never from a target.

Fields: transaction hash, operation count and types, source and fee source accounts (strkeys, `M…` when muxed),
memo type and value, time bounds, fee, and per operation its source, destination, assets, amounts and price.

## Normalisation rules

These rules are the whole of what xcheck forgives (`xdrcheck xcheck --rules` prints them):

| Rule | Fields | Equal |
|---|---|---|
| `op-type` | `operations[].type` | names without case and underscores: `ManageSellOffer`, `manageSellOffer`, `manage_sell_offer`; the `revoke*Sponsorship` spellings are one name |
| `amount` | amounts, limits, send and destination amounts | exact decimals: `10`, `10.0`, `10.0000000`, `1E1` |
| `price` | `operations[].price` | exact reduced fractions (`1/2`, `2/4`, `0.5`); a decimal with k fractional digits equals a fraction it is within 10^-k of |
| `time-bounds` | `time_bounds` | absent, and min = max = 0 |
| `hex` | `hash`, hash and return memos | lower-case hex |
| `integer` | `fee`, `op_count` | as numbers |
| `text` | accounts, assets, memo text | exactly |

## Output

`DIR/diffs.jsonl` (one row per differing field: ledger, tx, field, both targets and values, the rule that
applied), `DIR/summary.json` (per pair of targets: transactions compared, per field compared and differing),
`DIR/fields-<target>.jsonl` (each target's rows).

| Exit | Meaning |
|---|---|
| 0 | nothing differs |
| 1 | a field differs |
| 2 | the comparison could not run |
| 3 | a target is not available |

## Worked example

```
$ xdrcheck xcheck --target js@17.4.0 --target python@17.0.1 --ledgers 30941181,30941857 --out xc
js@17.4.0 vs python@17.0.1: 143 transactions, 0 fields differ
-> xc (diffs.jsonl, summary.json)
```

Each line under a pair names a field (operation indexes as `[]`) and how many of its comparisons differ;
`diffs.jsonl` has every instance with both values.
