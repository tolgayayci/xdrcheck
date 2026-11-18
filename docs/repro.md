# `xdrcheck repro`: a bundle anyone can run

Use a bundle to hand one result to an SDK or pipeline maintainer: it holds the ledger, the transaction, the command
and a standalone script, and runs on a clean machine.

| Command | Does |
|---|---|
| `xdrcheck repro pack` | cuts one result out of a run directory into a self-contained directory |
| `xdrcheck repro run` | runs the bundle on another machine and says whether the result came back |
| `xdrcheck repro verify` | checks that the input is a real ledger that stellar-core accepts |

```
xdrcheck repro pack RUN_DIR --cluster 'CHECK|CLASS' [--tx LEDGER:INDEX] [--out DIR]
xdrcheck repro run BUNDLE [--version V] [--out DIR]
xdrcheck repro verify BUNDLE
```

## What a bundle holds

| File | What |
|---|---|
| `bundle.json` | schema `xcc.bundle/v1` (`schemas/bundle.schema.json`): target, the version asked for and the version built, network, cluster key, ledger, transaction and its hash, the expected verdict (`check`, `class`), the one command that reproduces it, the standalone script, every input file with its sha256, the ledger header hash and the stellar-core commands |
| `ledger/<seq>.xdr.zst` | the ledger object, byte for byte as the run read it (for a pubnet ledger, the public lake's object) |
| `meta-<seq>.xdr` | the same `LedgerCloseMeta` as a one-record stream, the form `stellar-core dump-xdr` reads |
| `tx.envelope.b64` | the transaction's envelope (when the result is about a transaction) |
| `tx.meta.b64` | the transaction's meta (same condition); the JS and Python scripts convert its contract values with `scValToNative` / `scval.to_native` |
| `repro.mjs`, `main.go`, `repro.py` or `main.rs` | a standalone script of at most 20 lines that shows the result with the SDK alone (SDK targets) |
| `README.md` | the same, in words |

`repro run` checks every file's sha256 and the ledger header hash, then runs the bundle's command (an
`xdrcheck replay --target … --ledger-file ledger/<seq>.xdr.zst --tx …`) into `BUNDLE/run`, and looks for a row with the
expected check and class on the expected transaction. `--version` runs another version: a fixed version should give
`NOT REPRODUCED`.

| Exit | `repro run` result |
|---|---|
| 0 | `REPRODUCED` |
| 1 | `NOT REPRODUCED` |
| 2 | the replay could not run |
| 3 | the target is not available on the machine |

`repro verify` recomputes the header hash (sha256 of the `LedgerHeader` equals the hash the `LedgerCloseMeta`
records), and runs the stellar-core commands when `stellar-core` is on `PATH` or in `$XDRCHECK_STELLAR_CORE`:

```
stellar-core dump-xdr --compact meta-<seq>.xdr          # core's own decoder reads the whole LedgerCloseMeta
stellar-core print-xdr --filetype tx --base64 tx.envelope.b64
```

For a pubnet ledger the README also gives the public lake URL of the object, so `curl -s URL | sha256sum` shows
the bytes are the network's own.

## Worked example: js-stellar-sdk #1766 on a clean machine

```
$ xdrcheck replay --issue js-stellar-sdk#1766 --out runs/1766
$ xdrcheck repro pack runs/1766 --cluster 'tx-parse|Error:Assets are not in lexicographic order' --out bundles/js-1766
bundle bundles/js-1766: js 17.2.0, ledger 5521432 tx 2, expect tx-parse Error:Assets are not in lexicographic order
  reproduce: xdrcheck repro run bundles/js-1766
```

Copy `bundles/js-1766` anywhere a checkout of this repository and Node.js are, then one command:

```
$ xdrcheck repro run bundles/js-1766
$ xdrcheck replay --target js --version 17.2.0 --network testnet --ledger-file …/ledger/5521432.xdr.zst --out …/run --force --tx 5521432:2
built js 17.2.0 (~/.cache/xdrcheck/targets/js/17.2.0)
xdrcheck js@17.2.0: complete (rows limited to the selected transactions; tested counts cover whole ledgers); 2 rows in 2 clusters -> …/run
  candidate            1  op-decode|Error:Assets are not in lexicographic order
  candidate            1  tx-parse|Error:Assets are not in lexicographic order
REPRODUCED tx-parse Error:Assets are not in lexicographic order on ledger 5521432 tx 2 with js 17.2.0

$ xdrcheck repro run bundles/js-1766 --version 17.2.1 --out /tmp/fixed | tail -1
NOT REPRODUCED tx-parse Error:Assets are not in lexicographic order on ledger 5521432 tx 2 with js 17.2.1

$ xdrcheck repro verify bundles/js-1766
ok   files match bundle.json; ledger 5521432 header hashes to 99efd5ab770fe7f4369735804f6d2c2e372020ff832e0c8cc1ae8ff7b35e4bec
```

And without the kit:

```
$ cd bundles/js-1766 && npm install @stellar/stellar-sdk@17.2.0 && node repro.mjs
tx-parse throws Error: Assets are not in lexicographic order
op-decode throws Error: Assets are not in lexicographic order
```

A bundle names no internal finding: its cluster key is the target's own message, and dispositions are not copied
into it.
