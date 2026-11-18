# stellar-core `print-xdr` as a decoder column (2026-11-12) — throwaway research repro, not product code

Release stellar-core v30.0.0 (the `../local-core/` run's .deb binary, reused read-only from `../local-core/`), offline, no config file.
The transcripts and outputs in this folder are the evidence.

## Layout
- `cases.py` — builds every malformed input by hand (`in/<case>.bin`), runs `stellar-core print-xdr`, writes one
  transcript per case (`out/<case>.txt`: note, exact command, input hex, stdout, stderr, exit code) and
  `out/summary.tsv`; `--depth` bisects the nested `SCV_VEC` and `SCV_MAP` depth boundary (`out/depth.txt`, boundary
  transcripts `out/{vec,map}-depth-N.txt`).
- `out/misc-invocation.txt` — missing file, unknown filetype, `--base64` batch on stdin, no argument, bad base64.
- `out/dump-xdr.txt` (+ `dump-xdr-golden.json`, `dump-xdr-truncated.json`) — `dump-xdr` on a golden LCM stream,
  the same stream truncated, and a non-matching file name.
- `out/string-non-utf8.stdout.raw` — raw stdout bytes for the non-UTF-8 case (contains byte `ff`: not valid UTF-8).
- `src-xdrpp-a29a1703/` — `xdrpp/{marshal.h,marshal.cc,types.h}` at the submodule commit pinned by core v30.0.0
  (`lib/xdrpp` → `a29a1703699ad2b6cb4b28538d6ed4173eacdb60`), fetched read-only with `gh api` for the citations.

## Re-run (bash, from this directory; < 5 s)
```bash
export LD_LIBRARY_PATH=$PWD/../local-core/root/usr/lib/x86_64-linux-gnu
C=$PWD/../local-core/root/usr/bin/stellar-core
$C version; $C help; $C print-xdr --help
rm -rf in out && python3 -I cases.py $C --depth          # all cases + depth bisection
# by hand, e.g.:
$C print-xdr --filetype scval in/bool-2.bin; echo "exit $?"
printf "AAAAAAAAAAI= AAAAAQ==\n" | $C print-xdr --filetype scval --base64 --compact stdin
cp ../golden-mirror/golden/4c437318f87437c5.xdr in/meta-golden-4c437318.xdr && $C dump-xdr --compact in/meta-golden-4c437318.xdr
```
(`rm -rf in out` also removes the dump-xdr and misc transcripts; their commands are recorded inside those files.)

## Summary (all exit codes of `print-xdr` are 0, accepted or not)

| case | input | verdict | printed / error |
|---|---|---|---|
| bool-2, bool-ffffffff | `SCV_BOOL` with 2 / 0xFFFFFFFF | ACCEPTED | `"b": "TRUE"` |
| optional-flag-2 | `SCV_VEC` pointer flag 2 | rejected | `xdr::pointer size must be 0 or 1` |
| string/bytes/symbol-pad-nonzero | short value, non-zero padding | rejected | `Non-zero padding bytes encountered` |
| trailing-4 / trailing-1 | `SCV_VOID` + 4 / 1 bytes | rejected | `unmarshaling did not consume whole message` / `message size not multiple of 4` |
| enum-undeclared-scerrorcode | `SCV_ERROR{SCE_AUTH, 10}` | ACCEPTED | `"code": "10"` |
| enum-undeclared-durability | `ContractDataEntry.durability = 2` | ACCEPTED | `"durability": "2"` |
| enum-undeclared-scerrortype | `SCError` discriminant 10 | rejected | `bad value of type in SCError` |
| scv-executable-tag-22 | `SCVal` discriminant 22 | ACCEPTED (declared in P30 XDR) | `SCV_EXECUTABLE_TAG` |
| union-undeclared-scvaltype | `SCVal` discriminant 23 | rejected | `bad value of type in SCVal` |
| union-undeclared-scaddresstype | `SCAddress` discriminant 9 | rejected | `bad value of type in SCAddress` |
| symbol-33 | `SCSymbol<32>` with 33 bytes | rejected | `xstring overflow` |
| signers-21 | `AccountEntry.signers<20>` with 21 | rejected | `xvector overflow` |
| symbol-bad-charset | `SCV_SYMBOL "a b!"` | ACCEPTED | `"sym": "a b!"` |
| string-non-utf8, string-cesu-surrogate, symbol-non-utf8 | invalid UTF-8 | ACCEPTED | raw bytes copied into the JSON output |
| vec depth | nested `SCV_VEC` around `SCV_VOID` | ≤ 499 accepted, 500 rejected | `stack overflow in xdr_generic_get` |
| map depth | nested one-entry `SCV_MAP` | ≤ 374 accepted, 375 rejected | same |

## Pins
- stellar-core `30.0.0 (0e49751aa9ddf892302cca02cea7f3f5d97df9f1)`, binary sha256 `dd24eb86d322ca58345bcaa04dfe6bd5922f74fe49e4725cd36b92bc22ac3eac`
- XDR `src/protocol-curr/xdr` → stellar-xdr `4f524bbac80c781c06e4fb5fc93a2d0d331d6705`; xdrpp `a29a1703699ad2b6cb4b28538d6ed4173eacdb60`
