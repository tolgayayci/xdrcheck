"""The xdrcheck corpus as a stellar-sdk (py-stellar-base) test: copy this directory into the SDK's
repository (for example as tests/corpus/) and run it in CI.

For every entry outside the stress tier and every variant whose bytes an XDR decoder takes as they are, the blob
is decoded as its XDR type with ``stellar_sdk.xdr.<Type>.from_xdr_bytes``, conformance level L0:

- bytes a decoder must refuse (validity malformed or invalid): conforms when the SDK raises a decode error;
  accepting them is the failure ``accepted invalid input``;
- any other bytes: conforms when the SDK decodes them, consumes every byte (checked here with xdrlib3's
  ``Unpacker.done()``, not left to ``from_xdr_bytes``) and re-encodes them with ``to_xdr_bytes`` to the same
  bytes; with ``XDRCHECK_COMPARE_JSON=1`` also, as the separate level ``json``, when ``json.loads(value.to_json())``
  (SEP-51) equals the corpus's expected JSON (a list written without the option has no ``json`` lines);
- an XDR type the SDK does not generate: the variant is unread (``type_not_generated``);
- an exception that is not a decode error (anything but ValueError, EOFError, xdrlib3.Error, struct.error),
  including RecursionError and MemoryError: the failure ``crash: ...``.

The outcome is compared with ``expected-failures.txt`` next to this file, the SDK's own list of what it is known
to get wrong (the format of ``xdrcheck conform --expected-failures``): the test fails on a failure the list does not
name (NEW-FAILURE), on a listed failure that now conforms (UNEXPECTED-PASS: remove its line), and on a variant
that was not read and is not listed (NEW-UNREAD). Regenerate the list after a reviewed change with
``XDRCHECK_WRITE_EXPECTED_FAILURES=1``.

Environment:
  XDRCHECK_CORPUS                   the corpus: a release archive xdrcheck-<version>.tar.gz, an extracted
                               release, or a corpus directory holding index.json (required)
  XDRCHECK_CORPUS_SHA256            optional: the archive's expected sha256
  XDRCHECK_WRITE_EXPECTED_FAILURES  1: rewrite expected-failures.txt from this run instead of comparing
  XDRCHECK_COMPARE_JSON             1: also judge the SDK's SEP-51 JSON (level json) against the corpus

Run: XDRCHECK_CORPUS=path/to/xdrcheck-30.0.0.tar.gz python -m unittest -v test_corpus

Needs the loader module xdrcheck (packages/python in the corpus repository: one file to vendor, or
``pip install`` of that directory at a pinned commit) and the packages in requirements.txt.
"""
from __future__ import annotations

import inspect
import json
import os
import struct
import unittest
from importlib import metadata
from pathlib import Path

import xdrlib3
import xdrcheck
from stellar_sdk import xdr

HERE = Path(__file__).resolve().parent
LIST = HERE / "expected-failures.txt"
LEVEL = "L0"
# What the SDK and xdrlib3 raise for bytes they cannot decode; anything else is a crash.
DECODE_ERRORS = (ValueError, EOFError, xdrlib3.Error, struct.error)


def sdk_types() -> dict[str, type]:
    """Every generated XDR class by lower-cased name: the corpus spells ScVal, the SDK SCVal."""
    out = {}
    for name in dir(xdr):
        c = getattr(xdr, name)
        if inspect.isclass(c) and c.__module__.startswith("stellar_sdk.xdr.") and hasattr(c, "from_xdr_bytes"):
            out[name.lower()] = c
    return out


def short(e: BaseException) -> str:
    s = " ".join(f"{type(e).__name__}: {e}".split())
    return s if len(s) <= 200 else s[:199] + "…"


def first_difference(got, want, path: str = "") -> str:
    """The JSON pointer of the first place two JSON values differ, with both sides abbreviated."""
    if type(got) is not type(want):
        return f"{path or '/'}: {json.dumps(got)[:80]} != expected {json.dumps(want)[:80]}"
    if isinstance(got, dict):
        for k in sorted(set(got) | set(want)):
            if k not in got:
                return f"{path}/{k}: missing"
            if k not in want:
                return f"{path}/{k}: not expected"
            if got[k] != want[k]:
                return first_difference(got[k], want[k], f"{path}/{k}")
    if isinstance(got, list):
        if len(got) != len(want):
            return f"{path or '/'}: {len(got)} items, expected {len(want)}"
        for i, (a, b) in enumerate(zip(got, want)):
            if a != b:
                return first_difference(a, b, f"{path}/{i}")
    return f"{path or '/'}: {json.dumps(got)[:80]} != expected {json.dumps(want)[:80]}"


def judge(T: type, v: xdrcheck.Variant) -> tuple[str | None, str | None]:
    """(L0, json): None when the variant conforms at that level, else what went wrong; json is "" (not judged)
    when the bytes must be refused, have no expected JSON, or failed L0."""
    data = v.blob()
    try:
        value = T.from_xdr_bytes(data)
        u = xdrlib3.Unpacker(data)
        T.unpack(u)
        u.done()
    except DECODE_ERRORS as e:
        return (None if v.must_refuse() else f"refused valid bytes: {short(e)}"), ""
    except Exception as e:  # noqa: BLE001 - not a decode error
        return f"crash: {short(e)}", ""
    if v.must_refuse():
        return f"accepted invalid input ({v.validity}, {v.entry.expect_reject_reason() or 'negative entry'})", ""
    try:
        again = value.to_xdr_bytes()
    except Exception as e:  # noqa: BLE001
        return f"decoded, but re-encoding failed: {short(e)}", ""
    if again != data:
        return f"re-encoding differs: {len(again)} bytes from {len(data)}", ""
    want = v.expected_json()
    if want is None:
        return None, ""
    try:
        got = json.loads(value.to_json())
    except Exception as e:  # noqa: BLE001
        return None, f"decoded, but to_json failed: {short(e)}"
    if got != want:
        return None, f"SEP-51 JSON differs at {first_difference(got, want)}"
    return None, None


COMPARE_JSON = os.environ.get("XDRCHECK_COMPARE_JSON") == "1"


class CorpusConformance(unittest.TestCase):
    def test_l0_decode_reencode_json(self):
        path = os.environ.get("XDRCHECK_CORPUS")
        if not path:
            self.fail("XDRCHECK_CORPUS is not set: point it at the corpus release archive (xdrcheck-<version>.tar.gz), "
                      "an extracted release or a corpus directory")
        corpus = xdrcheck.open(path, os.environ.get("XDRCHECK_CORPUS_SHA256") or None)
        sdk = f"stellar-sdk {metadata.version('stellar-sdk')}"
        print(f"\ncorpus {corpus.version} from {corpus.source}; {sdk}")
        types = sdk_types()
        results = xdrcheck.Results(sdk)
        for e in corpus.entries():
            if e.tier == "stress":
                continue
            for v in e.variants:
                if not v.decodable():
                    continue
                T = types.get(v.xdr_type.lower())
                if T is None:
                    results.unread(e.id, v.key, "type_not_generated")
                    continue
                l0, js = judge(T, v)
                if l0 is None:
                    results.pass_(e.id, v.key, LEVEL)
                else:
                    results.fail(e.id, v.key, LEVEL, l0)
                if COMPARE_JSON and js is None:
                    results.pass_(e.id, v.key, "json")
                elif COMPARE_JSON and js:
                    results.fail(e.id, v.key, "json", js)
        if os.environ.get("XDRCHECK_WRITE_EXPECTED_FAILURES") == "1":
            LIST.write_text(xdrcheck.ExpectedFailures.write(results, corpus.version))
            print(f"wrote {LIST}")
            return
        cmp = results.compare(xdrcheck.ExpectedFailures.read(LIST), require_all_read=True)
        print(cmp.format(), end="")
        self.assertTrue(cmp.passed(), "the run differs from expected-failures.txt (lines above)")


if __name__ == "__main__":
    unittest.main()
