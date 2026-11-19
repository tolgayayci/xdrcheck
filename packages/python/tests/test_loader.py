"""Tests of xdrcheck against the repository's corpus, and against release trees and archives built from it
in a temporary directory. Counts come from corpus/index.json, never from constants.

Run from packages/python: python -m unittest discover -s tests (XDRCHECK_CORPUS=DIR overrides the corpus root).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import xdrcheck  # noqa: E402

CORPUS = Path(os.environ.get("XDRCHECK_CORPUS") or HERE.parents[2] / "corpus")
VERSION = "9.9.9"


def index_rows() -> list[dict]:
    return json.loads((CORPUS / "index.json").read_text())["entries"]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def first(pred):
    for row in index_rows():
        if pred(row):
            return row
    raise unittest.SkipTest("the corpus has no such entry")


def has_zstd() -> bool:
    for mod in ("compression.zstd", "zstandard"):
        try:
            __import__(mod)
            return True
        except ImportError:
            pass
    return shutil.which("zstd") is not None


def copy_rows(rows: list[dict], dst: Path) -> None:
    """Copy the files of the given index rows (manifest, blobs, sidecars) into the corpus root dst."""
    for row in rows:
        for rel in [row["manifest"]] + [p for v in row["variants"] for p in (v["blob"], v["decoded"]) if p]:
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(CORPUS / rel, dst / rel)


def write_manifest_sums(root: Path) -> None:
    lines = sorted(
        f"{sha(p.read_bytes())}  {p.relative_to(root).as_posix()}\n" for p in (root / "manifest").rglob("*.json")
    )
    (root / "manifest.sha256").write_text("".join(lines))


def make_corpus_root(dst: Path, rows: list[dict]) -> Path:
    """Layout 3: one corpus root holding index.json, corpus.json and the rows' files."""
    dst.mkdir(parents=True)
    copy_rows(rows, dst)
    (dst / "index.json").write_text(json.dumps({"schema": "xcc.index/v1", "entries": rows}))
    shutil.copyfile(CORPUS / "corpus.json", dst / "corpus.json")
    return dst


def make_release_tree(dst: Path, rows: list[dict]) -> Path:
    """Layout 2: the release's top-level directory, stress rows under stress/, the rest under corpus/."""
    top = dst / f"xdrcheck-{VERSION}"
    for root in ("corpus", "stress"):
        r = top / root
        r.mkdir(parents=True)
        copy_rows([x for x in rows if (x.get("tier") == "stress") == (root == "stress")], r)
        shutil.copyfile(CORPUS / "corpus.json", r / "corpus.json")
        write_manifest_sums(r)
    (top / "corpus" / "index.json").write_text(json.dumps({"schema": "xcc.index/v1", "entries": rows}))
    (top / "PROVENANCE.json").write_text(json.dumps({"schema": "xcc.release/v1", "version": VERSION}))
    files = sorted(p for p in top.rglob("*") if p.is_file())
    (top / "SHA256SUMS").write_text("".join(f"{sha(p.read_bytes())}  {p.relative_to(top).as_posix()}\n" for p in files))
    return top


def make_archive(tree: Path, out: Path) -> Path:
    """A gzip ustar archive of the tree with its one top-level directory, as docs/release.md lays it out."""
    with tarfile.open(out, "w:gz", format=tarfile.USTAR_FORMAT) as t:
        t.add(tree, arcname=tree.name)
    return out


def sample_rows() -> list[dict]:
    """A small selection: one ledger row with a sidecar, one negative xdr row, one stress row when there is one."""
    rows = index_rows()
    pick = [first(lambda r: r["kind"] == "ledger" and any(v["decoded"] for v in r["variants"]) and r["tier"] != "stress")]
    neg = [r for r in rows if r["kind"] == "xdr" and r["validity"] == "malformed" and r["tier"] != "stress"]
    stress = [r for r in rows if r["tier"] == "stress"]
    return pick + neg[:1] + stress[:1]


class RepositoryCorpus(unittest.TestCase):
    """The repository's own corpus root (layout 3)."""

    @classmethod
    def setUpClass(cls):
        cls.corpus = xdrcheck.open(CORPUS)

    def test_entries_match_index(self):
        rows = index_rows()
        self.assertEqual([e.id for e in self.corpus.entries()], [r["id"] for r in rows])
        want = json.loads((CORPUS / "corpus.json").read_text())["corpus_version"]
        self.assertEqual(self.corpus.version, want)
        r = rows[0]
        e = self.corpus.entry(r["id"])
        self.assertEqual((e.kind, e.caps, e.validity, e.tier, e.manifest_path), (r["kind"], r["caps"], r["validity"], r["tier"], r["manifest"]))
        self.assertEqual(e.protocol_introduced, r["protocol"]["introduced"])
        self.assertEqual(e.manifest()["id"], r["id"])
        with self.assertRaises(xdrcheck.CorpusError):
            self.corpus.entry("no/such-entry")

    def test_every_blob_verifies(self):
        want = sum(len(r["variants"]) for r in index_rows() if r["tier"] != "stress")
        n = 0
        for e in self.corpus.entries():
            if e.tier == "stress":
                continue
            for v in e.variants:
                b = v.blob()
                self.assertEqual(len(b), v.bytes)
                n += 1
        self.assertEqual(n, want)

    @unittest.skipUnless(has_zstd(), "no zstd decoder")
    def test_every_sidecar_verifies(self):
        want = sum(1 for r in index_rows() if r["tier"] != "stress" for v in r["variants"] if v["decoded"])
        n = 0
        for e in self.corpus.entries():
            if e.tier == "stress":
                continue
            for v in e.variants:
                j = v.expected_json()
                if v.decoded_path is None:
                    self.assertIsNone(j)
                else:
                    self.assertIsNotNone(j)
                    n += 1
        self.assertEqual(n, want)

    @unittest.skipUnless(has_zstd(), "no zstd decoder")
    def test_ledger_expected_json(self):
        row = first(lambda r: r["kind"] == "ledger" and r["variants"][0]["decoded"])
        v = self.corpus.entry(row["id"]).variants[0]
        raw = v.expected_json_bytes()
        self.assertEqual(sha(raw), row["variants"][0]["decoded_sha256"])
        j = v.expected_json()
        self.assertIsInstance(j, dict)
        self.assertEqual(j, json.loads(raw))
        # LedgerCloseMeta is a union: SEP-51 names the arm as the one key
        self.assertEqual(len(j), 1)

    def test_variant_key_rule(self):
        multi = first(lambda r: len({v["protocol"] for v in r["variants"]}) > 1)
        single = first(lambda r: len(r["variants"]) > 1 and len({v["protocol"] for v in r["variants"]}) == 1)
        for v, rv in zip(self.corpus.entry(multi["id"]).variants, multi["variants"]):
            self.assertEqual(v.key, f"{rv['network']}@{rv['protocol']}")
        for v, rv in zip(self.corpus.entry(single["id"]).variants, single["variants"]):
            self.assertEqual(v.key, rv["network"])

    def test_helpers(self):
        neg = first(lambda r: r["kind"] == "xdr" and r["validity"] == "malformed")
        e = self.corpus.entry(neg["id"])
        self.assertTrue(all(v.must_refuse() for v in e.variants))
        self.assertIsNotNone(e.expect_reject_reason())
        led = self.corpus.entry(first(lambda r: r["kind"] == "ledger")["id"])
        self.assertTrue(all(v.decodable() and not v.must_refuse() for v in led.variants))
        self.assertIsNone(led.expect_reject_reason())
        self.assertEqual(led.variants[0].framing, "none")
        spec = first(lambda r: r["kind"] == "spec" and r["variants"])
        self.assertFalse(any(v.decodable() for v in self.corpus.entry(spec["id"]).variants))


class Tampering(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xdrcheck-loader-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.row = sample_rows()[0]
        self.root = make_corpus_root(self.tmp / "c", [self.row])

    def test_tampered_blob_is_refused(self):
        v = self.row["variants"][0]
        p = self.root / v["blob"]
        b = bytearray(p.read_bytes())
        b[-1] ^= 1
        p.write_bytes(bytes(b))
        with self.assertRaisesRegex(xdrcheck.CorpusError, v["blob"].split("/")[-1]):
            xdrcheck.open(self.root).entry(self.row["id"]).variants[0].blob()

    def test_truncated_blob_is_refused(self):
        v = self.row["variants"][0]
        p = self.root / v["blob"]
        p.write_bytes(p.read_bytes()[:-4])
        with self.assertRaisesRegex(xdrcheck.CorpusError, "the index says"):
            xdrcheck.open(self.root).entry(self.row["id"]).variants[0].blob()

    @unittest.skipUnless(has_zstd(), "no zstd decoder")
    def test_tampered_sidecar_is_refused(self):
        v = self.row["variants"][0]
        other = next(x for r in index_rows() for x in r["variants"] if x["decoded"] and x["decoded"] != v["decoded"])
        shutil.copyfile(CORPUS / other["decoded"], self.root / v["decoded"])  # a valid zstd frame, wrong content
        with self.assertRaisesRegex(xdrcheck.CorpusError, "uncompressed sha256"):
            xdrcheck.open(self.root).entry(self.row["id"]).variants[0].expected_json()
        (self.root / v["decoded"]).write_bytes(b"not zstd")
        with self.assertRaises(xdrcheck.CorpusError):
            xdrcheck.open(self.root).entry(self.row["id"]).variants[0].expected_json()

    def test_missing_blob_names_the_file(self):
        v = self.row["variants"][0]
        (self.root / v["blob"]).unlink()
        with self.assertRaisesRegex(xdrcheck.CorpusError, v["sha256"]):
            xdrcheck.open(self.root).entry(self.row["id"]).variants[0].blob()

    def test_not_a_corpus(self):
        with self.assertRaisesRegex(xdrcheck.CorpusError, "neither a corpus root"):
            xdrcheck.open(self.tmp)
        with self.assertRaisesRegex(xdrcheck.CorpusError, "no such file"):
            xdrcheck.open(self.tmp / "missing")


class Releases(unittest.TestCase):
    """Layouts 1 (archive) and 2 (extracted release), built from a few real entries."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="xdrcheck-loader-"))
        cls.rows = sample_rows()
        cls.tree = make_release_tree(cls.tmp / "x", cls.rows)
        cls.archive = make_archive(cls.tree, cls.tmp / f"xdrcheck-{VERSION}.tar.gz")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def check(self, c: xdrcheck.Corpus):
        self.assertEqual(c.version, VERSION)
        self.assertEqual([e.id for e in c.entries()], [r["id"] for r in self.rows])
        for e, r in zip(c.entries(), self.rows):
            self.assertEqual(e.root, "stress" if r["tier"] == "stress" else "corpus")
            self.assertEqual(e.manifest()["id"], e.id)
            for v in e.variants:
                self.assertEqual(sha(v.blob()), v.sha256)
                if has_zstd() and v.decoded_path:
                    self.assertIsNotNone(v.expected_json())

    def test_extracted_release(self):
        self.check(xdrcheck.open(self.tree))

    def test_archive(self):
        digest = sha(self.archive.read_bytes())
        c = xdrcheck.open(self.archive, digest)
        self.assertIn(digest, c.source)
        self.check(c)
        self.check(xdrcheck.open(str(self.archive)))

    def test_archive_sha256_mismatch(self):
        with self.assertRaisesRegex(xdrcheck.CorpusError, "expected 0000"):
            xdrcheck.open(self.archive, "0" * 64)

    def test_archive_not_gzip(self):
        p = self.tmp / "bad.tar.gz"
        p.write_bytes(b"not an archive")
        with self.assertRaisesRegex(xdrcheck.CorpusError, "not a gzip-compressed tar archive"):
            xdrcheck.open(p)

    def test_tampered_manifest_is_refused(self):
        d = self.tmp / "t"
        shutil.copytree(self.tree, d / self.tree.name)
        top = d / self.tree.name
        row = self.rows[0]
        p = top / "corpus" / row["manifest"]
        p.write_text(p.read_text().replace(row["title"], row["title"] + "!", 1))
        with self.assertRaisesRegex(xdrcheck.CorpusError, "manifest.sha256 says"):
            xdrcheck.open(top).entry(row["id"]).manifest()
        a = make_archive(top, d / "t.tar.gz")
        with self.assertRaisesRegex(xdrcheck.CorpusError, "manifest.sha256 says"):
            xdrcheck.open(a).entry(row["id"]).manifest()


LIST = """\
# a comment line
cap-0001/a testnet L0   # listed, still fails
cap-0001/a pubnet L0    # listed, now passes
cap-0001/b - unread     # listed unread, still unread
cap-0001/c none unread  # listed unread, now read

cap-0001/d testnet L0   # selected entry, no such cell
cap-9999/z testnet L0   # entry not selected: ignored
"""


class ExpectedFailureLists(unittest.TestCase):
    def results(self) -> xdrcheck.Results:
        r = xdrcheck.Results("sdk 1.0")
        r.fail("cap-0001/a", "testnet", "L0", "refused valid bytes")
        r.pass_("cap-0001/a", "pubnet", "L0")
        r.unread("cap-0001/b", None, "type_not_generated")
        r.pass_("cap-0001/c", "none", "L0")
        r.select("cap-0001/d")
        r.fail("cap-0001/e", "testnet", "L0", "accepted invalid input")
        r.unread("cap-0001/f", "none", "type_not_generated")
        return r

    def test_parse(self):
        lst = xdrcheck.ExpectedFailures.parse(LIST, "ef.txt")
        self.assertEqual([str(f) for f in lst.items][:3], ["cap-0001/a testnet L0", "cap-0001/a pubnet L0", "cap-0001/b - unread"])
        self.assertEqual(lst.items[0].line, 2)
        with self.assertRaisesRegex(xdrcheck.CorpusError, r"ef.txt:2: want"):
            xdrcheck.ExpectedFailures.parse("# x\na b\n", "ef.txt")
        with self.assertRaisesRegex(xdrcheck.CorpusError, r"ef.txt:3: a b c is already listed on line 1"):
            xdrcheck.ExpectedFailures.parse("a b c\n\na b c # again\n", "ef.txt")
        with self.assertRaisesRegex(xdrcheck.CorpusError, r"ef.txt:1: want"):
            xdrcheck.ExpectedFailures.parse("a b c d\n", "ef.txt")

    def test_compare_all_outcomes(self):
        cmp = self.results().compare(xdrcheck.ExpectedFailures.parse(LIST, "ef.txt"), require_all_read=True)
        self.assertFalse(cmp.passed())
        self.assertEqual(
            cmp.format(),
            "NEW-FAILURE   cap-0001/e testnet L0: accepted invalid input\n"
            "UNEXPECTED-PASS cap-0001/a pubnet L0: listed as failing but now conforms; remove the line from ef.txt\n"
            "UNEXPECTED-PASS cap-0001/c none unread: listed as unread but the column now reads it; remove the line from ef.txt\n"
            "NEW-UNREAD    cap-0001/f none: never read (type_not_generated)\n"
            "NOT-RUN       cap-0001/d testnet L0 (ef.txt line 7): the run has no such cell; remove the line or fix its spelling\n"
            "expected failures sdk 1.0: 2 still as listed, 1 new failures, 1 new unread, 2 unexpected passes, 1 listed but not run\n",
        )

    def test_unread_not_required(self):
        cmp = self.results().compare(xdrcheck.ExpectedFailures.parse(LIST, "ef.txt"), require_all_read=False)
        self.assertEqual(cmp.new_unread, [])

    def test_listed_cell_now_n_a(self):
        r = xdrcheck.Results()
        r.unread("cap-0001/a", "testnet", "type_not_generated")
        cmp = r.compare(xdrcheck.ExpectedFailures.parse("cap-0001/a testnet L0\n", "ef.txt"))
        self.assertIn("listed as failing but is now n/a (type_not_generated)", cmp.format())

    def test_write_round_trip(self):
        r = self.results()
        text = xdrcheck.ExpectedFailures.write(r, "30.0.0")
        self.assertTrue(text.startswith("# Expected conformance failures of sdk 1.0 against corpus 30.0.0.\n"))
        body = [ln for ln in text.splitlines() if not ln.startswith("#")]
        self.assertEqual(
            body,
            [
                "cap-0001/a testnet L0  # refused valid bytes",
                "cap-0001/b - unread  # never read: type_not_generated",
                "cap-0001/e testnet L0  # accepted invalid input",
                "cap-0001/f none unread  # never read: type_not_generated",
            ],
        )
        cmp = r.compare(xdrcheck.ExpectedFailures.parse(text, "w.txt"), require_all_read=True)
        self.assertTrue(cmp.passed(), cmp.format())
        self.assertEqual(cmp.matched, 4)

    def test_read_file(self):
        with tempfile.TemporaryDirectory(prefix="xdrcheck-loader-") as d:
            p = Path(d) / "ef.txt"
            p.write_text("x - unread\n")
            self.assertEqual(xdrcheck.ExpectedFailures.read(p).name, str(p))
            with self.assertRaisesRegex(xdrcheck.CorpusError, "missing.txt"):
                xdrcheck.ExpectedFailures.read(Path(d) / "missing.txt")


if __name__ == "__main__":
    unittest.main()
