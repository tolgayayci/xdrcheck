"""Read the xdrcheck corpus from Python: entries, verified blobs, expected SEP-51 JSON, and
expected-failure lists for an SDK's CI.

One file, the standard library only (plus the optional ``zstandard`` module, see below), so an SDK can vendor it
or install it with ``pip install`` from a pinned commit of the corpus repository. It never writes and never uses
the network.

Opening a corpus
----------------
``open(path, archive_sha256=None)`` takes any of:

1. a release archive ``xdrcheck-<version>.tar.gz`` (docs/release.md): read into memory with ``gzip`` and
   ``tarfile``, never extracted; with ``archive_sha256`` its sha256 must match;
2. an extracted release: the directory holding ``corpus/`` (and ``stress/``);
3. a corpus root holding ``index.json`` directly (the repository's own ``corpus/``).

The entry list is ``corpus/index.json`` (docs/manifest.md, "The entry index"). In a release a ``tier: "stress"`` row's
files live under the ``stress/`` root and every other row's under ``corpus/``; in a plain corpus root everything is
under the one directory. The version is PROVENANCE.json ``version`` when present, else corpus.json
``corpus_version``.

::

    import xdrcheck

    corpus = xdrcheck.open(os.environ["XDRCHECK_CORPUS"])
    for entry in corpus.entries():
        if entry.tier == "stress":
            continue
        for v in entry.variants:
            if not v.decodable():
                continue
            data = v.blob()             # bytes, sha256 and length checked against the index
            want = v.expected_json()    # the SEP-51 JSON value, or None when the bytes do not decode
            ...

Every blob is checked against the sha256 and length the index states, every sidecar against its
``decoded_sha256``, and, when the corpus root has ``manifest.sha256`` (a release root does), every manifest file
against that list. A mismatch raises ``CorpusError``, the one error type, whose message names the file.

Sidecars are zstd-compressed. They are decompressed with ``compression.zstd`` (Python 3.14 and later), else the
``zstandard`` module, else the ``zstd -dc`` program; only ``expected_json()`` needs one of them.

Expected-failure lists
----------------------
The same file format as ``xdrcheck conform --expected-failures`` (docs/use-in-sdk-ci.md section 5): one item per line,
``<entry> <variant or -> <level or unread>``, ``#`` starts a comment, blank lines are ignored. A test records
what the SDK did in a ``Results`` collector and compares it with the list::

    results = xdrcheck.Results("stellar-sdk 17.0.1")
    results.pass_(entry.id, v.key, "L0")                     # conforms (pass is a keyword, hence pass_)
    results.fail(entry.id, v.key, "L0", "accepted invalid input")
    results.unread(entry.id, v.key, "type_not_generated")    # the SDK cannot read it at all
    cmp = results.compare(xdrcheck.ExpectedFailures.read("expected-failures.txt"), require_all_read=True)
    print(cmp.format(), end="")
    assert cmp.passed()

A failure the list does not name is NEW-FAILURE; a listed cell that passed, or a listed ``unread`` item that was
read, is UNEXPECTED-PASS (remove the line); an unread variant the list does not name is NEW-UNREAD under
``require_all_read``; a listed item of an entry the run touched that the run has no such cell for is NOT-RUN.
``ExpectedFailures.write(results, corpus_version)`` returns a list's text generated from a run.
"""
from __future__ import annotations

import builtins
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile

__all__ = [
    "CorpusError",
    "Corpus",
    "Entry",
    "Variant",
    "ExpectedFailures",
    "ExpectedFailure",
    "Results",
    "Comparison",
    "open",
    "UNREAD",
]

__version__ = "30.0.0"

UNREAD = "unread"

_read_file = builtins.open


class CorpusError(Exception):
    """Anything wrong with the corpus, an archive, a checksum or an expected-failure list."""


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---- zstd -------------------------------------------------------------------------------------------------------


def _zstd_decompress(data: bytes, what: str) -> bytes:
    try:
        from compression import zstd  # Python 3.14 and later

        return zstd.decompress(data)
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001 - any decoder error names the file
        raise CorpusError(f"{what}: zstd: {e}") from e
    try:
        import zstandard
    except ImportError:
        zstandard = None
    if zstandard is not None:
        try:
            # A streaming reader: the frame need not state its decompressed size.
            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as r:
                return r.read()
        except zstandard.ZstdError as e:
            raise CorpusError(f"{what}: zstd: {e}") from e
    prog = shutil.which("zstd")
    if prog is None:
        raise CorpusError(
            f"{what}: no zstd decoder: needs Python 3.14 (compression.zstd), the zstandard module or the zstd program"
        )
    p = subprocess.run([prog, "-dc"], input=data, capture_output=True, check=False)
    if p.returncode != 0:
        raise CorpusError(f"{what}: zstd -dc: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


# ---- where the files are ----------------------------------------------------------------------------------------


class _DirStore:
    def __init__(self, base: str):
        self.base = base

    def name(self, rel: str) -> str:
        return os.path.join(self.base, *rel.split("/"))

    def read(self, rel: str) -> bytes:
        try:
            with _read_file(self.name(rel), "rb") as f:
                return f.read()
        except OSError as e:
            raise CorpusError(f"{self.name(rel)}: {e.strerror or e}") from e

    def exists(self, rel: str) -> bool:
        return os.path.isfile(self.name(rel))


class _ArchiveStore:
    def __init__(self, path: str, files: dict[str, bytes], top: str):
        self.path, self.files, self.top = path, files, top

    def name(self, rel: str) -> str:
        return f"{self.path}:{self.top}/{rel}"

    def read(self, rel: str) -> bytes:
        b = self.files.get(f"{self.top}/{rel}")
        if b is None:
            raise CorpusError(f"{self.path}: {self.top}/{rel} is not in the archive")
        return b

    def exists(self, rel: str) -> bool:
        return f"{self.top}/{rel}" in self.files


def _read_archive(path: str, archive_sha256: str | None) -> tuple[_ArchiveStore, str]:
    try:
        with _read_file(path, "rb") as f:
            gz = f.read()
    except OSError as e:
        raise CorpusError(f"{path}: {e.strerror or e}") from e
    got = _sha256(gz)
    if archive_sha256 is not None and got != archive_sha256.strip().lower():
        raise CorpusError(f"{path}: sha256 {got}, expected {archive_sha256.strip().lower()}")
    try:
        raw = gzip.decompress(gz)
        files: dict[str, bytes] = {}
        tops = set()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            for m in tf:
                name = m.name
                while name.startswith("./"):
                    name = name[2:]
                name = name.rstrip("/")
                if name in ("", "."):
                    continue
                if name.startswith("/") or ".." in name.split("/"):
                    raise CorpusError(f"{path}: archive member {m.name!r} is not a relative path")
                tops.add(name.split("/", 1)[0])
                if m.isfile():
                    fo = tf.extractfile(m)
                    files[name] = fo.read() if fo is not None else b""
                elif not m.isdir():
                    raise CorpusError(f"{path}: archive member {m.name!r} is neither a file nor a directory")
    except (OSError, EOFError, tarfile.TarError) as e:
        raise CorpusError(f"{path}: not a gzip-compressed tar archive: {e}") from e
    if len(tops) != 1:
        raise CorpusError(f"{path}: want one top-level directory, found {sorted(tops)}")
    top = tops.pop()
    return _ArchiveStore(path, files, top), f"{path} (sha256 {got})"


# ---- corpus, entries, variants ----------------------------------------------------------------------------------


class Corpus:
    """An opened corpus: ``version``, ``source`` (for logs), ``entries()``, ``entry(id)``."""

    def __init__(self, store, roots: dict[str, str], source: str):
        # roots: "corpus" and "stress" -> the prefix of that corpus root inside the store ("" for layout 3)
        self._store = store
        self._roots = roots
        self.source = source
        index = self._json(self._rel("corpus", "index.json"))
        if not isinstance(index, dict) or index.get("schema") != "xcc.index/v1" or not isinstance(index.get("entries"), list):
            raise CorpusError(f"{self._store.name(self._rel('corpus', 'index.json'))}: not an xcc.index/v1 entry index")
        self._sums: dict[str, dict[str, str] | None] = {}
        self._entries = [Entry(self, row) for row in index["entries"]]
        self._by_id = {e.id: e for e in self._entries}
        self.version = self._version()

    def _rel(self, root: str, rel: str) -> str:
        prefix = self._roots[root]
        return f"{prefix}/{rel}" if prefix else rel

    def _read(self, root: str, rel: str) -> bytes:
        return self._store.read(self._rel(root, rel))

    def _json(self, rel: str):
        b = self._store.read(rel)
        try:
            return json.loads(b)
        except ValueError as e:
            raise CorpusError(f"{self._store.name(rel)}: not JSON: {e}") from e

    def _version(self) -> str:
        if "corpus" in self._roots and self._roots["corpus"] and self._store.exists("PROVENANCE.json"):
            v = self._json("PROVENANCE.json").get("version")
            if isinstance(v, str) and v:
                return v
        rel = self._rel("corpus", "corpus.json")
        if self._store.exists(rel):
            v = self._json(rel).get("corpus_version")
            if isinstance(v, str) and v:
                return v
        raise CorpusError(f"{self.source}: no PROVENANCE.json version and no corpus.json corpus_version")

    def _manifest_sums(self, root: str) -> dict[str, str] | None:
        if root not in self._sums:
            rel = self._rel(root, "manifest.sha256")
            if not self._store.exists(rel):
                self._sums[root] = None
            else:
                sums = {}
                for n, line in enumerate(self._store.read(rel).decode("utf-8").splitlines(), 1):
                    if not line.strip():
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2 or len(parts[0]) != 64:
                        raise CorpusError(f"{self._store.name(rel)}:{n}: not a sha256sum line")
                    sums[parts[1].lstrip("*").strip()] = parts[0].lower()
                self._sums[root] = sums
        return self._sums[root]

    def _root_of(self, tier: str) -> str:
        return "stress" if tier == "stress" and "stress" in self._roots else "corpus"

    def entries(self) -> list[Entry]:
        """Every index row, in index order, stress rows included."""
        return list(self._entries)

    def entry(self, id: str) -> Entry:
        try:
            return self._by_id[id]
        except KeyError:
            raise CorpusError(f"{self.source}: no entry {id}") from None

    def __repr__(self) -> str:
        return f"Corpus({self.version!r}, {self.source!r})"


class Entry:
    """One index row. ``manifest()`` reads the full manifest entry; ``variants`` are ``Variant`` objects."""

    def __init__(self, corpus: Corpus, row: dict):
        self._corpus = corpus
        self._manifest = None
        try:
            self.id: str = row["id"]
            self.title: str = row.get("title", "")
            self.kind: str = row["kind"]
            self.caps: list[int] = list(row.get("caps", []))
            self.rows: list[str] = list(row.get("rows", []))
            self.protocol_introduced = (row.get("protocol") or {}).get("introduced")
            self.synthetic: bool = bool(row.get("synthetic", False))
            self.validity: str = row["validity"]
            self.flags: list[str] = list(row.get("flags", []))
            self.sources: list[str] = list(row.get("sources", []))
            self.tier: str = row.get("tier", "curated")
            self.manifest_path: str = row["manifest"]
            rows = list(row.get("variants") or [])
        except (KeyError, TypeError, AttributeError) as e:
            raise CorpusError(f"index.json: entry row {row.get('id') if isinstance(row, dict) else row!r}: missing {e}") from e
        self.root = corpus._root_of(self.tier)
        multi = len({v.get("protocol") for v in rows}) > 1
        self.variants: list[Variant] = [Variant(self, i, v, multi) for i, v in enumerate(rows)]

    def manifest(self) -> dict:
        """The manifest entry (parsed JSON), checked against the root's manifest.sha256 when it has one."""
        if self._manifest is None:
            c = self._corpus
            b = c._read(self.root, self.manifest_path)
            sums = c._manifest_sums(self.root)
            name = c._store.name(c._rel(self.root, self.manifest_path))
            if sums is not None:
                want = sums.get(self.manifest_path)
                if want is None:
                    raise CorpusError(f"{name}: not listed in manifest.sha256")
                if _sha256(b) != want:
                    raise CorpusError(f"{name}: sha256 {_sha256(b)}, manifest.sha256 says {want}")
            try:
                m = json.loads(b)
            except ValueError as e:
                raise CorpusError(f"{name}: not JSON: {e}") from e
            if not isinstance(m, dict) or m.get("id") != self.id:
                raise CorpusError(f"{name}: not the manifest of {self.id}")
            self._manifest = m
        return self._manifest

    def expect_reject_reason(self) -> str | None:
        """The manifest's ``expect.reject.reason``, or None."""
        r = ((self.manifest().get("expect") or {}).get("reject") or {}).get("reason")
        return r if isinstance(r, str) else None

    def __repr__(self) -> str:
        return f"Entry({self.id!r})"


class Variant:
    """One variant of an entry: the index row's fields plus the manifest's ``framing`` and ``frame_index``."""

    def __init__(self, entry: Entry, i: int, row: dict, multi_protocol: bool):
        self.entry = entry
        self._i = i
        try:
            self.network: str = row["network"]
            self.protocol: int = row["protocol"]
            self.ledger_seq = row.get("ledger_seq")
            self.xdr_type: str = row["xdr_type"]
            self.validity: str = row.get("validity") or entry.validity
            self.blob_path: str = row["blob"]
            self.sha256: str = row["sha256"]
            self.bytes: int = row["bytes"]
            self.decoded_path: str | None = row.get("decoded")
            self.decoded_sha256: str | None = row.get("decoded_sha256")
        except (KeyError, TypeError) as e:
            raise CorpusError(f"index.json: {entry.id} variant {i}: missing {e}") from e
        self.key: str = f"{self.network}@{self.protocol}" if multi_protocol else self.network

    def _mv(self) -> dict:
        vs = self.entry.manifest().get("variants") or []
        if self._i >= len(vs) or (vs[self._i].get("blob") or {}).get("sha256") != self.sha256:
            raise CorpusError(f"{self.entry.manifest_path}: variant {self._i} does not match index.json")
        return vs[self._i]

    @property
    def framing(self) -> str:
        return self._mv().get("framing") or "none"

    @property
    def frame_index(self) -> int:
        return int(self._mv().get("frame_index") or 0)

    def must_refuse(self) -> bool:
        """An L0 byte decoder must refuse these bytes (validity malformed or invalid)."""
        return self.validity in ("malformed", "invalid")

    def decodable(self) -> bool:
        """Bytes an SDK's XDR decoder takes as they are: a ledger or xdr entry with no record framing."""
        return self.entry.kind in ("ledger", "xdr") and self.framing == "none"

    def blob(self) -> bytes:
        """The blob, checked against the index's sha256 and length."""
        c = self.entry._corpus
        b = c._read(self.entry.root, self.blob_path)
        if len(b) != self.bytes or _sha256(b) != self.sha256:
            name = c._store.name(c._rel(self.entry.root, self.blob_path))
            raise CorpusError(
                f"{name}: {len(b)} bytes with sha256 {_sha256(b)}, the index says {self.bytes} bytes with sha256 {self.sha256}"
            )
        return b

    def expected_json_bytes(self) -> bytes | None:
        """The sidecar's uncompressed bytes (compact JSON and a newline), checked against decoded_sha256."""
        if self.decoded_path is None:
            return None
        c = self.entry._corpus
        name = c._store.name(c._rel(self.entry.root, self.decoded_path))
        raw = _zstd_decompress(c._read(self.entry.root, self.decoded_path), name)
        if _sha256(raw) != self.decoded_sha256:
            raise CorpusError(f"{name}: uncompressed sha256 {_sha256(raw)}, the index says {self.decoded_sha256}")
        return raw

    def expected_json(self):
        """The SEP-51 JSON value of the bytes, or None when they do not decode."""
        raw = self.expected_json_bytes()
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError as e:
            raise CorpusError(f"{self.decoded_path}: not JSON: {e}") from e

    def __repr__(self) -> str:
        return f"Variant({self.entry.id!r}, {self.key!r})"


def open(path, archive_sha256: str | None = None) -> Corpus:  # noqa: A001 - the module's entry point
    """Open a release archive (.tar.gz), an extracted release, or a corpus root holding index.json."""
    path = os.fspath(path)
    if os.path.isdir(path):
        if archive_sha256 is not None:
            raise CorpusError(f"{path}: a directory has no archive sha256 to check")
        store = _DirStore(path)
        if store.exists("index.json"):
            return Corpus(store, {"corpus": ""}, path)
        if store.exists("corpus/index.json"):
            roots = {"corpus": "corpus"}
            if os.path.isdir(os.path.join(path, "stress")):
                roots["stress"] = "stress"
            return Corpus(store, roots, path)
        raise CorpusError(f"{path}: neither a corpus root (index.json) nor a release (corpus/index.json)")
    if os.path.isfile(path):
        store, source = _read_archive(path, archive_sha256)
        if not store.exists("corpus/index.json"):
            raise CorpusError(f"{path}: {store.top}/corpus/index.json is not in the archive")
        roots = {"corpus": "corpus"}
        if any(k.startswith(f"{store.top}/stress/") for k in store.files):
            roots["stress"] = "stress"
        return Corpus(store, roots, source)
    raise CorpusError(f"{path}: no such file or directory")


# ---- expected-failure lists -------------------------------------------------------------------------------------


def _dash(v: str | None) -> str:
    return v if v else "-"


class ExpectedFailure:
    """One line of a list: ``entry``, ``variant`` ("-" for none), ``level`` (or "unread"), ``line`` number."""

    __slots__ = ("entry", "variant", "level", "line")

    def __init__(self, entry: str, variant: str, level: str, line: int):
        self.entry, self.variant, self.level, self.line = entry, _dash(variant), level, line

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.entry, self.variant, self.level)

    def __str__(self) -> str:
        return f"{self.entry} {self.variant} {self.level}"

    def __repr__(self) -> str:
        return f"ExpectedFailure({str(self)!r}, line {self.line})"


class ExpectedFailures:
    """A parsed expected-failure list: ``items`` and the ``name`` used in messages (its path)."""

    def __init__(self, items: list[ExpectedFailure], name: str):
        self.items, self.name = items, name

    @classmethod
    def parse(cls, text: str, name: str = "expected-failures") -> ExpectedFailures:
        items, seen = [], {}
        for n, line in enumerate(text.splitlines(), 1):
            body = line.split("#", 1)[0]
            fields = body.split()
            if not fields:
                continue
            if len(fields) != 3:
                raise CorpusError(f"{name}:{n}: want `<entry> <variant or -> <level or unread>`, got {body.strip()!r}")
            f = ExpectedFailure(fields[0], fields[1], fields[2], n)
            if f.key in seen:
                raise CorpusError(f"{name}:{n}: {f} is already listed on line {seen[f.key]}")
            seen[f.key] = n
            items.append(f)
        return cls(items, name)

    @classmethod
    def read(cls, path) -> ExpectedFailures:
        path = os.fspath(path)
        try:
            with _read_file(path, encoding="utf-8") as f:
                return cls.parse(f.read(), path)
        except OSError as e:
            raise CorpusError(f"{path}: {e.strerror or e}") from e

    @staticmethod
    def write(results: Results, corpus_version: str | None = None) -> str:
        """The text of a list holding the run's failures and unread variants, sorted, each with a comment."""
        lines = []
        for k, (ok, detail) in results._cells.items():
            if not ok:
                lines.append((k, f"{k[0]} {k[1]} {k[2]}  # {_one_line(detail)}"))
        for (e, v), reason in results._unread.items():
            lines.append(((e, v, UNREAD), f"{e} {v} {UNREAD}  # never read: {_one_line(reason)}"))
        lines.sort(key=lambda x: x[0])
        who = results.name or "this SDK"
        head = [
            f"# Expected conformance failures of {who}" + (f" against corpus {corpus_version}." if corpus_version else "."),
            "# The test passes only when the run's failures are exactly these lines: a new failure fails, and so",
            "# does a listed cell that passes (remove its line when a bug is fixed).",
            "# <entry> <variant or -> <level>  # what the SDK did",
            "# <entry> <variant or -> unread   # a variant the SDK never reads",
        ]
        return "\n".join(head + [t for _, t in lines]) + "\n"


def _one_line(s, n: int = 400) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


class Results:
    """What a run did, per cell (entry, variant, level), and the variants it never read."""

    def __init__(self, name: str | None = None):
        self.name = name
        self._cells: dict[tuple[str, str, str], tuple[bool, str]] = {}
        self._unread: dict[tuple[str, str], str] = {}
        self._selected: set[str] = set()

    def select(self, entry: str) -> None:
        """Mark an entry as selected by the run even when nothing was recorded for it."""
        self._selected.add(entry)

    def fail(self, entry: str, variant: str | None, level: str, detail: str) -> None:
        self._selected.add(entry)
        self._cells[(entry, _dash(variant), level)] = (False, str(detail))

    def pass_(self, entry: str, variant: str | None, level: str) -> None:
        self._selected.add(entry)
        self._cells[(entry, _dash(variant), level)] = (True, "")

    def unread(self, entry: str, variant: str | None, reason: str) -> None:
        self._selected.add(entry)
        self._unread[(entry, _dash(variant))] = str(reason)

    def failures(self) -> list[tuple[str, str, str, str]]:
        """(entry, variant, level, detail) of every failing cell, sorted."""
        return sorted((*k, d) for k, (ok, d) in self._cells.items() if not ok)

    def compare(self, expected: ExpectedFailures, require_all_read: bool = False) -> Comparison:
        """The run compared with a list, by the rules of ``xdrcheck conform --expected-failures``."""
        cmp = Comparison(self.name or expected.name, expected.name)
        listed = {f.key: f for f in expected.items}
        read_variants = {(e, v) for (e, v, _l) in self._cells}
        for k, (ok, detail) in sorted(self._cells.items()):
            if not ok and k in listed:
                cmp.matched += 1
            elif not ok:
                cmp.new.append((*k, detail))
            elif k in listed:
                cmp.now_passing.append((*k, "now conforms"))
        for (e, v), reason in sorted(self._unread.items()):
            if (e, v, UNREAD) in listed:
                cmp.matched += 1
            elif require_all_read:
                cmp.new_unread.append((e, v, reason))
        for f in expected.items:
            ev = (f.entry, f.variant)
            if f.level == UNREAD:
                if ev in read_variants:
                    cmp.now_read.append(f)
                elif ev not in self._unread and f.entry in self._selected:
                    cmp.not_run.append(f)
            elif f.key not in self._cells:
                if ev in self._unread:
                    # a listed failing cell of a variant the run now answers n/a: no longer a failure
                    cmp.now_passing.append((*f.key, f"is now n/a ({self._unread[ev]})"))
                elif f.entry in self._selected:
                    cmp.not_run.append(f)
        return cmp


class Comparison:
    """The outcome of ``Results.compare``: the five kinds of difference, ``passed()`` and ``format()``."""

    def __init__(self, name: str, list_name: str):
        self.name, self.list_name = name, list_name
        self.matched = 0
        self.new: list[tuple[str, str, str, str]] = []  # entry, variant, level, detail
        self.now_passing: list[tuple[str, str, str, str]] = []  # entry, variant, level, what
        self.now_read: list[ExpectedFailure] = []
        self.new_unread: list[tuple[str, str, str]] = []  # entry, variant, reason
        self.not_run: list[ExpectedFailure] = []

    def passed(self) -> bool:
        return not (self.new or self.now_passing or self.now_read or self.new_unread or self.not_run)

    def format(self) -> str:
        out = []
        for e, v, lvl, d in self.new:
            out.append(f"NEW-FAILURE   {e} {v} {lvl}: {d}")
        for e, v, lvl, what in self.now_passing:
            out.append(f"UNEXPECTED-PASS {e} {v} {lvl}: listed as failing but {what}; remove the line from {self.list_name}")
        for f in self.now_read:
            out.append(f"UNEXPECTED-PASS {f}: listed as unread but the column now reads it; remove the line from {self.list_name}")
        for e, v, reason in self.new_unread:
            out.append(f"NEW-UNREAD    {e} {v}: never read ({reason})")
        for f in self.not_run:
            out.append(
                f"NOT-RUN       {f} ({self.list_name} line {f.line}): the run has no such cell; remove the line or fix its spelling"
            )
        out.append(
            f"expected failures {self.name}: {self.matched} still as listed, {len(self.new)} new failures, "
            f"{len(self.new_unread)} new unread, {len(self.now_passing) + len(self.now_read)} unexpected passes, "
            f"{len(self.not_run)} listed but not run"
        )
        return "\n".join(out) + "\n"
