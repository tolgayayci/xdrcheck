#!/usr/bin/env python3
"""Validate the real corpus data, not just schema examples:
- every corpus/manifest/**.json against manifest-entry.schema.json, every corpus/chains/**.json against
  chain-index.schema.json, corpus/corpus.json (when present) against corpus-index.schema.json;
- every variant's blob exists under corpus/ and its sha256 and byte length match; every decoded sidecar is the
  shared one of its blob (decoded/<aa>/<blob sha256>.json.zst), exists, and its uncompressed JSON matches
  decoded_sha256 when given;
- every manifest file is in the canonical form `xdrcheck-corpus render` writes: two-space JSON, non-ASCII escaped as
  \\uXXXX, a trailing newline;
- every captured lake object under corpus/objects/ matches the sha256 in its capture.json;
- every vendored history-archive object (corpus/objects/<network>/history-archive/<checkpoint>/, capture schema
  xcc.capture.history-archive/v1): the HAS and the gzipped bucket match their recorded sha256 and size, the HAS lists
  the bucket at the recorded level and slot, the gunzipped bucket's sha256 is its hash, and every record cut into a
  blob is framed by its record mark at byte_offset and equals that blob;
- every path a manifest, chain index or capture file cites inside the repository (corpus/…, evidence/…) exists;
- corpus.json `tiers.curated` states the real counts: manifest entries, blob files and their total bytes
  (`--fix` rewrites them);
- every manifest entry states `validity`, carries the flag named by its `expect.reject.reason`, and carries
  `core-lenient` exactly when `core_behaviour.accepts` is true (docs/manifest.md section 9.5);
- corpus/index.json validates against entry-index.schema.json and has one row per manifest entry whose fields
  equal the entry's (the coverage rows and the tier are checked by `xdrcheck-corpus index --check`).
Exit 1 on any failure."""
import glob, gzip, hashlib, json, os, re, sys
import jsonschema
import zstandard
from referencing import Registry, Resource

root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
corpus = os.path.join(root, "corpus")
reg, schemas = Registry(), {}
for f in glob.glob(os.path.join(corpus, "schema", "*.schema.json")):
    s = json.load(open(f))
    schemas[os.path.basename(f)[: -len(".schema.json")]] = s
    reg = reg.with_resource(s["$id"], Resource.from_contents(s))
def validator(name):
    return jsonschema.Draft202012Validator(schemas[name], registry=reg, format_checker=jsonschema.FormatChecker())
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
def unzstd_sha(p):
    try:
        with open(p, "rb") as f:
            return hashlib.sha256(zstandard.ZstdDecompressor().stream_reader(f).read()).hexdigest()
    except zstandard.ZstdError as e:
        return f"not zstd: {e}"
bad, counts = [], {"entries": 0, "variants": 0, "chains": 0, "objects": 0, "archive_objects": 0, "paths": 0}
path_rx = re.compile(r"(?<![\w/.-])((?:corpus|evidence)/[A-Za-z0-9_./-]*[A-Za-z0-9_-])")
def cited_paths(obj, where):
    text = json.dumps(obj)
    for m in path_rx.finditer(text):
        p = m.group(1).rstrip(".")
        counts["paths"] += 1
        if not os.path.exists(os.path.join(root, p)):
            bad.append(f"{where}: cites {p}, which does not exist")
def check(name, f):
    d = json.load(open(f))
    for e in validator(name).iter_errors(d):
        bad.append(f"{os.path.relpath(f, root)}: {e.message[:160]} at /{'/'.join(map(str, e.absolute_path))}")
    return d
def utf16_escape(m):
    b = m.group(0).encode("utf-16-be")
    return "".join(f"\\u{int.from_bytes(b[i:i + 2], 'big'):04x}" for i in range(0, len(b), 2))
def canonical(text):
    # The form `xdrcheck-corpus render` writes: serde_json's pretty printer (control characters escaped, DEL kept),
    # then every non-ASCII character as lower-case \uXXXX UTF-16 escapes, and a trailing newline.
    pretty = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    return re.sub(r"[^\x00-\x7f]", utf16_escape, pretty) + "\n"
entries = {}
for f in sorted(glob.glob(os.path.join(corpus, "manifest", "**", "*.json"), recursive=True)):
    e = check("manifest-entry", f)
    counts["entries"] += 1
    rel = os.path.relpath(f, root)
    text = open(f, encoding="utf-8").read()
    if text != canonical(text):
        bad.append(f"{rel}: not in canonical manifest form (two-space JSON, non-ASCII as \\uXXXX, trailing newline); "
                   "rewrite it as `xdrcheck-corpus render` writes")
    for v in e.get("variants", []):
        counts["variants"] += 1
        b = v.get("blob", {})
        bp = os.path.join(corpus, b.get("path") or f"blobs/{b.get('sha256','')[:2]}/{b.get('sha256','')}.xdr")
        if not os.path.exists(bp):
            bad.append(f"{rel}: blob {os.path.relpath(bp, root)} missing")
        else:
            if sha(bp) != b.get("sha256"): bad.append(f"{rel}: blob {os.path.relpath(bp, root)} sha256 mismatch")
            if os.path.getsize(bp) != b.get("bytes"): bad.append(f"{rel}: blob {os.path.relpath(bp, root)} length mismatch")
        dec = v.get("decoded")
        if dec:
            # One zstd-compressed sidecar per blob; decoded_sha256 is the hash of the uncompressed JSON.
            want = f"decoded/{b.get('sha256','')[:2]}/{b.get('sha256','')}.json.zst"
            dp = os.path.join(corpus, dec)
            if dec != want: bad.append(f"{rel}: sidecar {dec} is not {want}")
            if not os.path.exists(dp): bad.append(f"{rel}: sidecar {dec} missing")
            elif v.get("decoded_sha256") and unzstd_sha(dp) != v["decoded_sha256"]: bad.append(f"{rel}: sidecar {dec} sha256 mismatch")
    cited_paths(e, rel)
    if e.get("validity") is None:
        bad.append(f"{rel}: no validity (valid, malformed, invalid or acceptable)")
    flags = e.get("flags") or []
    reason = ((e.get("expect") or {}).get("reject") or {}).get("reason")
    if reason and reason.replace("_", "-") not in flags:
        bad.append(f"{rel}: expect.reject.reason {reason} without the flag {reason.replace('_', '-')}")
    if ((e.get("core_behaviour") or {}).get("accepts") is True) != ("core-lenient" in flags):
        bad.append(f"{rel}: the core-lenient flag must be set exactly when core_behaviour.accepts is true")
    entries[e.get("id")] = e
for f in sorted(glob.glob(os.path.join(corpus, "chains", "**", "*.json"), recursive=True)):
    cited_paths(check("chain-index", f), os.path.relpath(f, root)); counts["chains"] += 1
def curated_counts(base):
    """The curated tier as it is on disk: manifest entries, blob files, total blob bytes."""
    blobs = [f for f in glob.glob(os.path.join(base, "blobs", "**", "*"), recursive=True) if os.path.isfile(f)]
    return {"entries": len(glob.glob(os.path.join(base, "manifest", "**", "*.json"), recursive=True)),
            "blobs": len(blobs), "bytes": sum(os.path.getsize(f) for f in blobs)}
def set_curated_counts(path, want):
    """Rewrite the three counts in place, keeping the file's layout."""
    text = open(path, encoding="utf-8").read()
    head, sep, tail = text.partition('"curated"')
    for k, v in want.items():
        tail = re.sub(r'("%s":\s*)\d+' % k, r"\g<1>%d" % v, tail, count=1)
    open(path, "w", encoding="utf-8").write(head + sep + tail)
cj = os.path.join(corpus, "corpus.json")
if os.path.exists(cj):
    check("corpus-index", cj)
    want = curated_counts(corpus)
    have = {k: json.load(open(cj))["tiers"]["curated"].get(k) for k in want}
    if have != want:
        if "--fix" in sys.argv[1:]:
            set_curated_counts(cj, want)
            print(f"corpus.json tiers.curated updated: {want}")
        else:
            bad.append(f"corpus/corpus.json: tiers.curated says {have}, the corpus has {want} "
                       "(run scripts/py/check_corpus.py --fix)")
def index_row(e):
    """The fields of an index.json row that follow from the manifest entry alone (xdrcheck-corpus index)."""
    variants, sources = [], []
    for v in e.get("variants") or []:
        kind = (v.get("source") or {}).get("kind", "")
        if kind not in sources:
            sources.append(kind)
        b = v.get("blob") or {}
        variants.append({"network": v.get("network"), "protocol": v.get("protocol"), "ledger_seq": v.get("ledger_seq"),
                         "xdr_type": v.get("xdr_type"), "validity": v.get("validity", e.get("validity")),
                         "source": kind, "blob": b.get("path"), "sha256": b.get("sha256"), "bytes": b.get("bytes"),
                         "decoded": v.get("decoded"), "decoded_sha256": v.get("decoded_sha256"),
                         "focus": v.get("focus")})
    return {"id": e.get("id"), "title": e.get("title"), "kind": e.get("kind"), "caps": e.get("caps"),
            "protocol": e.get("protocol"), "synthetic": e.get("synthetic"), "validity": e.get("validity"),
            "flags": e.get("flags") or [], "sources": sorted(sources), "manifest": f"manifest/{e.get('id')}.json",
            "variants": variants}
ix = os.path.join(corpus, "index.json")
if not os.path.exists(ix):
    bad.append("corpus/index.json is missing (run `xdrcheck-corpus index`)")
else:
    rows = {r.get("id"): r for r in check("entry-index", ix).get("entries", [])}
    for i in sorted(set(rows) | set(entries)):
        if i not in rows or i not in entries:
            bad.append(f"corpus/index.json: entry {i} is {'missing' if i not in rows else 'not in the manifest'} "
                       "(run `xdrcheck-corpus index`)")
            continue
        want, have = index_row(entries[i]), rows[i]
        diff = sorted(k for k in want if want[k] != have.get(k))
        if diff:
            bad.append(f"corpus/index.json: row {i} differs from its manifest in {', '.join(diff)} "
                       "(run `xdrcheck-corpus index`)")
for c in sorted(glob.glob(os.path.join(corpus, "objects", "*", "*", "capture.json"))):
    d = json.load(open(c)); counts["objects"] += 1
    objs = glob.glob(os.path.join(os.path.dirname(c), "*.xdr.zst"))
    want = d.get("sha256_compressed") or d.get("object_sha256")
    if len(objs) != 1: bad.append(f"{os.path.relpath(c, root)}: expected one .xdr.zst next to it, found {len(objs)}")
    elif sha(objs[0]) != want: bad.append(f"{os.path.relpath(c, root)}: object sha256 mismatch")
def check_archive_object(c):
    rc = os.path.relpath(c, root)
    d, here = json.load(open(c)), os.path.dirname(c)
    if d.get("schema") != "xcc.capture.history-archive/v1":
        bad.append(f"{rc}: schema is {d.get('schema')!r}, not xcc.capture.history-archive/v1"); return
    def sized(what, data, sha256, size):
        if hashlib.sha256(data).hexdigest() != sha256: bad.append(f"{rc}: {what} sha256 mismatch")
        if size is not None and len(data) != size: bad.append(f"{rc}: {what} is {len(data)} bytes, recorded {size}")
    has = d.get("has", {})
    hp = os.path.join(here, has.get("file", ""))
    if not os.path.isfile(hp): bad.append(f"{rc}: HAS {has.get('file')!r} missing"); return
    raw = open(hp, "rb").read()
    sized("HAS", raw, has.get("sha256"), has.get("bytes"))
    state, bucket = json.loads(raw), d.get("bucket_hash")
    if state.get("currentLedger") != d.get("checkpoint"): bad.append(f"{rc}: HAS currentLedger is not the checkpoint")
    try: listed = state["currentBuckets"][d["bucket_level"]][d["bucket_slot"]]
    except (KeyError, IndexError, TypeError): listed = None
    if listed != bucket: bad.append(f"{rc}: HAS does not list bucket {bucket} at level {d.get('bucket_level')} {d.get('bucket_slot')}")
    obj = d.get("object_file", "")
    if obj != d.get("object", "").rsplit("/", 1)[-1] or obj != f"bucket-{bucket}.xdr.gz":
        bad.append(f"{rc}: object_file {obj!r} is not the object's base name bucket-<bucket_hash>.xdr.gz")
    op = os.path.join(here, obj)
    if not os.path.isfile(op): bad.append(f"{rc}: object {obj!r} missing"); return
    raw = open(op, "rb").read()
    sized("object", raw, d.get("object_sha256"), d.get("object_bytes"))
    try: dec = gzip.decompress(raw)
    except (OSError, EOFError) as e: bad.append(f"{rc}: object does not gunzip: {e}"); return
    sized("gunzipped object", dec, d.get("decompressed_sha256"), d.get("decompressed_bytes"))
    if hashlib.sha256(dec).hexdigest() != bucket: bad.append(f"{rc}: gunzipped object's sha256 is not the bucket hash")
    for r in d.get("records", []):
        off, where = r.get("byte_offset", -1), f"{rc}: record for {r.get('entry')}"
        mark = int.from_bytes(dec[off:off + 4], "big") if 0 <= off <= len(dec) - 4 else None
        if mark is None or not mark & 0x80000000 or f"{mark:08x}" != r.get("record_mark"):
            bad.append(f"{where}: no last-fragment record mark {r.get('record_mark')} at byte {off}"); continue
        body = dec[off + 4:off + 4 + (mark & 0x7fffffff)]
        if r.get("blob_offset") != off + 4 or len(body) != r.get("blob_bytes") or hashlib.sha256(body).hexdigest() != r.get("blob_sha256"):
            bad.append(f"{where}: the record at byte {off} is not the recorded blob"); continue
        sha = r["blob_sha256"]
        bp = os.path.join(corpus, "blobs", sha[:2], f"{sha}.xdr")
        if not os.path.isfile(bp) or open(bp, "rb").read() != body:
            bad.append(f"{where}: blob {os.path.relpath(bp, root)} missing or not the record")
for c in sorted(glob.glob(os.path.join(corpus, "objects", "*", "history-archive", "*", "capture.json"))):
    check_archive_object(c); counts["archive_objects"] += 1
print(" ".join(f"{k}: {v};" for k, v in counts.items()))
for b in bad: print("FAIL", b)
sys.exit(1 if bad else 0)
