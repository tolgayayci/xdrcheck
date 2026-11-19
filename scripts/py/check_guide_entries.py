#!/usr/bin/env python3
"""Check that every corpus entry the guide cites exists in the corpus, not only in the plan.

`check_guide_claims.py` and `xdrcheck-corpus guide-claims --check` accept any canonical ID (a row or
`<row>.<member>` of corpus/plan.json), which includes entries that are planned but have no bytes yet. A guide
that cites such an entry sends the reader to something that does not exist. This check reads:

- guide/indexer-hardening.mdx, guide/checklist.mdx and guide/generated/*.mdx: every `group/name` token whose
  group is a corpus group;
- guide/claims.yaml: every `corpus_entries` item and every `source` of kind `corpus`;

and fails when a cited ID is neither an entry of corpus/index.json nor the base of at least one entry there (a
citation of a whole member group, such as `strkey/sep-0023-v1.4.0-vectors`). Lines of the field table that the
table generator lists as not yet established may name planned entries; they are skipped (`(planned: …)`).

Usage: check_guide_entries.py [--root DIR]. Exit 1 on any failure. `guide/review/build.py --check` runs it too."""
import glob, json, os, re, sys
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
ENTRY_RE = re.compile(r"(?<![\w/.-])([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:[.-][a-z0-9]+)*)")
PLANNED_RE = re.compile(r"\(planned: [^)]*\)")


def existing(root):
    """(set of entry IDs in corpus/index.json, set of corpus group names)."""
    with open(os.path.join(root, "corpus", "index.json"), encoding="utf-8") as f:
        ids = {e["id"] for e in json.load(f)["entries"]}
    with open(os.path.join(root, "corpus", "plan.json"), encoding="utf-8") as f:
        groups = {r["id"].split("/")[0] for r in json.load(f)}
    return ids, groups | {i.split("/")[0] for i in ids}


def exists(cid, ids):
    return cid in ids or any(i.startswith(cid + ".") for i in ids)


def problems(root=ROOT):
    ids, groups = existing(root)
    bad = []
    pages = ["guide/indexer-hardening.mdx", "guide/checklist.mdx"] + sorted(
        os.path.relpath(p, root) for p in glob.glob(os.path.join(root, "guide", "generated", "*.mdx")))
    for page in pages:
        with open(os.path.join(root, page), encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = PLANNED_RE.sub("", line)
                line = re.sub(r"https?://\S+", "", line)
                for m in ENTRY_RE.finditer(line):
                    if m.group(1) in groups and not exists(m.group(0), ids):
                        bad.append(f"{page}:{n}: cites {m.group(0)!r}, which is not an entry of corpus/index.json")
    with open(os.path.join(root, "guide", "claims.yaml"), encoding="utf-8") as f:
        claims = yaml.safe_load(f)["claims"]
    for c in claims:
        cited = list(c.get("corpus_entries") or []) + [s["ref"] for s in c.get("source") or [] if s.get("kind") == "corpus"]
        for cid in sorted(set(cited)):
            if not exists(cid, ids):
                bad.append(f"guide/claims.yaml: {c['claim_id']} cites {cid!r}, which is not an entry of corpus/index.json")
    return bad, len(ids)


def main(argv):
    root = ROOT
    if len(argv) == 2 and argv[0] == "--root":
        root = os.path.abspath(argv[1])
    elif argv:
        sys.exit(__doc__)
    bad, n = problems(root)
    print(f"guide entries: every cited corpus entry checked against {n} entries of corpus/index.json")
    for b in bad:
        print("FAIL", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
