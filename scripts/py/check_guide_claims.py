#!/usr/bin/env python3
"""Check the guide page (guide/indexer-hardening.mdx) against its claim map (guide/claims.yaml).

A normative sentence is tagged by an MDX comment placed right after it: `sentence. {/* claim: C-0123 */}`.
Checks, each a failure:
- every claim tag names a claim in guide/claims.yaml, and no claim is tagged twice;
- every sentence that contains "must", "never", "should" or "do not" (outside code) carries a claim tag;
- a tagged claim's `sentence` equals the tagged sentence of the page (links reduced to their text, bold
  markers removed), and its `guide_anchor` is the anchor of the section the sentence sits in;
- every corpus entry ID mentioned in the page is canonical (a row or `<row>.<member>` of corpus/plan.json);
- generated-table markers are paired, CAP and SEP numbers are unpadded in prose, and the page names no
  internal working file.

Sentences are split per paragraph line and list item; a table row counts as one statement, cells joined
with " | ". Fenced code blocks, front matter, other MDX comments and the generated field tables (between
BEGIN GENERATED and END GENERATED; `xdrcheck-corpus guide-table --check` checks them against fields.yaml) are
not split into sentences. `xdrcheck-corpus guide-claims --check` runs the same checks. Exit 1 on any failure."""
import json, os, re, sys
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PAGE = os.path.join("guide", "indexer-hardening.mdx")
TAG_RE = re.compile(r"\{/\*\s*claim:\s*(C-[0-9]{3,4})\s*\*/\}")
COMMENT_RE = re.compile(r"\{/\*.*?\*/\}")
MARK_RE = re.compile(r"\x00(\d+)\x00")
TRIGGER_RE = re.compile(r"\b(must|never|should|do not)\b", re.I)
ANCHOR_RE = re.compile(r"^#{2,6}\s.*\{#([a-z0-9-]+)\}\s*$")
SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
ENTRY_RE = re.compile(r"(?<![\w/.-])([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:[.-][a-z0-9]+)*)")
BANNED = [(re.compile(r"\bADR[- ]?\d"), "ADR number"), (re.compile(r"\d{4}-\d{2}-\d{2}\.md|-2026-\d\d-\d\d"), "research note name"),
          (re.compile(r"fields\.yaml|claims\.yaml|plan\.json|draft\.yaml"), "internal file name")]
# Machine-local paths, private names and the internal research folder are caught by check_public.py.
PADDED_RE = re.compile(r"\b(CAP|SEP)-0\d+")


def clean(text):
    """Sentence text as stored in claims.yaml: links reduced to their text, bold removed, spaces collapsed."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("**", "")
    return re.sub(r"\s+", " ", text).strip()


def segments(lines):
    """Yield (line number, anchor, text) for each paragraph line, list item and table cell."""
    anchor, in_code, in_front, in_generated = "", False, False, False
    for n, line in enumerate(lines, start=1):
        s = line.strip()
        if n == 1 and s == "---":
            in_front = True
            continue
        if in_front:
            in_front = s != "---"
            continue
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not s:
            continue
        if "BEGIN GENERATED:" in s or "END GENERATED" in s:
            in_generated = "BEGIN GENERATED:" in s
            continue
        if in_generated:
            continue
        m = ANCHOR_RE.match(s)
        if m:
            anchor = "#" + m.group(1)
        if s.startswith("|"):
            if re.fullmatch(r"\|[\s:|-]+\|", s):
                continue
            yield n, anchor, "\x01" + " | ".join(c.strip() for c in s.strip("|").split("|"))
        elif s.startswith("<") and not TAG_RE.match(s):
            continue
        else:
            yield n, anchor, re.sub(r"^(?:[-*]|\d+\.)\s+", "", s)


def sentences(text):
    """Split one segment into [(sentence, [claim IDs])]; a tag belongs to the sentence before it.
    A table row (marked with a leading \\x01) is a single statement whose tags cover the row."""
    tags = []

    def mark(m):
        tags.append(m.group(1))
        return f" \x00{len(tags) - 1}\x00 "

    row = text.startswith("\x01")
    text = TAG_RE.sub(mark, text.lstrip("\x01"))
    text = COMMENT_RE.sub(" ", text)
    if row:  # a table row is one statement: its tags cover the whole row
        return [(clean(MARK_RE.sub(" ", text)), [tags[int(i)] for i in MARK_RE.findall(text)])]
    out = []
    for piece in SPLIT_RE.split(text):
        lead = re.match(r"^(\s*\x00\d+\x00\s*)+", piece)
        if lead:
            ids = [tags[int(i)] for i in MARK_RE.findall(lead.group(0))]
            if out:
                out[-1][1].extend(ids)
            else:
                out.append(["", ids])
            piece = piece[lead.end():]
        if not piece.strip():
            continue
        ids = [tags[int(i)] for i in MARK_RE.findall(piece)]
        out.append([clean(MARK_RE.sub(" ", piece)), ids])
    return [(s, ids) for s, ids in out]


def tagged_sentences(path=os.path.join(ROOT, PAGE)):
    """[(line, anchor, sentence, [claim IDs])] for the whole page."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    return [(n, anchor, s, ids) for n, anchor, seg in segments(lines) for s, ids in sentences(seg)]


def main():
    bad = []
    with open(os.path.join(ROOT, PAGE), encoding="utf-8") as f:
        raw = f.read()
    with open(os.path.join(ROOT, "guide", "claims.yaml"), encoding="utf-8") as f:
        claims = {c["claim_id"]: c for c in yaml.safe_load(f)["claims"]}
    with open(os.path.join(ROOT, "corpus", "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    canon = {r["id"] for r in plan} | {f"{r['id']}.{m}" for r in plan for m in r.get("members", [])}
    groups = {i.split("/")[0] for i in canon}

    seen, n_sent, n_norm = {}, 0, 0
    for line, anchor, sent, ids in tagged_sentences():
        n_sent += 1
        if TRIGGER_RE.search(re.sub(r"`[^`]*`", "", sent)):
            n_norm += 1
            if not ids:
                bad.append(f"{PAGE}:{line}: normative sentence without a claim tag: {sent[:120]!r}")
        for cid in ids:
            if cid in seen:
                bad.append(f"{PAGE}:{line}: {cid} is tagged twice (first on line {seen[cid]})")
            seen[cid] = line
            c = claims.get(cid)
            if c is None:
                bad.append(f"{PAGE}:{line}: {cid} is not in guide/claims.yaml")
                continue
            if c["sentence"] != sent:
                bad.append(f"{PAGE}:{line}: {cid} sentence differs from claims.yaml:\n    page:   {sent!r}\n"
                           f"    claims: {c['sentence']!r}")
            if c["guide_anchor"] != anchor:
                bad.append(f"{PAGE}:{line}: {cid} guide_anchor {c['guide_anchor']!r} but the section is {anchor!r}")

    body = re.sub(r"```.*?```", "", raw, flags=re.S)
    for m in ENTRY_RE.finditer(body):
        if m.group(1) in groups and m.group(0) not in canon:
            bad.append(f"{PAGE}: {m.group(0)!r} is not a canonical corpus entry ID")
    if len(re.findall(r"BEGIN GENERATED:", raw)) != len(re.findall(r"END GENERATED", raw)):
        bad.append(f"{PAGE}: unpaired BEGIN GENERATED / END GENERATED markers")
    prose = re.sub(r"`[^`]*`|\([^)\s]*\)|https?://\S+", "", body)
    for m in PADDED_RE.finditer(prose):
        bad.append(f"{PAGE}: write {m.group(0)} without zero padding in prose")
    for rx, why in BANNED:
        for m in rx.finditer(raw):
            bad.append(f"{PAGE}: {why}: {m.group(0)!r}")

    print(f"guide: {n_sent} sentences, {n_norm} normative, {len(seen)} claim tags, "
          f"{len(set(m.group(0) for m in ENTRY_RE.finditer(body) if m.group(1) in groups))} corpus entries named")
    for b in bad:
        print("FAIL", b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
