#!/usr/bin/env bash
# Build and check the corpus release archive. The layout, the stress-entry rule and the reproducibility options
# are specified in docs/release.md; this script implements that page.
#
# Usage:
#   scripts/release.sh build [OUT_DIR]   write xdrcheck-<version>.tar.gz into OUT_DIR (default dist)
#   scripts/release.sh check             build twice and compare the sha256; extract into an empty directory, run
#                                        the public-tree scan over it with no exemption, check that every file a
#                                        manifest names is in it (refs), and run `xdrcheck-corpus
#                                        verify` on both corpus roots there, offline
#   scripts/release.sh npm               build into dist, run the npm package's unit tests, pack packages/npm
#                                        around the archive and run its whole corpus/ root through it against
#                                        the pinned JavaScript SDK, offline (packages/npm/check.sh)
#   scripts/release.sh refs ARCHIVE      every blob, sidecar, chain and recipe path a manifest of the archive (or
#                                        of an extracted archive directory) names is in it; `check` runs this too
#   scripts/release.sh channels          the channel split on a copy of the commit's tree: a stable archive
#                                        leaves next-protocol entries out, a -next archive carries them and
#                                        refuses to build without one; `check` runs this too
#   scripts/release.sh version           print the release version and its channel (stable or next)
#   scripts/release.sh all               check, then npm (stable channel only), then `scripts/dist.sh sums`
#                                        (what `make release` runs); leaves the archive, the package, SHA256SUMS
#                                        and the release provenance in dist/
#
# Environment:
#   COMMIT          the commit to release (default HEAD); only its committed files are read (`git archive`)
#   VERSION         the release version (default: corpus.json corpus_version without a pre-release suffix).
#                   MAJOR.MINOR.PATCH is the stable channel, MAJOR = pins.toml protocol.max_supported;
#                   MAJOR.MINOR.PATCH-rc.N with MAJOR = max_supported + 1 is the -next channel (docs/release.md
#                   section 8)
#   XDRCHECK_CORPUS_BIN  the xdrcheck-corpus binary for `check` (default target/release/xdrcheck-corpus)
#   XDRCHECK_GOLDENS     golden cache for the extra ag1/ag3 run in `check` (default ~/.cache/xdrcheck/goldens)
#
# Everything is written under dist/ (ignored by git); nothing is published anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
export LC_ALL=C
py() { python3 -I "$@"; }

commit=$(git rev-parse --verify "${COMMIT:-HEAD}^{commit}")
epoch=$(git log -1 --format=%ct "$commit")

# The release version: VERSION, else corpus.json's corpus_version without a pre-release suffix. A plain
# MAJOR.MINOR.PATCH is the stable channel and its MAJOR must be the highest protocol the pins support; a
# MAJOR.MINOR.PATCH-rc.N is the -next channel, one protocol above it (docs/release.md section 8).
vline=$(py -c '
import json, re, subprocess, sys, tomllib
commit, given = sys.argv[1], sys.argv[2]
show = lambda p: subprocess.check_output(["git", "show", f"{commit}:{p}"])
cv = json.loads(show("corpus/corpus.json"))["corpus_version"]
v = given or re.sub(r"-.*$", "", cv)
num = r"(0|[1-9][0-9]*)"
m = re.fullmatch(num + r"\." + num + r"\." + num + r"(-rc\.([1-9][0-9]*))?", v)
if not m:
    sys.exit(f"release: version {v!r} is neither MAJOR.MINOR.PATCH nor MAJOR.MINOR.PATCH-rc.N")
maxp = tomllib.loads(show("pins.toml").decode())["protocol"]["max_supported"]
channel = "next" if m.group(4) else "stable"
if channel == "stable" and int(m.group(1)) != maxp:
    sys.exit(f"release: version {v} does not cover protocol {maxp} (pins.toml protocol.max_supported)")
if channel == "next" and int(m.group(1)) != maxp + 1:
    sys.exit(f"release: version {v}: a -next release covers protocol {maxp + 1} (pins.toml protocol.max_supported + 1)")
print(v, channel, maxp)' "$commit" "${VERSION:-}")
read -r version channel maxp <<< "$vline"
top="xdrcheck-$version"
archive="$top.tar.gz"

# Files of the commit that go into the archive (docs/release.md section 2). Nothing else is read.
INPUTS=(corpus pins.toml LICENSE NOTICE CHANGELOG.md docs/manifest.md docs/release.md)

# stage SRC STAGE CHANNEL VERSION: write the archive tree of SRC (the commit's exported inputs) into STAGE.
stage() {
  local tools
  tools=$(printf '%s\n' "$(git --version)" "$(tar --version | head -1)" "$(gzip --version | head -1)" \
    "$(python3 --version)")
  py - "$1" "$2" "$4" "$commit" "$epoch" "xdrcheck-$4.tar.gz" "$tools" "$3" "$maxp" <<'PY'
# Stage the archive tree from the exported commit: split stress entries into their own corpus root, ship each
# root only the recipes of its own entries, strip the planning fields from the entry-ID registry, stamp the
# release version, write manifest.sha256 per root, PROVENANCE.json and SHA256SUMS (docs/release.md).
import hashlib, json, os, re, shutil, sys
src, stage, version, commit, epoch, archive, tools, channel = sys.argv[1:9]
max_supported = int(sys.argv[9])
corpus = os.path.join(src, "corpus")

def load(p):
    with open(p, "rb") as f:
        return json.loads(f.read())

def files_under(d):
    out = []
    for dirpath, dirs, names in os.walk(d):
        dirs.sort()
        for n in sorted(names):
            out.append(os.path.relpath(os.path.join(dirpath, n), d).replace(os.sep, "/"))
    return sorted(out)

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

AS_PROFILE = re.compile(r"^address-space cap RLIMIT_AS [1-9][0-9]* ?(KiB|MiB|GiB)$")

def is_stress(e):
    """docs/release.md section 3; the same rule the conformance orchestrator uses to isolate an entry."""
    if e["id"].startswith("limits/"):
        return True
    for k in (e.get("conformance") or {}).get("known_divergences") or []:
        if k.get("level") != "replay" and k.get("outcome") in ("crash", "hang"):
            return True
        if AS_PROFILE.match(k.get("profile") or ""):
            return True
    return False

entries = {}
for rel in files_under(os.path.join(corpus, "manifest")):
    if rel.endswith(".json"):
        e = load(os.path.join(corpus, "manifest", rel))
        entries[rel[:-5]] = e

def is_next(e):
    """docs/release.md section 8: an entry of the next protocol, above pins.toml protocol.max_supported."""
    if ((e.get("protocol") or {}).get("introduced") or 0) > max_supported:
        return True
    return any((v.get("protocol") or 0) > max_supported for v in e.get("variants") or [])

next_ids = sorted(i for i, e in entries.items() if is_next(e))
if channel == "stable":
    # The stable channel is the set a reader of the released protocol must pass: no next-protocol entry, and
    # nothing that only such an entry reaches.
    for i in next_ids:
        del entries[i]
elif not next_ids:
    sys.exit("release: no next-protocol entry (protocol.introduced or a variant's protocol above %d); "
             "a -next release needs at least one" % max_supported)
stress_ids = sorted(i for i, e in entries.items() if is_stress(e))
roots = {"corpus": sorted(set(entries) - set(stress_ids)), "stress": stress_ids}

chains = {}
for rel in files_under(os.path.join(corpus, "chains")):
    if rel.endswith(".json"):
        chains["chains/" + rel] = load(os.path.join(corpus, "chains", rel))

def reached(ids):
    """Blobs, sidecars, chain files and vendored objects the given entries reach (as the orphans check)."""
    blobs, blob_paths, chain_ids, objects = set(), set(), set(), set()
    for i in ids:
        e = entries[i]
        if (e.get("replay") or {}).get("chain"):
            chain_ids.add(e["replay"]["chain"])
        for v in e.get("variants") or []:
            sha = (v.get("blob") or {}).get("sha256")
            if sha:
                blobs.add(sha)
            if (v.get("blob") or {}).get("path"):
                blob_paths.add(v["blob"]["path"])
            s = v.get("source") or {}
            if s.get("kind") == "history":
                op = s.get("object_path") or "objects/%s/%s/%s" % (
                    v.get("network", ""), v.get("ledger_seq"), (s.get("key") or "").rsplit("/", 1)[-1])
                objects.add(os.path.dirname(op))
            elif s.get("kind") == "history-archive":
                objects.add("objects/%s/history-archive" % v.get("network", ""))
    keep = set()
    # A blob is blobs/<aa>/<sha256>.<container extension> (.xdr, .wasm, ...): keep every file a variant names,
    # and any other file of a referenced sha256 whatever its extension.
    for rel in files_under(os.path.join(corpus, "blobs")):
        if "blobs/" + rel in blob_paths or rel.split("/")[-1].split(".", 1)[0] in blobs:
            keep.add("blobs/" + rel)
    for rel in files_under(os.path.join(corpus, "decoded")):
        if rel.split("/")[-1].removesuffix(".json.zst") in blobs:
            keep.add("decoded/" + rel)
    for rel, c in chains.items():
        if c.get("id") in chain_ids or any(r.get("blob_sha256") in blobs for r in c.get("ledgers") or []):
            keep.add(rel)
            if (c.get("stream") or {}).get("path"):
                keep.add(c["stream"]["path"])
    for d in objects:
        for rel in files_under(os.path.join(corpus, d)):
            keep.add(d + "/" + rel)
    return keep

ALWAYS = ("corpus.json", "plan.json", "schema/")
SPLIT = ("manifest/", "blobs/", "decoded/", "chains/", "recipes/")
# The repository's plan schema describes the planning registry, which the archive does not ship (section 4).
NEVER = ("schema/plan.schema.json", "schema/examples/plan/")
# Planning fields of the entry-ID registry: what each row was planned for, where it was to come from, its
# priority and collection status. The archive keeps the rows' description of the entry (docs/release.md §4).
PLAN_INTERNAL = ("priority", "serves", "locator", "evidence")
all_files = files_under(corpus)
counts = {}
for name, ids in roots.items():
    # A recipe is recipes/<entry id>.json; it ships only with its entry, so limits/ recipes go with stress/.
    recipes = {"recipes/%s.json" % i for i in ids}
    keep = reached(ids) | {"manifest/%s.json" % i for i in ids} | (recipes & set(all_files))
    dst = os.path.join(stage, name)
    for d in ("manifest", "blobs", "decoded", "chains"):
        os.makedirs(os.path.join(dst, d), exist_ok=True)
    for rel in all_files:
        if rel.startswith(NEVER):
            continue
        if rel in keep or rel.startswith(ALWAYS) or (name == "corpus" and not rel.startswith(SPLIT)):
            os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(corpus, rel), os.path.join(dst, rel))
    counts[name] = {"entries": len(ids), "blobs": sum(1 for k in keep if k.startswith("blobs/"))}

    p = os.path.join(dst, "plan.json")
    rows = [{k: v for k, v in r.items() if k not in PLAN_INTERNAL} for r in load(p)]
    open(p, "w", encoding="utf-8").write(json.dumps(rows, indent=1, ensure_ascii=False) + "\n")

    # Stamp the release version (docs/release.md section 4).
    old = load(os.path.join(dst, "corpus.json"))["corpus_version"]
    for f in ("corpus.json", "coverage.json"):
        p = os.path.join(dst, f)
        if os.path.exists(p):
            text = open(p, encoding="utf-8").read()
            new, n = re.subn(r'("corpus_version":\s*)"[^"]*"', r'\g<1>"%s"' % version, text, count=1)
            if n != 1:
                sys.exit(f"release: {name}/{f} has no corpus_version")
            open(p, "w", encoding="utf-8").write(new)
    # Each root states its own curated-tier counts (the repository's are checked by scripts/py/check_corpus.py).
    blob_files = [os.path.join(dst, "blobs", r) for r in files_under(os.path.join(dst, "blobs"))]
    tier = {"entries": len(ids), "blobs": len(blob_files), "bytes": sum(os.path.getsize(f) for f in blob_files)}
    p = os.path.join(dst, "corpus.json")
    head, sep, tail = open(p, encoding="utf-8").read().partition('"curated"')
    for k, v in tier.items():
        tail, n = re.subn(r'("%s":\s*)\d+' % k, r"\g<1>%d" % v, tail, count=1)
        if n != 1:
            sys.exit(f"release: {name}/corpus.json tiers.curated has no {k}")
    open(p, "w", encoding="utf-8").write(head + sep + tail)

    p = os.path.join(dst, "COVERAGE.md")
    if os.path.exists(p):
        text = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(text.replace("Corpus %s." % old, "Corpus %s." % version))

    lines = ["%s  manifest/%s\n" % (sha256(os.path.join(dst, "manifest", r)), r)
             for r in files_under(os.path.join(dst, "manifest"))]
    open(os.path.join(dst, "manifest.sha256"), "w").write("".join(lines))

for f in ("pins.toml", "LICENSE", "NOTICE", "CHANGELOG.md", "docs/manifest.md", "docs/release.md"):
    os.makedirs(os.path.dirname(os.path.join(stage, f)) or stage, exist_ok=True)
    shutil.copyfile(os.path.join(src, f), os.path.join(stage, f))

# Never anything private or ignored: the input is `git archive` of named paths, and this allow-list is a second
# guard (no secrets file, report, finding or overlay can sit under these names).
TOP = {"pins.toml", "LICENSE", "NOTICE", "CHANGELOG.md", "docs/manifest.md", "docs/release.md"}
for rel in files_under(stage):
    if not (rel in TOP or rel.startswith(("corpus/", "stress/"))) or "/." in "/" + rel:
        sys.exit(f"release: {rel} must never be in a release")

cj = load(os.path.join(corpus, "corpus.json"))
prov = {
    "schema": "xcc.release/v1",
    "version": version,
    "channel": channel,
    "protocol": int(version.split(".")[0]),
    "archive": {"file": archive, "top": os.path.basename(stage)},
    "source": {"commit": commit, "commit_time": int(epoch), "input": "git archive of the commit"},
    "pins": {"pins_toml_sha256": sha256(os.path.join(src, "pins.toml")), "corpus": cj.get("pins")},
    "entries": {"corpus": counts["corpus"], "stress": dict(counts["stress"], ids=stress_ids),
                "next": next_ids if channel == "next" else []},
    "tools": [t for t in tools.split("\n") if t],
    "reproducible": {"mtime": int(epoch), "owner": "0:0", "modes": "0644 files, 0755 directories and executables",
                     "tar": "GNU tar --sort=name --format=ustar", "gzip": "gzip -n -9"},
}
open(os.path.join(stage, "PROVENANCE.json"), "w").write(json.dumps(prov, indent=2) + "\n")

sums = ["%s  %s\n" % (sha256(os.path.join(stage, r)), r) for r in files_under(stage)]
open(os.path.join(stage, "SHA256SUMS"), "w").write("".join(sums))
PY
}

# build OUT_DIR: write OUT_DIR/$archive. Runs in a subshell so its clean-up trap is its own.
build() (
  out=${1:-dist}
  case "$out" in /*) ;; *) out="$root/$out" ;; esac
  mkdir -p "$out" "$root/dist"
  work=$(mktemp -d "$root/dist/.release-build.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  mkdir "$work/src" "$work/$top"
  git archive --format=tar "$commit" -- "${INPUTS[@]}" | tar -xf - -C "$work/src"
  stage "$work/src" "$work/$top" "$channel" "$version"

  tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --mode='u=rwX,go=rX,a-st' -C "$work" -cf - "$top" | gzip -n -9 > "$out/$archive.tmp"
  mv "$out/$archive.tmp" "$out/$archive"
  echo "release: $out/$archive ($(stat -c %s "$out/$archive") bytes) sha256 $(sha256sum "$out/$archive" | cut -d' ' -f1)"
)

# refs_check DIR: every file a manifest of DIR/corpus or DIR/stress names (blobs/, decoded/, chains/, recipes/
# paths anywhere in the entry) is in that root. A filter that drops one kind of file fails here by name.
refs_check() {
  py - "$1" <<'PY'
import json, os, sys
top = sys.argv[1]
PREFIXES = ("blobs/", "decoded/", "chains/", "recipes/")
missing, seen = [], 0
def walk(x, out):
    if isinstance(x, dict):
        for v in x.values():
            walk(v, out)
    elif isinstance(x, list):
        for v in x:
            walk(v, out)
    elif isinstance(x, str) and x.startswith(PREFIXES) and "/" in x and " " not in x:
        out.add(x)
for root in ("corpus", "stress"):
    mdir = os.path.join(top, root, "manifest")
    for dirpath, _, names in os.walk(mdir):
        for n in sorted(names):
            if not n.endswith(".json"):
                continue
            p = os.path.join(dirpath, n)
            refs = set()
            walk(json.load(open(p, "rb")), refs)
            for r in sorted(refs):
                seen += 1
                if not os.path.isfile(os.path.join(top, root, r)):
                    missing.append("%s/%s: %s" % (root, os.path.relpath(p, mdir), r))
for m in missing:
    print("release check: missing from the archive: " + m, file=sys.stderr)
if missing:
    sys.exit("release check: %d manifest-referenced file(s) missing from the archive" % len(missing))
print("release check: every manifest-referenced file is in the archive (%d references)" % seen)
PY
}

# check: reproducibility, then `xdrcheck-corpus verify` from an empty directory holding only the extracted archive and
# the binary, with the network cut.
check() {
  bin=${XDRCHECK_CORPUS_BIN:-target/release/xdrcheck-corpus}
  test -x "$bin" || { echo "release check: $bin is not built (make build)" >&2; exit 2; }
  w="$root/dist/.release-check"
  rm -rf "$w"
  trap 'rm -rf "$root/dist/.release-check"' EXIT
  mkdir -p "$w/a" "$w/b" "$w/clean"
  build "$w/a"
  build "$w/b"
  a=$(sha256sum "$w/a/$archive" | cut -d' ' -f1)
  b=$(sha256sum "$w/b/$archive" | cut -d' ' -f1)
  echo "release check: build 1 sha256 $a"
  echo "release check: build 2 sha256 $b"
  [ "$a" = "$b" ] || { echo "release check: the two builds differ; the archive is not reproducible" >&2; exit 1; }

  clean="$w/clean"
  tar --no-same-owner -xzf "$w/a/$archive" -C "$clean"
  cp "$bin" "$clean/xdrcheck-corpus"
  echo "release check: clean directory holds: $(cd "$clean" && ls | tr '\n' ' ')"
  (cd "$clean/$top" && sha256sum -c --quiet SHA256SUMS) || { echo "release check: SHA256SUMS does not match" >&2; exit 1; }
  echo "release check: SHA256SUMS ok ($(wc -l < "$clean/$top/SHA256SUMS") files)"
  refs_check "$clean/$top"
  # Every rule of the public-tree scan over everything the archive holds, with no exemption (plan.json included).
  py scripts/py/check_public.py --tree "$clean/$top" || { echo "release check: the archive fails the public-tree scan" >&2; exit 1; }
  # Every default check except ag1 and ag3, which need stellar-core's golden files (not in the archive).
  local checks=schema,ids,hashes,roundtrip,reject,sidecar,pinpoints,extractor,orphans
  for r in corpus stress; do
    (cd "$clean" && "$root/scripts/offline-run.sh" ./xdrcheck-corpus --corpus "$top/$r" verify --checks "$checks")
  done
  goldens=${XDRCHECK_GOLDENS:-${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/goldens}
  if [ -d "$goldens" ]; then
    for r in corpus stress; do
      (cd "$clean" && "$root/scripts/offline-run.sh" ./xdrcheck-corpus --corpus "$top/$r" verify --checks ag1,ag3 --goldens "$goldens")
    done
  else
    echo "release check: no golden cache at $goldens; ag1 and ag3 not run (make fetch fills it)"
  fi
  rm -rf "$w"
  channels
  echo "release check: ok"
}

# channels: the channel split (docs/release.md section 8), on a copy of the commit's inputs in which one entry is
# made a next-protocol entry. The stable stage must leave it out, the -next stage must carry it and name it in
# PROVENANCE.json, and a -next stage of the unchanged inputs must refuse. Nothing is archived or kept.
channels() (
  w=$(mktemp -d "$root/dist/.release-channels.XXXXXX")
  trap 'rm -rf "$w"' EXIT
  mkdir "$w/src"
  git archive --format=tar "$commit" -- "${INPUTS[@]}" | tar -xf - -C "$w/src"
  nv="$((maxp + 1)).0.0-rc.1"
  mkdir "$w/plain"
  if stage "$w/src" "$w/plain" next "$nv" 2> "$w/plain.err"; then
    echo "release channels: the commit has next-protocol entries; a -next release can be built from it"
  elif grep -q 'no next-protocol entry' "$w/plain.err"; then
    echo "release channels: a -next stage of this commit refuses: $(tail -1 "$w/plain.err")"
  else
    cat "$w/plain.err" >&2; echo "release channels: the -next stage failed for another reason" >&2; exit 1
  fi
  # Make one plain stable entry (not a stress entry) a next-protocol entry.
  id=$(py - "$w/src/corpus" "$maxp" <<'PY'
import json, os, sys
corpus, maxp = sys.argv[1], int(sys.argv[2])
mdir = os.path.join(corpus, "manifest")
for d, dirs, names in sorted(os.walk(mdir)):
    dirs.sort()
    for n in sorted(names):
        p = os.path.join(d, n)
        e = json.load(open(p, "rb"))
        if e["id"].startswith("limits/") or e.get("kind") != "xdr" or (e.get("conformance") or {}).get("known_divergences"):
            continue
        e.setdefault("protocol", {})["introduced"] = maxp + 1
        for v in e.get("variants") or []:
            if "protocol" in v:
                v["protocol"] = maxp + 1
        open(p, "w").write(json.dumps(e, indent=2) + "\n")
        print(e["id"])
        sys.exit(0)
sys.exit("release channels: no xdr entry to mark")
PY
)
  mkdir "$w/stable" "$w/next"
  stage "$w/src" "$w/stable" stable "$version" > /dev/null
  stage "$w/src" "$w/next" next "$nv" > /dev/null
  py - "$w" "$id" "$nv" <<'PY'
import json, os, sys
w, id_, nv = sys.argv[1:4]
def has(root):
    return any(os.path.isfile(os.path.join(w, root, r, "manifest", id_ + ".json")) for r in ("corpus", "stress"))
ok = True
if has("stable"):
    print("release channels: the stable stage carries the next-protocol entry " + id_, file=sys.stderr); ok = False
if not has("next"):
    print("release channels: the -next stage lacks the next-protocol entry " + id_, file=sys.stderr); ok = False
prov = json.load(open(os.path.join(w, "next", "PROVENANCE.json")))
if prov.get("channel") != "next" or prov["entries"].get("next") != [id_] or prov.get("version") != nv:
    print("release channels: the -next PROVENANCE.json does not state the channel, version and entry", file=sys.stderr); ok = False
cv = json.load(open(os.path.join(w, "next", "corpus", "corpus.json")))["corpus_version"]
if cv != nv:
    print("release channels: the -next corpus.json says %s" % cv, file=sys.stderr); ok = False
st = json.load(open(os.path.join(w, "stable", "PROVENANCE.json")))
if st.get("channel") != "stable" or st["entries"].get("next") != []:
    print("release channels: the stable PROVENANCE.json is wrong", file=sys.stderr); ok = False
if not ok:
    sys.exit(1)
print("release channels: ok (%s marked next: left out of stable, carried by %s)" % (id_, nv))
PY
)

# npm: the package's unit tests, then pack it around dist/$archive and run its corpus/ root through the pinned SDK.
npm_step() {
  build dist
  mkdir -p dist/.npm-test
  (cd packages/npm && TMPDIR="$root/dist/.npm-test" node --test test/archive.test.mjs)
  rm -rf dist/.npm-test
  packages/npm/pack.sh "dist/$archive" dist
  packages/npm/check.sh "dist/xdrcheck-$version.tgz"
}

case "${1:-}" in
  build) build "${2:-dist}" ;;
  check) check ;;
  refs)
    [ -n "${2:-}" ] || { echo "usage: $0 refs ARCHIVE.tar.gz|DIR" >&2; exit 2; }
    if [ -d "$2" ]; then refs_check "$2"; else
      d=$(mktemp -d "$root/dist/.release-refs.XXXXXX"); trap 'rm -rf "$d"' EXIT
      tar --no-same-owner -xzf "$2" -C "$d"; refs_check "$d"/*/
    fi ;;
  npm) npm_step ;;
  channels) channels ;;
  version) echo "$version $channel" ;;
  all)
    check
    if [ "$channel" = stable ]; then
      npm_step
    else
      # The npm package's version is the stable corpus version (packages/npm/package.json); -next releases
      # ship the archive only.
      build dist
    fi
    VERSION=$version scripts/dist.sh sums ;;
  *) echo "usage: $0 build [OUT_DIR] | check | refs ARCHIVE | npm | channels | version | all" >&2; exit 2 ;;
esac
