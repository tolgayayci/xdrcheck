# Release archive

For anyone who pins a corpus release in CI, and for whoever cuts one. After this page you know what a release
contains, how it is laid out, which channel to pin, and how to check its bytes before anything reads them; and how
a release is built reproducibly.
The release procedure around it (version numbers, changelog, what may never be in a release) is in
[maintenance.md §3](maintenance.md#3-versioning-and-releases); the files inside the corpus are specified in
[manifest.md](manifest.md). `scripts/release.sh` implements this page and `make release` runs it.

## 1. Name and version

The archive is `xdrcheck-<version>.tar.gz` with a single top-level directory `xdrcheck-<version>/`.
`<version>` is the corpus version `MAJOR.MINOR.PATCH`, where MAJOR is the highest Stellar protocol the corpus
covers: the first release is `30.0.0`, covering Protocol 30. A consumer that pins `^30.0.0` (the npm package's
version is the corpus version) therefore never receives the release covering Protocol 31; moving to it is a
deliberate change of the pin. The change rule for `PROVENANCE.json`'s `xcc.release/v1` and the other schemas is
in [architecture.md](architecture.md#the-corpus): every `/v1` schema is closed from the first release, `30.0.0`, on.

The release version is `corpus.json` `corpus_version` with any pre-release suffix removed (`30.0.0-dev` gives
`30.0.0`), or `VERSION=<x.y.z>` given to the script. The script refuses a version that is not plain
`MAJOR.MINOR.PATCH` or whose MAJOR differs from `pins.toml` `protocol.max_supported`, with one exception: a
version `MAJOR.MINOR.PATCH-rc.N` whose MAJOR is one above it is a release of the `-next` channel (section 8).

## 2. Layout

```
xdrcheck-<version>/
  SHA256SUMS            sha256sum list of every other file in the archive
  PROVENANCE.json       version, source commit, pins, entry counts, the tools that wrote the archive
  pins.toml             the pins file of the source commit
  LICENSE  NOTICE  CHANGELOG.md
  docs/manifest.md      the manifest specification
  docs/release.md       this page
  corpus/               the default corpus root: every entry that is safe to run in another project's CI
  stress/               a second corpus root: the stress entries only (section 3)
```

Both `corpus/` and `stress/` are complete corpus roots: each holds `corpus.json`, `plan.json`, `schema/`,
`manifest/`, `blobs/`, `decoded/`, `chains/`, the recipes of its own entries and `manifest.sha256`, so a tool that
takes a corpus root (`xdrcheck-corpus --corpus DIR`) works on either one unchanged.

| Path | Holds |
|---|---|
| `corpus/manifest/<group>/<slug>.json` | the manifest entries that are not stress entries |
| `corpus/blobs/`, `corpus/decoded/` | the blobs those entries' variants name, whatever their container (`.xdr`, `.wasm`), and one sidecar per blob |
| `corpus/chains/` | the chain indexes those entries reach (a ledger of the chain is one of their blobs, or `replay.chain` names it), with any meta stream an index vendors |
| `corpus/objects/` | every vendored public-lake and history-archive object (provenance of `history` entries) |
| `corpus/schema/`, `corpus/plan.json`, `corpus/corpus.json` | the JSON Schemas (without the plan schema, section 4), the entry-ID registry and the corpus index |
| `corpus/coverage.json`, `corpus/COVERAGE.md` | the per-CAP coverage report |
| `corpus/recipes/` | the synthesis recipe of each entry in `corpus/` that has one (`recipes/<entry id>.json`); a recipe whose entry is in neither root is not shipped |
| `corpus/scenarios/`, `corpus/settings/`, `corpus/contracts/`, `corpus/caps.toml`, `corpus/fields.yaml`, `corpus/bulk/` | what the entries were made from: scenario files, network settings, test contracts, the CAP inventory, the guide's field-table source and the bulk-tier hash index |
| `corpus/manifest.sha256` | sha256sum list of every file under `corpus/manifest/`, paths relative to `corpus/` (`corpus.json` `checksums.manifest`) |
| `stress/` | the same kinds of files for the stress entries: their manifests, blobs, sidecars, recipes (every `limits/` recipe among them), the chains they reach and the objects their `history` variants are cut from, plus copies of `corpus.json`, `plan.json` and `schema/` |

A blob or chain reached from both roots is in both. Nothing else in the repository is in the archive: no tool
source, no reports, no findings, no evidence transcripts.

## 3. Stress entries

Some entries are built to stress a reader: deep nesting, length prefixes far beyond the input, allocations sized
from untrusted input. Run inside another project's CI without limits they can exhaust its memory, stack or time
([threat-model.md](threat-model.md)). They sit in `stress/`, so a consumer who runs `corpus/` never meets them and
one who wants them opts in by pointing at `stress/`.

An entry is a stress entry when any of these holds; it is the same rule by which the conformance orchestrator runs
an entry in a fresh driver process ([driver-protocol.md §2](driver-protocol.md#2-transport)):

1. its ID is in the `limits/` group;
2. a known divergence at a conformance level (not `replay`) records the outcome `crash` or `hang`;
3. a known divergence names an address-space sandbox as its profile (`address-space cap RLIMIT_AS <n> MiB|GiB`,
   [conformance-protocol.md](conformance-protocol.md)).

Negative entries that meet none of these (malformed strkeys, trailing bytes, bad discriminants) stay in `corpus/`:
a correct reader rejects them cheaply. `PROVENANCE.json` lists the stress entry IDs.

## 4. Changes the release makes to the committed files

The archive is the committed tree of one commit, with exactly these changes:

- `corpus_version` in `corpus.json` and `coverage.json`, and the version in the first paragraph of `COVERAGE.md`,
  are set to the release version (on every corpus root that has the file);
- `manifest.sha256` is written in each corpus root;
- stress entries and the files only they reach are moved from `corpus/` to `stress/` (section 3), their recipes
  with them; a recipe whose entry is in neither root is left out;
- `corpus.json` `tiers.curated` (`entries`, `blobs`, `bytes`) is set, in each root, to that root's own counts, so
  `corpus/` and `stress/` each state what they hold; `PROVENANCE.json` `entries` repeats the per-root entry and
  blob counts;
- `plan.json`, the entry-ID registry, keeps every row and each row's description of the entry (kind, CAPs,
  protocol, sources, levels, shape, members) but loses the repository's planning fields: `priority`, `serves`,
  `locator` and `evidence`. The plan schema (`schema/plan.schema.json` and its examples), which requires those
  fields, is left out of the archive; `xdrcheck-corpus verify` reads only the registry's IDs.

`make release` runs the repository's public-tree scan (`scripts/py/check_public.py --tree`) over the extracted
archive with every rule and no exemption: no machine path, private name, internal planning label or requirement
ID, and no report carrying a hostname.

## 5. Checksums and provenance

`SHA256SUMS` covers every file in the archive except itself, sorted by path, paths relative to the top-level
directory:

```sh
tar -xzf xdrcheck-30.0.0.tar.gz
cd xdrcheck-30.0.0 && sha256sum -c --quiet SHA256SUMS
```

Inside the corpus, blobs are named by their sha256 and each variant states its sidecar's `decoded_sha256`
([manifest.md §2](manifest.md#2-files-and-layout)); `manifest.sha256` covers the manifest files.

`PROVENANCE.json`:

| Field | Meaning |
|---|---|
| `schema` | `xcc.release/v1` |
| `version`, `protocol` | the release version and the highest protocol it covers |
| `archive` | the archive's file name and top-level directory |
| `source` | the repository's commit (full hash), its commit time, and that the archive was built from that commit with `git archive`, never from a working tree |
| `pins` | `pins.toml`'s sha256, and the pins `corpus.json` states (stellar-core, the XDR definitions, the oracle crate) |
| `entries` | entry counts of `corpus/` and `stress/`, and the stress entry IDs |
| `tools` | versions of the programs that wrote the archive's bytes: git, GNU tar, gzip, Python |
| `reproducible` | the timestamp every file carries and the archive options (section 6) |

`PROVENANCE.json` also states the `channel` (`stable` or `next`, section 8), and `entries.next` lists the
next-protocol entry IDs of a `-next` release (empty in a stable one).

The provenance is not signed yet; a release workflow would attach a signed build attestation for the archive's
sha256.

## 6. Reproducibility

The same commit gives a byte-identical archive with the same tool versions (those in `PROVENANCE.json`):

- input is `git archive <commit>`, so only committed files are read and the working tree, untracked and ignored
  files never are;
- every file and directory has the commit's timestamp as its modification time, owner and group 0 with no names,
  mode `0644` for files and `0755` for directories and executables;
- entries are sorted by name (`tar --sort=name`) in the POSIX ustar format, which has no access or change times;
- the tar stream is compressed with `gzip -n -9`, which writes neither a file name nor a time.

`make release` builds the archive twice from the same commit, in separate directories, and fails unless both have
the same sha256.

## 7. Checking a release

`make release` (`scripts/release.sh all`) builds the archive into `dist/`, then:

1. builds it a second time and compares the sha256 of the two archives;
2. extracts it into an empty directory, copies in only a built `xdrcheck-corpus`, checks `SHA256SUMS`, checks that
   every file a manifest of either root names (`blobs/`, `decoded/`, `chains/` and `recipes/` paths) is in that
   root (`scripts/release.sh refs ARCHIVE` runs this check alone), runs the
   public-tree scan over the extracted tree (section 4), and runs, with
   the network cut (`scripts/offline-run.sh`), `xdrcheck-corpus --corpus <dir>/corpus verify` and the same on
   `<dir>/stress` with every check except `ag1` and `ag3`; those two compare golden entries with stellar-core's
   own golden files, which are fetched by `make fetch` and are not in the archive, so they run in addition, with
   `--goldens`, when the golden cache is present;
3. runs the npm package's unit tests, packs it around the archive (`dist/xdrcheck-<version>.tgz`) and
   runs the whole `corpus/` root through it against the pinned JavaScript SDK, also offline, with the entries'
   declared divergences as the baseline ([use-in-sdk-ci.md](use-in-sdk-ci.md));
4. checks the channel split (section 8) on a copy of the commit's tree: one entry is made a next-protocol entry,
   and the stable archive must leave it out while the `-next` archive carries it and names it in
   `PROVENANCE.json` (`scripts/release.sh channels` runs this alone);
5. writes `dist/SHA256SUMS` and the release provenance over every asset of the version in `dist/` (section 9).

A `-next` release (`make release VERSION=<MAJOR+1>.0.0-rc.N`) runs steps 1, 2, 4 and 5; it has no npm package.

Steps: `scripts/release.sh build [OUT_DIR]`, `scripts/release.sh check`, `scripts/release.sh refs ARCHIVE`,
`scripts/release.sh npm`, `scripts/release.sh channels`, `scripts/release.sh version`. The commit is
`COMMIT=<rev>` (default `HEAD`). Publishing the archive or a package is a separate, manual step.

## 8. Channels: stable and `-next`

Two channels: the set every reader must pass, and an advisory set for the coming protocol.

| Channel | Version and tag | Holds | For |
|---|---|---|---|
| stable | `MAJOR.MINOR.PATCH`, tag `vMAJOR.MINOR.PATCH`; MAJOR = `pins.toml` `protocol.max_supported` | every entry of the released protocols, none above it | a reader's CI: pin it and require it to pass |
| `-next` | `MAJOR.MINOR.PATCH-rc.N`, tag `vMAJOR.MINOR.PATCH-rc.N`; MAJOR = `max_supported` + 1 | every stable entry plus the next-protocol entries | advisory: see what the next protocol's shapes do to a reader before it is released |

A next-protocol entry is one whose `protocol.introduced`, or the `protocol` of one of its variants, is above
`max_supported` (shapes from stellar-core's next-protocol build, for example). The stable channel leaves such
entries out, and every blob, sidecar and chain only they reach; the `-next` channel carries them. A `-next`
release refuses to build while the corpus has no next-protocol entry, so the channel never repeats the stable
one under another name. A GitHub release for a `-next` tag is marked as a pre-release. Moving from `-next` to
stable happens when the protocol is released and `max_supported` is raised: the next stable major then carries
those entries.

## 9. Release assets, prebuilt binaries and the pin helper

A version's assets, built into `dist/` and attached to the GitHub release of its tag:

| Asset | Made by | Holds |
|---|---|---|
| `xdrcheck-<version>.tar.gz` | `make release` | the corpus archive (sections 1 to 6) |
| `xdrcheck-<version>.tgz` | `make release` | the npm package around it, stable channel only ([use-in-sdk-ci.md](use-in-sdk-ci.md)) |
| `xdrcheck-<version>-<os>-<arch>.tar.gz` | `make dist-bin` | prebuilt tools for one platform, under `xdrcheck-<version>-<os>-<arch>/bin/`, with `LICENSE`, `NOTICE` and `BUILDINFO.json` (commit, toolchains, whether the sources were clean) |
| `xdrcheck-<version>.provenance.json` | `make release`, `make dist-bin`, `make release-assets` | `xcc.release-assets/v1`: version, channel, protocol, tag, source commit, and each asset's name, kind, platform, size and sha256 |
| `SHA256SUMS` | the same | `sha256sum` lines for every asset above |

The tools per platform:

| Platform | Tools | Built |
|---|---|---|
| `linux-amd64`, `linux-arm64` | `xdrcheck`, `xdrcheck-corpus`, `xdrlint`, and the adapters `minimal` (the template) and `demo` (the template with a planted bug, `make demo`) | Go cross-compiled with `CGO_ENABLED=0` and `-trimpath` (static); `xdrcheck-corpus` (Rust) natively on a machine of that architecture, or with a cross C toolchain, since its zstd dependency compiles C |
| `darwin-amd64`, `darwin-arm64` | `xdrcheck`, `xdrlint`, `minimal`, `demo` | Go cross-compiled with `CGO_ENABLED=0` and `-trimpath` |

On macOS `xdrcheck` runs without the Linux process controls it uses on Linux (a parent-death signal for the
processes it starts, cgroup memory limits), so the replay harness's memory bound is not enforced there; the
macOS builds are cross-compiled and not exercised by the kit's own CI. `xdrcheck-corpus`, the corpus author's tool,
is built for Linux only; on macOS run it in the container image (section 10). The Go tools are
static; `xdrcheck-corpus` links against the C library of the machine that built it (the release workflow builds it on
Ubuntu 24.04). The binaries are reproducible: the same commit and toolchains give byte-identical archives.

`make dist-bin` builds every platform of `DIST_PLATFORMS` (default all four) whose tools all build on this
machine, says for each one it leaves out what is missing (a Rust target or cross C toolchain, typically), and with
`DIST_STRICT=1` fails instead. It refuses to call the binaries the commit's when the tools' sources differ from it
under `DIST_STRICT=1`, and otherwise records `source.dirty: true` in `BUILDINFO.json`. `make release-assets`
(`scripts/dist.sh assemble`) rewrites `SHA256SUMS` and the provenance over everything of the version in `dist/`,
checks every asset against them, and runs the image smoke test (section 10). `scripts/dist.sh verify DIR` checks a
downloaded or assembled set.

**The release workflow** (`.github/workflows/release.yml`) runs on a version tag: `make release` on one runner,
`make dist-bin` with `DIST_STRICT=1` on an x86-64 runner (`linux-amd64` and both macOS archives) and an arm64
runner (`linux-arm64`), then `make release-assets` over all of it. Its result is one workflow artifact,
`xdrcheck-release-<tag>`, holding exactly the files to attach. The workflow only reads the repository, so
attaching is the maintainers' step, after they have looked at the run:

```sh
gh run download <run-id> --name xdrcheck-release-v30.0.0 --dir release-v30.0.0
scripts/dist.sh verify release-v30.0.0
gh release create v30.0.0 --verify-tag --title "XDRCheck 30.0.0" release-v30.0.0/*     # add --prerelease for -rc
git tag -f v30 v30.0.0 && git push -f origin v30   # the major tag the GitHub Action is used by
```

**The pin helper.** A consumer's CI pins a version, and better also the sha256 of its `SHA256SUMS`, and
downloads only what it needs with `action/fetch-release.sh` (bash, curl, tar, sha256sum or shasum; Linux and
macOS). Every asset is checked against `SHA256SUMS` before it is extracted, the corpus also against its own
`SHA256SUMS`, and the script prints `XDRCHECK_CORPUS=…` and `XDRCHECK_BIN=…` lines for `$GITHUB_ENV` or `eval`:

```make
# In your Makefile:
XDRCHECK_VERSION    ?= 30.0.0
XDRCHECK_SHA256SUMS ?= <sha256 of the release's SHA256SUMS>
xdrcheck:
	curl -fsSLO https://raw.githubusercontent.com/OWNER/REPO/v$(XDRCHECK_VERSION)/action/fetch-release.sh
	bash fetch-release.sh --version $(XDRCHECK_VERSION) --sha256sums $(XDRCHECK_SHA256SUMS) \
	  --corpus --binaries auto --out .xdrcheck > .xdrcheck.env
```

`OWNER/REPO` is this repository on GitHub. Options: `--npm` for the npm package, `--repo OWNER/REPO` for a fork's
releases, `--base URL|DIR` for a mirror or a local `dist/`. The GitHub Action ([github-action.md](github-action.md))
uses the same script.

## 10. Container image

`release/Dockerfile` builds an image of one version from its release assets, with nothing compiled inside: the
first stage checks the corpus archive and the Linux binaries of the target architecture against `SHA256SUMS` and
unpacks them, the corpus also against its own `SHA256SUMS`; the second copies them onto the same base, pinned by
digest (`debian:trixie-slim@sha256:…`), as a non-root user. The image holds the release's layout under
`/opt/xdrcheck` (`corpus/`, `stress/`, `pins.toml`, `PROVENANCE.json`) with the tools in `/opt/xdrcheck/bin` on
`PATH`, and works there, so the tools' default `--corpus corpus` is the bundled corpus:

```sh
docker run --rm --network none IMAGE xdrcheck replay --adapter minimal --target-version demo --input sep54-dir \
  --entries 'cap-0015/*' --report /tmp/report
docker run --rm -v "$PWD/my-adapter:/work/my-adapter:ro" IMAGE xdrcheck replay --adapter /work/my-adapter …
```

`make dist-image` (`scripts/dist.sh image`) builds it locally as `xdrcheck-dist:<version>` from `dist/` with
the network off, and smoke-tests it with no network: every tool starts, `xdrcheck-corpus verify --checks
schema,ids,hashes` passes on the bundled corpus, the `demo` adapter's replay of the CAP-15 and CAP-27 entries
finds its planted bug, and the `minimal` adapter's replay of the same entries passes. It then removes the image
(`KEEP_IMAGE=1` keeps it). The release workflow runs the same test; it does not push the image to a registry.
