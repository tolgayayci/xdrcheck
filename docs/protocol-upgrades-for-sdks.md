# Protocol upgrades: what XDRCheck gives an SDK

For SDK and XDR-library maintainers preparing a release for a new protocol. After this page you can run the next
protocol's shapes through your SDK before the release, track the update as a shrinking expected-failure list, and
test the unreleased branch at every conformance level.

When a protocol changes the XDR, each SDK regenerates its types and ships a release. XDRCheck turns "the SDK can
now decode Protocol N" into a CI check: real bytes for the new shapes, the value each must decode to, and a job that
fails until the SDK reads them. Section 1 is a block you can paste into an "SDK Updates for Protocol N
Compatibility" issue, with `N` replaced by the protocol number and `OWNER/REPO` by this repository on GitHub.
Section 2 explains each piece it links to. How new shapes reach the corpus before the mainnet vote is on
[maintenance.md §5](maintenance.md).

## 1. The block to paste

````markdown
### Test the update against XDRCheck

XDRCheck publishes a versioned corpus of real ledger and XDR bytes, each tagged with the CAP and the protocol
that introduced it, with the decoded value every SDK must produce
(https://github.com/OWNER/REPO).

1. **Corpus for Protocol N.** Before the protocol is released, the advisory `-next` release `N.0.0-rc.K` carries
   the new shapes; after it, the stable release `N.0.0`. Fetch and verify one in CI with the pin helper
   (`action/fetch-release.sh` of that release):
   `bash fetch-release.sh --version N.0.0-rc.K --sha256sums <sha256 of its SHA256SUMS> --corpus --out .xdrcheck`
2. **Run it with your decoder.** Copy the recipe for your language into your repository: Go, Rust and Python in
   `examples/sdk-ci/<language>`; JavaScript with the npm runner (`npx xdrcheck-corpus-run --sdk . --dir "$XDRCHECK_RELEASE"`).
   Each decodes every entry and checks the bytes re-encode identically; the Rust recipe, and the Python one with
   `XDRCHECK_COMPARE_JSON=1`, also compare the decoded value with the corpus's expected JSON.
3. **Keep an expected-failure list.** Write it once from a run (`XDRCHECK_WRITE_EXPECTED_FAILURES=1`), review it and
   commit it. Until the update lands, every Protocol N entry the SDK cannot read shows as a `NEW-FAILURE`; when a
   listed entry starts to pass the run fails with `UNEXPECTED-PASS` until its line is removed. With the all-read
   check on, nothing is skipped silently.
4. **Or use the GitHub Action** (`mode: conform`, `corpus-version: N.0.0-rc.K`) to run the pinned SDK releases the
   corpus ships drivers for.
5. **Test the unreleased branch before tagging** (Go, Rust, Python):
   `xdrcheck conform run --columns '<column>' --sdk ../<your-sdk-checkout> --expected-failures <list> --require-all-read`

Full steps: https://github.com/OWNER/REPO/blob/main/docs/protocol-upgrades-for-sdks.md
````

## 2. The pieces

**The versioned corpus.** A release's major version is the protocol it covers ([release.md §8](release.md#8-channels-stable-and--next)):
`N.0.0` is stable and holds every entry of the released protocols; `N.0.0-rc.K` is the advisory `-next` channel,
published before Protocol N is released, with the next protocol's entries added. Each release has a `SHA256SUMS`;
pin its sha256 next to the version, and the pin helper `action/fetch-release.sh` checks every byte before anything
reads it ([release.md §9](release.md#9-release-assets-prebuilt-binaries-and-the-pin-helper)):

```sh
curl -fsSLO https://raw.githubusercontent.com/OWNER/REPO/vN.0.0-rc.K/action/fetch-release.sh
bash fetch-release.sh --version N.0.0-rc.K --sha256sums <sha256 of SHA256SUMS> --corpus --out .xdrcheck >> "$GITHUB_ENV"
```

It sets `XDRCHECK_RELEASE` (the extracted release) and `XDRCHECK_CORPUS`. Moving from the `-rc` to the stable
release when the protocol ships is one change of the pin.

**The CI recipe per language** ([use-in-sdk-ci.md](use-in-sdk-ci.md)):

| Language | Recipe | Runs |
|---|---|---|
| Go | `examples/sdk-ci/go` | `go test -count=1 -v ./...` with `XDRCHECK_CORPUS` set to the archive |
| Rust | `examples/sdk-ci/rust` | `cargo test --locked --manifest-path xdrcheck/Cargo.toml` |
| Python | `examples/sdk-ci/python` | `python -I -m unittest discover -s tests/corpus -p 'test_*.py'` |
| JavaScript | the npm runner (stable releases ship it as a package) | `npx xdrcheck-corpus-run --sdk . --expected-failures FILE --require-all-read`; for a `-next` release, add `--dir "$XDRCHECK_RELEASE"` to read the extracted corpus |

Each recipe pins the corpus by version and sha256. To test the coming protocol, point the version at the `-rc`
release:

```yaml
env:
  CORPUS_VERSION: "N.0.0-rc.K"
  CORPUS_SHA256: "<the archive's sha256, from the release page>"
```

**The expected-failure list workflow** ([use-in-sdk-ci.md §7](use-in-sdk-ci.md#7-an-expected-failure-list-and-the-all-read-check)).
Against the `-rc` corpus, before the SDK has the new XDR, the run lists the Protocol N entries as new failures.
That list is the to-do list of the update. Commit it, regenerate the types, and remove lines as entries start to
pass; the run fails on a line that now passes, so the list only shrinks with real fixes. When the list holds no
Protocol N line, the SDK decodes every shape the corpus has for that protocol.

```sh
XDRCHECK_WRITE_EXPECTED_FAILURES=1 go test ./...        # Go recipe: write expected-failures.txt, then review it
go test ./...                                      # passes only when the failures are exactly the list
```

**The GitHub Action, conform mode** ([github-action.md §3](github-action.md#3-sdk-maintainers-conform)) runs the
corpus through the conformance drivers of the SDK releases the corpus release pins, at every level (decoded values,
transaction parsing, native conversion, the `api` operations), from prebuilt tools:

```yaml
- uses: OWNER/REPO@vN.0.0-rc.K
  with:
    mode: conform
    corpus-version: N.0.0-rc.K
    columns: js@<version>
    expected-failures: conformance/js.failures
    require-all-read: "true"
```

**An unreleased branch: `xdrcheck conform --sdk`** ([use-in-sdk-ci.md §8](use-in-sdk-ci.md#8-an-unreleased-sdk-branch-xdrcheck-conform---sdk)).
In a checkout of this repository, a Go, Rust or Python column builds from your SDK checkout instead of its pinned
release, so the regenerated types can be tested at every level before the release is tagged:

```sh
xdrcheck conform fetch --columns 'go@<version>' --sdk ../go-stellar-sdk     # network: the checkout's dependencies
xdrcheck conform build --columns 'go@<version>' --sdk ../go-stellar-sdk     # offline
xdrcheck conform run --columns 'go@<version>' --sdk ../go-stellar-sdk --report out \
  --expected-failures conformance/go.failures --require-all-read
```

**Which released versions are ready.** After a run over every pinned SDK version, `xdrcheck conform readiness` writes a
table with one row per SDK version and one column per protocol and per CAP: `full`, `partial n of m`,
`refuses new arms` (the version predates the shapes and refuses them cleanly) or `not run`:

```sh
xdrcheck conform run --set public --report out
xdrcheck conform readiness --protocol N --report out       # out/readiness.md and out/readiness.json
```

## 3. When it fails, and limits

| You see | Meaning | Do |
|---|---|---|
| `NEW-FAILURE` on a Protocol N entry | your SDK does not read that shape yet | expected before the update; list it, then remove the line when the regenerated types read it |
| `UNEXPECTED-PASS` | a listed entry now passes | remove its line in the same change |
| `refused valid bytes` on a Protocol N variant | your generated XDR lacks a new arm or field | regenerate from the XDR definitions at the protocol's tag |
| the pin helper stops with a sha256 mismatch | the download is not the release you pinned | check `--sha256sums` against the release page |

- A `-next` release is advisory. Its next-protocol entries come from stellar-core's next-protocol build and can
  change before the protocol is released; pin the stable `N.0.0` once it exists.
- The recipes judge bytes (level L0). Decoded values, transaction parsing and the `api` operations need
  `xdrcheck conform` (the Action's `conform` mode, or `--sdk` on a checkout).
- `xdrcheck conform --sdk` builds Go, Rust and Python checkouts; for a JavaScript checkout use the npm runner
  with `--sdk .`, which covers bytes only.
- No next-protocol release candidate is published yet (the stable release is `30.0.0`). Until one is, run the recipes against a checkout of this repository
  (`make sdk-ci-examples`) and read `N.0.0-rc.K` as the release you will pin.
