# XDRCheck dashboard

A static page that shows, from the repository's own files, the corpus's rare ledger shapes by CAP, the scan of
pubnet history (with mainnet counts for the rare union arms the corpus joins to), and which SDKs and pipelines
mishandle each shape. Views: overview, ledger history (protocol bands and
per-CAP first and last mainnet ledger), CAPs (each row and each entry), problems (findings by component, severity,
state and CAP, and the linter's rules), SDK matrix, one fix across every SDK, and replay. Every view is a URL hash
(`#/cap/cap-0040`, `#/problems?state=filed`, `#/entry/<entry-id>`), so any filtered view can be linked.

## View it

```sh
python3 -m http.server -d apps/dashboard/site 8000    # then open http://localhost:8000/
```

Plain HTML, CSS and JavaScript modules: no build step, no framework, no package install, and no request leaves the
page (no fonts, scripts or styles from elsewhere; its two fonts are in `site/fonts/`, under the SIL Open Font
License 1.1, text in `site/fonts/OFL.txt`). Browsers refuse to read the data files from a `file://` URL, so
serve the folder as above; the page says so if it is opened as a file.

## Data

`site/data/*.json` is generated; do not edit it. The page fetches only the files a view needs: the overview reads
`summary.json` and `scan.json`; the SDK matrix (`matrix.json`), the replay grid (`replay.json`) and the sibling matrix
(`siblings.json`) are fetched by their own views only. `scripts/build_data.py` (standard library only) builds it from
tracked files only: `corpus/index.json`, `corpus/coverage.json`, `corpus/mirrors.json`, `corpus/COVERAGE.md`, the manifests under `corpus/manifest/`,
`apps/docs/data/cap-prevalence.json`, `evidence/mainnet-scan/`, `evidence/results/`, `findings/F-*/finding.json`,
`findings/pending/`, `lint/expected/*/*.pending.json`, `lint/docs/README.md`, `drivers/sets.toml`,
`drivers/sets.d/` and `pins.toml`. It also writes the landing page's `apps/landing/site/data/summary.json`.

```sh
python3 apps/dashboard/scripts/build_data.py           # regenerate after a source changes
python3 apps/dashboard/scripts/build_data.py --check   # fail when the committed data is stale (make repo-checks)
python3 apps/dashboard/scripts/build_data.py --from HEAD   # build from a commit's sources, not the working tree
python3 apps/dashboard/scripts/test_site.py            # load every data file, resolve every link and route
```

The builder refuses to write another project's issue or pull-request number, a link to an upstream item other than
an issue this kit filed, a machine path, or a non-public record. Rows that wait on finding review appear only as a
count. A result file that is not committed yet (for example `evidence/results/acceptance.json`) is treated as
absent, and the view that would use it says what it shows instead.

The page's outbound links (documentation site, landing) are set in `LINKS` at the top of `build_data.py`.

## Deployment

Manual, and not part of this repository: copy `site/` to any static host. Nothing here deploys or publishes it.
The page sets no cookies and loads no analytics; the colour-theme choice is kept in the browser's local storage.
