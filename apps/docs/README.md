# XDRCheck documentation site

Mintlify project for the XDRCheck documentation (`docs.json`, `.mdx` pages).

Most pages are generated from the repository so the site cannot drift from it: the CLI reference from
`docs/cli.md`, the specifications and guides from `docs/`, `go/adapters/`, `examples/` and `crates/xdrcheck-judge/`
(a page may append further sources as sections), the lint rule reference from `lint/docs/`, and the CAP
coverage page (`caps/overview.mdx`, a section per coverage row) from `corpus/index.json`, `corpus/coverage.json` and
`data/cap-prevalence.json`. The results pages (`results/`, including the findings table `results/findings.mdx`) and
`start/read-an-entry.mdx` come from `evidence/results/*.json`, `evidence/mainnet-scan/` and the corpus;
`hardening/outline.mdx` from `guide/`; the acceptance checks page (`results/acceptance.mdx`) from
`docs/acceptance.md` and `evidence/results/acceptance.json`. The introduction (`index.mdx`), `guides/ci.mdx` and
`guides/add-corpus-entries.mdx` start from hand-written templates in `data/*.mdx.in`: edit the template (the
introduction's `@@name@@` figures are filled from the same files as the results pages, from `pins.toml` and from
`drivers/sets.toml`). Each generated page says its source in its first line; edit the source, not the page. The
quickstart, `start/how-it-works.mdx`, `start/for-sdk-maintainers.mdx`, `start/for-indexers.mdx`, `concepts/`,
`architecture/` and `hardening/overview.mdx` are written by hand.

Three references are long, so the generator writes each as an index page and sub-pages: the CLI reference
(`reference/cli.mdx` and `reference/cli/`, a page per tool or group of commands), the manifest format
(`reference/manifest.mdx` and `reference/manifest/`, a page per group of top-level sections of `docs/manifest.md`) and
the lint rules (`reference/lint-rules.mdx` and `reference/lint-rules/`, a page per rule family). The sources stay
whole. A link in a source names the document and its heading as before; the generator points it at the page that
holds the heading. A hand-written page must name the sub-page itself, and `--check` says which one when it does not.
The lint index keeps a short section per rule ID, so `/reference/lint-rules#xdr301` still resolves.

The navigation in `docs.json` (tabs, groups, nested groups, page order) and its icon library are written by
`generate.py` from the table `NAV` in the script: add a page there, not in `docs.json`. The same table holds the sidebar label and icon of
every generated page. A hand-written page carries its own `sidebarTitle`, `icon` (a Lucide name) and `description`.

`--check` fails when a generated page is stale, when a page breaks a page rule, when an internal link names a page
or a heading anchor that does not exist (anchors as Mintlify slugs headings), when a page is in no navigation
group, and when a page has no description, no icon or a sidebar label longer than three words. A change to any of the sources above therefore needs `generate.py` run and its pages committed with it.

```sh
python3 apps/docs/scripts/generate.py           # from the repository root: regenerate the generated pages
python3 apps/docs/scripts/generate.py --check   # fail on a stale page, a broken internal link or a page rule (run by make repo-checks)
python3 apps/docs/scripts/generate.py --capture-help target/release   # refresh data/help/ from built binaries
python3 apps/docs/scripts/cap_prevalence.py --xdrcheck-corpus target/release/xdrcheck-corpus --index LOCATE_INDEX_DIR
pnpm install --frozen-lockfile && pnpm --filter docs validate && pnpm --filter docs broken-links
(cd apps/docs && mint validate && mint broken-links --check-anchors)   # the same with a mint CLI already installed
pnpm --filter docs dev                          # preview at http://localhost:3000
```

`cap_prevalence.py` is the only step that needs data outside the repository: a locate index built by
`xdrcheck-corpus scan locate-build` over a scan of pubnet history. Its output, `data/cap-prevalence.json`, is committed.
