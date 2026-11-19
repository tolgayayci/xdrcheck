# XDRCheck landing page

The one-page site for xdrcheck.dev: what an SDK maintainer or an indexer team gets from the kit, a quick start, and links to
the documentation, the dashboard and the repository. Static files in `site/`; no build step, no framework, two
self-hosted fonts (`site/fonts/`, SIL Open Font License 1.1, text in `site/fonts/OFL.txt`) with system fallbacks,
and no request to another origin.

## View it

```sh
python3 -m http.server -d apps/landing/site 4321    # then open http://localhost:4321/
```

## Figures

No number on the page is typed into the HTML. `site/app.js` reads them from `site/data/summary.json`, which
`apps/dashboard/scripts/build_data.py` writes from tracked repository files together with the dashboard's data
(see `apps/dashboard/README.md`). Regenerate both with `python3 apps/dashboard/scripts/build_data.py`;
`--check` (run by `make repo-checks`) fails when the committed file is stale, and
`python3 apps/dashboard/scripts/test_site.py` fails when a figure is typed into the page.

The first screen states three results, each from that file: the scanned pubnet range and its integrity checks, the
wallet-backend incidents replayed before and after their fixes, and the SDK defect class that reproduces in the most
SDK lines (a major line or decode-limit profile of one SDK; the text names both counts). `app.js` shows a result only when the data backs it (`data-need`): the replay line, for example, only
when every pair fails before its fix and passes after it and at the current pinned commit.

The outbound links (documentation, dashboard, repository) come from `LINKS` in that script. A link whose value is
empty is hidden; the repository link is empty until the public repository exists.

## Deployment

Manual, and not part of this repository: copy `site/` to any static host and serve `404.html` for missing paths.
Nothing here deploys or publishes it. The page sets no cookies and loads no analytics.
