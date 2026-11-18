# Replaying real ledgers in CI

For SDK maintainers who want real mainnet ledgers, not only corpus entries, in their CI. This recipe runs
`xdrcheck replay --set controls` against a branch of an SDK on every push and pull request: the same ledgers each
time, from a pinned dataset version, and a failed build when the branch shows a class of failure the released
version does not.

## What gets pinned

| Pin | How |
|---|---|
| the kit | a commit of this repository (`KIT_COMMIT`); `go build ./cmd/xdrcheck` from it |
| the dataset | a portable dataset archive made once with `xdrcheck data export` and published as a release asset; its sha256 is in the workflow (`DATASET_SHA256`) |
| the ledgers | they are the dataset's `controls` set; each ledger is fetched from the public lake and checked against its MD5, and the run manifest records each object's sha256 |
| the SDK | the branch under test is checked out by the job and given as a local path: `--version $GITHUB_WORKSPACE/sdk` |

Make the dataset archive once, where the full dataset is:

```
xdrcheck data export --set controls --out dataset-2026-11-17.1
tar -czf dataset-2026-11-17.1.tar.gz dataset-2026-11-17.1
sha256sum dataset-2026-11-17.1.tar.gz
```

## The job (GitHub Actions, in the SDK's repository)

This is the Go SDK; for JavaScript set up Node.js, check out `js-stellar-sdk`, build it (`npm ci && npm run build`)
and use `--target js`; for Python use `--target python` with a checkout of `py-stellar-base`.

```yaml
name: xdrcheck replay
on: [push, pull_request]
permissions:
  contents: read
jobs:
  replay:
    runs-on: ubuntu-24.04
    env:
      KIT_COMMIT: 0000000000000000000000000000000000000000      # a commit of the kit
      DATASET_URL: https://github.com/OWNER/REPO/releases/download/dataset-2026-11-17.1/dataset-2026-11-17.1.tar.gz
      DATASET_SHA256: 0000000000000000000000000000000000000000000000000000000000000000
      XDRCHECK_DATASET: ${{ github.workspace }}/dataset-2026-11-17.1
      XDRCHECK_CACHE: ${{ github.workspace }}/.xdrcheck-cache
    steps:
      - uses: actions/checkout@v4
        with: { path: sdk }
      - uses: actions/checkout@v4
        with: { repository: OWNER/REPO, ref: ${{ env.KIT_COMMIT }}, path: kit }
      - uses: actions/setup-go@v5
        with: { go-version-file: kit/go/go.mod }
      - name: kit
        run: cd kit/go && go build -o "$GITHUB_WORKSPACE/xdrcheck" ./cmd/xdrcheck
      - name: dataset (pinned)
        run: |
          curl -sSfL "$DATASET_URL" -o dataset.tar.gz
          echo "$DATASET_SHA256  dataset.tar.gz" | sha256sum -c -
          tar -xzf dataset.tar.gz
          ./xdrcheck data status
      - uses: actions/cache@v4
        with:
          path: ${{ env.XDRCHECK_DATASET }}/lake
          key: lake-${{ env.DATASET_SHA256 }}
      - name: replay the controls through the released version (the baseline)
        run: ./xdrcheck replay --target go --version v0.9.0 --set controls --out run-base
      - name: replay the controls through this branch
        run: ./xdrcheck replay --target go --version "$GITHUB_WORKSPACE/sdk" --set controls --out run
      - name: check the run directories
        if: always()
        run: ./xdrcheck runs validate run-base run
      - name: no new class of failure
        run: ./xdrcheck runs compare --new-only run-base run
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: xdrcheck-run, path: run }
```

`runs compare --new-only` exits 1 when the branch has a cluster key the released version does not (`+` lines),
and 0 when the branch only removes some (`-` lines, a fix). A released SDK already shows candidates on real
ledgers, so failing on every candidate (`replay --fail-on candidate`) is only useful together with a dispositions
file (`--dispositions FILE`, kept in the SDK's repository) that names the accepted ones.

The exported dataset becomes a public release asset. Export only a set whose ledgers you are willing to publish
(`xdrcheck data export --set NAME`).

Any cluster in the job's run directory can be packed into a bundle (`xdrcheck repro pack run --cluster KEY`,
[repro.md](repro.md)) that reproduces it on a laptop with one command.

Limits: the job needs the network to fetch ledgers from the public lake on a cold cache (the `actions/cache` step
keeps them afterwards). `--target` takes `go`, `js`, `python`, `rust` and the service rigs
([replay.md](replay.md)); the comparison is by cluster key, so a branch that changes a failure's details without
changing its class is not reported.
