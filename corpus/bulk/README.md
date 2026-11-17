# Bulk tier: stellar-core's golden LedgerCloseMeta files

The bulk tier is stellar-core's own golden tree, `test-lcm-{current,next}/<TestFileStem>/<hash16>.xdr`, at
the tag pinned in `pins.toml` (`v30.0.0`, commit `0e49751aa9ddf892302cca02cea7f3f5d97df9f1`, Apache-2.0). Its
bytes are not committed here; they are fetched into a cache and checked against the hash index committed in
this directory.

| File | Content |
|---|---|
| `core-v30.0.0-current.sha256` | 866 lines, one per `.xdr` file of `test-lcm-current` (15,306 ledgers, Protocol 30) |
| `core-v30.0.0-next.sha256` | 866 lines, one per `.xdr` file of `test-lcm-next` (Protocol 31) |

Format: `sha256sum` output, `<sha256>␠␠<path>`, paths relative to the root of the stellar-core repository,
sorted bytewise. `index.json` files are not listed: the tree is read from git at the pinned commit, which the
fetch checks.

## Fetch and verify

```sh
xdrcheck-corpus fetch-goldens v30.0.0      # or: make fetch (scripts/fetch.d/goldens.sh)
```

writes the tree to `$HOME/.cache/xcc/goldens/v30.0.0/` (`XCC_CACHE_DIR` moves the cache), from a shallow
fetch of the tag from GitHub, or from a local clone named by `XCC_STELLAR_CORE_REPO`, and fails unless every
listed file is present with its hash and no unlisted `.xdr` file exists. The same check without our tool:

```sh
cd "$HOME/.cache/xcc/goldens/v30.0.0" && sha256sum -c --quiet <corpus>/bulk/core-v30.0.0-current.sha256
```

## How the index was made

From a tree fetched at the pinned commit, with the standard tool rather than ours:

```sh
cd "$HOME/.cache/xcc/goldens/v30.0.0"
for t in current next; do
  find test-lcm-$t -name '*.xdr' | LC_ALL=C sort | xargs sha256sum > <corpus>/bulk/core-v30.0.0-$t.sha256
done
```

A new core tag gets new index files the same way; the old ones stay for entries pinned to the old tag.

## Checks on the tree

- **AG-1** (pinned import): a `core-golden` entry's blob equals the named frame of the named file, whose
  sha256 is recorded in the entry (`xdrcheck-corpus import-golden` writes such entries; `verify` checks them).
- **AG-3** (decoder consistency): every ledger of every file decodes under explicit limits and re-encodes
  byte-exactly in the oracle (`verify --tier bulk --checks ag3`).
