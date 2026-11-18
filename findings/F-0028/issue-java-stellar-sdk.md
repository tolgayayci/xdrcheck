Title: Release request: Liquidity pool asset order compared as strkey text: valid pairs refused and reversed pairs accepted

Affected: `network.lightsail:stellar-sdk@6.0.0`     Fixed in: merged in https://github.com/lightsail-network/java-stellar-sdk/pull/832, not released

## Summary

https://github.com/lightsail-network/java-stellar-sdk/pull/832 (merged 2026-11-05) fixes this, but the latest release, 6.0.0 (2026-10-28), predates it. Users of the released package still hit the defect: network.lightsail:stellar-sdk 6.0.0 shows this on the corpus cells below: the SDK refuses input that stellar-core accepts, and accepts input that stellar-core refuses. Other SDKs had the same defect and fixed it (below).

Could a patch release include the fix?

## Reproduce on the released version

- `cap-0038/api-liquidity-pool-issuer-ordering.go-pair-network-order`, level L4
  - observed: Executed on java@6.0.0: outcome reject (ordering), message "Assets are not in lexicographic order"; verdict reject_valid.
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.go-pair-reversed-order`, level L4
  - observed: Executed on java@6.0.0: outcome ok; verdict accepts_invalid.
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.network-order`, level L4
  - observed: Executed on java@6.0.0: outcome reject (ordering), message "Assets are not in lexicographic order"; verdict reject_valid.
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.reversed-order`, level L4
  - observed: Executed on java@6.0.0: outcome ok; verdict accepts_invalid.
  - expected: order the pool assets by XDR bytes
- `cap-0038/pool-issuers-order-by-bytes-not-strkey` (variant `testnet`), level L1
  - observed: Executed on java@6.0.0: outcome reject (ordering), message "Assets are not in lexicographic order"; verdict reject_valid.
  - expected: order the pool assets by XDR bytes

Executed through the kit's conformance runner (`xcc conform run`) on java@6.0.0.

## Why this is expected

stellar-core orders the assets of a constant-product pool by XDR bytes (CAP-38).

## Same defect elsewhere

- stellar/js-stellar-sdk: https://github.com/stellar/js-stellar-sdk/pull/1766, fixed in 17.2.1
- stellar/go-stellar-sdk: https://github.com/stellar/go-stellar-sdk/pull/5974, fixed in v0.7.2
- StellarCN/py-stellar-base: https://github.com/StellarCN/py-stellar-base/issues/1246, fixed in 17.0.1
- Beans-BV/dotnet-stellar-sdk: https://github.com/Beans-BV/dotnet-stellar-sdk/issues/257

## Corpus

The entries above are public corpus entries (`corpus/manifest/cap-0038/`) and hold the inputs and the values
stellar-core expects. The kit's java@6.0.0 column is run by the maintainer outside the public repository, so the rows
above come from that run; the defect itself is the one https://github.com/lightsail-network/java-stellar-sdk/pull/832
fixes.
