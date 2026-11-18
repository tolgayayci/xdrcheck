Additional evidence for #257: reading the source of `stellar-dotnet-sdk@17.0.0` shows the same outcome for these conformance corpus cells (read, not executed).

- `cap-0038/api-liquidity-pool-issuer-ordering.go-pair-network-order`, level L4
  - observed: Not executed: source reading of 17.0.0 (the kit has no driver for this SDK). Same comparison as the network-order member: the pair in XDR byte order is refused with 'Asset A must be < Asset B (Lexicographic Order).'
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.go-pair-reversed-order`, level L4
  - observed: Not executed: source reading of 17.0.0 (the kit has no driver for this SDK). Same comparison as the reversed-order member: the reversed pair is accepted.
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.network-order`, level L4
  - observed: Not executed: source reading of 17.0.0 (the kit has no driver for this SDK). The two issuers order differently as strkey text and as XDR bytes, so the constructor's text comparison finds the pair in XDR byte order out of order and throws 'Asset A must be < Asset B (Lexicographic Order).'
  - expected: order the pool assets by XDR bytes
- `cap-0038/api-liquidity-pool-issuer-ordering.reversed-order`, level L4
  - observed: Not executed: source reading of 17.0.0 (the kit has no driver for this SDK). The reversed pair is in strkey text order, so the constructor accepts it and the pool ID is derived from parameters stellar-core refuses.
  - expected: order the pool assets by XDR bytes
- `cap-0038/pool-issuers-order-by-bytes-not-strkey` (variant `testnet`), level L1
  - observed: Not executed: source reading of 17.0.0 (the kit has no driver for this SDK). FromXdr calls the same constructor, so reading the pool-share ChangeTrust of this network transaction throws.
  - expected: order the pool assets by XDR bytes

Not executed: the kit has no conformance driver for this SDK. The outcomes above are read from the source of stellar-dotnet-sdk 17.0.0 (2026-11-12). Read at commit 6eea5fcadff5bd64bd418f1995a1c6c1d11055d3 (release 17.0.0): StellarDotnetSdk/Assets/AssetTypeCreditAlphaNum4.cs lines 69-71 and AssetTypeCreditAlphaNum12.cs lines 65-67 order two credit assets with the same code by string.Compare(Issuer, other.Issuer, StringComparison.Ordinal), that is by strkey text; StellarDotnetSdk/LiquidityPool/LiquidityPoolConstantProductParameters.cs lines 29-31 throw ArgumentException when assetA.CompareTo(assetB) >= 0, and FromXdr (lines 97-102) calls that constructor.

Why this is expected: stellar-core orders the assets of a constant-product pool by XDR bytes (CAP-38).

The same defect in other SDKs:

- stellar/js-stellar-sdk: https://github.com/stellar/js-stellar-sdk/pull/1766, fixed in 17.2.1
- stellar/go-stellar-sdk: https://github.com/stellar/go-stellar-sdk/pull/5974, fixed in v0.7.2
- StellarCN/py-stellar-base: https://github.com/StellarCN/py-stellar-base/issues/1246, fixed in 17.0.1
- lightsail-network/java-stellar-sdk: https://github.com/lightsail-network/java-stellar-sdk/pull/832, fix merged, not yet released

Pull request #272, which is open, says it fixes this issue; the cells above could serve as its test vectors, and the conformance corpus would then show the fix the same way it shows the fixes in the other SDKs.

To run the cells:

    # The kit has no driver for this SDK; these run the same cells on the SDKs it has drivers for:
    xcc conform run --entries cap-0038/api-liquidity-pool-issuer-ordering.go-pair-network-order --levels L4 --report out/
    xcc conform run --entries cap-0038/api-liquidity-pool-issuer-ordering.go-pair-reversed-order --levels L4 --report out/
    xcc conform run --entries cap-0038/api-liquidity-pool-issuer-ordering.network-order --levels L4 --report out/
    xcc conform run --entries cap-0038/api-liquidity-pool-issuer-ordering.reversed-order --levels L4 --report out/
    xcc conform run --entries cap-0038/pool-issuers-order-by-bytes-not-strkey --levels L1 --report out/
