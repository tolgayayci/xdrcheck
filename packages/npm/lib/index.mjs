// Programmatic use: open the release, list its entries, run them through an SDK (see bin/xdrcheck-corpus-run.mjs).
export { openRelease, entries, blob, releaseInfo, untar, ToolError } from "./archive.mjs";
export { loadSDK, runEntry, matcher, knownDivergences, classify, inRange, mustRefuse } from "./run.mjs";
export { Results, parseExpectedFailures, readExpectedFailures, formatComparison, UNREAD } from "./expected.mjs";
