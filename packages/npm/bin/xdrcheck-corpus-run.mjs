#!/usr/bin/env node
// xdrcheck-corpus-run: put chosen entries of the corpus release through a Stellar JavaScript SDK (docs/use-in-sdk-ci.md).
//
//   xdrcheck-corpus-run [--entries GLOB[,GLOB…]] [--stress] [--sdk DIR] [--archive FILE | --dir DIR] [--list]
//                  [--expected-failures FILE | --write-expected-failures FILE] [--require-all-read]
//
//   --entries  entry IDs to run; `*` matches any characters (including `/`), `?` one. Default: every entry
//   --stress   also select from the stress root (entries built to exhaust a reader; docs/release.md §3)
//   --sdk      the SDK package directory, or a project whose node_modules holds @stellar/stellar-sdk
//              (default: found from the current directory upwards)
//   --archive  a release archive instead of the embedded one (also XDRCHECK_CORPUS_ARCHIVE); its sha256 must be the
//              one this package was packed for
//   --dir      an extracted release (its top-level directory) instead of an archive
//   --list     print the selected entry IDs and stop
//   --expected-failures FILE        the SDK's expected-failure list: the run passes only when its failing variants
//                                   (FAIL and KNOWN) are exactly the list's lines
//   --write-expected-failures FILE  write the run's failing and unread variants as such a list
//   --require-all-read              fail the run when a ledger or xdr variant was never read (UNREAD) and no
//                                   expected-failure line names it as unread
//
// Each variant is PASS (conforms), KNOWN (shows the outcome a known divergence the entry records for this SDK
// version predicts: the baseline, expected), FIXED (conforms although such a record covers this version), FAIL,
// UNREAD (a ledger or xdr variant the SDK could not be asked about: a type it does not generate, a framing only
// xdrcheck conform reads) or SKIP (an api, strkey or spec entry: nothing to decode at L0). Exit codes, as every tool of
// the kit: 0 no variant failed, 1 a variant failed (with --expected-failures: the run differs from the list; with
// --require-all-read: a variant was not read), 2 the runner itself could not run (bad arguments, no SDK, an
// archive or blob that fails its checksum, a known divergence whose version range does not parse).
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { openRelease, entries, ToolError } from "../lib/archive.mjs";
import { Results, readExpectedFailures, formatComparison } from "../lib/expected.mjs";
import { loadSDK, runEntry, matcher, knownDivergences } from "../lib/run.mjs";

async function main() {
  const { values: o } = parseArgs({
    options: {
      entries: { type: "string" },
      stress: { type: "boolean", default: false },
      sdk: { type: "string" },
      archive: { type: "string" },
      dir: { type: "string" },
      list: { type: "boolean", default: false },
      "expected-failures": { type: "string" },
      "write-expected-failures": { type: "string" },
      "require-all-read": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (o.help) {
    console.log(
      "usage: xdrcheck-corpus-run [--entries GLOB[,GLOB…]] [--stress] [--sdk DIR] [--archive FILE | --dir DIR] [--list]\n" +
        "                      [--expected-failures FILE | --write-expected-failures FILE] [--require-all-read]",
    );
    return 0;
  }
  if (o["expected-failures"] && o["write-expected-failures"]) {
    throw new ToolError("--expected-failures and --write-expected-failures do not go together: write the list, then check against it");
  }
  const list = o["expected-failures"] ? readExpectedFailures(o["expected-failures"]) : null;
  const release = openRelease({ archive: o.archive ?? (process.env.XDRCHECK_CORPUS_ARCHIVE || undefined), dir: o.dir });
  const want = matcher(o.entries);
  const roots = o.stress ? ["corpus", "stress"] : ["corpus"];
  const selected = roots.flatMap((r) => entries(release, r)).filter((e) => want(e.id));
  if (selected.length === 0) throw new ToolError(`no entry matches ${o.entries}${o.stress ? "" : " (stress entries need --stress)"}`);
  if (o.list) {
    for (const e of selected) console.log(`${e.id}\t${e.json.kind}\t${e.root}`);
    return 0;
  }
  const sdk = await loadSDK(o.sdk);
  console.log(`corpus ${release.version} from ${release.source}`);
  console.log(`sdk ${sdk.name}@${sdk.version} from ${sdk.dir}`);
  const n = { pass: 0, known: 0, fixed: 0, fail: 0, unread: 0, skip: 0 };
  const res = new Results();
  const record = (k) => `${k.target} ${k.versions}: ${k.outcome}${k.match?.reason ? ` (${k.match.reason})` : ""}${k.reference ? ` ${k.reference}` : ""}`;
  for (const e of selected) {
    for (const r of runEntry(release, sdk, e)) {
      n[r.status]++;
      console.log(`${r.status.toUpperCase().padEnd(6)}  ${r.id}  ${r.variant}  ${r.type}  ${r.detail}`);
      if (r.status === "known") console.log(`        expected: known divergence ${record(r.known)}`);
      if (r.status === "fixed") console.log(`        the entry still records ${record(r.known)}; the record's range is stale`);
      if (r.status === "fail") {
        for (const k of knownDivergences(e, sdk)) console.log(`        recorded for this version, another outcome: ${record(k)}`);
      }
      // The list is the SDK's own account: a known divergence is still a failure to list.
      if (r.status === "pass" || r.status === "fixed") res.pass(r.id, r.variant, "L0");
      else if (r.status === "fail" || r.status === "known") res.fail(r.id, r.variant, "L0", r.detail);
      else if (r.status === "unread") res.unread(r.id, r.variant, r.detail);
      else res.select(r.id);
    }
  }
  const read = n.pass + n.known + n.fixed + n.fail;
  console.log(
    `entries ${selected.length}: ${n.pass} passed, ${n.known} known divergences, ${n.fixed} fixed, ${n.fail} failed, ${n.unread} unread, ${n.skip} skipped`,
  );
  console.log(`all read: ${read} of ${read + n.unread} ledger and xdr variants read${n.unread ? `; ${n.unread} never read (UNREAD lines)` : ""}`);
  const name = `${sdk.name}@${sdk.version}`;
  if (o["write-expected-failures"]) {
    writeFileSync(o["write-expected-failures"], res.writeExpectedFailures(name, release.version));
    console.log(`wrote ${res.cells.filter((c) => c.failed).length + res.unreads.length} line(s) to ${o["write-expected-failures"]}; review them before committing`);
    return 0;
  }
  if (list) {
    const cmp = res.compare(list, o["require-all-read"]);
    console.log(formatComparison(cmp, name, o["expected-failures"]));
    return cmp.passed ? 0 : 1;
  }
  if (o["require-all-read"] && n.unread) {
    console.log(`--require-all-read: ${n.unread} variant(s) never read; list them as unread in an --expected-failures file, or fix what keeps them unread`);
    return 1;
  }
  return n.fail ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`xdrcheck-corpus-run: ${e instanceof ToolError ? e.message : (e?.stack ?? e)}`);
    process.exit(2);
  },
);
