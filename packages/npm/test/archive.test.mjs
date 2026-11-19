// Unit tests: the in-memory tar reader against archives GNU tar writes the way scripts/release.sh does, the
// release checksum gate, entry globs, decode-error classes, version ranges and the known-divergence baseline.
// Run with `node --test test/` (scripts/release.sh npm runs them).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { untar, openRelease, entries, blob, ToolError } from "../lib/archive.mjs";
import { matcher, classify, inRange, runEntry } from "../lib/run.mjs";
import { Results, parseExpectedFailures, formatComparison } from "../lib/expected.mjs";

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

// A miniature release: one entry with one blob, a path longer than ustar's 100-byte name field.
function miniRelease() {
  const base = mkdtempSync(join(tmpdir(), "xdrcheck-npm-test-"));
  const top = "xdrcheck-30.0.0";
  const bytes = Buffer.from([0, 0, 0, 4, 0, 0, 0, 7]); // ScVal u32 7
  const sha = sha256(bytes);
  const id = "group/a-slug-long-enough-that-the-archive-path-needs-the-ustar-prefix-field-to-hold-it-all";
  const entry = {
    id, kind: "xdr", negative: false,
    variants: [{ network: "none", protocol: 30, xdr_type: "ScVal", blob: { sha256: sha, bytes: bytes.length } }],
  };
  mkdirSync(join(base, top, "corpus", "manifest", "group"), { recursive: true });
  mkdirSync(join(base, top, "corpus", "blobs", sha.slice(0, 2)), { recursive: true });
  mkdirSync(join(base, top, "stress", "manifest"), { recursive: true });
  writeFileSync(join(base, top, "corpus", "manifest", `${id}.json`), JSON.stringify(entry));
  writeFileSync(join(base, top, "corpus", "blobs", sha.slice(0, 2), `${sha}.xdr`), bytes);
  writeFileSync(join(base, top, "PROVENANCE.json"), JSON.stringify({ version: "30.0.0" }));
  const archive = join(base, `${top}.tar.gz`);
  execFileSync("bash", ["-c",
    `tar --sort=name --format=ustar --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$1" -cf - "$2" | gzip -n -9 > "$3"`,
    "sh", base, top, archive]);
  const pkg = join(base, "pkg");
  mkdirSync(pkg);
  const gz = readFileSync(archive);
  writeFileSync(join(pkg, "release.json"), JSON.stringify({ version: "30.0.0", archive: `${top}.tar.gz`, top, sha256: sha256(gz), bytes: gz.length }));
  return { base, top, archive, pkg, id, bytes };
}

test("untar reads ustar members, including prefix-split long paths", () => {
  const r = miniRelease();
  try {
    const files = untar(gunzipSync(readFileSync(r.archive)));
    const name = `${r.top}/corpus/manifest/${r.id}.json`;
    assert.ok(name.length > 100);
    assert.equal(JSON.parse(files.get(name).toString()).id, r.id);
    assert.ok(![...files.keys()].some((k) => k.endsWith("/")), "directories are not files");
  } finally {
    rmSync(r.base, { recursive: true, force: true });
  }
});

test("an archive is read only when its sha256 is the packed one", () => {
  const r = miniRelease();
  try {
    const rel = openRelease({ archive: r.archive, pkgDir: r.pkg });
    const [e] = entries(rel, "corpus");
    assert.equal(e.id, r.id);
    assert.deepEqual(blob(rel, "corpus", e.json.variants[0]), r.bytes);
    assert.deepEqual(entries(rel, "stress"), []);
    const other = join(r.base, "other.tar.gz");
    writeFileSync(other, Buffer.concat([readFileSync(r.archive), Buffer.from([0])]));
    assert.throws(() => openRelease({ archive: other, pkgDir: r.pkg }), ToolError);
  } finally {
    rmSync(r.base, { recursive: true, force: true });
  }
});

test("an extracted release directory reads the same entries", () => {
  const r = miniRelease();
  try {
    const rel = openRelease({ dir: join(r.base, r.top) });
    assert.equal(rel.version, "30.0.0");
    const [e] = entries(rel, "corpus");
    assert.deepEqual(blob(rel, "corpus", e.json.variants[0]), r.bytes);
  } finally {
    rmSync(r.base, { recursive: true, force: true });
  }
});

test("entry globs", () => {
  const m = matcher("cap-0040/*,limits/scvec-nesting-9?");
  assert.ok(m("cap-0040/signed-payload-signer-added"));
  assert.ok(m("limits/scvec-nesting-99"));
  assert.ok(!m("limits/scvec-nesting-100"));
  assert.ok(!m("cap-0073/x"));
  assert.ok(matcher(undefined)("anything"));
  assert.ok(matcher("a.b")("a.b") && !matcher("a.b")("axb"));
});

class XdrError extends Error {
  constructor(m) {
    super(m);
    this.name = "XdrError";
  }
}

test("decode errors are classed by reason; other exceptions have no reason; a stack overflow is a crash", () => {
  assert.deepEqual(classify(new XdrError("ScVal.b: non-zero XDR padding")).reasons, ["nonzero_padding"]);
  assert.deepEqual(classify(new TypeError("XDR Read Error: saw 9 length VarArray, max allowed is 8")).reasons, ["length_exceeds_max"]);
  assert.deepEqual(classify(new XdrError("ScVal.type: unknown enum value 99")).reasons, ["enum_undeclared", "union_arm_undeclared"]);
  assert.deepEqual(classify(new XdrError("something new")).reasons, ["decode_error"]);
  assert.deepEqual(classify(new TypeError("Cannot read properties of undefined")).reasons, []);
  assert.deepEqual(classify(new Error("boom")).reasons, []);
  assert.equal(classify(new RangeError("Maximum call stack size exceeded")).fault, true);
});

test("version ranges", () => {
  assert.ok(inRange("16.4.1", "16.3.0 || 16.3.1 || 16.4.1"));
  assert.ok(!inRange("17.4.0", "16.3.0 || 16.3.1 || 16.4.1"));
  assert.ok(inRange("17.2.0", "<16.3.1 || >=17.0.0 <17.2.1") && !inRange("17.2.1", "<16.3.1 || >=17.0.0 <17.2.1"));
  assert.ok(inRange("1.5.0", "1.0.0 - 2.0.0") && inRange("9.9.9", "*"));
  assert.ok(!inRange("1.0.0", "a..b"), "a commit range never matches a package version");
  assert.throws(() => inRange("1.0.0", "1.0.0 ||"), ToolError);
});

// A fake SDK whose one XDR type decodes or throws as told, and a release whose blob is fixed bytes.
function fakeRun({ negative = false, reason, throws, divergences = [], version = "1.0.0", validity, variantValidity, type = "ScVal" }) {
  const bytes = Buffer.from([0, 0, 0, 1]);
  const T = {
    fromXdr(b) {
      if (throws) throw throws;
      return { toXdr: () => Buffer.from(b) };
    },
  };
  const sdk = { name: "@stellar/stellar-sdk", version, xdr: { [type]: T } };
  const json = {
    kind: "xdr", negative, validity,
    expect: reason ? { reject: { reason } } : {},
    conformance: { known_divergences: divergences },
    variants: [{ network: "none", protocol: 30, xdr_type: "ScVal", validity: variantValidity, blob: { sha256: sha256(bytes), bytes: bytes.length } }],
  };
  const release = { read: () => bytes };
  return runEntry(release, sdk, { id: "g/e", root: "corpus", json })[0];
}

test("a negative entry conforms only when refused for its declared reason class", () => {
  assert.equal(fakeRun({ negative: true, reason: "nonzero_padding", throws: new XdrError("x: non-zero XDR padding") }).status, "pass");
  assert.equal(fakeRun({ negative: true, reason: "nonzero_padding", throws: new XdrError("x: trailing 3 bytes") }).status, "fail");
  assert.equal(fakeRun({ negative: true, reason: "nonzero_padding", throws: new TypeError("undefined is not a function") }).status, "fail");
  assert.equal(fakeRun({ negative: true, reason: "nonzero_padding" }).status, "fail", "accepting invalid bytes fails");
});

test("the known-divergence baseline: a predicted outcome is expected, anything else fails", () => {
  const k = { target: "@stellar/stellar-sdk", versions: "1.0.0", level: "L0", outcome: "reject", match: { reason: "depth" }, reference: "https://example.org/1" };
  const depth = new TypeError("XDR Read Error: exceeded max decoding depth");
  assert.equal(fakeRun({ throws: depth, divergences: [k] }).status, "known");
  assert.equal(fakeRun({ throws: depth, divergences: [k], version: "1.0.1" }).status, "fail", "outside the range");
  assert.equal(fakeRun({ throws: new XdrError("x: trailing 1 byte"), divergences: [k] }).status, "fail", "another reason than declared");
  assert.equal(fakeRun({ throws: depth, divergences: [{ ...k, level: "L1" }] }).status, "fail", "another level");
  assert.equal(fakeRun({ throws: depth, divergences: [{ ...k, profile: "address-space cap RLIMIT_AS 2 GiB" }] }).status, "fail", "a sandbox profile");
  assert.equal(fakeRun({ divergences: [k] }).status, "fixed", "conforming inside the range");
  assert.equal(fakeRun({}).status, "pass");
  const neg = { ...k, outcome: "accepts_invalid", match: undefined };
  assert.equal(fakeRun({ negative: true, reason: "bool_range", divergences: [neg] }).status, "known");
});

test("validity decides what must be refused; a variant's own overrides its entry's", () => {
  const err = new XdrError("x: trailing 3 bytes");
  assert.equal(fakeRun({ validity: "malformed", throws: err }).status, "pass");
  assert.equal(fakeRun({ validity: "invalid" }).status, "fail", "accepting an invalid input fails");
  assert.equal(fakeRun({ validity: "valid", negative: true }).status, "pass", "validity wins over the negative flag");
  assert.equal(fakeRun({ validity: "valid", variantValidity: "malformed", throws: err }).status, "pass");
  assert.equal(fakeRun({ validity: "malformed", variantValidity: "valid" }).status, "pass");
});

test("a type the SDK does not generate is unread, not a failure", () => {
  const r = fakeRun({ type: "SomethingElse" });
  assert.equal(r.status, "unread");
});

test("expected-failure lists: every outcome, and a written list passes against its own run", () => {
  const list = parseExpectedFailures(
    ["# comment", "still/failing testnet L0  # why", "now/passing pubnet L0", "now/read none unread", "still/unread none unread",
      "selected/missing typo L0", "not/selected testnet L0"].join("\n"),
    "list.txt",
  );
  assert.throws(() => parseExpectedFailures("a b\n"), ToolError);
  assert.throws(() => parseExpectedFailures("a b L0\na b L0\n"), ToolError);
  const r = new Results();
  r.fail("still/failing", "testnet", "L0", "refused");
  r.pass("now/passing", "pubnet", "L0");
  r.pass("now/read", "none", "L0");
  r.unread("still/unread", "none", "type");
  r.fail("new/failure", "testnet", "L0", "accepted invalid input");
  r.unread("new/unread", "none", "type");
  r.select("selected/missing");
  const c = r.compare(list, false);
  assert.deepEqual([c.matched, c.newFailures.length, c.nowPassing.length, c.nowRead.length, c.newUnread.length, c.notRun.length, c.passed], [2, 1, 1, 1, 0, 1, false]);
  const all = r.compare(list, true);
  assert.equal(all.newUnread.length, 1);
  const text = formatComparison(all, "sdk@1", "list.txt");
  for (const want of [
    "NEW-FAILURE   new/failure testnet L0: accepted invalid input",
    "UNEXPECTED-PASS now/passing pubnet L0: listed as failing but now conforms; remove the line from list.txt",
    "UNEXPECTED-PASS now/read none unread: listed as unread",
    "NEW-UNREAD    new/unread none: never read (type)",
    "NOT-RUN       selected/missing typo L0 (list.txt line 6)",
    "expected failures sdk@1: 2 still as listed, 1 new failures, 1 new unread, 2 unexpected passes, 1 listed but not run",
  ]) assert.ok(text.includes(want), `missing ${want} in\n${text}`);
  assert.equal(r.compare(parseExpectedFailures(r.writeExpectedFailures("sdk@1", "30.0.0")), true).passed, true);
});
