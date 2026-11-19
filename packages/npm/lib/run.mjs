// Running corpus entries through a JavaScript SDK at the byte level (conformance level L0, docs/manifest.md §10):
// every variant's blob is decoded as its XDR type with the SDK's own generated XDR classes and re-encoded.
//   positive entry: conforms when the SDK decodes the bytes and re-encodes them byte for byte
//   negative entry: conforms when the SDK refuses the bytes with an XDR decode error of the reason class the
//                   entry declares (`expect.reject.reason`); any other exception, or a refusal for another
//                   reason, is not a conforming refusal
// The expected outcome comes from the bytes and the entry, never from another reader. The baseline is the
// entry's own record of known divergences: one that names the SDK under test (`target` is its package name), the
// level L0 (or no level), no sandbox profile, and a version range holding the SDK's version predicts an outcome;
// when the SDK shows that outcome the variant is `known` (expected, not a failure). Higher levels (transaction
// parsing, decoded values, api calls) need the conformance orchestrator, `xdrcheck conform`.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { blob, ToolError } from "./archive.mjs";

/**
 * Load the SDK under test: `sdk` is a package directory (one holding package.json), or a project directory
 * whose node_modules holds @stellar/stellar-sdk; default the current directory, searched upwards. Any package
 * whose entry point exports `xdr` works (the SDK itself, @stellar/stellar-base).
 */
export async function loadSDK(sdk) {
  const start = resolve(sdk ?? process.cwd());
  let pkgDir = null;
  if (sdk && existsSync(join(start, "package.json")) && !existsSync(join(start, "node_modules", "@stellar", "stellar-sdk"))) {
    pkgDir = start;
  } else {
    for (let d = start; ; d = dirname(d)) {
      const c = join(d, "node_modules", "@stellar", "stellar-sdk");
      if (existsSync(join(c, "package.json"))) {
        pkgDir = c;
        break;
      }
      if (dirname(d) === d) break;
    }
  }
  if (!pkgDir) throw new ToolError(`no @stellar/stellar-sdk found from ${start}; pass --sdk DIR`);
  const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  const exp = pkg.exports?.["."];
  const entry = (typeof exp === "string" ? exp : exp?.import?.default ?? exp?.import ?? exp?.default) ?? pkg.module ?? pkg.main;
  if (typeof entry !== "string") throw new ToolError(`${pkgDir}: cannot find the package's entry point`);
  const mod = await import(pathToFileURL(join(pkgDir, entry)).href);
  const xdr = mod.xdr ?? mod.default?.xdr;
  if (!xdr) throw new ToolError(`${pkg.name}@${pkg.version} (${pkgDir}) exports no xdr namespace`);
  return { name: pkg.name, version: pkg.version, dir: pkgDir, xdr };
}

/** Generated XDR type by the corpus's type name, case-insensitively (the corpus spells ScVal, the SDK SCVal). */
const decodes = (T) => typeof T?.fromXdr === "function" || typeof T?.fromXDR === "function";

function xdrType(xdr, name) {
  if (decodes(xdr[name])) return xdr[name];
  const want = String(name).toLowerCase();
  for (const [k, v] of Object.entries(xdr)) {
    if (k.toLowerCase() === want && decodes(v)) return v;
  }
  return undefined;
}

/** `*` matches any run of characters (including `/`), `?` one character; several globs separated by commas. */
export function matcher(globs) {
  if (!globs) return () => true;
  const res = globs
    .split(",")
    .map((g) => g.trim())
    .filter(Boolean)
    .map((g) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`));
  return (id) => res.some((r) => r.test(id));
}

function variantKey(e, v) {
  const protocols = new Set((e.json.variants ?? []).map((x) => x.protocol));
  return protocols.size > 1 ? `${v.network}@${v.protocol}` : v.network;
}

const short = (e) => String(e?.message ?? e).split("\n")[0].slice(0, 160);

/**
 * What an exception thrown while decoding means: { fault, reasons }. A stack overflow is a crash, never a
 * refusal. js-xdr's decoder errors (XdrError in js-xdr 5 and later, the SDK 17 line; a TypeError whose message
 * starts "XDR Read Error:" or "Bad union switch" in js-xdr 4, the SDK 16 line) name the reason in their message;
 * the classes are the manifest's `expect.reject.reason` values. Where the message does not say which of two
 * constructs failed (an unknown enum value may be an undeclared enum value or union arm; js-xdr 4's bool error
 * covers optional flags too), it matches either. Any other exception (a TypeError from inside the SDK, a plain
 * Error) has no reason class: the SDK refused, but not as an XDR decoder refuses invalid bytes.
 */
export function classify(err) {
  const m = String(err?.message ?? err);
  if (err instanceof RangeError && /Maximum call stack size exceeded/.test(m)) return { fault: true, reasons: [] };
  const xdr5 = err instanceof Error && err.name === "XdrError";
  const xdr4 = err instanceof TypeError && (m.startsWith("XDR Read Error:") || /^Bad union switch/.test(m));
  if (!xdr5 && !xdr4) return { fault: false, reasons: [] };
  if (/invalid bool discriminant/.test(m)) return { fault: false, reasons: [/\.present: /.test(m) ? "optional_flag_range" : "bool_range"] };
  const rules = [
    [/when trying to read a bool/, ["bool_range", "optional_flag_range"]],
    [/non-zero XDR padding|invalid padding/, ["nonzero_padding"]],
    [/trailing \d+ byte|not entirely consumed/, ["trailing_bytes"]],
    [/max recursion depth|max decoding depth/, ["depth"]],
    [/exceeds maximum|saw \d+ length \w+, max allowed/, ["length_exceeds_max"]],
    [/exceeds remaining|incomplete XDR data|outside the boundary/, ["length_exceeds_input"]],
    [/no case for union discriminator|^Bad union switch/, ["union_arm_undeclared"]],
    [/unknown enum value|unknown \w+ member for value/, ["enum_undeclared", "union_arm_undeclared"]],
    [/out of range|expected integer in range|expected bigint in range/, ["value_out_of_range"]],
  ];
  for (const [re, reasons] of rules) if (re.test(m)) return { fault: false, reasons };
  return { fault: false, reasons: ["decode_error"] };
}

// ---- version ranges (the same grammar `xdrcheck conform` reads: `a || b`, `>=x <y`, `x - y`, `*`, exact) ----

function parseVersion(s) {
  const t = String(s).trim().replace(/^v/, "").replace(/\+.*$/, "");
  const [core, ...rest] = t.split("-");
  const nums = core.split(".");
  if (!core || nums.length > 3 || nums.some((n) => !/^\d+$/.test(n))) throw new ToolError(`version ${JSON.stringify(s)} is not MAJOR.MINOR.PATCH`);
  return { nums: [0, 1, 2].map((i) => Number(nums[i] ?? 0)), pre: rest.length ? rest.join("-").split(".") : null };
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i] < b.nums[i] ? -1 : 1;
  if (!a.pre || !b.pre) return !a.pre && !b.pre ? 0 : a.pre ? -1 : 1;
  for (let i = 0; i < Math.min(a.pre.length, b.pre.length); i++) {
    const [x, y] = [a.pre[i], b.pre[i]];
    const [nx, ny] = [/^\d+$/.test(x), /^\d+$/.test(y)];
    if (nx && ny && Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return Math.sign(a.pre.length - b.pre.length);
}

/** Whether version `ver` is in the range `rng`; an unparsable range is a tool error (it would assert nothing). */
export function inRange(ver, rng) {
  if (String(rng).includes("..")) return false; // a commit range names a repository, not a package version
  const v = parseVersion(ver);
  let any = false;
  for (const alt of String(rng).split("||").map((a) => a.trim())) {
    if (alt === "*") {
      any = true;
      continue;
    }
    if (!alt) throw new ToolError(`version range ${JSON.stringify(rng)} has an empty alternative`);
    const hy = alt.split(" - ");
    if (hy.length === 2) {
      any ||= cmp(v, parseVersion(hy[0])) >= 0 && cmp(v, parseVersion(hy[1])) <= 0;
      continue;
    }
    let all = true;
    for (const c of alt.split(/\s+/)) {
      const op = [">=", "<=", ">", "<", "="].find((p) => c.startsWith(p)) ?? "";
      const d = cmp(v, parseVersion(c.slice(op.length)));
      all &&= { "": d === 0, "=": d === 0, "<": d < 0, "<=": d <= 0, ">": d > 0, ">=": d >= 0 }[op];
    }
    any ||= all;
  }
  return any;
}

/**
 * The baseline: the known divergences an entry records for this SDK package at L0 (or with no level), with no
 * sandbox profile (the runner runs none), whose version range holds the SDK's version.
 */
export function knownDivergences(e, sdk) {
  return (e.json.conformance?.known_divergences ?? []).filter(
    (k) => k.target === sdk.name && (k.level ?? "L0") === "L0" && !k.profile && inRange(sdk.version, k.versions),
  );
}

// The verdict a known divergence's outcome predicts (as `xdrcheck conform` maps it).
const PREDICTS = { reject: "reject_valid", wrong_value: "diverge", accepts_invalid: "accepts_invalid", crash: "crash", hang: "crash" };

/** Observe one variant: { verdict, reasons, detail } with verdict conform | reject_valid | diverge | accepts_invalid | wrong_reason | crash | no_type. */
/**
 * Whether a byte decoder must refuse the variant: its validity (the variant's own, else the entry's) is malformed
 * or invalid (docs/manifest.md §9.5); an entry without a validity says it with `negative`.
 */
export function mustRefuse(j, v) {
  const validity = v?.validity ?? j.validity;
  if (validity) return validity === "malformed" || validity === "invalid";
  return Boolean(j.negative);
}

function observe(sdk, j, v, bytes) {
  const refuse = mustRefuse(j, v);
  const T = xdrType(sdk.xdr, v.xdr_type);
  if (!T) return { verdict: "no_type", detail: `the SDK has no XDR type ${v.xdr_type}` };
  const decode = typeof T.fromXdr === "function" ? T.fromXdr.bind(T) : T.fromXDR.bind(T);
  let value;
  try {
    value = decode(new Uint8Array(bytes));
  } catch (err) {
    const c = classify(err);
    const what = `${err?.name ?? typeof err}: ${short(err)}`;
    if (c.fault) return { verdict: "crash", detail: `crashed: ${what}` };
    if (!refuse) return { verdict: "reject_valid", reasons: c.reasons, detail: `refused valid bytes (${c.reasons[0] ?? "not an XDR decode error"}): ${what}` };
    const want = j.expect?.reject?.reason;
    if (!c.reasons.length) return { verdict: "wrong_reason", detail: `threw ${what}, not an XDR decode refusal${want ? ` for ${want}` : ""}` };
    if (want && !c.reasons.includes(want)) return { verdict: "wrong_reason", reasons: c.reasons, detail: `refused for ${c.reasons.join("/")}, the entry declares ${want}: ${short(err)}` };
    return { verdict: "conform", reasons: c.reasons, detail: `refused (${want ?? c.reasons[0]}): ${short(err)}` };
  }
  if (refuse) return { verdict: "accepts_invalid", detail: `accepted ${bytes.length} bytes a correct reader refuses (${j.expect?.reject?.reason ?? "negative entry"})` };
  let again;
  try {
    again = Buffer.from(typeof value.toXdr === "function" ? value.toXdr() : value.toXDR());
  } catch (err) {
    return { verdict: "diverge", detail: `decoded, but re-encoding failed: ${short(err)}` };
  }
  if (again.equals(bytes)) return { verdict: "conform", detail: `${bytes.length} bytes decoded and re-encoded byte for byte` };
  return { verdict: "diverge", detail: `re-encoding differs: ${again.length} bytes from ${bytes.length}` };
}

/**
 * Run one entry; returns one result per variant: { id, variant, type, status, detail, known } where status is
 *   pass   the variant conforms and no known divergence covers this SDK version
 *   known  the SDK shows the outcome a known divergence predicts for its version (expected; `known` is that record)
 *   fixed  the variant conforms although a known divergence covers this SDK version (the record's range is stale)
 *   fail   anything else
 *   unread a ledger or xdr variant the runner could not put through the SDK: a type the SDK does not generate, or a
 *          framing only `xdrcheck conform` reads (counted by the all-read check)
 *   skip   an entry kind with no bytes to decode at L0 (api, strkey, spec): not selected at this level
 */
export function runEntry(release, sdk, e) {
  const j = e.json;
  if (j.kind !== "ledger" && j.kind !== "xdr") {
    return [{ id: e.id, variant: "-", type: j.kind, status: "skip", detail: `kind ${j.kind} has no bytes; run it with xdrcheck conform (L4)` }];
  }
  const baseline = knownDivergences(e, sdk);
  const out = [];
  for (const v of j.variants ?? []) {
    const r = { id: e.id, variant: variantKey(e, v), type: v.xdr_type, status: "fail", detail: "" };
    out.push(r);
    if ((v.framing ?? "none") !== "none") {
      Object.assign(r, { status: "unread", detail: `framing ${v.framing} needs xdrcheck conform` });
      continue;
    }
    const o = observe(sdk, j, v, blob(release, e.root, v));
    r.detail = o.detail;
    if (o.verdict === "no_type") {
      r.status = "unread";
      continue;
    }
    if (o.verdict === "conform") {
      r.status = baseline.length ? "fixed" : "pass";
      if (baseline.length) r.known = baseline[0];
      continue;
    }
    const k = baseline.find((k) => PREDICTS[k.outcome] === o.verdict && (!k.match?.reason || (o.reasons ?? []).includes(k.match.reason)));
    if (k) Object.assign(r, { status: "known", known: k });
  }
  return out;
}
