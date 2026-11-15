// Loading the SDK under test from one install directory, and the facts about it that `describe` reports: all
// read from the installed artefacts at start-up, never from the driver's own configuration.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const PACKAGE = "@stellar/stellar-sdk";
// The libraries whose versions decide decoding and numeric behaviour.
const DEPENDENCIES = ["@stellar/js-xdr", "bignumber.js"];

function readJSON(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

export async function loadSDK(installDir) {
  const nm = join(installDir, "node_modules");
  const pkgDir = join(nm, PACKAGE);
  const pkg = readJSON(join(pkgDir, "package.json"));
  // npm's record of what it installed, with each package's registry integrity.
  let installed = {};
  try {
    installed = readJSON(join(nm, ".package-lock.json")).packages ?? {};
  } catch {
    installed = {};
  }
  const integrity = (name) => installed[`node_modules/${name}`]?.integrity;
  const deps = [];
  for (const name of DEPENDENCIES) {
    try {
      const d = readJSON(join(nm, name, "package.json"));
      const e = { package: name, version: d.version };
      if (integrity(name)) e.integrity = integrity(name);
      deps.push(e);
    } catch {
      // not installed: not reported
    }
  }
  const entry = pkg.exports?.["."]?.import ?? pkg.module ?? pkg.main;
  const S = await import(pathToFileURL(join(pkgDir, entry)).href);
  const jsxdrPkg = readJSON(join(nm, "@stellar/js-xdr", "package.json"));
  const jsxdrEntry = jsxdrPkg.exports?.["."]?.import ?? jsxdrPkg.module ?? jsxdrPkg.main;
  const jsxdr = await import(pathToFileURL(join(nm, "@stellar/js-xdr", typeof jsxdrEntry === "string" ? jsxdrEntry : jsxdrEntry.default)).href);
  const sdk = { ecosystem: "npm", package: PACKAGE, version: pkg.version };
  if (integrity(PACKAGE)) sdk.integrity = integrity(PACKAGE);
  sdk.dependencies = deps;
  return { S, jsxdr, sdk, defaultDepth: probeDefaultDepth(jsxdr), argTypes: declaredArgTypes(pkgDir), builderRules: declaredBuilderRules(pkgDir) };
}

// What the installed TransactionBuilder's own declaration (transaction_builder.d.ts) says build() refuses beyond
// the time bounds every version requires: { sorobanNoMemo, sorobanNoMuxed } (docs/conformance-protocol.md, the
// rebuild fact). Read per version, so a version that does not declare a rule is rebuilt and judged.
export function declaredBuilderRules(pkgDir) {
  let text = "";
  try {
    text = readFileSync(join(pkgDir, "lib/esm/base/transaction_builder.d.ts"), "utf8");
  } catch {
    text = "";
  }
  const m = text.match(/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*build\(\): Transaction;/);
  const doc = m ? m[1].replace(/\s*\*\s*/g, " ") : "";
  return {
    sorobanNoMuxed: /@throws If a Soroban transaction has a muxed \(`M\.\.\.`\) source account/.test(doc),
    sorobanNoMemo: /Soroban transaction[^@]*or has a memo/.test(doc),
  };
}

// The JavaScript types the SDK's published type declarations allow for the api arguments whose type decides
// whether a tagged value can be passed at all (docs/conformance-protocol.md, argument_type_not_accepted): op →
// argument → Set of typeof names. Read from the installed .d.ts files, so each version answers for itself; an
// argument whose declaration is not found is passed as tagged, whatever its kind.
const DECLARATIONS = [
  ["muxed_account.encode", "id", "lib/esm/base/muxed_account.d.ts", /constructor\(baseAccount: Account, id: ([^)]+)\)/],
  ["offer.manage_sell", "offer_id", "lib/esm/base/operations/types.d.ts", /offerId\?: ([^;]+);/],
  ["offer.manage_buy", "offer_id", "lib/esm/base/operations/types.d.ts", /offerId\?: ([^;]+);/],
];

export function declaredArgTypes(pkgDir) {
  const out = {};
  for (const [op, arg, file, re] of DECLARATIONS) {
    let m;
    try {
      m = readFileSync(join(pkgDir, file), "utf8").match(re);
    } catch {
      m = null;
    }
    if (!m) continue;
    (out[op] ??= {})[arg] = new Set(m[1].split("|").map((t) => t.trim()));
  }
  return out;
}

// The reader's default depth limit, in js-xdr's own units (one per struct, union, array, option and lazy
// level): measured by entering levels on a default reader until it refuses.
function probeDefaultDepth(jsxdr) {
  if (typeof jsxdr.Reader !== "function") return null;
  const r = new jsxdr.Reader(new Uint8Array(0));
  for (let i = 0; i < 1 << 20; i++) {
    try {
      r.enter("probe");
    } catch {
      return i;
    }
  }
  return null;
}
