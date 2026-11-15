// Loading the v16 SDK under test from one install directory, and the facts about it that `describe` reports: all
// read from the installed artefacts at start-up, never from the driver's own configuration.
//
// The 16.x ESM build carries its own copy of @stellar/js-xdr (lib/esm/node_modules/.pnpm/@stellar_js-xdr@<v>/…),
// which is what decodes; the version in that path is reported, with the registry integrity of the installed
// @stellar/js-xdr package when it is the same release.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { recordSchema } from "./schema.mjs";

const PACKAGE = "@stellar/stellar-sdk";

function readJSON(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

/** The js-xdr release bundled into the SDK's ESM build, from its directory name. */
function bundledJsXdr(pkgDir) {
  try {
    for (const d of readdirSync(join(pkgDir, "lib/esm/node_modules/.pnpm"))) {
      const m = d.match(/^@stellar_js-xdr@(\d+\.\d+\.\d+.*)$/);
      if (m) return m[1];
    }
  } catch {
    // no bundled copy: the installed package decodes
  }
  return undefined;
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
  const version = (name) => {
    try {
      return readJSON(join(nm, name, "package.json")).version;
    } catch {
      return undefined;
    }
  };
  const jsxdr = bundledJsXdr(pkgDir) ?? version("@stellar/js-xdr");
  if (jsxdr) {
    const e = { package: "@stellar/js-xdr", version: jsxdr };
    if (version("@stellar/js-xdr") === jsxdr && integrity("@stellar/js-xdr")) e.integrity = integrity("@stellar/js-xdr");
    deps.push(e);
  }
  const bn = version("bignumber.js");
  if (bn) deps.push({ package: "bignumber.js", version: bn, ...(integrity("bignumber.js") ? { integrity: integrity("bignumber.js") } : {}) });

  const entry = pkg.exports?.["."]?.import ?? pkg.module ?? pkg.main;
  const S = await import(pathToFileURL(join(pkgDir, entry)).href);
  const sdk = { ecosystem: "npm", package: PACKAGE, version: pkg.version };
  if (integrity(PACKAGE)) sdk.integrity = integrity(PACKAGE);
  sdk.dependencies = deps;
  return {
    S, sdk, schema: recordSchema(pkgDir, S.xdr), defaultDepth: defaultDepth(S.xdr),
    argTypes: declaredArgTypes(pkgDir), xdrConfig: await bundledConfig(pkgDir),
    builderRules: declaredBuilderRules(pkgDir),
  };
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

// js-xdr 4's schema-definition entry point (config) from the copy bundled into the SDK's ESM build, the copy
// that decodes; undefined when the build carries none (xdr.custom_union_encode is then not offered).
async function bundledConfig(pkgDir) {
  const v = bundledJsXdr(pkgDir);
  if (!v) return undefined;
  const p = join(pkgDir, "lib/esm/node_modules/.pnpm", `@stellar_js-xdr@${v}`, "node_modules/@stellar/js-xdr/src/config.js");
  try {
    return (await import(pathToFileURL(p).href)).config;
  } catch {
    return undefined;
  }
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

function declaredArgTypes(pkgDir) {
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

// The reader's default depth budget, in js-xdr 4's own units (one per struct, union, array, option level): the
// budget a generated type decodes with when fromXDR is called without one.
function defaultDepth(xdr) {
  const d = xdr.ScVal?._maxDepth;
  return Number.isInteger(d) ? d : null;
}
