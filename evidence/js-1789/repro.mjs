// Reproduction of js-stellar-sdk#1789 (scValToNative silently drops scvMap
// entries whose keys convert to the same object property).
// Usage: node repro.mjs <dir-with-node_modules>
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2]);
const pkgDir = resolve(dir, "node_modules/@stellar/stellar-sdk");
const pkg = JSON.parse(readFileSync(resolve(pkgDir, "package.json"), "utf8"));
const S = await import(pathToFileURL(resolve(pkgDir, pkg.exports["."].import)).href);
const { xdr, scValToNative } = S;

const run = (label, fn) => {
  try { console.log(`${label}: OK ${fn()}`); }
  catch (e) { console.log(`${label}: THROWS ${e.constructor.name}: ${e.message}`); }
};
console.log(`@stellar/stellar-sdk ${pkg.version}  node ${process.version}`);

// Wire bytes of ScVal::Map([{U32(1): U32(10)}, {Symbol("1"): U32(20)}]).
// Keys are in Soroban host order (type U32=3 < Symbol=15), so a contract can
// emit this map in an event or a return value. Built by hand from the XDR spec:
//   00000011 scvMap, 00000001 present, 00000002 two entries,
//   00000003 00000001 | 00000003 0000000a   key u32 1   -> val u32 10
//   0000000f 00000001 31000000 | 00000003 00000014   key sym "1" -> val u32 20
const HEX =
  "00000011" + "00000001" + "00000002" +
  "00000003" + "00000001" + "00000003" + "0000000a" +
  "0000000f" + "00000001" + "31000000" + "00000003" + "00000014";

run("xdr.ScVal.fromXdr(hex) entries / round trip", () => {
  const v = xdr.ScVal.fromXdr(HEX, "hex");
  return `entries=${v.value.length} roundtrip=${v.toXdr("hex") === HEX}`;
});
run("scValToNative(decoded map)  [expected: 2 entries, or an error]", () => {
  const n = scValToNative(xdr.ScVal.fromXdr(HEX, "hex"));
  return `${JSON.stringify(n)} (${Object.keys(n).length} entries)`;
});

// Same map built through the API, as in the issue body.
run("scValToNative(issue #1789 example)", () => {
  const m = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvU32(1), val: xdr.ScVal.scvU32(10) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("1"), val: xdr.ScVal.scvU32(20) }),
  ]);
  return JSON.stringify(scValToNative(m));
});
// Control: distinct keys still decode.
run("scValToNative(u32 1 -> 10, symbol \"a\" -> 20)  [control]", () => {
  const m = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvU32(1), val: xdr.ScVal.scvU32(10) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("a"), val: xdr.ScVal.scvU32(20) }),
  ]);
  return JSON.stringify(scValToNative(m));
});
