// Reproduction of js-stellar-sdk#1766 (Asset.compare orders issuers by strkey
// text, not raw key bytes). Usage: node repro.mjs <dir-with-node_modules>
// The SDK is loaded from <dir>/node_modules, so one script runs against both
// the pre-fix and the fixed install.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2]);
const pkgDir = resolve(dir, "node_modules/@stellar/stellar-sdk");
const pkg = JSON.parse(readFileSync(resolve(pkgDir, "package.json"), "utf8"));
const xdrPkg = JSON.parse(
  readFileSync(resolve(dir, "node_modules/@stellar/js-xdr/package.json"), "utf8"),
);
const S = await import(pathToFileURL(resolve(pkgDir, pkg.exports["."].import)).href);
const { Asset, LiquidityPoolAsset, LiquidityPoolFeeV18, getLiquidityPoolId,
  StrKey, TransactionBuilder, Networks, Operation, xdr } = S;

const hex = (u) => Buffer.from(u).toString("hex");
const run = (label, fn) => {
  try { console.log(`${label}: OK ${fn()}`); }
  catch (e) { console.log(`${label}: THROWS ${e.constructor.name}: ${e.message}`); }
};

console.log(`@stellar/stellar-sdk ${pkg.version}  @stellar/js-xdr ${xdrPkg.version}  node ${process.version}`);

// Issuers of testnet pool c2a73012…2d5e (Horizon reserves order = core order).
const ISS_A = "GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL";
const ISS_B = "GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO";
const POOL_ID = "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e";
const TX_HASH = "0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f";

const ka = StrKey.decodeEd25519PublicKey(ISS_A);
const kb = StrKey.decodeEd25519PublicKey(ISS_B);
console.log(`issuer A ${ISS_A} key ${hex(ka)}`);
console.log(`issuer B ${ISS_B} key ${hex(kb)}`);
console.log(`text order  A<B: ${ISS_A < ISS_B}   (expected false: '3'=0x33 < 'R'=0x52)`);
console.log(`byte order  A<B: ${Buffer.compare(Buffer.from(ka), Buffer.from(kb)) < 0}   (expected true: 0xe3 < 0xf7)`);

const a = new Asset("USD", ISS_A);
const b = new Asset("USD", ISS_B);

console.log("\n-- builder / comparator API --");
run("Asset.compare(A,B)  [core: -1]", () => Asset.compare(a, b));
run("Asset.compare(B,A)  [core: 1]", () => Asset.compare(b, a));
run("new LiquidityPoolAsset(A,B,30)  [core: valid]", () =>
  new LiquidityPoolAsset(a, b, LiquidityPoolFeeV18).getLiquidityPoolParameters().assetA.getIssuer());
run("new LiquidityPoolAsset(B,A,30)  [core: invalid order]", () =>
  new LiquidityPoolAsset(b, a, LiquidityPoolFeeV18).getLiquidityPoolParameters().assetA.getIssuer());
run(`getLiquidityPoolId(A,B)  [core: ${POOL_ID}]`, () =>
  hex(getLiquidityPoolId("constant_product", { assetA: a, assetB: b, fee: LiquidityPoolFeeV18 })));
run("getLiquidityPoolId(B,A)  [core: invalid order, no such pool]", () =>
  hex(getLiquidityPoolId("constant_product", { assetA: b, assetB: a, fee: LiquidityPoolFeeV18 })));
run("Operation.changeTrust({asset: LP(A,B)}) type", () =>
  Operation.changeTrust({ asset: new LiquidityPoolAsset(a, b, LiquidityPoolFeeV18) }).body.type);

console.log("\n-- decode of the core-accepted testnet transaction (ledger 5521432) --");
const env = readFileSync(new URL("./testnet-tx-0126748091.envelope.b64", import.meta.url), "utf8").trim();
run("xdr.TransactionEnvelope.fromXdr (raw XDR layer)", () => {
  const e = xdr.TransactionEnvelope.fromXdr(env, "base64");
  return `type=${e.type} ops=${e.value.tx.operations.length} roundtrip=${e.toXdr("base64") === env}`;
});
run("TransactionBuilder.fromXdr (SDK Transaction layer)", () => {
  const tx = TransactionBuilder.fromXdr(env, Networks.TESTNET);
  const lp = tx.operations[2].line;
  return `hash=${hex(tx.hash())} hashOk=${hex(tx.hash()) === TX_HASH} op[2]=${tx.operations[2].type} ` +
    `poolId=${hex(getLiquidityPoolId("constant_product", lp.getLiquidityPoolParameters()))}`;
});
run("Operation.fromXdrObject(op[2]) (SDK Operation layer)", () => {
  const e = xdr.TransactionEnvelope.fromXdr(env, "base64");
  return Operation.fromXdrObject(e.value.tx.operations[2]).type;
});

console.log("\n-- ScVal map key order (second half of #1766) --");
const { scvSortedMap, nativeToScVal } = S;
const keys = (m) => m.value.map((e) => `${e.key.type}(${
  e.key.type === "scvBytes" ? hex(e.key.value.toBytes ? e.key.value.toBytes() : e.key.value) : String(e.key.value)})`).join(", ");
run("scvSortedMap(bytes 0x0a, bytes 0x09)  [host: 09, 0a]", () => keys(scvSortedMap([
  new xdr.ScMapEntry({ key: xdr.ScVal.scvBytes(new Uint8Array([10])), val: xdr.ScVal.scvVoid() }),
  new xdr.ScMapEntry({ key: xdr.ScVal.scvBytes(new Uint8Array([9])), val: xdr.ScVal.scvVoid() }),
])));
run("scvSortedMap(symbol \"a\", string \"b\")  [host: string before symbol]", () => keys(scvSortedMap([
  new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("a"), val: xdr.ScVal.scvVoid() }),
  new xdr.ScMapEntry({ key: xdr.ScVal.scvString("b"), val: xdr.ScVal.scvVoid() }),
])));
run("nativeToScVal({10:1, 9:2}, u32 keys)  [host: 9, 10]", () =>
  keys(nativeToScVal({ 10: 1, 9: 2 }, { type: { 10: ["u32", "u32"], 9: ["u32", "u32"] } })));
