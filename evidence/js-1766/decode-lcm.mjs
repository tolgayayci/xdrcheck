// Decode the core-emitted testnet LedgerCloseMetaBatch for ledger 5521432
// (Galexie layout, public data lake) and parse every transaction envelope in
// its tx set with the SDK object layer. Usage:
//   node decode-lcm.mjs <dir-with-node_modules> <path-to-uncompressed-lcm.xdr>
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const pkgDir = resolve(process.argv[2], "node_modules/@stellar/stellar-sdk");
const pkg = JSON.parse(readFileSync(resolve(pkgDir, "package.json"), "utf8"));
const S = await import(pathToFileURL(resolve(pkgDir, pkg.exports["."].import)).href);
const { xdr, TransactionBuilder, Networks } = S;
const hex = (u) => Buffer.from(u).toString("hex");
console.log(`@stellar/stellar-sdk ${pkg.version}  node ${process.version}`);

const bytes = readFileSync(process.argv[3]);
let batch;
try {
  batch = xdr.LedgerCloseMetaBatch.fromXdr(bytes);
  console.log(`LedgerCloseMetaBatch decode: OK ledgers ${batch.startSequence}-${batch.endSequence} ` +
    `roundtrip=${Buffer.compare(Buffer.from(batch.toXdr()), bytes) === 0}`);
} catch (e) {
  console.log(`LedgerCloseMetaBatch decode: THROWS ${e.message}`);
  process.exit(0);
}

const envs = [];
const seen = new Set();
const visit = (x) => {
  if (x === null || typeof x !== "object" || seen.has(x) || x instanceof Uint8Array) return;
  seen.add(x);
  if (x instanceof xdr.TransactionEnvelope) { envs.push(x); return; }
  if (Array.isArray(x)) { x.forEach(visit); return; }
  for (const k of Object.keys(x)) visit(x[k]);
  if ("value" in x) visit(x.value);
};
visit(batch);
console.log(`envelopes in tx set: ${envs.length}`);

let ok = 0;
for (const env of envs) {
  const b64 = env.toXdr("base64");
  try {
    const tx = TransactionBuilder.fromXdr(b64, Networks.TESTNET);
    ok++;
    const h = hex(tx.hash());
    if (h.startsWith("01267480")) console.log(`  ${h}: OK ops=${tx.operations.map((o) => o.type).join(",")}`);
  } catch (e) {
    const h = hex(S.hash(Buffer.concat([
      S.hash(Buffer.from(Networks.TESTNET)), Buffer.from([0, 0, 0, 2]),
      Buffer.from(env.value.tx.toXdr())])));
    console.log(`  ${h}: TransactionBuilder.fromXdr THROWS ${e.message}`);
  }
}
console.log(`parsed by SDK object layer: ${ok}/${envs.length}`);
