// Reproduction of js-stellar-sdk#1785 (muxed account IDs and offer IDs accept
// values that encode a different ID). Builder-API defect: no decode involved.
// Usage: node repro.mjs <dir-with-node_modules>
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2]);
const pkgDir = resolve(dir, "node_modules/@stellar/stellar-sdk");
const pkg = JSON.parse(readFileSync(resolve(pkgDir, "package.json"), "utf8"));
const S = await import(pathToFileURL(resolve(pkgDir, pkg.exports["."].import)).href);
const { Account, MuxedAccount, Asset, Operation, encodeMuxedAccount,
  encodeMuxedAccountToAddress, xdr } = S;

const run = (label, fn) => {
  try { console.log(`${label}: OK ${fn()}`); }
  catch (e) { console.log(`${label}: THROWS ${e.constructor.name}: ${e.message}`); }
};
console.log(`@stellar/stellar-sdk ${pkg.version}  node ${process.version}`);

const G = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
const base = new Account(G, "0");

console.log("\n-- MuxedAccount IDs (expected: only canonical decimal uint64 accepted) --");
for (const id of ["16", "0x10", "016", " 16 ", "", "-1", "18446744073709551616"]) {
  run(`new MuxedAccount(G, ${JSON.stringify(id)}) -> id() / M-address`, () => {
    const m = new MuxedAccount(base, id);
    const back = MuxedAccount.fromAddress(m.accountId(), "0");
    return `id()=${JSON.stringify(m.id())} M=${m.accountId()} decodedId=${back.id()}`;
  });
}
run(`encodeMuxedAccount(G, "0x10") -> M-address`, () =>
  encodeMuxedAccountToAddress(encodeMuxedAccount(G, "0x10")));

console.log("\n-- offerId (expected: non-negative safe integer / bigint / decimal string <= int64 max) --");
const selling = Asset.native();
const buying = new Asset("USD", G);
const encodedOfferId = (offerId) => {
  const op = Operation.manageSellOffer({ selling, buying, amount: "1", price: "1", offerId });
  const back = Operation.fromXdrObject(op);
  return `encoded offerId=${back.offerId}`;
};
run("manageSellOffer offerId=9007199254740993 (number literal, > 2^53)", () => encodedOfferId(9007199254740993));
run("manageSellOffer offerId=2**63 (number)", () => encodedOfferId(2 ** 63));
run('manageSellOffer offerId="" (empty string; 0 = create new offer)', () => encodedOfferId(""));
run('manageSellOffer offerId="-5"', () => encodedOfferId("-5"));
run("manageSellOffer offerId=-5", () => encodedOfferId(-5));
run('manageSellOffer offerId="0x10"', () => encodedOfferId("0x10"));
run('manageSellOffer offerId="9007199254740993" (string, exact)', () => encodedOfferId("9007199254740993"));
run("manageBuyOffer offerId=9007199254740993 (number)", () => {
  const op = Operation.manageBuyOffer({ selling, buying, buyAmount: "1", price: "1", offerId: 9007199254740993 });
  return `encoded offerId=${Operation.fromXdrObject(op).offerId}`;
});
