// Throwaway conformance probe for @stellar/stellar-sdk (v16 and v17 lines).
// Usage: node probe.mjs <install-dir> <vectors.json> [vectorId ...]
// Prints one JSON line per vector: {vector,sdk,version,outcome,detail,got}
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2]);
const vecPath = resolve(process.argv[3]);
const pkgDir = resolve(dir, "node_modules/@stellar/stellar-sdk");
const pkg = JSON.parse(readFileSync(resolve(pkgDir, "package.json"), "utf8"));
const xdrVer = JSON.parse(readFileSync(resolve(dir, "node_modules/@stellar/js-xdr/package.json"), "utf8")).version;
const S = await import(pathToFileURL(resolve(pkgDir, pkg.exports["."].import)).href);
const { xdr, StrKey, Asset, LiquidityPoolAsset, LiquidityPoolFeeV18, getLiquidityPoolId, TransactionBuilder,
  Operation, MuxedAccount, Account, Memo, Address, scValToNative, nativeToScVal, scvSortedMap,
  encodeMuxedAccountToAddress } = S;
const VERSION = `${pkg.version} (js-xdr ${xdrVer})`;
const [maj, min] = pkg.version.split(".").map(Number);
const V17 = maj >= 17;
// P30 schema = XDR knows CAP-0084 ScAddressType 5 and CAP-0088 StellarValueType SIGNED_MS (detected, not assumed)
const P30 = !!(xdr.ScAddressType && xdr.ScAddressType.scAddressTypeMuxedContract && xdr.StellarValueType && xdr.StellarValueType.stellarValueSignedMs);
const vectors = JSON.parse(readFileSync(vecPath, "utf8"));
const vecDir = dirname(vecPath);

// ---- v16/v17 adapters ----
const hex = (u) => Buffer.from(u).toString("hex");
const fromX = (T, bytes) => (T.fromXdr ? T.fromXdr(Uint8Array.from(bytes)) : T.fromXDR(Buffer.from(bytes)));
const toX = (v) => hex(v.toXdr ? v.toXdr() : v.toXDR());
const f = (o, k) => (typeof o[k] === "function" ? o[k]() : o[k]);
const arm = (u) => { if (V17) return u.type; const sw = u.switch(); return sw && sw.name !== undefined ? sw.name : String(sw); };
const uval = (u) => (V17 ? u.value : u.value());
const txFrom = (b64, net) => (TransactionBuilder.fromXdr ? TransactionBuilder.fromXdr(b64, net) : TransactionBuilder.fromXDR(b64, net));
const opFromObj = (o) => (Operation.fromXdrObject ? Operation.fromXdrObject(o) : Operation.fromXDRObject(o));
const memoFromObj = (o) => (Memo.fromXdrObject ? Memo.fromXdrObject(o) : Memo.fromXDRObject(o));
const memoToObj = (m) => (m.toXdrObject ? m.toXdrObject() : m.toXDRObject());
const envOf = (tx) => tx.toEnvelope();
const b = (h) => Buffer.from(h, "hex");
const muxIdOf = (M) => BigInt("0x" + hex(StrKey.decodeMed25519PublicKey(M)).slice(64)).toString();
const keyStr = (sv) => {
  const t = arm(sv).replace(/^scv/, "").toLowerCase();
  let v = uval(sv);
  if (t === "bytes") v = hex(v.toBytes ? v.toBytes() : v);
  else v = v && v.toString ? v.toString() : String(v);
  return `${t}:${v}`;
};
const mkKey = (spec) => {
  const [t, v] = spec.split(":");
  if (t === "u32") return xdr.ScVal.scvU32(Number(v));
  if (t === "bytes") return xdr.ScVal.scvBytes(new Uint8Array(b(v))); // plain Uint8Array: the v17 public byte type (a Buffer hides the #1766 bug)
  if (t === "symbol") return xdr.ScVal.scvSymbol(v);
  if (t === "string") return xdr.ScVal.scvString(v);
};
const idInput = (p) => (p.kind === "number" ? Number(p.value) : p.value);

const decoders = { G: "decodeEd25519PublicKey", M: "decodeMed25519PublicKey", S: "decodeEd25519SecretSeed", T: "decodePreAuthTx",
  X: "decodeSha256Hash", P: "decodeSignedPayload", C: "decodeContract", L: "decodeLiquidityPool", B: "decodeClaimableBalance", W: "decodeMuxedContract" };

const NA = (why) => { const e = new Error(why); e.na = true; throw e; };

function run(v) {
  const p = v.params;
  const g = v.group;
  if (g === 1 && v.id !== "1c") {
    const A = new Asset(p.code, p.a), B = new Asset(p.code, p.b);
    new LiquidityPoolAsset(A, B, LiquidityPoolFeeV18);
    return hex(getLiquidityPoolId("constant_product", { assetA: A, assetB: B, fee: LiquidityPoolFeeV18 }));
  }
  if (v.id === "1c") {
    const tx = txFrom(b(v.hex).toString("base64"), p.network);
    const lp = tx.operations[2].line;
    return `hash=${hex(tx.hash())} pool=${hex(getLiquidityPoolId("constant_product", lp.getLiquidityPoolParameters()))}`;
  }
  if (g === 2 && v.id.startsWith("2m")) {
    const m = new MuxedAccount(new Account(p.g, "0"), idInput(p));
    return muxIdOf(m.accountId());
  }
  if (g === 2) {
    const op = Operation.manageSellOffer({ selling: Asset.native(), buying: new Asset("USD", p.g), amount: "1", price: "1", offerId: idInput(p) });
    return String(opFromObj(op).offerId);
  }
  if (g === 3 || v.id === "6d2") {
    const raw = v.id === "6d2" ? "skipped" : toX(fromX(xdr.TransactionEnvelope, b(v.hex))) === v.hex; // 6d2: high-level parser only
    const tx = txFrom(b(v.hex).toString("base64"), p.network);
    const sdk = toX(envOf(tx)) === v.hex;
    return `roundtrip=${raw === true && sdk} src_id=${muxIdOf(tx.source)} offer=${tx.operations[1].offerId}` + (raw === true && sdk ? "" : ` [raw=${raw} sdk=${sdk}]`);
  }
  if (g === 4) {
    const n = scValToNative(fromX(xdr.ScVal, b(v.hex)));
    const cnt = n instanceof Map ? n.size : Object.keys(n).length;
    return { got: `entries=${cnt}`, detail: JSON.stringify(n instanceof Map ? [...n] : n) };
  }
  if (g === 5) {
    let m;
    if (v.id === "5a") m = nativeToScVal({ 10: 1, 9: 2 }, { type: { 10: ["u32", "u32"], 9: ["u32", "u32"] } });
    else m = scvSortedMap(p.keys.map((k) => new xdr.ScMapEntry({ key: mkKey(k), val: xdr.ScVal.scvVoid() })));
    return uval(m).map((e) => keyStr(f(e, "key"))).join(",");
  }
  if (g === 6 || g === 8) {
    const T = xdr[p.type];
    const val = fromX(T, b(v.hex));
    if (g === 8) return "decoded";
    return toX(val);
  }
  if (g === 7) {
    if (v.id === "7a") {
      const m = memoFromObj(fromX(xdr.Memo, b(v.hex)));
      const back = toX(memoToObj(Memo.text(m.value)));
      return { got: back, detail: `native=${JSON.stringify(m.value)} (${typeof m.value})` };
    }
    if (v.id === "7b") {
      const o = opFromObj(fromX(xdr.Operation, b(v.hex)));
      const back = toX(Operation.manageData({ name: o.name, value: o.value }));
      return { got: back, detail: `value=${o.value && hex(o.value)} (${o.value?.constructor?.name})` };
    }
    const sv = fromX(xdr.ScVal, b(v.hex));
    const n = scValToNative(sv);
    const back = toX(nativeToScVal(n, { type: v.id === "7c" ? "string" : "symbol" }));
    return { got: back, detail: `native=${typeof n === "string" ? JSON.stringify(n) : n?.constructor?.name + ":" + hex(n)}` };
  }
  if (g === 9) {
    if (v.id === "9E1") {
      if (!StrKey.encodeMuxedContract) NA("no encodeMuxedContract in this version");
      return StrKey.encodeMuxedContract(Buffer.concat([b(p.contract), b(BigInt(p.id).toString(16).padStart(16, "0"))]));
    }
    if (v.id === "9E2") return Address.fromScAddress(fromX(xdr.ScAddress, b(v.hex))).toString();
    if (v.id === "9E3") return StrKey.encodeSignedPayload(Buffer.concat([b(p.key), b("00000000")]));
    if (v.id === "9E4") return encodeMuxedAccountToAddress(fromX(xdr.MuxedAccount, b(v.hex)));
    const c = String.fromCharCode(p.s.charCodeAt(0) & 0xff).toUpperCase();
    const fn = StrKey[decoders[c]];
    if (!fn) NA(`no StrKey.${decoders[c]} in this version`);
    return hex(fn.call(StrKey, p.s));
  }
  if (g === 10) {
    const raw = readFileSync(resolve(vecDir, "..", p.file));
    const batch = fromX(xdr.LedgerCloseMetaBatch, raw);
    const lcm = (batch.ledgerCloseMetas !== undefined ? batch.ledgerCloseMetas : f(batch, "ledgerCloseMeta"))[0];
    const hdr = f(f(uval(lcm), "ledgerHeader"), "header");
    const ext = f(f(hdr, "scpValue"), "ext");
    return `lcm=${arm(lcm)} seq=${f(hdr, "ledgerSeq")} proto=${f(hdr, "ledgerVersion")} sv_ext=${arm(ext)} roundtrip=${toX(batch) === raw.toString("hex")}`;
  }
  NA("not implemented");
}

function judge(v, accepted, got) {
  let acc = v.expect.accept;
  if (acc === "p30") acc = P30;
  if (!accepted) return "reject";
  if (acc === false) return "wrong";
  if (v.expect.value !== undefined && got !== v.expect.value) return "wrong";
  return "ok";
}

const ids = process.argv.slice(4);
for (const v of vectors) {
  if (ids.length && !ids.includes(v.id)) continue;
  let line;
  try {
    let r = run(v);
    let detail = "";
    if (r && typeof r === "object") { detail = r.detail; r = r.got; }
    const outcome = judge(v, true, r);
    line = { outcome, got: r, detail: detail || (outcome === "wrong" ? `got ${String(r).slice(0, 120)}` : "") };
  } catch (e) {
    if (e.na) line = { outcome: "n/a", detail: e.message };
    else {
      const crash = e instanceof RangeError && /call stack/.test(e.message);
      line = { outcome: crash ? "crash" : "reject", detail: `${e.constructor.name}: ${String(e.message).slice(0, 200)}` };
    }
  }
  console.log(JSON.stringify({ vector: v.id, sdk: "js", version: VERSION, p30: P30, ...line }));
}
