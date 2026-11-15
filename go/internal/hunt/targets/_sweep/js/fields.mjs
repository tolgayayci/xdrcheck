// Fields mode (xcheck): for each transaction of the reference cut, the fields @stellar/stellar-sdk computes.
// usage: node fields.mjs SDK_DIR LIST_TSV TXS_DIR OUT.jsonl   (env SWEEP_PASSPHRASE)
import fs from "node:fs";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [sdkDir, listTsv, txsDir, outPath] = process.argv.slice(2);
const sdkPkg = path.join(sdkDir, "node_modules/@stellar/stellar-sdk");
const sdk = await import(pathToFileURL(path.join(sdkPkg, "lib/esm/index.js")).href).catch(async () =>
  import(pathToFileURL(path.join(sdkPkg, "lib/index.js")).href));
const { TransactionBuilder, xdr, scValToNative, StrKey, Asset, getLiquidityPoolId } = sdk;
const PASS = process.env.SWEEP_PASSPHRASE || "Public Global Stellar Network ; September 2015";
const out = fs.openSync(outPath, "w");
const asset = (a) => {
  if (a === undefined || a === null) return undefined;
  if (typeof a.getLiquidityPoolParameters === "function") return "pool:" + Buffer.from(getLiquidityPoolId("constant_product", a.getLiquidityPoolParameters())).toString("hex");
  if (typeof a.isNative === "function" && a.isNative()) return "native";
  if (a.liquidityPoolId) return "pool:" + a.liquidityPoolId;
  if (typeof a.getLiquidityPoolId === "function") return "pool:" + a.getLiquidityPoolId();
  if (typeof a.getCode === "function") return a.getCode() + ":" + a.getIssuer();
  return String(a);
};
const memo = (m) => {
  const t = m?.type ?? "none";
  if (t === "none") return { type: "none" };
  let v = m.value;
  if (t === "text") v = typeof v === "string" ? v : Buffer.from(v).toString("utf8");
  else if (t === "hash" || t === "return") v = Buffer.from(v).toString("hex");
  else v = String(v);
  return { type: t, value: v };
};
const u8cmp = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
const byKey = (a, b) => u8cmp(JSON.stringify(a[0]), JSON.stringify(b[0]));
// canonical native form of a contract value (xcheck compares it with python's to_native)
const canon = (v) => {
  if (v === null || v === undefined) return null;
  if (typeof v === "bigint" || typeof v === "number") return "n:" + v.toString();
  if (typeof v === "boolean") return v;
  if (typeof v === "string") return "s:" + v;
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) return "b:" + Buffer.from(v).toString("hex");
  if (Array.isArray(v)) return v.map(canon);
  if (v instanceof Map) return [...v.entries()].map(([k, x]) => [canon(k), canon(x)]).sort(byKey);
  if (typeof v.toString === "function" && v.constructor && v.constructor.name === "Address") return "s:" + v.toString();
  if (typeof v === "object") return Object.entries(v).map(([k, x]) => ["s:" + k, canon(x)]).sort(byKey);
  return "?:" + String(v);
};
function eventVals(meta) {
  const out = [];
  const ev = (e) => { const b = e?.body?.value; if (b) { for (const t of b.topics ?? []) out.push(t); if (b.data) out.push(b.data); } };
  const m = meta.value;
  if (!m || Array.isArray(m)) return out;
  const sm = m.sorobanMeta;
  if (sm) { for (const e of sm.events ?? []) ev(e); if (sm.returnValue) out.push(sm.returnValue); for (const d of sm.diagnosticEvents ?? []) ev(d.event); }
  for (const e of m.events ?? []) ev(e.event ?? e);
  for (const d of m.diagnosticEvents ?? []) ev(d.event);
  for (const o of m.operations ?? []) for (const e of o.events ?? []) ev(e);
  return out;
}
const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v;
// sha256 (12 hex) of the canonical SEP-51 JSON (sorted keys, compact) of an XDR value; xcheck compares it across SDKs
const jsonDigest = (T, b64) => { try { return createHash("sha256").update(JSON.stringify(sortKeys(T.fromXdr(b64, "base64").toJson()))).digest("hex").slice(0, 12); } catch (e) { return "error: " + e?.message; } };
const str = (v) => (v === undefined || v === null ? undefined : typeof v === "object" && "n" in v ? undefined : String(v));
for (const line of fs.readFileSync(listTsv, "utf8").split("\n")) {
  const seq = line.split("\t")[0];
  if (!/^\d+$/.test(seq)) continue;
  const rows = zlib.zstdDecompressSync(fs.readFileSync(`${txsDir}/${seq}.jsonl.zst`)).toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  for (const r of rows) {
    const row = { ledger: r.seq, tx: r.idx };
    try {
      const t = TransactionBuilder.fromXDR(r.env, PASS);
      row.hash = Buffer.from(t.hash()).toString("hex");
      let tx = t;
      if (t.innerTransaction) { row.fee_source = t.feeSource; row.fee = String(t.fee); tx = t.innerTransaction; row.inner_hash = Buffer.from(tx.hash()).toString("hex"); }
      else row.fee = String(tx.fee);
      row.source = tx.source;
      row.op_count = tx.operations.length;
      row.seq = String(tx.sequence);
      if (tx.ledgerBounds) row.ledger_bounds = `${tx.ledgerBounds.minLedger}-${tx.ledgerBounds.maxLedger}`;
      if (tx.minAccountSequence !== undefined && tx.minAccountSequence !== null) row.min_seq_num = String(tx.minAccountSequence);
      if (tx.minAccountSequenceAge !== undefined && tx.minAccountSequenceAge !== null) row.min_seq_age = String(tx.minAccountSequenceAge);
      if (tx.minAccountSequenceLedgerGap !== undefined && tx.minAccountSequenceLedgerGap !== null) row.min_seq_ledger_gap = String(tx.minAccountSequenceLedgerGap);
      if (tx.extraSigners && tx.extraSigners.length) row.extra_signers = tx.extraSigners.map((k) => typeof k === "string" ? k : sdk.SignerKey.encodeSignerKey(k));
      row.memo = memo(tx.memo);
      row.time_bounds = tx.timeBounds && (String(tx.timeBounds.minTime) !== "0" || String(tx.timeBounds.maxTime) !== "0")
        ? { min: String(tx.timeBounds.minTime), max: String(tx.timeBounds.maxTime) } : null;
      row.operations = tx.operations.map((o, i) => {
        const x = { type: o.type };
        if (o.type === "manageBuyOffer" && o.buyAmount !== undefined) x.amount = String(o.buyAmount);
        if (o.type === "createAccount") x.amount = String(o.startingBalance);
        for (const k of ["offerId", "bumpTo", "homeDomain", "trustor", "balanceId", "liquidityPoolId", "masterWeight", "lowThreshold", "medThreshold", "highThreshold", "setFlags", "clearFlags", "inflationDest", "from", "sponsoredId", "name"]) if (o[k] !== undefined && o[k] !== null) x[k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase())] = String(o[k]);
        if (o.type === "manageData" && o.value !== undefined) x.data_value = o.value === null ? null : Buffer.from(o.value).toString("hex");
        if (o.signer && o.type === "setOptions") { const sg = o.signer; x.signer_weight = String(sg.weight); x.signer_key = sg.ed25519PublicKey ?? (sg.sha256Hash ? StrKey.encodeSha256Hash(Buffer.from(sg.sha256Hash)) : sg.preAuthTx ? StrKey.encodePreAuthTx(Buffer.from(sg.preAuthTx)) : sg.ed25519SignedPayload ?? undefined); }
        if (o.type === "createClaimableBalance") { try { x.cb_id = tx.getClaimableBalanceId(i); } catch (e) { x.cb_id = "error: " + e.message; } }
        const a = o.asset ?? o.line;
        if (a && typeof a.contractId === "function") { try { x.asset_cid = a.contractId(PASS); } catch (e) { x.asset_cid = "error: " + e.message; } }
        if (o.source) x.source = o.source;
        for (const k of ["destination", "amount", "limit", "sendAmount", "destMin", "sendMax", "destAmount", "price"]) if (o[k] !== undefined) x[k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase())] = typeof o[k] === "object" ? `${o[k].n}/${o[k].d}` : String(o[k]);
        for (const k of ["asset", "selling", "buying", "sendAsset", "destAsset", "line"]) if (o[k] !== undefined) x[k === "line" ? "asset" : k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase())] = asset(o[k]);
        return x;
      });
      if (typeof xdr.TransactionEnvelope.prototype.toJson === "function") row.json = { env: jsonDigest(xdr.TransactionEnvelope, r.env), pair: jsonDigest(xdr.TransactionResultPair, r.pair), meta: jsonDigest(xdr.TransactionMeta, r.meta) };
      try {
        const fc = xdr.TransactionResultPair.fromXdr(r.pair, "base64").result.feeCharged; row.fee_charged = String(fc);
      } catch (e) { row.fee_charged = "error: " + e.message; }
      try {
        const vals = eventVals(xdr.TransactionMeta.fromXdr(r.meta, "base64"));
        row.scv_count = vals.length;
        // keyed by the value's own XDR bytes (sha256, 12 hex), so both sides compare the same values whatever order
        row.scv = {};
        for (const v of vals) {
          const k = createHash("sha256").update(Buffer.from(v.toXdr())).digest("hex").slice(0, 12);
          try { row.scv[k] = JSON.stringify(canon(scValToNative(v))); } catch (e) { row.scv[k] = "error: " + e?.constructor?.name; }
        }
      } catch (e) { row.scv_count = "error: " + e.message; }
    } catch (e) { row.error = `${e?.constructor?.name}: ${e?.message}`; }
    fs.writeSync(out, JSON.stringify(row) + "\n");
  }
}
fs.closeSync(out);
