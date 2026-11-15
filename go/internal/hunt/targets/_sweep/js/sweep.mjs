// JS sweep: every check of the kit's js target (@stellar/stellar-sdk) over a list of ledgers.
// usage: node sweep.mjs SDK_DIR LIST_TSV TXS_DIR OUT_DIR
//   SDK_DIR: a directory whose node_modules holds @stellar/stellar-sdk (the kit installs one per version).
//   LIST_TSV rows: seq<TAB>path of the zstd LedgerCloseMetaBatch object.
//   TXS_DIR/<seq>.jsonl.zst: the reference cut of each ledger (one row per transaction in apply order: seq, idx,
//   hash, env, pair, meta as base64; optionally env_json, pair_json, meta_json in the Rust reference form).
//   env SWEEP_PASSPHRASE: network passphrase (default pubnet).
// Writes OUT_DIR/rows.jsonl (one JSON row per failure: check, class, ledger, tx, hash, op, op_type, detail) and
// OUT_DIR/stats.json (version, ledgers, txs, tested count per check).
// Checks: codec (batch decode + re-encode), tx-hash, envelope-encode (toEnvelope bytes), tx-parse (fromXDR),
// op-rebuild (Operation[type](record)), tx-rebuild (cloneFrom(parsed).build()), json-roundtrip
// (fromJson(toJson)), json-reference (toJson against the reference form, when the cut carries it), op-decode
// (Operation.fromXDRObject), scval-native (scValToNative on event and return values), feebump-rebuild
// (buildFeeBumpTransaction on the parsed inner transaction), cb-id / pool-id / contract-id (computed helpers against
// the ids the result and meta state, from the cut's truth), auth-tree (buildInvocationTree on every authorization
// entry of the envelope), events-humanize (humanizeEvents on the meta's contract and diagnostic events).
import fs from "node:fs";
import zlib from "node:zlib";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [sdkDir, listTsv, txsDir, outDir] = process.argv.slice(2);
const sdkPkg = path.join(sdkDir, "node_modules/@stellar/stellar-sdk");
const sdk = await import(pathToFileURL(path.join(sdkPkg, "lib/esm/index.js")).href).catch(async () =>
  import(pathToFileURL(path.join(sdkPkg, "lib/index.js")).href));
const version = JSON.parse(fs.readFileSync(path.join(sdkPkg, "package.json"))).version;
const { xdr, TransactionBuilder, Operation, scValToNative, Asset, getLiquidityPoolId, buildInvocationTree, humanizeEvents } = sdk;
const PASS = process.env.SWEEP_PASSPHRASE || "Public Global Stellar Network ; September 2015";
fs.mkdirSync(outDir, { recursive: true });
const out = fs.openSync(`${outDir}/rows.jsonl`, "w");
const clean = (s) => String(s).replace(/[\t\r\n]+/g, " ").slice(0, 400);
const strip = (s) => String(s)
  .replace(/"[^"]*"/g, "<s>").replace(/'[^']*'/g, "<s>")
  .replace(/\b[GCMBTXP][A-Z2-7]{55,}\b/g, "<key>")
  .replace(/\b[0-9a-fA-F]{16,}\b/g, "<hex>")
  .replace(/-?\d+(\.\d+)?n?/g, "N")
  .replace(/[\t\r\n]+/g, " ").slice(0, 140);
const CHECKS = ["codec", "tx-hash", "envelope-encode", "tx-parse", "op-rebuild", "tx-rebuild", "json-roundtrip", "json-reference", "op-decode", "scval-native", "load", "feebump-rebuild", "cb-id", "pool-id", "contract-id", "auth-tree", "events-humanize"];
const stats = { target: "js", version, ledgers: 0, txs: 0, tested: Object.fromEntries(CHECKS.map((c) => [c, 0])) };
let buf = [];
const fail = (check, seq, idx, hash, op, opType, cls, detail) => {
  buf.push(JSON.stringify({ check, class: cls, ledger: Number(seq), tx: idx === "" ? -1 : Number(idx), hash, op: op === "" ? "" : String(op), op_type: opType, detail: clean(detail) }));
};
const tested = (c, n = 1) => { stats.tested[c] += n; };
const hex = (u) => Buffer.from(u).toString("hex");
const b64 = (u) => Buffer.from(u).toString("base64");

function diff(a, b, p) {
  if (a === b) return null;
  const ta = a === null ? "null" : Array.isArray(a) ? "array" : typeof a;
  const tb = b === null ? "null" : Array.isArray(b) ? "array" : typeof b;
  if (ta !== tb) return [p, `type:${ta}>${tb}`, `type ${ta} vs ${tb}: ${show(a)} vs ${show(b)}`];
  if (ta === "array") {
    if (a.length !== b.length) return [p, "array-length", `array length ${a.length} vs ${b.length}`];
    for (let i = 0; i < a.length; i++) { const d = diff(a[i], b[i], p + "[*]"); if (d) return d; }
    return null;
  }
  if (ta === "object") {
    const ka = Object.keys(a), kb = Object.keys(b);
    for (const k of ka) if (!(k in b)) return [p + "." + k, "key-only-in-sdk", `key only in sdk json (sdk keys ${ka.join(",")} | ref keys ${kb.join(",")})`];
    for (const k of kb) if (!(k in a)) return [p + "." + k, "key-only-in-ref", `key only in ref json (sdk keys ${ka.join(",")} | ref keys ${kb.join(",")})`];
    for (const k of ka) { const d = diff(a[k], b[k], p + "." + k); if (d) return d; }
    return null;
  }
  return [p, "value", `value ${show(a)} vs ${show(b)}`];
}
const show = (v) => { try { return (typeof v === "bigint" ? v + "n" : JSON.stringify(v) ?? String(v)).slice(0, 80); } catch { return String(v).slice(0, 80); } };
const pathCls = (d) => `${d[0].replace(/\.v\d+\b/g, ".vN")}:${d[1]}`;

function scvalsOfMeta(meta) {
  const vals = [];
  const ev = (e) => { const b = e?.body?.value; if (b) { for (const t of b.topics ?? []) vals.push(t); if (b.data) vals.push(b.data); } };
  const m = meta.value;
  if (!m || Array.isArray(m)) return vals;
  const sm = m.sorobanMeta;
  if (sm) {
    for (const e of sm.events ?? []) ev(e);
    if (sm.returnValue) vals.push(sm.returnValue);
    for (const d of sm.diagnosticEvents ?? []) ev(d.event);
  }
  for (const e of m.events ?? []) ev(e.event ?? e);
  for (const d of m.diagnosticEvents ?? []) ev(d.event);
  if (meta.type === "v4" || meta.type === 4) for (const o of m.operations ?? []) for (const e of o.events ?? []) ev(e);
  return vals;
}
const rawOps = (env) => { const v = env.value; if (v.tx.operations) return v.tx.operations; return v.tx.innerTx.value.tx.operations; };
const opTypeOf = (op) => { try { return String(op.body.type); } catch { return "?"; } };
function safeType(v) { try { return String(v.type); } catch { return "?"; } }
function describeOpDiff(a, b) {
  try { const ja = a.toJson ? a.toJson() : null, jb = b.toJson ? b.toJson() : null; if (ja && jb) { const d = diff(ja, jb, "Operation"); if (d) return d; } } catch {}
  return null;
}

function resourceFeeOf(env) {
  try { const v = env.value; const t = v.tx.innerTx ? v.tx.innerTx.value.tx : v.tx; const ext = t.ext; if (ext && ext.type !== 0 && ext.value && ext.value.resourceFee !== undefined) return BigInt(ext.value.resourceFee.toString()); } catch {}
  return 0n;
}
function helperChecks(tx, inner, env, r, seq, idx, hash, types) {
  if (tx.innerTransaction && env) {
    tested("feebump-rebuild");
    try {
      const n = BigInt(inner.operations.length), rf = resourceFeeOf(env), oi = BigInt(tx.fee) - rf;
      const tags = oi % (n + 1n) ? ["feebump.fee:not-multiple"] : [];
      const nb = TransactionBuilder.buildFeeBumpTransaction(tx.feeSource, (oi / (n + 1n)).toString(), inner, PASS);
      const a = nb.toEnvelope().value.tx, b = env.value.tx;
      if (b64(a.toXdr()) !== b64(b.toXdr())) {
        const d = diff(a.toJson(), b.toJson(), "FeeBumpTransaction");
        fail("feebump-rebuild", seq, idx, hash, "", types, "rebuild-differs:" + (d ? pathCls(d) : "bytes") + (tags.length ? ";" + tags.join(";") : ""), d ? `buildFeeBumpTransaction differs: ${d[0]} :: ${d[2]}` : "buildFeeBumpTransaction bytes differ");
      }
    } catch (e) { fail("feebump-rebuild", seq, idx, hash, "", types, "rebuild-throws:" + strip(e?.message), `buildFeeBumpTransaction throws: ${e?.message}`); }
  }
  const tr = r.truth || {};
  for (const [i, want] of Object.entries(tr.cb_ids || {})) {
    tested("cb-id");
    try { const got = inner.getClaimableBalanceId(Number(i)); if (got.toLowerCase() !== want.toLowerCase()) fail("cb-id", seq, idx, hash, i, "createClaimableBalance", "id-differs", `getClaimableBalanceId ${got} ledger ${want}`); }
    catch (e) { fail("cb-id", seq, idx, hash, i, "createClaimableBalance", "throws:" + strip(e?.message), `getClaimableBalanceId throws: ${e?.message}`); }
  }
  for (const [i, want] of Object.entries(tr.pool_ids || {})) {
    tested("pool-id");
    try {
      const line = inner.operations[Number(i)].line;
      const got = Buffer.from(getLiquidityPoolId("constant_product", line.getLiquidityPoolParameters())).toString("hex");
      if (got !== want.toLowerCase()) fail("pool-id", seq, idx, hash, i, "changeTrust", "id-differs", `getLiquidityPoolId ${got} ledger ${want}`);
    } catch (e) { fail("pool-id", seq, idx, hash, i, "changeTrust", "throws:" + strip(e?.message), `pool id throws: ${e?.message}`); }
  }
  for (const [i, want] of Object.entries(tr.contract_ids || {})) {
    let pre;
    try { pre = inner.operations[Number(i)].func.value.contractIdPreimage; } catch { continue; }
    if (!pre || !String(pre.type).includes("Asset")) continue;
    tested("contract-id");
    try { const got = Asset.fromOperation(pre.value).contractId(PASS); if (got !== want) fail("contract-id", seq, idx, hash, i, "invokeHostFunction", "asset-contract-id-differs", `Asset.contractId ${got} ledger ${want}`); }
    catch (e) { fail("contract-id", seq, idx, hash, i, "invokeHostFunction", "throws:" + strip(e?.message), `Asset.contractId throws: ${e?.message}`); }
  }
}

const list = fs.readFileSync(listTsv, "utf8").split("\n").filter(Boolean).map((l) => l.split("\t"));
for (const [seq0, file] of list) {
  if (!/^\d+$/.test(seq0)) continue;
  let rows;
  tested("load");
  try { rows = zlib.zstdDecompressSync(fs.readFileSync(`${txsDir}/${seq0}.jsonl.zst`)).toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); }
  catch (e) { fail("load", seq0, "", "", "", "", "no-reference-rows", e.message); continue; }
  const raw = zlib.zstdDecompressSync(fs.readFileSync(file));
  tested("codec");
  try {
    const b = xdr.LedgerCloseMetaBatch.fromXdr(raw);
    stats.ledgers += b.ledgerCloseMetas.length;
    if (Buffer.compare(Buffer.from(b.toXdr()), raw) !== 0) fail("codec", seq0, "", "", "", "", "re-encode-differs", "re-encode differs");
  } catch (e) { fail("codec", seq0, "", "", "", "", "exception:" + strip(e.message), "exception: " + e.message); }
  for (const r of rows) {
    stats.txs++;
    const { seq, idx, hash } = r;
    let env = null, ops = [], types = "?";
    try { env = xdr.TransactionEnvelope.fromXdr(r.env, "base64"); ops = rawOps(env); types = [...new Set(ops.map(opTypeOf))].join("+"); } catch (e) { fail("codec", seq, idx, hash, "", "", "envelope-decode:" + strip(e.message), "TransactionEnvelope.fromXDR: " + e.message); }
    let tx = null;
    tested("tx-parse");
    try { tx = TransactionBuilder.fromXDR(r.env, PASS); } catch (e) { fail("tx-parse", seq, idx, hash, "", types, `${e?.constructor?.name}:${strip(e?.message)}`, `${e?.constructor?.name}: ${e?.message}`); }
    if (tx) {
      tested("tx-hash");
      try { const h = hex(tx.hash()); if (h !== hash) fail("tx-hash", seq, idx, hash, "", types, "hash-differs", `sdk hash ${h}`); } catch (e) { fail("tx-hash", seq, idx, hash, "", types, "exception:" + strip(e.message), "exception: " + e.message); }
      tested("envelope-encode");
      try { const o = tx.toEnvelope().toXdr("base64"); if (o !== r.env) fail("envelope-encode", seq, idx, hash, "", types, "toEnvelope-differs", "toEnvelope().toXdr() differs from input"); } catch (e) { fail("envelope-encode", seq, idx, hash, "", types, "exception:" + strip(e.message), "exception: " + e.message); }
      const inner = tx.innerTransaction ?? tx;
      const recs = inner.operations;
      if (recs.length !== ops.length) { tested("op-rebuild"); fail("op-rebuild", seq, idx, hash, "", types, "op-count-differs", `parsed ${recs.length} ops, envelope has ${ops.length}`); }
      else recs.forEach((rec, i) => {
        tested("op-rebuild");
        try {
          const rebuilt = Operation[rec.type](rec);
          if (b64(rebuilt.toXdr()) !== b64(ops[i].toXdr())) {
            const d = describeOpDiff(rebuilt, ops[i]);
            fail("op-rebuild", seq, idx, hash, i, rec.type, d ? "op-differs:" + pathCls(d) : "bytes-differ", d ? `rebuilt op differs: ${d[0]} :: ${d[2]}` : "rebuilt op bytes differ");
          }
        } catch (e) { fail("op-rebuild", seq, idx, hash, i, rec.type, "throws:" + strip(e?.message), `exception rebuilding: ${e?.message}`); }
      });
      tested("tx-rebuild");
      try {
        const re = TransactionBuilder.cloneFrom(inner).build();
        if (hex(re.hash()) !== hex(inner.hash())) {
          let d = null;
          try { d = diff(re.toEnvelope().value.tx.toJson(), xdr.TransactionEnvelope.fromXdr(inner.toEnvelope().toXdr()).value.tx.toJson(), "Transaction"); } catch {}
          fail("tx-rebuild", seq, idx, hash, "", types, d ? "rebuild-differs:" + pathCls(d) : "rebuild-differs", d ? `cloneFrom(parsed).build() has another hash: ${d[0]} :: ${d[2]}` : "cloneFrom(parsed).build() has another hash");
        }
      } catch (e) { fail("tx-rebuild", seq, idx, hash, "", types, "rebuild-throws:" + strip(e?.message), `cloneFrom(parsed).build() throws: ${e?.message}`); }
      helperChecks(tx, inner, env, r, seq, idx, hash, types);
    }
    for (const [name, T, b, ref] of [["TransactionEnvelope", xdr.TransactionEnvelope, r.env, r.env_json], ["TransactionResultPair", xdr.TransactionResultPair, r.pair, r.pair_json], ["TransactionMeta", xdr.TransactionMeta, r.meta, r.meta_json]]) {
      if (typeof T.fromJson !== "function") continue;
      let j;
      tested("json-roundtrip");
      try {
        j = T.fromXdr(b, "base64").toJson();
        if (T.fromJson(j).toXdr("base64") !== b) fail("json-roundtrip", seq, idx, hash, "", types, `${name}:reencode-differs`, `${name}: fromJson(toJson(x)) re-encodes differently`);
      } catch (e) { fail("json-roundtrip", seq, idx, hash, "", types, `${name}:exception:${strip(e?.message)}`, `${name}: exception: ${e?.message}`); }
      if (j !== undefined && ref !== undefined && ref !== null) {
        tested("json-reference");
        const d = diff(j, ref, name);
        if (d) fail("json-reference", seq, idx, hash, "", types, pathCls(d), `${d[0]} :: ${d[2]}`);
      }
    }
    ops.forEach((op, i) => { tested("op-decode"); try { Operation.fromXDRObject(op); } catch (e) { fail("op-decode", seq, idx, hash, i, opTypeOf(op), `${e?.constructor?.name}:${strip(e?.message)}`, `${e?.constructor?.name}: ${e?.message}`); } });
    ops.forEach((op, i) => {
      if (opTypeOf(op) !== "invokeHostFunction") return;
      for (const a of op.body.value.auth ?? []) {
        tested("auth-tree");
        try { buildInvocationTree(a.rootInvocation); } catch (e) { fail("auth-tree", seq, idx, hash, i, "invokeHostFunction", `${e?.constructor?.name}:${strip(e?.message)}`, `buildInvocationTree: ${e?.constructor?.name}: ${e?.message}`); }
      }
    });
    try {
      const m = xdr.TransactionMeta.fromXdr(r.meta, "base64").value;
      const lists = [];
      if (m && !Array.isArray(m)) {
        if (m.sorobanMeta?.events?.length) lists.push(["contract", m.sorobanMeta.events]);
        if (m.sorobanMeta?.diagnosticEvents?.length) lists.push(["diagnostic", m.sorobanMeta.diagnosticEvents]);
        if (m.diagnosticEvents?.length) lists.push(["diagnostic", m.diagnosticEvents]);
        for (const o of m.operations ?? []) if (o.events?.length) lists.push(["contract", o.events]);
      }
      for (const [kind, l] of lists) {
        tested("events-humanize");
        try { humanizeEvents(l); } catch (e) { fail("events-humanize", seq, idx, hash, "", types, `${kind}:${e?.constructor?.name}:${strip(e?.message)}`, `humanizeEvents(${kind}): ${e?.constructor?.name}: ${e?.message}`); }
      }
    } catch {}
    let vals = [];
    try { vals = scvalsOfMeta(xdr.TransactionMeta.fromXdr(r.meta, "base64")); } catch (e) { tested("scval-native"); fail("scval-native", seq, idx, hash, "", types, "meta-walk:" + strip(e.message), "meta decode/walk: " + e.message); }
    for (const v of vals) { tested("scval-native"); try { scValToNative(v); } catch (e) { fail("scval-native", seq, idx, hash, "", types, `${safeType(v)}:${e?.constructor?.name}:${strip(e?.message)}`, `scValToNative(${safeType(v)}): ${e?.constructor?.name}: ${e?.message}`); } }
  }
  if (buf.length) { fs.writeSync(out, buf.join("\n") + "\n"); buf = []; }
}
fs.closeSync(out);
fs.writeFileSync(`${outDir}/stats.json`, JSON.stringify(stats));
