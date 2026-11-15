// xdrcheck-driver-js (adapter js-v16): the conformance driver for @stellar/stellar-sdk's v16 API generation (the LTS
// line, @stellar/js-xdr 4). One source serves every pinned 16.x version; each version directory under
// drivers/js16/ holds its own locked install and runs this file with `--install <that directory>`.
//
// It speaks the driver protocol xcc.driver/1 (corpus/schema/driver-protocol.schema.json; contract in
// drivers/README.md) exactly as the v17 driver (drivers/js/src/driver.mjs) does, and reports the same facts at
// every level; only the SDK calls differ. It reports what the SDK did, never compares with expected values and
// never reads the manifest.
//
// Levels (all five are declared):
//   L0  xdr.<Type>.fromXDR(bytes) (strict: rejects trailing bytes), re-encode with toXDR; validateXDR is listed
//       under lenient_entry_points if it ever disagrees. js-xdr 4 has no separate lenient decoder.
//   L1  TransactionEnvelope: TransactionBuilder.fromXDR(base64, passphrase); LedgerCloseMeta(Batch): every
//       envelope of the transaction set, in set order, through TransactionBuilder.fromXDR; Memo, Operation,
//       Asset, ScAddress, MuxedAccount, SignerKey through their object classes (fromXDRObject / toXDRObject)
//   L2  the neutral value projection of the decoded value (project.mjs), whole or at the requested pointers
//   L3  ScVal through scValToNative and back through nativeToScVal; Memo through Memo.fromXDRObject
//   L4  api operations (api.mjs) and strkey texts
//
// v16 against v17, as the driver sees it: decoded values are js-xdr 4 objects (unions through switch() / arm() /
// value(), struct fields through accessor methods, 64-bit values as Hyper / UnsignedHyper, bytes as Buffer); the
// reader's default depth budget is 200 units, not 1500; scValToNative returns a decoded string for a non-UTF-8
// ScString / ScSymbol where v17 returns bytes; StrKey has no muxed-contract (W…) codec.
//
// Byte arguments reach the SDK as plain Uint8Array, never Buffer; 64-bit values are BigInt or decimal strings.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { loadSDK } from "./sdk.mjs";
import { beyondKnown, schemaProtocol } from "./reach.mjs";
import { project, pinpoint, enumName } from "./project.mjs";
import { decodeCode, objectCodeOf, isFault, faultCode, reason, trim, locate } from "./errors.mjs";
import { makeAPI, strkeyDecode, scalarHint, ArgError } from "./api.mjs";
import { hex, sha256, bytesEqual, fromHex, u8, toBase64, summary, nativeType } from "./util.mjs";
import { readSpec, entryFact } from "./spec.mjs";

const TAG = "xcc.driver/1";
const DRIVER = { name: "xdrcheck-driver-js", version: "0.1.0", adapter: "js-v16" };
const LEVELS = ["L0", "L1", "L2", "L3", "L4", "spec"];

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const installDir = argValue("--install") ?? process.cwd();
const { S, sdk, schema, defaultDepth, argTypes, xdrConfig, builderRules } = await loadSDK(installDir);
const { xdr } = S;
const { XdrReader, XdrWriter } = S.cereal;
const api = makeAPI(S, { argTypes, xdrConfig });

// ---- helpers -------------------------------------------------------------------------------------------------

/** Generated XDR types by name, case-insensitively (the corpus spells ScVal, the XDR files SCVal). */
const xdrTypes = new Map();
for (const [k, v] of Object.entries(xdr)) {
  if (v && typeof v.fromXDR === "function" && typeof v.read === "function" && schema.defs.has(k)) xdrTypes.set(k.toLowerCase(), k);
}
/** The SDK's own spelling of a type name, or undefined. */
function canonicalName(name) {
  return schema.defs.has(name) && xdr[name] ? name : xdrTypes.get(String(name).toLowerCase());
}
const ref = (name) => ({ kind: "ref", name });

/** Encode a value of a generated type: classes have a static toXDR; typedef'd containers are type instances. */
function encode(T, value) {
  if (typeof T === "function") return T.toXDR(value);
  const w = new XdrWriter();
  T.write(value, w);
  return w.finalize();
}


// RFC 5531 record marking: 4-byte header, high bit = last fragment, low 31 bits = fragment length.
function frame(bytes, index) {
  const frames = [];
  let off = 0;
  let cur = [];
  while (off < bytes.length) {
    if (off + 4 > bytes.length) throw new Error("record mark truncated");
    const h = new DataView(bytes.buffer, bytes.byteOffset + off, 4).getUint32(0, false);
    const len = h & 0x7fffffff;
    off += 4;
    if (off + len > bytes.length) throw new Error("record fragment truncated");
    cur.push(bytes.subarray(off, off + len));
    off += len;
    if (h & 0x80000000) {
      frames.push(cur.length === 1 ? cur[0] : Uint8Array.from(cur.flatMap((c) => [...c])));
      cur = [];
    }
  }
  if (index >= frames.length) throw new Error(`frame ${index} of ${frames.length}`);
  return frames[index];
}

function inputBytes(input) {
  let b;
  if (input.path !== undefined) b = u8(readFileSync(input.path));
  else b = fromHex(input.xdr_hex ?? "");
  if (input.framing === "record-marked") b = frame(b, input.frame_index ?? 0);
  return Uint8Array.from(b); // a plain Uint8Array of its own
}

class Outcome {
  constructor(outcome, rsn, actual) {
    this.outcome = outcome;
    this.reason = rsn;
    this.actual = actual;
  }
}
const ok = (actual) => new Outcome("ok", undefined, actual);
const na = (code, msg) => new Outcome("n_a", { code, ...(msg ? { message: msg } : {}) });

/** Decode with the strict entry point; returns {value, T, name, bytes} or an Outcome (reject / n_a). */
function decodeStrict(input) {
  const name = canonicalName(input.xdr_type);
  if (!name) return na("type_not_generated", `no generated XDR type ${input.xdr_type}`);
  const T = xdr[name];
  const bytes = inputBytes(input);
  try {
    return { T, name, bytes, value: T.fromXDR(bytes) };
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("reject", reason(decodeCode(e, () => locate(T, bytes, XdrReader)), e, `xdr.${input.xdr_type}.fromXDR`));
  }
}

// ---- L0 ------------------------------------------------------------------------------------------------------

function runL0(input) {
  const d = decodeStrict(input);
  if (d instanceof Outcome) {
    if (d.outcome === "reject") {
      const name = canonicalName(input.xdr_type);
      const lenient = lenientEntryPoints(xdr[name], name, inputBytes(input), false);
      if (lenient.length) d.actual = { lenient_entry_points: lenient };
    }
    return d;
  }
  let re;
  try {
    re = u8(encode(d.T, d.value));
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("diverge", reason("own_output_rejected", e, `xdr.${input.xdr_type}.toXDR`), { consumed_bytes: d.bytes.length });
  }
  const actual = { consumed_bytes: d.bytes.length, reencoded_sha256: sha256(re) };
  const lenient = lenientEntryPoints(d.T, d.name, d.bytes, true);
  if (lenient.length) actual.lenient_entry_points = lenient;
  if (!bytesEqual(re, d.bytes)) {
    if (re.length <= 4096) actual.reencoded_hex = hex(re);
    return new Outcome("diverge", { code: "reencode_mismatch", entry_point: `xdr.${input.xdr_type}.toXDR` }, actual);
  }
  return ok(actual);
}

// The SDK's other documented single-value decode entry points, listed only where they disagree with the strict
// one.
function lenientEntryPoints(T, name, bytes, strictAccepted) {
  const out = [];
  if (typeof T?.validateXDR !== "function") return out;
  let accepted;
  try {
    accepted = T.validateXDR(bytes) === true;
  } catch (e) {
    if (isFault(e)) throw e;
    accepted = false;
  }
  if (accepted !== strictAccepted) out.push({ entry_point: `xdr.${name}.validateXDR`, accepted });
  return out;
}

// ---- L1 ------------------------------------------------------------------------------------------------------

/** Every TransactionEnvelope below a decoded value, in schema (= transaction-set) order. */
function collectEnvelopes(v, out) {
  if (v instanceof xdr.TransactionEnvelope) out.push(v);
  else if (Array.isArray(v)) for (const x of v) collectEnvelopes(x, out);
  else if (v && typeof v === "object" && v._attributes && Array.isArray(v.constructor._fields)) {
    for (const [f] of v.constructor._fields) collectEnvelopes(v._attributes[f], out);
  } else if (v && typeof v === "object" && typeof v.switch === "function" && typeof v.value === "function") {
    collectEnvelopes(v.value(), out);
  }
  return out;
}

// The envelope's hash computed from the XDR layer alone (for envelopes the transaction parser refused):
// sha256(sha256(passphrase) || envelope type || transaction), a v0 transaction re-tagged as v1 (its optional
// time bounds and v1's preconditions share one encoding).
function envelopeHash(env, passphrase) {
  const type = env.switch().value;
  const txBytes = env.value().tx().toXDR();
  const tagged = type === 0 ? concatBytes([0, 0, 0, 2], [0, 0, 0, 0], txBytes) : concatBytes([0, 0, 0, type], txBytes);
  const networkId = createHash("sha256").update(passphrase).digest();
  return createHash("sha256").update(networkId).update(tagged).digest("hex");
}
function concatBytes(...parts) {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}

// The canonical L1 layout nests the focus facts as object.focus {tx_hash, operation_types, derived}, as the driver
// protocol schema in corpus/schema has them. false reports them at the top level of `object` instead.
const NESTED_FOCUS = true;

function putFocus(object, focus) {
  if (NESTED_FOCUS) object.focus = { ...focus, derived: focus.derived ?? {} };
  else Object.assign(object, focus);
}

/** The XDR-JSON name of an operation's type (change_trust, …), from the operation's XDR body arm. */
const operationType = (xop) => enumName(schema.defs.get("OperationType"), xop.body().switch().value);

/** The XDR operations of a decoded envelope (the inner transaction's for a fee bump). */
function xdrOperations(env) {
  let e = env;
  if (e.switch().name === "envelopeTypeTxFeeBump") e = e.value().tx().innerTx();
  return e.value().tx().operations();
}

/**
 * Derived values read back from one operation (the canonical closed list): operation_type from its XDR, the rest
 * from the SDK's operation object.
 */
// The counterpart address of an operation (the SDK object's field), and its asset, per operation type.
const ADDRESS_FIELD = {
  createAccount: "destination", payment: "destination", pathPaymentStrictReceive: "destination", pathPaymentStrictSend: "destination",
  accountMerge: "destination", allowTrust: "trustor", setTrustLineFlags: "trustor", clawback: "from",
  beginSponsoringFutureReserves: "sponsoredId",
};
const ASSET_FIELD = {
  payment: "asset", pathPaymentStrictReceive: "destAsset", pathPaymentStrictSend: "destAsset", setTrustLineFlags: "asset",
  clawback: "asset", createClaimableBalance: "asset",
};

/** The muxed ID of an M… address, as the SDK reads it; undefined for any other address. */
function muxedId(address) {
  if (typeof address !== "string" || address[0] !== "M") return undefined;
  return String(S.MuxedAccount.fromAddress(address, "0").id());
}

/**
 * Derived facts of one parsed operation: what the SDK's operation object says, keys that do not apply left out.
 * operation_source is the operation's own source; muxed_id is the counterpart address's muxed ID, else the
 * own source's.
 */
function deriveFromOperation(op, xop) {
  const d = {};
  try {
    const t = String(op.type);
    d.operation_type = operationType(xop);
    const line = op.line ?? op.asset;
    if (line && typeof line.getLiquidityPoolParameters === "function") {
      d.pool_id = hex(S.getLiquidityPoolId("constant_product", line.getLiquidityPoolParameters()));
    } else if (typeof op.liquidityPoolId === "string") d.pool_id = op.liquidityPoolId;
    else if (t === "changeTrust" && op.line) d.asset = op.line.toString();
    if (ASSET_FIELD[t] && op[ASSET_FIELD[t]]) d.asset = op[ASSET_FIELD[t]].toString();
    if (ADDRESS_FIELD[t] && typeof op[ADDRESS_FIELD[t]] === "string") d.address = op[ADDRESS_FIELD[t]];
    if (typeof op.source === "string") d.operation_source = op.source;
    const id = muxedId(d.address) ?? muxedId(d.operation_source);
    if (id !== undefined) d.muxed_id = id;
    if (op.offerId !== undefined && op.offerId !== null) d.offer_id = String(op.offerId);
  } catch (e) {
    if (isFault(e)) throw e;
  }
  return d;
}

/** memo_type of a parsed transaction (a fee bump's inner transaction). */
function memoType(tx) {
  const inner = tx.innerTransaction ?? tx;
  return inner.memo && typeof inner.memo.type === "string" ? inner.memo.type : undefined;
}

function opsOf(tx) {
  return tx.innerTransaction ? tx.innerTransaction.operations : tx.operations;
}

// The rebuild fact (docs/conformance-protocol.md, "The rebuild fact"): the parsed transaction handed to the
// SDK's own rebuild API as its declaration documents it, TransactionBuilder.cloneFrom(tx), with the
// SorobanTransactionData set again through setSorobanData (cloneFrom's declaration says it does not clone it),
// then build(), hashed under the same passphrase. What the builder's declaration cannot express is not rebuilt,
// decided before the call: a fee bump (cloneFrom takes a Transaction), a transaction without time bounds (build
// requires them), an inclusion fee that is not a whole multiple of the operation count (the builder takes a
// fee per operation), and the Soroban rules a version's build() declares it refuses (no memo, no muxed source).
const REBUILD_ENTRY = "TransactionBuilder.cloneFrom";
const SOROBAN_OPS = new Set(["invokeHostFunction", "extendFootprintTtl", "restoreFootprint"]);

/** The Transaction fields (by XDR field name) whose XDR differs between two envelopes: a diagnostic only. */
function differingFields(a, b) {
  const ta = a.value().tx()._attributes;
  const tb = b.value().tx()._attributes;
  const enc = (v) => (Array.isArray(v) ? v.map(enc).join("|") : v && typeof v.toXDR === "function" ? hex(v.toXDR()) : String(v));
  const keys = [...new Set([...Object.keys(ta), ...Object.keys(tb)])];
  return keys.filter((k) => enc(ta[k]) !== enc(tb[k]));
}

function rebuildFact(tx) {
  const fact = { entry_point: REBUILD_ENTRY };
  const notRebuilt = (r) => ({ ...fact, outcome: "not_rebuilt", reason: r });
  if (tx instanceof S.FeeBumpTransaction) return notRebuilt("fee_bump");
  if (!tx.timeBounds) return notRebuilt("no_time_bounds");
  const env = tx.toEnvelope();
  let sorobanData;
  if (env.switch().name === "envelopeTypeTx" && env.v1().tx().ext().switch() !== 0) sorobanData = env.v1().tx().ext().value();
  const inclusion = BigInt(tx.fee) - (sorobanData ? sorobanData.resourceFee().toBigInt() : 0n);
  if (tx.operations.length === 0 || inclusion < 0n || inclusion % BigInt(tx.operations.length) !== 0n) return notRebuilt("fee_not_per_operation");
  const soroban = sorobanData !== undefined || tx.operations.some((o) => SOROBAN_OPS.has(o.type));
  if (soroban && builderRules.sorobanNoMemo && tx.memo && tx.memo.type !== "none") return notRebuilt("soroban_memo");
  const muxed = (a) => typeof a === "string" && a.startsWith("M");
  if (soroban && builderRules.sorobanNoMuxed && (muxed(tx.source) || tx.operations.some((o) => muxed(o.source)))) return notRebuilt("soroban_muxed_source");
  let built;
  try {
    const b = S.TransactionBuilder.cloneFrom(tx);
    if (sorobanData) b.setSorobanData(sorobanData);
    built = b.build();
  } catch (e) {
    if (isFault(e)) throw e;
    return { ...fact, outcome: "refused", message: trim(String(e?.message ?? e), 500) };
  }
  fact.outcome = "rebuilt";
  fact.tx_hash = hex(built.hash());
  if (fact.tx_hash !== hex(tx.hash())) fact.differs = differingFields(env, built.toEnvelope());
  return fact;
}

/** Focus facts of one parsed transaction and its decoded envelope. */
function focusOf(tx, env, opIndex) {
  const ops = opsOf(tx);
  const xops = xdrOperations(env);
  const focus = { tx_hash: hex(tx.hash()), operation_types: xops.map(operationType) };
  focus.derived = opIndex !== undefined && opIndex < ops.length ? deriveFromOperation(ops[opIndex], xops[opIndex]) : {};
  const memo = memoType(tx);
  if (memo !== undefined) focus.derived.memo_type = memo;
  focus.rebuild = rebuildFact(tx);
  return focus;
}

function runL1Ledger(input, d) {
  const passphrase = input.passphrase ?? "";
  // A batch carries several ledgers; each is read in order.
  let lcms = [d.value];
  if (d.name === "LedgerCloseMetaBatch") {
    for (const [f, t] of d.T._fields) if (t._childType === xdr.LedgerCloseMeta) lcms = d.value._attributes[f];
  }
  const envs = [];
  const applyHashes = [];
  for (const lcm of lcms) {
    const body = lcm.value();
    collectEnvelopes(body.txSet(), envs);
    for (const r of body.txProcessing() ?? []) applyHashes.push(hex(r.result().transactionHash()));
  }
  // Apply order is the order of the ledger's transaction results; an envelope whose hash is not among them keeps
  // its transaction-set position after them.
  const applyIndex = new Map(applyHashes.map((h, i) => [h, i]));
  const order = (h, setIndex) => applyIndex.get(h) ?? applyHashes.length + setIndex;
  const object = { transactions: envs.length, envelopes_parsed: 0 };
  const rejected = [];
  const hashes = []; // [apply position, hash]
  let operations = 0;
  const parsed = new Map(); // hash → [tx, envelope]
  let first;
  envs.forEach((env, i) => {
    try {
      const tx = S.TransactionBuilder.fromXDR(toBase64(u8(env.toXDR())), passphrase);
      const h = hex(tx.hash());
      hashes.push([order(h, i), h]);
      parsed.set(h, [tx, env]);
      operations += opsOf(tx).length;
      object.envelopes_parsed++;
    } catch (e) {
      if (isFault(e)) throw e;
      const code = objectCodeOf(e, "object_validation");
      let h;
      try {
        h = envelopeHash(env, passphrase);
      } catch {
        // no hash for this envelope
      }
      const r = { tx_index: h !== undefined ? order(h, i) : applyHashes.length + i };
      if (h !== undefined) r.tx_hash = h;
      Object.assign(r, { code, message: trim(e.message, 500) });
      rejected.push(r);
      first ??= reason(code, e, "TransactionBuilder.fromXDR");
    }
  });
  object.operations = operations;
  object.tx_hashes = hashes.sort((a, b) => a[0] - b[0]).map(([, h]) => h);
  if (rejected.length) {
    object.envelopes_rejected = rejected.sort((a, b) => a.tx_index - b.tx_index);
    return new Outcome("reject", first, { object });
  }
  const f = input.focus;
  if (f && f.tx_index !== undefined && f.tx_index < applyHashes.length) {
    const p = parsed.get(applyHashes[f.tx_index]);
    if (p) putFocus(object, focusOf(p[0], p[1], f.op_index));
  }
  return ok({ object });
}

function runL1Envelope(input) {
  const T = xdr.TransactionEnvelope;
  const bytes = inputBytes(input);
  let tx;
  try {
    tx = S.TransactionBuilder.fromXDR(toBase64(bytes), input.passphrase ?? "");
  } catch (e) {
    if (isFault(e)) throw e;
    const code = objectCodeOf(e, "object_validation");
    const refined = code === "bool_range" || code === "enum_undeclared" ? decodeCode(e, () => locate(T, bytes, XdrReader)) : code;
    return new Outcome("reject", reason(refined, e, "TransactionBuilder.fromXDR"));
  }
  // The parser accepted the bytes, so the XDR layer reads them too: operation types come from the XDR arms.
  const focus = focusOf(tx, T.fromXDR(bytes), input.focus?.op_index);
  const object = { tx_hash: focus.tx_hash, operation_types: focus.operation_types, operations: opsOf(tx).length };
  object.derived = focus.derived ?? {};
  object.rebuild = focus.rebuild;
  let re;
  try {
    re = u8(tx.toEnvelope().toXDR());
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("diverge", reason("own_output_rejected", e, "Transaction.toEnvelope"), { object });
  }
  object.reencoded_sha256 = sha256(re);
  if (!bytesEqual(re, bytes)) {
    const actual = { object };
    if (re.length <= 4096) actual.reencoded_hex = hex(re);
    return new Outcome("diverge", { code: "object_reencode_mismatch", entry_point: "Transaction.toEnvelope" }, actual);
  }
  return ok({ object });
}

// L1 for single values with an object class: [entry point, parse(value) → {derived, back}] where back is the
// object's own XDR, compared with the input.
const OBJECT_PARSERS = {
  Memo: ["Memo.fromXDRObject", (v) => {
    const m = S.Memo.fromXDRObject(v);
    return { derived: { memo_type: String(m.type) }, back: m.toXDRObject().toXDR() };
  }],
  Operation: ["Operation.fromXDRObject", (v) => {
    const o = S.Operation.fromXDRObject(v);
    return { derived: deriveFromOperation(o, v), operation_types: [operationType(v)] };
  }],
  Asset: ["Asset.fromOperation", (v) => {
    const a = S.Asset.fromOperation(v);
    return { derived: { asset: a.toString() }, back: a.toXDRObject().toXDR() };
  }],
  ScAddress: ["Address.fromScAddress", (v) => {
    const a = S.Address.fromScAddress(v);
    return { derived: { address: a.toString() }, back: a.toScAddress().toXDR() };
  }],
  MuxedAccount: ["encodeMuxedAccountToAddress", (v) => {
    const address = S.encodeMuxedAccountToAddress(v);
    const derived = { address };
    if (address.startsWith("M")) derived.muxed_id = String(S.MuxedAccount.fromAddress(address, "0").id());
    return { derived };
  }],
  SignerKey: ["SignerKey.encodeSignerKey", (v) => ({ derived: { address: S.SignerKey.encodeSignerKey(v) } })],
};

function runL1(input) {
  const name = canonicalName(input.xdr_type);
  if (name === "TransactionEnvelope") return runL1Envelope(input);
  const d = decodeStrict(input);
  if (d instanceof Outcome) return d;
  if (name === "LedgerCloseMeta" || name === "LedgerCloseMetaBatch") return runL1Ledger(input, d);
  const p = OBJECT_PARSERS[name];
  if (!p) return na("no_object_layer", `no object parser for ${name}`);
  let r;
  try {
    r = p[1](d.value);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("reject", reason(objectCodeOf(e, "object_validation"), e, p[0]));
  }
  const object = {};
  if (r.derived && Object.keys(r.derived).length) object.derived = r.derived;
  if (r.operation_types) {
    object.operation_types = r.operation_types;
    object.operations = r.operation_types.length;
  }
  if (r.back) {
    const back = u8(r.back);
    object.reencoded_sha256 = sha256(back);
    if (!bytesEqual(back, d.bytes)) {
      const actual = { object };
      if (back.length <= 4096) actual.reencoded_hex = hex(back);
      return new Outcome("diverge", { code: "object_reencode_mismatch", entry_point: p[0] }, actual);
    }
  }
  return ok({ object });
}

// ---- L2 ------------------------------------------------------------------------------------------------------

function runL2(input) {
  const d = decodeStrict(input);
  if (d instanceof Outcome) return d;
  if (input.pinpoints === undefined) return ok({ projection: project(d.value, ref(d.name), schema) });
  return ok({
    pinpoints: input.pinpoints.map((p) => {
      const r = pinpoint(d.value, ref(d.name), schema, p);
      return r.found ? { path: p, found: true, value: r.value } : { path: p, found: false };
    }),
  });
}

// ---- L3 ------------------------------------------------------------------------------------------------------

// The native error fact (docs/conformance-protocol.md, "The native error fact"): the ScErrorType and ScErrorCode
// the SDK's native value of an scvError carries, as XDR-JSON names (a contract error's code as its decimal
// number), a key left out when the native value does not carry it. The native value is read, never the XDR: a
// contract error is {type: "contract", code}; any other string property that names an ScErrorType (sceStorage,
// or storage) or an ScErrorCode (scecExceededLimit, or exceeded_limit) is taken as that name.
const SC_ERROR_TYPES = ["contract", "wasm_vm", "context", "storage", "object", "crypto", "events", "budget", "value", "auth"];
const SC_ERROR_CODES = ["arith_domain", "index_bounds", "invalid_input", "missing_value", "existing_value", "exceeded_limit",
  "invalid_action", "internal_error", "unexpected_type", "unexpected_size"];
const snakeOf = (s, prefix) => s.slice(prefix.length).replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
function nativeError(n) {
  const out = {};
  if (!n || typeof n !== "object") return out;
  if (n.type === "contract") {
    out.type = "contract";
    if (n.code !== undefined && n.code !== null) out.code = String(n.code);
    return out;
  }
  for (const v of Object.values(n)) {
    if (typeof v !== "string") continue;
    if (/^scec[A-Z]/.test(v) && SC_ERROR_CODES.includes(snakeOf(v, "scec"))) out.code = snakeOf(v, "scec");
    else if (/^sce[A-Z]/.test(v) && SC_ERROR_TYPES.includes(snakeOf(v, "sce"))) out.type = snakeOf(v, "sce");
    else if (SC_ERROR_CODES.includes(v)) out.code = v;
    else if (SC_ERROR_TYPES.includes(v)) out.type = v;
  }
  return out;
}

function runL3(input) {
  const name = canonicalName(input.xdr_type);
  if (name !== "ScVal" && name !== "Memo") return na("no_native_layer", `no native conversion for ${input.xdr_type}`);
  const d = decodeStrict(input);
  if (d instanceof Outcome) return d;
  if (name === "Memo") {
    let m;
    try {
      m = S.Memo.fromXDRObject(d.value);
    } catch (e) {
      if (isFault(e)) throw e;
      return new Outcome("reject", reason(objectCodeOf(e, "other"), e, "Memo.fromXDRObject"));
    }
    const native = { type: nativeType(m.value), summary: summary(m.value) };
    try {
      const back = u8(new S.Memo(m.type, m.value).toXDRObject().toXDR());
      native.reencoded_sha256 = sha256(back);
      native.bytes_preserved = bytesEqual(back, d.bytes);
    } catch (e) {
      if (isFault(e)) throw e;
      native.bytes_preserved = false;
    }
    return ok({ native });
  }
  let n;
  try {
    n = S.scValToNative(d.value);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("reject", reason(objectCodeOf(e, "other"), e, "scValToNative"));
  }
  const native = { type: nativeType(n), summary: summary(n) };
  if (d.value.switch().name === "scvError") native.error = nativeError(n);
  if (d.value.switch().name === "scvMap") {
    native.map_entries = n instanceof Map ? n.size : n && typeof n === "object" ? Object.keys(n).length : 0;
  }
  try {
    const hint = scalarHint(d.value);
    const back = u8((hint ? S.nativeToScVal(n, { type: hint }) : S.nativeToScVal(n)).toXDR());
    native.reencoded_sha256 = sha256(back);
    native.bytes_preserved = bytesEqual(back, d.bytes);
  } catch (e) {
    if (isFault(e)) throw e;
    native.bytes_preserved = false;
  }
  return ok({ native });
}

// ---- L4 ------------------------------------------------------------------------------------------------------

// A malformed request (a missing or unusable argument of a listed op) throws ArgError: a protocol error.
function runL4(input) {
  if (input.kind === "strkey") {
    if (typeof input.text !== "string") throw new ArgError("a strkey input needs text");
    return strkeyDecode(S, input.text, input.declared_type);
  }
  const args = input.args ?? {};
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new ArgError("api args must be an object");
  return api.run(input.api_op, args);
}

// ---- protocol ------------------------------------------------------------------------------------------------

function describe(id) {
  const has = (e, v) => !!xdr[e]?._byValue?.[v];
  const probes = {
    sc_address_type_muxed_contract: has("ScAddressType", 5),
    stellar_value_signed_ms: has("StellarValueType", 3),
  };
  const xdr_schema = { probes };
  const values = (e) => {
    const m = xdr[e]?._byValue;
    return m instanceof Map ? [...m.keys()] : Object.keys(m ?? {}).map(Number);
  };
  const protocol = schemaProtocol(probes, beyondKnown(values));
  if (protocol !== undefined) xdr_schema.protocol = protocol;
  return {
    xcc: TAG, id, op: "describe",
    driver: DRIVER,
    sdk,
    runtime: { name: "node", version: process.versions.node, os: process.platform, arch: process.arch },
    xdr_schema,
    levels: LEVELS,
    object_parsers: {
      TransactionEnvelope: "TransactionBuilder.fromXDR",
      LedgerCloseMeta: "TransactionBuilder.fromXDR (every envelope of the transaction set)",
      LedgerCloseMetaBatch: "TransactionBuilder.fromXDR (every envelope of the transaction set)",
      ...Object.fromEntries(Object.entries(OBJECT_PARSERS).map(([k, v]) => [k, v[0]])),
    },
    object_rebuild: REBUILD_ENTRY,
    native_converters: { ScVal: "scValToNative", Memo: "Memo.fromXDRObject" },
    api_ops: api.ops,
    decode: { entry_point: "xdr.<Type>.fromXDR", default_depth: defaultDepth, depth_configurable: false, checks_consumed_length: true },
  };
}

// The spec level: the SDK's spec reader; a refusal is classified from the SDK's error, the facts read from its
// objects (spec.mjs).
function runSpec(input) {
  const bytes = new Uint8Array(readFileSync(input.path));
  let r;
  try {
    r = readSpec(S, bytes, input.container);
  } catch (e) {
    if (isFault(e)) throw e;
    const code = /at most one 'contractspecv0'/.test(String(e?.message)) ? "spec_sections" : decodeCode(e);
    return new Outcome("reject", reason(code, e, input.container === "wasm" ? "contract.Spec.fromWasm" : "new contract.Spec(stream)"));
  }
  return ok({ spec: { entries: r.spec.entries.map(entryFact), entry_point: r.entryPoint } });
}

function runRequest(req) {
  const input = req.input ?? {};
  const level = req.level;
  if (level === "spec") return input.kind === "spec" ? runSpec(input) : na("op_not_supported", "spec needs a spec input");
  if (level === "L4") {
    if (input.kind !== "api" && input.kind !== "strkey") return na("op_not_supported", "L4 needs an api or strkey input");
    return runL4(input);
  }
  if (input.kind !== "xdr") return na("op_not_supported", `${level} needs an xdr input`);
  switch (level) {
    case "L0":
      return runL0(input);
    case "L1":
      return runL1(input);
    case "L2":
      return runL2(input);
    case "L3":
      return runL3(input);
  }
  return na("other", `unknown level ${level}`);
}

function respond(req) {
  const resp = { xcc: TAG, id: req.id, op: "run", entry: req.entry };
  if (req.variant !== undefined) resp.variant = req.variant;
  resp.level = req.level;
  if (req.profile !== undefined) resp.profile = req.profile;
  let o;
  try {
    o = runRequest(req);
  } catch (e) {
    if (e instanceof ArgError) return { xcc: TAG, id: req.id, op: "protocol_error", error: e.message };
    // Fault-class errors and driver bugs: never a reject.
    o = new Outcome("crash", reason(isFault(e) ? faultCode(e) : "internal_error", e));
  }
  resp.outcome = o.outcome;
  if (o.reason) resp.reason = o.reason;
  if (o.actual && Object.keys(o.actual).length) resp.actual = o.actual;
  return resp;
}

const out = process.stdout;
function send(obj) {
  const line = JSON.stringify(obj) + "\n";
  return new Promise((res) => {
    if (out.write(line)) res();
    else out.once("drain", res);
  });
}

const LEVEL_SET = new Set(LEVELS);
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (line.trim() === "") continue;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    await send({ xcc: TAG, op: "protocol_error", error: "the request is not JSON" });
    continue;
  }
  const idOK = Number.isInteger(req?.id) && req.id >= 1;
  const perr = (msg) => send({ xcc: TAG, ...(idOK ? { id: req.id } : {}), op: "protocol_error", error: msg });
  if (req === null || typeof req !== "object" || req.xcc !== TAG) {
    await perr(`unsupported protocol tag ${JSON.stringify(req?.xcc)}`);
    continue;
  }
  if (!idOK) {
    await perr("the request has no valid id");
    continue;
  }
  if (req.op === "describe") await send(describe(req.id));
  else if (req.op === "shutdown") {
    await send({ xcc: TAG, id: req.id, op: "shutdown", ok: true });
    break;
  } else if (req.op === "run") {
    if (typeof req.entry !== "string" || !LEVEL_SET.has(req.level) || typeof req.input !== "object" || req.input === null) {
      await perr("a run request needs entry, level and input");
      continue;
    }
    await send(respond(req));
  } else await perr(`unknown op ${JSON.stringify(req.op)}`);
}
rl.close();
process.stdin.destroy();
