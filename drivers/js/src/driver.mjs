// xdrcheck-driver-js: the conformance driver for @stellar/stellar-sdk's v17 API generation (js-xdr 5). One source
// serves every pinned 17.x version; each version directory under drivers/js/ holds its own locked install and
// runs this file with `--install <that directory>`.
//
// It speaks the driver protocol xcc.driver/1 (corpus/schema/driver-protocol.schema.json; contract in
// drivers/README.md): one JSON request per line on stdin, one response per line on stdout, serially. It reports
// what the SDK did, never compares with expected values and never reads the manifest.
//
// Levels (all five are declared):
//   L0  xdr.<Type>.fromXdr(bytes) (strict: rejects trailing bytes), re-encode with .toXdr(); ok always carries
//       consumed_bytes and reencoded_sha256; the deprecated fromXDR alias and validateXdr are listed under
//       lenient_entry_points when they disagree
//   L1  TransactionEnvelope: TransactionBuilder.fromXdr(base64, passphrase) → tx_hash, operation_types,
//       operations, reencoded_sha256, derived. LedgerCloseMeta(Batch): every envelope of the transaction set
//       through TransactionBuilder.fromXdr, in apply order (each envelope placed by its XDR-layer hash among the
//       ledger's result hashes) → transactions, envelopes_parsed, operations, tx_hashes, envelopes_rejected
//       (apply-order tx_index, the ledger's own hash) and, for a request focus with tx_index, focus {tx_hash,
//       operation_types, derived}. Memo, Operation, Asset, ScAddress, MuxedAccount, SignerKey through their
//       object classes → derived. Operation types are XDR-JSON snake_case arms; derived keys are the driver
//       protocol's closed list
//   L2  the neutral value projection of the decoded value (project.mjs), whole or at the requested pointers
//   L3  ScVal through scValToNative and back through nativeToScVal; Memo through Memo.fromXdrObject; ok carries
//       type, bytes_preserved, reencoded_sha256 (and map_entries for a map)
//   L4  api operations (api.mjs) and strkey texts
//
// A request the driver cannot understand (a malformed, missing or unknown argument, an input of the wrong kind
// for the level, a focus outside the ledger) is answered with a protocol_error message, never an SDK outcome.
// Byte arguments reach the SDK as plain Uint8Array, never Buffer; 64-bit values are BigInt or decimal strings.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { loadSDK } from "./sdk.mjs";
import { beyondKnown, schemaProtocol } from "./reach.mjs";
import { project, pinpoint, snake } from "./project.mjs";
import { decodeCode, objectCode, isFault, faultCode, reason, trim } from "./errors.mjs";
import { makeAPI, strkeyDecode, ArgError } from "./api.mjs";
import { hex, sha256, bytesEqual, fromHex, toBase64, summary, nativeType, scalarHint } from "./util.mjs";
import { readSpec, entryFact } from "./spec.mjs";

const TAG = "xcc.driver/1";
const DRIVER = { name: "xdrcheck-driver-js", version: "0.1.0", adapter: "js-v17" };
const LEVELS = ["L0", "L1", "L2", "L3", "L4", "spec"];

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const installDir = argValue("--install") ?? process.cwd();
const { S, jsxdr, sdk, defaultDepth, argTypes, builderRules } = await loadSDK(installDir);
const { xdr } = S;
const api = makeAPI(S, { argTypes, jsxdr });

// ---- helpers -------------------------------------------------------------------------------------------------

/** Generated XDR types by name, case-insensitively (the corpus spells ScVal, the XDR files SCVal). */
const xdrTypes = new Map();
for (const [k, v] of Object.entries(xdr)) {
  if (v && v.schema && typeof v.fromXdr === "function" && typeof v.fromXdrObject === "function") {
    xdrTypes.set(k.toLowerCase(), k);
  }
}
function xdrType(name) {
  const k = xdr[name]?.schema ? name : xdrTypes.get(String(name).toLowerCase());
  return k ? xdr[k] : undefined;
}

const unwrap = (s) => {
  while (s && s.kind === "lazy") s = s.getSchema();
  return s;
};

/**
 * Does the dotted path of an XdrError end at a union's discriminant? Follows the path through the schema the
 * way js-xdr builds it: struct fields, union case then arm name, `[i]` for array elements, `.present` /
 * `.value` for optionals.
 */
function unionKeyAt(rootSchema) {
  return (path) => {
    const segs = path.split(".").flatMap((seg) => {
      const parts = [];
      const m = seg.match(/^([^[]*)((?:\[\d+\])*)$/);
      if (!m) return [seg];
      if (m[1] !== "") parts.push(m[1]);
      for (const _ of m[2].match(/\[\d+\]/g) ?? []) parts.push("[]");
      return parts;
    });
    let s = unwrap(rootSchema);
    let i = 1; // the first segment is the root type's name
    while (s && i < segs.length) {
      const seg = segs[i];
      if (s.kind === "union") {
        if (seg === s.switchKey) return i === segs.length - 1;
        const c = s.cases.find((x) => x.name === seg) ?? (seg === "default" ? { arm: s.defaultArm } : undefined);
        if (!c || !c.arm) return false;
        if ("schema" in c.arm) {
          i++;
          if (segs[i] !== c.arm.name) return false;
          s = unwrap(c.arm.schema);
        } else return false;
        i++;
      } else if (s.kind === "struct") {
        const e = s.entries.find(([k]) => k === seg);
        if (!e) return false;
        s = unwrap(e[1]);
        i++;
      } else if (s.kind === "array" || s.kind === "fixedArray") {
        if (seg !== "[]") return false;
        s = unwrap(s.element);
        i++;
      } else if (s.kind === "option") {
        if (seg === "present") return false;
        if (seg !== "value") return false;
        s = unwrap(s.element);
        i++;
      } else return false;
    }
    return false;
  };
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
  if (input.path !== undefined) {
    const buf = readFileSync(input.path);
    b = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  } else {
    if (typeof input.xdr_hex !== "string" || !/^([0-9a-f]{2})*$/.test(input.xdr_hex)) throw new RequestError("input.xdr_hex is not lower-case hex");
    b = fromHex(input.xdr_hex);
  }
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

/** Decode with the strict entry point; returns {value, T} or an Outcome (reject / n_a). */
function decodeStrict(input) {
  const T = xdrType(input.xdr_type);
  if (!T) return na("type_not_generated", `no generated XDR type ${input.xdr_type}`);
  const bytes = inputBytes(input);
  try {
    return { T, bytes, value: T.fromXdr(bytes) };
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("reject", reason(decodeCode(e, unionKeyAt(T.schema)), e, `xdr.${input.xdr_type}.fromXdr`));
  }
}

// ---- L0 ------------------------------------------------------------------------------------------------------

function runL0(input) {
  const d = decodeStrict(input);
  if (d instanceof Outcome) {
    if (d.outcome === "reject") {
      const lenient = lenientEntryPoints(xdrType(input.xdr_type), inputBytes(input), false);
      if (lenient.length) d.actual = { lenient_entry_points: lenient };
    }
    return d;
  }
  let re;
  try {
    re = d.value.toXdr();
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("diverge", reason("own_output_rejected", e, `xdr.${input.xdr_type}.toXdr`), { consumed_bytes: d.bytes.length });
  }
  const actual = { consumed_bytes: d.bytes.length, reencoded_sha256: sha256(re) };
  const lenient = lenientEntryPoints(d.T, d.bytes, true);
  if (lenient.length) actual.lenient_entry_points = lenient;
  if (!bytesEqual(re, d.bytes)) {
    if (re.length <= 4096) actual.reencoded_hex = hex(re);
    return new Outcome("diverge", { code: "reencode_mismatch", entry_point: `xdr.${input.xdr_type}.toXdr` }, actual);
  }
  return ok(actual);
}

// The SDK's other documented single-value decode entry points, listed only where they disagree with the strict
// one.
function lenientEntryPoints(T, bytes, strictAccepted) {
  const out = [];
  const probes = [
    ["fromXDR", () => (T.fromXDR(bytes), true)],
    ["validateXdr", () => T.validateXdr(bytes) === true],
  ];
  for (const [name, f] of probes) {
    if (typeof T[name] !== "function") continue;
    let accepted;
    try {
      accepted = f();
    } catch (e) {
      if (isFault(e)) throw e;
      accepted = false;
    }
    if (accepted !== strictAccepted) out.push({ entry_point: `xdr.${T.name.replace(/Base$/, "")}.${name}`, accepted });
  }
  return out;
}

// ---- L1 ------------------------------------------------------------------------------------------------------

/** Every TransactionEnvelope wire value below a value, in schema (= transaction-set) order. */
function collectEnvelopes(wire, schema, out) {
  const s = unwrap(schema);
  if (s.name === "TransactionEnvelope") {
    out.push(wire);
    return out;
  }
  switch (s.kind) {
    case "struct":
      for (const [k, fs] of s.entries) collectEnvelopes(wire[k], fs, out);
      break;
    case "union": {
      const c = s.cases.find((x) => x.discriminant === wire[s.switchKey]);
      const arm = c ? c.arm : s.defaultArm;
      if (arm && "schema" in arm) collectEnvelopes(wire[arm.name], arm.schema, out);
      break;
    }
    case "array":
    case "fixedArray":
      for (const v of wire) collectEnvelopes(v, s.element, out);
      break;
    case "option":
      if (wire !== null) collectEnvelopes(wire, s.element, out);
      break;
  }
  return out;
}

function armOf(wire, schema) {
  const s = unwrap(schema);
  const c = s.cases.find((x) => x.discriminant === wire[s.switchKey]);
  return { value: wire[c.arm.name], schema: unwrap(c.arm.schema) };
}

function fieldSchema(s, name) {
  const e = s.entries.find(([k]) => k === name);
  return e ? unwrap(e[1]) : undefined;
}

// The envelope's hash computed from the XDR layer alone (for envelopes the transaction parser refused):
// sha256(sha256(passphrase) || envelope type || transaction), a v0 transaction re-tagged as v1 (its optional
// time bounds and v1's preconditions share one encoding).
function envelopeHash(envWire, passphrase) {
  const s = unwrap(xdr.TransactionEnvelope.schema);
  const c = s.cases.find((x) => x.discriminant === envWire[s.switchKey]);
  const inner = envWire[c.arm.name];
  const innerSchema = unwrap(c.arm.schema);
  const txSchema = fieldSchema(innerSchema, "tx");
  let tagged;
  const txBytes = txSchema.encode(inner.tx);
  if (envWire[s.switchKey] === 0) tagged = concatBytes([0, 0, 0, 2], [0, 0, 0, 0], txBytes);
  else tagged = concatBytes([0, 0, 0, envWire[s.switchKey]], txBytes);
  const networkId = createHash("sha256").update(passphrase).digest();
  return createHash("sha256").update(networkId).update(tagged).digest("hex");
}
function concatBytes(...parts) {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}

/** The XDR-JSON snake_case operation arm of an SDK operation object's type (revoke*Sponsorship is one arm). */
function opType(o) {
  const t = String(o.type);
  return /^revoke\w*Sponsorship$/.test(t) ? "revoke_sponsorship" : snake(t);
}

/** The muxed ID of an M… address, as the SDK reads it; undefined for any other address. */
function muxedId(address) {
  if (typeof address !== "string" || address[0] !== "M") return undefined;
  return String(S.MuxedAccount.fromAddress(address, "0").id());
}

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

/**
 * Derived values (the closed list of the driver protocol) read back from one parsed operation: what the SDK's
 * operation object says, keys that do not apply left out. operation_source is the operation's own source;
 * muxed_id is the counterpart address's muxed ID, else the own source's.
 */
function deriveFromOperation(op) {
  const d = {};
  const t = String(op.type);
  d.operation_type = opType(op);
  if (typeof op.source === "string") d.operation_source = op.source;
  const line = t === "changeTrust" ? op.line : undefined;
  if (line && typeof line.getLiquidityPoolParameters === "function") {
    d.pool_id = hex(S.getLiquidityPoolId("constant_product", line.getLiquidityPoolParameters()));
  } else if (line) d.asset = line.toString();
  if ((t === "liquidityPoolDeposit" || t === "liquidityPoolWithdraw") && typeof op.liquidityPoolId === "string") d.pool_id = op.liquidityPoolId.toLowerCase();
  if (ASSET_FIELD[t] && op[ASSET_FIELD[t]]) d.asset = op[ASSET_FIELD[t]].toString();
  if (ADDRESS_FIELD[t] && typeof op[ADDRESS_FIELD[t]] === "string") d.address = op[ADDRESS_FIELD[t]];
  const id = muxedId(d.address) ?? muxedId(d.operation_source);
  if (id !== undefined) d.muxed_id = id;
  if ((t === "manageSellOffer" || t === "manageBuyOffer") && op.offerId !== undefined) d.offer_id = String(op.offerId);
  return d;
}

/** The transaction object the operations live in (a fee bump's inner transaction). */
const innerOf = (tx) => tx.innerTransaction ?? tx;
const opsOf = (tx) => innerOf(tx).operations;

/** memo_type of a transaction, plus the operation keys of operation opIndex (when given and present). */
function deriveFromTransaction(tx, opIndex) {
  const inner = innerOf(tx);
  const d = {};
  const ops = inner.operations;
  if (opIndex !== undefined && opIndex < ops.length) Object.assign(d, deriveFromOperation(ops[opIndex]));
  if (inner.memo && typeof inner.memo.type === "string") d.memo_type = inner.memo.type;
  return d;
}

/** A request the driver cannot answer as asked (a focus outside the ledger): a protocol error. */
class RequestError extends Error {}

// The rebuild fact (docs/conformance-protocol.md, "The rebuild fact"): the parsed transaction handed to the
// SDK's own rebuild API as its declaration documents it, TransactionBuilder.cloneFrom(tx), with the
// SorobanTransactionData set again through setSorobanData (cloneFrom's declaration says it does not clone it),
// then build(), hashed under the same passphrase. What the builder's declaration cannot express is not rebuilt,
// decided before the call: a fee bump (cloneFrom takes a Transaction), a transaction without time bounds (build
// requires them), an inclusion fee that is not a whole multiple of the operation count (the builder takes a
// fee per operation), and the Soroban rules a version's build() declares it refuses (no memo, no muxed source).
const REBUILD_ENTRY = "TransactionBuilder.cloneFrom";
const REBUILD_FIELDS = ["sourceAccount", "sourceAccountEd25519", "fee", "seqNum", "cond", "timeBounds", "memo", "operations", "ext"];
const SOROBAN_OPS = new Set(["invokeHostFunction", "extendFootprintTtl", "restoreFootprint"]);

/** The Transaction fields (by XDR field name) whose value differs between two envelopes: a diagnostic only. */
function differingFields(a, b) {
  const txOf = (env) => (env.value ?? env).tx;
  const ta = txOf(a);
  const tb = txOf(b);
  const enc = (v) => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x instanceof Uint8Array ? hex(x) : x));
  return REBUILD_FIELDS.filter((k) => (k in ta || k in tb) && enc(ta[k]) !== enc(tb[k]));
}

function rebuildFact(tx) {
  const fact = { entry_point: REBUILD_ENTRY };
  const notRebuilt = (r) => ({ ...fact, outcome: "not_rebuilt", reason: r });
  if (tx instanceof S.FeeBumpTransaction) return notRebuilt("fee_bump");
  if (!tx.timeBounds) return notRebuilt("no_time_bounds");
  const env = tx.toEnvelope();
  const ext = env.type === "envelopeTypeTx" ? env.value.tx.ext : undefined;
  const sorobanData = ext && ext.type === "sorobanData" ? ext.value : undefined;
  const inclusion = BigInt(tx.fee) - (sorobanData ? BigInt(sorobanData.resourceFee) : 0n);
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

function runL1Ledger(input, d) {
  const passphrase = input.passphrase ?? "";
  const wire = d.value.toXdrObject();
  const lcmSchema = unwrap(d.T.schema);
  // A batch carries several ledgers; each is read in order.
  let lcms = [{ wire, schema: lcmSchema }];
  if (lcmSchema.kind === "struct") {
    for (const [k, fs] of lcmSchema.entries) {
      const u = unwrap(fs);
      if (u.kind === "array" && unwrap(u.element).name === "LedgerCloseMeta") lcms = wire[k].map((w) => ({ wire: w, schema: unwrap(u.element) }));
    }
  }
  const envs = [];
  const applyHashes = [];
  for (const l of lcms) {
    const arm = armOf(l.wire, l.schema);
    const txSetField = arm.schema.entries.find(([k]) => k === "txSet");
    collectEnvelopes(arm.value.txSet, txSetField[1], envs);
    for (const r of arm.value.txProcessing ?? []) applyHashes.push(hex(r.result.transactionHash));
  }
  // Apply order: each envelope is placed by its hash computed from the XDR layer alone (never by the SDK, whose
  // own hash is what is under test) among the ledger's result hashes; an envelope that cannot be placed goes
  // after the placed ones, in set order.
  const applyIndex = new Map(applyHashes.map((h, i) => [h, i]));
  const placed = envs.map((envWire, setIndex) => {
    let xh;
    try {
      xh = envelopeHash(envWire, passphrase);
    } catch {
      xh = undefined;
    }
    const ai = xh !== undefined ? applyIndex.get(xh) : undefined;
    return { envWire, setIndex, xh, order: ai ?? applyHashes.length + setIndex };
  });
  placed.sort((a, b) => a.order - b.order);
  const object = { transactions: envs.length, envelopes_parsed: 0 };
  const rejected = [];
  const hashes = [];
  let operations = 0;
  const byApply = new Map(); // apply index → parsed transaction
  let first;
  placed.forEach((p, i) => {
    try {
      const b64 = toBase64(xdr.TransactionEnvelope.fromXdrObject(p.envWire).toXdr());
      const tx = S.TransactionBuilder.fromXdr(b64, passphrase);
      hashes.push(hex(tx.hash()));
      byApply.set(i, tx);
      operations += opsOf(tx).length;
      object.envelopes_parsed++;
    } catch (e) {
      if (isFault(e)) throw e;
      const code = objectCode(e, "object_validation");
      const txHash = p.order < applyHashes.length ? applyHashes[p.order] : p.xh;
      if (txHash === undefined) throw new Error(`envelope ${p.setIndex} of the transaction set cannot be hashed`);
      rejected.push({ tx_index: i, tx_hash: txHash, code, message: trim(e.message, 500) });
      first ??= reason(code, e, "TransactionBuilder.fromXdr");
    }
  });
  object.operations = operations;
  object.tx_hashes = hashes;
  if (rejected.length) {
    object.envelopes_rejected = rejected;
    return new Outcome("reject", first, { object });
  }
  const f = input.focus;
  if (f && f.tx_index !== undefined) {
    const tx = byApply.get(f.tx_index);
    if (!tx) throw new RequestError(`focus.tx_index ${f.tx_index} is outside the ledger's ${envs.length} transactions`);
    object.focus = {
      tx_hash: hex(tx.hash()),
      operation_types: opsOf(tx).map(opType),
      derived: deriveFromTransaction(tx, f.op_index),
      rebuild: rebuildFact(tx),
    };
  }
  return ok({ object });
}

function runL1Envelope(input) {
  const T = xdr.TransactionEnvelope;
  const bytes = inputBytes(input);
  let tx;
  try {
    tx = S.TransactionBuilder.fromXdr(toBase64(bytes), input.passphrase ?? "");
  } catch (e) {
    if (isFault(e)) throw e;
    const code = e && e.name === "XdrError" ? decodeCode(e, unionKeyAt(T.schema)) : objectCode(e, "object_validation");
    return new Outcome("reject", reason(code, e, "TransactionBuilder.fromXdr"));
  }
  const ops = opsOf(tx);
  // The operation keys: the focus operation when the request names one, else the only operation.
  const opIndex = input.focus?.op_index ?? (ops.length === 1 ? 0 : undefined);
  const object = { tx_hash: hex(tx.hash()), operation_types: ops.map(opType), operations: ops.length, derived: deriveFromTransaction(tx, opIndex) };
  object.rebuild = rebuildFact(tx);
  let re;
  try {
    re = tx.toEnvelope().toXdr();
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
  Memo: ["Memo.fromXdrObject", (v) => {
    const m = S.Memo.fromXdrObject(v);
    return { derived: { memo_type: String(m.type) }, back: m.toXdrObject().toXdr() };
  }],
  Operation: ["Operation.fromXdrObject", (v) => {
    const o = S.Operation.fromXdrObject(v);
    return { derived: deriveFromOperation(o), operation_types: [opType(o)] };
  }],
  Asset: ["Asset.fromOperation", (v) => {
    const a = S.Asset.fromOperation(v);
    return { derived: { asset: a.toString() }, back: a.toXdrObject().toXdr() };
  }],
  ScAddress: ["Address.fromScAddress", (v) => {
    const a = S.Address.fromScAddress(v);
    return { derived: { address: a.toString() }, back: a.toScAddress().toXdr() };
  }],
  MuxedAccount: ["encodeMuxedAccountToAddress", (v) => {
    const address = S.encodeMuxedAccountToAddress(v);
    const d = { address };
    const id = muxedId(address);
    if (id !== undefined) d.muxed_id = id;
    return { derived: d };
  }],
  SignerKey: ["SignerKey.encodeSignerKey", (v) => ({ derived: { address: S.SignerKey.encodeSignerKey(v) } })],
};

function canonicalName(name) {
  const T = xdrType(name);
  return T ? Object.keys(xdr).find((k) => xdr[k] === T && k.toLowerCase() === String(name).toLowerCase()) ?? name : name;
}

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
    return new Outcome("reject", reason(objectCode(e, "object_validation"), e, p[0]));
  }
  const object = { derived: r.derived ?? {} };
  if (r.operation_types) {
    object.operation_types = r.operation_types;
    object.operations = r.operation_types.length;
  }
  if (r.back) {
    object.reencoded_sha256 = sha256(r.back);
    if (!bytesEqual(r.back, d.bytes)) {
      const actual = { object };
      if (r.back.length <= 4096) actual.reencoded_hex = hex(r.back);
      return new Outcome("diverge", { code: "object_reencode_mismatch", entry_point: p[0] }, actual);
    }
  }
  return ok({ object });
}

// ---- L2 ------------------------------------------------------------------------------------------------------

function runL2(input) {
  const d = decodeStrict(input);
  if (d instanceof Outcome) return d;
  const wire = d.value.toXdrObject();
  if (input.pinpoints === undefined) return ok({ projection: project(wire, d.T.schema) });
  return ok({
    pinpoints: input.pinpoints.map((p) => {
      const r = pinpoint(wire, d.T.schema, p);
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
      m = S.Memo.fromXdrObject(d.value);
    } catch (e) {
      if (isFault(e)) throw e;
      return new Outcome("reject", reason(objectCode(e, "other"), e, "Memo.fromXdrObject"));
    }
    const native = { type: nativeType(m.value), summary: summary(m.value) };
    return nativeBack(native, d.bytes, "new Memo", () => new S.Memo(m.type, m.value).toXdrObject().toXdr());
  }
  let n;
  try {
    n = S.scValToNative(d.value);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Outcome("reject", reason(objectCode(e, "other"), e, "scValToNative"));
  }
  const native = { type: nativeType(n), summary: summary(n) };
  if (d.value.type === "scvError") native.error = nativeError(n);
  if (d.value.type === "scvMap") {
    native.map_entries = n instanceof Map ? n.size : n && typeof n === "object" ? Object.keys(n).length : 0;
  }
  const hint = scalarHint(d.value);
  return nativeBack(native, d.bytes, "nativeToScVal", () => (hint ? S.nativeToScVal(n, { type: hint }) : S.nativeToScVal(n)).toXdr());
}

// The way back from the native value: ok with reencoded_sha256 and bytes_preserved; when the SDK cannot rebuild
// the value from its own native form, diverge/native_reencode_mismatch.
function nativeBack(native, input, entryPoint, rebuild) {
  let back;
  try {
    back = rebuild();
  } catch (e) {
    if (isFault(e)) throw e;
    native.bytes_preserved = false;
    return new Outcome("diverge", reason("native_reencode_mismatch", e, entryPoint), { native });
  }
  native.reencoded_sha256 = sha256(back);
  native.bytes_preserved = bytesEqual(back, input);
  return ok({ native });
}

// ---- L4 ------------------------------------------------------------------------------------------------------

function runL4(input) {
  if (input.kind === "strkey") return strkeyDecode(S, input.text, input.declared_type);
  return api.run(input.api_op, input.args ?? {});
}

// ---- protocol ------------------------------------------------------------------------------------------------

function describe(id) {
  const has = (e, v) => !!xdr[e]?.schema?.nameByValue?.has(v);
  const probes = {
    sc_address_type_muxed_contract: has("ScAddressType", 5),
    stellar_value_signed_ms: has("StellarValueType", 3),
  };
  const xdr_schema = { probes };
  const values = (e) => [...(xdr[e]?.schema?.nameByValue?.keys() ?? [])];
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
      TransactionEnvelope: "TransactionBuilder.fromXdr",
      LedgerCloseMeta: "TransactionBuilder.fromXdr (every envelope of the transaction set)",
      LedgerCloseMetaBatch: "TransactionBuilder.fromXdr (every envelope of the transaction set)",
      ...Object.fromEntries(Object.entries(OBJECT_PARSERS).map(([k, v]) => [k, v[0]])),
    },
    object_rebuild: REBUILD_ENTRY,
    native_converters: { ScVal: "scValToNative", Memo: "Memo.fromXdrObject" },
    api_ops: api.ops,
    decode: { entry_point: "xdr.<Type>.fromXdr", default_depth: defaultDepth, depth_configurable: false, checks_consumed_length: true },
  };
}

// The spec level: the SDK's spec reader; a refusal is classified from the SDK's error, the facts read from its
// objects (spec.mjs).
function runSpec(input) {
  if (input.container !== "wasm" && input.container !== "xdr-stream") throw new RequestError(`unknown container ${input.container}`);
  const bytes = new Uint8Array(readFileSync(input.path));
  let r;
  try {
    r = readSpec(S, bytes, input.container);
  } catch (e) {
    if (isFault(e)) throw e;
    const code = /at most one 'contractspecv0'/.test(String(e?.message)) ? "spec_sections" : decodeCode(e);
    return new Outcome("reject", reason(code, e, input.container === "wasm" ? "contract.Spec.fromWasm" : "new contract.Spec(stream)"));
  }
  return new Outcome("ok", null, { spec: { entries: r.spec.entries.map(entryFact), entry_point: r.entryPoint } });
}

function runRequest(req) {
  const input = req.input ?? {};
  const level = req.level;
  if (level === "spec") {
    if (input.kind !== "spec") throw new RequestError("spec needs a spec input");
    return runSpec(input);
  }
  if (level === "L4") {
    if (input.kind !== "api" && input.kind !== "strkey") throw new RequestError("L4 needs an api or strkey input");
    return runL4(input);
  }
  if (input.kind !== "xdr") throw new RequestError(`${level} needs an xdr input`);
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
  throw new RequestError(`unknown level ${level}`);
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
    // A request the driver cannot understand is a protocol error, never an SDK outcome.
    if (e instanceof ArgError || e instanceof RequestError) return { xcc: TAG, id: req.id, op: "protocol_error", error: trim(e.message, 500) };
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
