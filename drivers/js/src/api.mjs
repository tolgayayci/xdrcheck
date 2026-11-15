// L4: the SDK-neutral api operations (the manifest schema's apiOp list) mapped onto @stellar/stellar-sdk 17.x,
// and strkey texts. Arguments are the manifest entry's api.input, verbatim, in the canonical vocabulary of the
// driver protocol (docs/conformance-protocol.md): exactly the names below, no aliases.
//
//   {"native": "number", "value": "<decimal>"}   a JavaScript number literal, built as an application would
//                                                write it (already rounded before the SDK sees it)
//   {"native": "bigint" | "string", "value": …}  a BigInt or a string; a bare JSON string is a native string
//   {"hex": …} or {"native": "bytes", "hex": …}  a plain Uint8Array; a plain string under a name ending _hex too
//
// Bytes always reach the SDK as plain Uint8Array. Arguments per op ([…] optional):
//
//   asset.compare            asset_a, asset_b                         → value: -1, 0 or 1
//   liquidity_pool.id        asset_a, asset_b, [fee = 30]             → value: pool ID hex
//   liquidity_pool.asset     asset_a, asset_b, [fee = 30]             → value: pool ID hex, xdr_hex: ChangeTrustAsset
//   muxed_account.encode     account (G…), id                         → value: M…, xdr_hex: MuxedAccount
//   muxed_account.decode     text (M…)                                → value: {account, id}
//   offer.manage_sell / _buy offer_id, [selling = native], [buying = USD:GA7Q…VSGZ], [amount = "1"], [price = "1"]
//                                                                     → value: offer ID read back, xdr_hex: Operation
//   scval.from_native        value (JSON, tagged leaves), [type]      → value: map keys "<arm>:<text>" or the key,
//                                                                       xdr_hex: ScVal
//   scval.sort_map           keys ("u32:10", "bytes:0a", "symbol:a", "string:b", … or {"xdr_hex"})
//                                                                     → value: keys in resulting order, xdr_hex
//   scval.to_native          xdr_hex (ScVal)                          → value: the native value as JSON
//                                                                       ({"map_entries": n} for a map)
//   scval.native_roundtrip   xdr_hex (ScVal), [type]                  → value: bytes_preserved, xdr_hex: the ScVal
//   strkey.encode            type, payload_hex                        → value: strkey
//   strkey.decode            text, [type]                             → value: payload hex
//   transaction.parse        xdr_hex (TransactionEnvelope), passphrase → value: {tx_hash, operations}, xdr_hex
//   transaction.hash         xdr_hex, passphrase                      → value: hash hex
//   memo.text_roundtrip      xdr_hex (Memo)                           → value: hex of the native text's bytes,
//                                                                       xdr_hex: the Memo rebuilt from it
//   address.to_strkey        xdr_hex, [xdr_type = MuxedAccount | AccountId] → value: strkey
//   address.from_sc_address  xdr_hex (ScAddress)                      → value: strkey
//   signer_key.to_strkey     xdr_hex (SignerKey)                      → value: strkey
//   operation.object_roundtrip xdr_hex (Operation)                    → value: bytes_preserved, xdr_hex: rebuilt
//   asset.from_operation     xdr_hex (Asset)                          → value: {type, code, issuer}
//
//   xdr.custom_union_encode  switch_on, cases, discriminant, [value]  → value: the discriminant read back,
//                                                                       xdr_hex: the encoded union (js-xdr's
//                                                                       own schema API: union, case, field)
//
// self_decode (the SDK's own decoder on its own output) accompanies every xdr_hex and every strkey produced; an
// output the SDK's own decoder refuses is diverge/own_output_rejected. A missing, unknown or malformed argument
// is not an SDK outcome: ArgError, which the driver answers as a protocol error. A declared op never answers
// op_not_supported; a sub-case this SDK version has no function for is n_a/type_not_generated. A tagged
// argument whose kind the SDK's TypeScript declaration of that parameter does not take (read from the installed
// package by sdk.mjs: the muxed-account ID is declared a string, the offer ID number | string, from 17.3.0 also
// bigint) is n_a/argument_type_not_accepted, decided before the call. xdrjson.decode and price.encode are not
// offered (n_a / op_not_supported).
import { decodeCode, objectCode, strkeyCode, isFault, reason } from "./errors.mjs";
import { hex, fromHex, jsonable, bytesEqual, scalarHint, toBase64 } from "./util.mjs";

const DEFAULT_ISSUER = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

/** A run outcome. */
export class Result {
  constructor(outcome, rsn, actual) {
    this.outcome = outcome;
    this.reason = rsn;
    this.actual = actual;
  }
}

/** A request the driver cannot understand (malformed, missing or unknown argument): a protocol error. */
export class ArgError extends Error {}

const DECIMAL = /^-?[0-9]+$/;
const NUMBER = /^-?[0-9]+(\.[0-9]+)?$/;

/** Build the native JavaScript value a tagged argument stands for. */
export function nativeArg(v, name = "argument") {
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    if ("native" in v) {
      const keys = Object.keys(v).sort().join(",");
      if (v.native === "bytes") {
        if (keys !== "hex,native") throw new ArgError(`${name}: a bytes tag is {"native":"bytes","hex":…}`);
        return bytesOf(v.hex, name);
      }
      if (keys !== "native,value") throw new ArgError(`${name}: a native tag is {"native":…,"value":…}`);
      const s = v.value;
      switch (v.native) {
        case "number":
          if (typeof s !== "string" || !NUMBER.test(s)) throw new ArgError(`${name}: a number tag needs a decimal value`);
          return Number(s);
        case "bigint":
          if (typeof s !== "string" || !DECIMAL.test(s)) throw new ArgError(`${name}: a bigint tag needs a decimal integer value`);
          return BigInt(s);
        case "string":
          if (typeof s !== "string") throw new ArgError(`${name}: a string tag needs a string value`);
          return s;
      }
      throw new ArgError(`${name}: unknown native tag ${JSON.stringify(v.native)}`);
    }
    if (Object.keys(v).length === 1 && "hex" in v) return bytesOf(v.hex, name);
  }
  return v;
}

function bytesOf(h, name) {
  if (typeof h !== "string" || !/^([0-9a-f]{2})*$/.test(h)) throw new ArgError(`${name}: not lower-case hex`);
  return fromHex(h);
}

/** A string argument: a bare string or a string tag. */
function str(args, name) {
  const v = nativeArg(args[name], name);
  if (typeof v !== "string") throw new ArgError(`${name}: want a string`);
  return v;
}

/** A byte argument: {"hex"}, a bytes tag, or a plain hex string under a name ending _hex. */
function bytes(args, name) {
  const v = args[name];
  if (typeof v === "string" && name.endsWith("_hex")) return bytesOf(v, name);
  const n = nativeArg(v, name);
  if (!(n instanceof Uint8Array)) throw new ArgError(`${name}: want bytes`);
  return n;
}

/** A numeric argument: a number, string or bigint tag, or a bare decimal string. */
function num(args, name) {
  const v = nativeArg(args[name], name);
  if (typeof v === "number" || typeof v === "bigint") return v;
  if (typeof v === "string") return v; // the SDK decides what a string means
  throw new ArgError(`${name}: want a tagged number or a string`);
}

/** Check the argument names: required ones present, nothing else. */
function argNames(op, args, required, optional = []) {
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new ArgError(`${op}: args must be an object`);
  for (const r of required) if (!(r in args)) throw new ArgError(`${op}: argument ${r} is required`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(args)) if (!allowed.has(k)) throw new ArgError(`${op}: unknown argument ${k}`);
}

/** Decode tagged values anywhere inside a JSON value (for scval.from_native). */
function nativeDeep(v, name) {
  if (v !== null && typeof v === "object" && !Array.isArray(v) && ("native" in v || (Object.keys(v).length === 1 && "hex" in v))) {
    return nativeArg(v, name);
  }
  if (Array.isArray(v)) return v.map((x) => nativeDeep(x, name));
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, nativeDeep(x, name)]));
  return v;
}

export const STRKEY = {
  account: ["encodeEd25519PublicKey", "decodeEd25519PublicKey"],
  muxed_account: ["encodeMed25519PublicKey", "decodeMed25519PublicKey"],
  secret_seed: ["encodeEd25519SecretSeed", "decodeEd25519SecretSeed"],
  pre_auth_tx: ["encodePreAuthTx", "decodePreAuthTx"],
  hash_x: ["encodeSha256Hash", "decodeSha256Hash"],
  signed_payload: ["encodeSignedPayload", "decodeSignedPayload"],
  contract: ["encodeContract", "decodeContract"],
  muxed_contract: ["encodeMuxedContract", "decodeMuxedContract"],
  liquidity_pool: ["encodeLiquidityPool", "decodeLiquidityPool"],
  claimable_balance: ["encodeClaimableBalance", "decodeClaimableBalance"],
};
const BY_LETTER = { G: "account", M: "muxed_account", S: "secret_seed", T: "pre_auth_tx", X: "hash_x", P: "signed_payload", C: "contract", W: "muxed_contract", L: "liquidity_pool", B: "claimable_balance" };

/** Strkey text → payload (the strkey entry kind, and strkey.decode). */
export function strkeyDecode(S, text, declared) {
  if (typeof text !== "string") throw new ArgError("text: want a string");
  let type = declared;
  if (type === undefined || type === null) {
    // The letter decides which decoder an application would call; a non-ASCII first character is folded to
    // its low byte, so look-alike letters still reach a decoder (which must refuse them).
    const c = String.fromCharCode(String(text).charCodeAt(0) & 0xff).toUpperCase();
    type = BY_LETTER[c] ?? "account";
  }
  const names = STRKEY[type];
  if (!names) throw new ArgError(`unknown strkey type ${JSON.stringify(type)}`);
  const fn = S.StrKey[names[1]];
  if (typeof fn !== "function") return new Result("n_a", { code: "type_not_generated", message: `no StrKey.${names[1]} in this version` });
  try {
    return new Result("ok", undefined, { api: { value: hex(fn.call(S.StrKey, text)) } });
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("reject", reason(strkeyCode(e), e, `StrKey.${names[1]}`));
  }
}

/** Whether the SDK's own strkey decoder (chosen by the text's letter) accepts a strkey it produced. */
function strkeySelf(S, text) {
  const names = STRKEY[BY_LETTER[String(text)[0]] ?? ""];
  const fn = names && S.StrKey[names[1]];
  if (typeof fn !== "function") return "not_checked";
  try {
    fn.call(S.StrKey, text);
    return "accepted";
  } catch (e) {
    if (isFault(e)) throw e;
    return "rejected";
  }
}

/** The kind a tagged argument passes (number, string, bigint), or undefined for anything else. */
function tagKind(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
  return ["number", "string", "bigint"].includes(v.native) ? v.native : undefined;
}

// js-xdr schema constructors for xdr.custom_union_encode, by XDR type name.
const SWITCH_TYPES = { int: "int32", "unsigned int": "uint32", hyper: "int64", "unsigned hyper": "uint64", float: "float", double: "double", bool: "bool" };

/**
 * xdr.custom_union_encode on js-xdr 5: define union U over switch_on with the given cases, encode the selected
 * discriminant (and value), decode it back with the same schema.
 */
function customUnion(X, a) {
  const typeOf = (name, what) => {
    const ctor = typeof name === "string" && Object.hasOwn(SWITCH_TYPES, name) ? X[SWITCH_TYPES[name]] : undefined;
    if (typeof ctor !== "function") throw new ArgError(`${what}: ${JSON.stringify(name)} is not one of ${Object.keys(SWITCH_TYPES).join(", ")}`);
    return ctor();
  };
  if (!Array.isArray(a.cases) || a.cases.length === 0) throw new ArgError("cases: want a non-empty list");
  const specs = a.cases.map((c, i) => {
    if (c === null || typeof c !== "object" || Object.keys(c).sort().join(",") !== "arm,discriminant") throw new ArgError(`cases[${i}]: want {"discriminant", "arm"}`);
    if (!tagKind(c.discriminant)) throw new ArgError(`cases[${i}].discriminant: want a tagged number`);
    return { name: `c${i}`, disc: nativeArg(c.discriminant, `cases[${i}].discriminant`), arm: c.arm === "void" ? null : c.arm };
  });
  if (!tagKind(a.discriminant)) throw new ArgError("discriminant: want a tagged number");
  const disc = nativeArg(a.discriminant, "discriminant");
  const ep = "js-xdr union";
  let U;
  try {
    const switchOn = typeOf(a.switch_on, "switch_on");
    const mkCase = X.unionCase ?? X.case;
    U = X.union("U", { switchOn, cases: specs.map((c) => mkCase(c.name, c.disc, c.arm === null ? X.void() : X.field("value", typeOf(c.arm, `arm ${c.name}`)))) });
  } catch (e) {
    if (isFault(e) || e instanceof ArgError) throw e;
    return new Result("reject", reason(objectCode(e, "other"), e, ep));
  }
  const val = { type: disc };
  if ("value" in a) val.value = nativeArg(a.value, "value");
  let b;
  try {
    b = U.encode(val);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("reject", reason(objectCode(e, "other"), e, "js-xdr UnionType.encode"));
  }
  let back;
  try {
    back = U.decode(b);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("diverge", reason("own_output_rejected", e, "js-xdr UnionType.decode"), { api: { xdr_hex: hex(b), self_decode: "rejected" } });
  }
  return { value: String(back.type), xdr_hex: hex(b), self_decode: "accepted" };
}

export function makeAPI(S, { argTypes = {}, jsxdr } = {}) {
  const { xdr } = S;

  const asset = (args, name, dflt) => {
    const a = name in args ? str(args, name) : dflt;
    if (a === "native") return S.Asset.native();
    const i = a.lastIndexOf(":");
    if (i <= 0 || i === a.length - 1) throw new ArgError(`${name}: ${a}: want native or CODE:ISSUER`);
    return new S.Asset(a.slice(0, i), a.slice(i + 1));
  };
  const fee = (args) => ("fee" in args ? Number(num(args, "fee")) : S.LiquidityPoolFeeV18);
  const xdrArg = (args, name) => {
    const T = xdr[name];
    if (!T || !T.schema) return undefined;
    return { T, bytes: bytes(args, "xdr_hex"), name };
  };
  // The decode step of an op is the XDR layer, not the API under test: a refusal there is reported with the
  // decode reason and entry point.
  const decode = (T, b, name) => {
    try {
      return T.fromXdr(b);
    } catch (e) {
      if (isFault(e)) throw e;
      throw Object.assign(e, { decodeEntryPoint: `xdr.${name}.fromXdr` });
    }
  };
  const keyText = (sv) => {
    const t = sv.type.replace(/^scv/, "").toLowerCase();
    let v = sv.value;
    if (t === "bytes") v = hex(v.toBytes ? v.toBytes() : v);
    else if (v instanceof Uint8Array) v = hex(v);
    else v = v && v.toString ? v.toString() : String(v);
    return `${t}:${v}`;
  };
  const KEY_TYPES = new Set(["u32", "i32", "u64", "i64", "u128", "i128", "u256", "i256", "bytes", "symbol", "string"]);
  const mkKey = (spec) => {
    if (spec && typeof spec === "object" && !Array.isArray(spec)) {
      if (Object.keys(spec).join(",") !== "xdr_hex") throw new ArgError(`keys: a key is "<type>:<text>" or {"xdr_hex"}`);
      return decode(xdr.ScVal, bytesOf(spec.xdr_hex, "keys"), "ScVal");
    }
    if (typeof spec !== "string" || spec.indexOf(":") < 0) throw new ArgError(`keys: ${JSON.stringify(spec)}: want "<type>:<text>"`);
    const i = spec.indexOf(":");
    const [t, v] = [spec.slice(0, i), spec.slice(i + 1)];
    if (!KEY_TYPES.has(t)) throw new ArgError(`keys: unknown key type ${t}`);
    switch (t) {
      case "u32":
        return xdr.ScVal.scvU32(Number(v));
      case "i32":
        return xdr.ScVal.scvI32(Number(v));
      case "bytes":
        return xdr.ScVal.scvBytes(bytesOf(v, "keys")); // a plain Uint8Array, as the v17 API takes bytes
      case "symbol":
        return xdr.ScVal.scvSymbol(v);
      case "string":
        return xdr.ScVal.scvString(v);
      default:
        return S.nativeToScVal(v, { type: t });
    }
  };
  const mapKeys = (sv) => (sv.type === "scvMap" ? sv.value.map((e) => keyText(e.key)) : keyText(sv));
  const selfDecode = (T, b) => {
    try {
      T.fromXdr(b);
      return "accepted";
    } catch (e) {
      if (isFault(e)) throw e;
      return "rejected";
    }
  };
  const xdrOut = (T, b) => ({ xdr_hex: hex(b), self_decode: selfDecode(T, b) });
  const strkeyOut = (text) => ({ value: text, self_decode: strkeySelf(S, text) });

  const offer = (args, buy) => {
    const p = {
      selling: asset(args, "selling", "native"),
      buying: asset(args, "buying", `USD:${DEFAULT_ISSUER}`),
      price: "price" in args ? String(num(args, "price")) : "1",
      offerId: num(args, "offer_id"),
    };
    const amount = "amount" in args ? String(num(args, "amount")) : "1";
    if (buy) p.buyAmount = amount;
    else p.amount = amount;
    const ep = buy ? "Operation.manageBuyOffer" : "Operation.manageSellOffer";
    let op;
    try {
      op = buy ? S.Operation.manageBuyOffer(p) : S.Operation.manageSellOffer(p);
    } catch (e) {
      if (isFault(e)) throw e;
      return new Result("reject", reason(objectCode(e, "other"), e, ep));
    }
    const b = op.toXdr();
    let back;
    try {
      back = S.Operation.fromXdrObject(xdr.Operation.fromXdr(b));
    } catch (e) {
      if (isFault(e)) throw e;
      return new Result("diverge", reason("own_output_rejected", e, "Operation.fromXdrObject"), { api: { xdr_hex: hex(b), self_decode: "rejected" } });
    }
    return { value: String(back.offerId), xdr_hex: hex(b), self_decode: "accepted" };
  };
  const envelope = (args) => {
    const b = bytes(args, "xdr_hex");
    return [toBase64(b), str(args, "passphrase")];
  };

  // op → [entry point, required args, optional args, fn(args) → api result object or Result]
  const OPS = {
    "asset.compare": ["Asset.compare", ["asset_a", "asset_b"], [], (a) => ({ value: S.Asset.compare(asset(a, "asset_a"), asset(a, "asset_b")) })],
    "liquidity_pool.id": ["getLiquidityPoolId", ["asset_a", "asset_b"], ["fee"], (a) => ({
      value: hex(S.getLiquidityPoolId("constant_product", { assetA: asset(a, "asset_a"), assetB: asset(a, "asset_b"), fee: fee(a) })),
    })],
    "liquidity_pool.asset": ["LiquidityPoolAsset", ["asset_a", "asset_b"], ["fee"], (a) => {
      const lpa = new S.LiquidityPoolAsset(asset(a, "asset_a"), asset(a, "asset_b"), fee(a));
      const b = lpa.toXdrObject().toXdr();
      return { value: hex(S.getLiquidityPoolId("constant_product", lpa.getLiquidityPoolParameters())), ...xdrOut(xdr.ChangeTrustAsset, b) };
    }],
    "muxed_account.encode": ["MuxedAccount", ["account", "id"], [], (a) => {
      const m = new S.MuxedAccount(new S.Account(str(a, "account"), "0"), num(a, "id"));
      const b = m.toXdrObject().toXdr();
      const text = m.accountId();
      const xo = xdrOut(xdr.MuxedAccount, b);
      const so = strkeyOut(text);
      return { value: text, xdr_hex: xo.xdr_hex, self_decode: xo.self_decode === "rejected" || so.self_decode === "rejected" ? "rejected" : "accepted" };
    }],
    "muxed_account.decode": ["MuxedAccount.fromAddress", ["text"], [], (a) => {
      const m = S.MuxedAccount.fromAddress(str(a, "text"), "0");
      return { value: { account: m.baseAccount().accountId(), id: String(m.id()) } };
    }],
    "offer.manage_sell": ["Operation.manageSellOffer", ["offer_id"], ["selling", "buying", "amount", "price"], (a) => offer(a, false)],
    "offer.manage_buy": ["Operation.manageBuyOffer", ["offer_id"], ["selling", "buying", "amount", "price"], (a) => offer(a, true)],
    "scval.from_native": ["nativeToScVal", ["value"], ["type"], (a) => {
      const opts = "type" in a ? { type: a.type } : undefined;
      const sv = S.nativeToScVal(nativeDeep(a.value, "value"), opts);
      return { value: mapKeys(sv), ...xdrOut(xdr.ScVal, sv.toXdr()) };
    }],
    "scval.sort_map": ["scvSortedMap", ["keys"], [], (a) => {
      if (!Array.isArray(a.keys)) throw new ArgError("keys: want a list");
      const sv = S.scvSortedMap(a.keys.map((k) => new xdr.ScMapEntry({ key: mkKey(k), val: xdr.ScVal.scvVoid() })));
      return { value: mapKeys(sv), ...xdrOut(xdr.ScVal, sv.toXdr()) };
    }],
    "scval.to_native": ["scValToNative", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "ScVal");
      const sv = decode(T, b, name);
      const n = S.scValToNative(sv);
      if (sv.type === "scvMap") return { value: { map_entries: n instanceof Map ? n.size : n && typeof n === "object" ? Object.keys(n).length : 0 } };
      return { value: jsonable(n) };
    }],
    "scval.native_roundtrip": ["scValToNative + nativeToScVal", ["xdr_hex"], ["type"], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "ScVal");
      const sv = decode(T, b, name);
      const n = S.scValToNative(sv);
      const hint = "type" in a ? str(a, "type") : scalarHint(sv);
      const back = (hint ? S.nativeToScVal(n, { type: hint }) : S.nativeToScVal(n)).toXdr();
      return { value: bytesEqual(back, b), ...xdrOut(xdr.ScVal, back) };
    }],
    "strkey.encode": ["StrKey.encode*", ["type", "payload_hex"], [], (a) => {
      const type = str(a, "type");
      const names = STRKEY[type];
      if (!names) throw new ArgError(`type: unknown strkey type ${type}`);
      const enc = S.StrKey[names[0]];
      const dec = S.StrKey[names[1]];
      if (typeof enc !== "function") return new Result("n_a", { code: "type_not_generated", message: `no StrKey.${names[0]} in this version` });
      const payload = bytes(a, "payload_hex");
      let text;
      try {
        text = enc.call(S.StrKey, payload);
      } catch (e) {
        if (isFault(e)) throw e;
        return new Result("reject", reason(objectCode(e, "strkey_payload"), e, `StrKey.${names[0]}`));
      }
      let back;
      try {
        back = dec.call(S.StrKey, text);
      } catch (e) {
        if (isFault(e)) throw e;
        return new Result("diverge", reason("own_output_rejected", e, `StrKey.${names[0]}`), { api: { value: text, self_decode: "rejected" } });
      }
      if (!bytesEqual(back, payload)) {
        return new Result("diverge", { code: "own_output_rejected", message: `StrKey.${names[1]} returned ${hex(back)}`, entry_point: `StrKey.${names[0]}` }, { api: { value: text, self_decode: "rejected" } });
      }
      return { value: text, self_decode: "accepted" };
    }],
    "strkey.decode": ["StrKey.decode*", ["text"], ["type"], (a) => strkeyDecode(S, str(a, "text"), "type" in a ? str(a, "type") : undefined)],
    "transaction.parse": ["TransactionBuilder.fromXdr", ["xdr_hex", "passphrase"], [], (a) => {
      const tx = S.TransactionBuilder.fromXdr(...envelope(a));
      const ops = tx.innerTransaction ? tx.innerTransaction.operations : tx.operations;
      return { value: { tx_hash: hex(tx.hash()), operations: ops.length }, ...xdrOut(xdr.TransactionEnvelope, tx.toEnvelope().toXdr()) };
    }],
    "transaction.hash": ["Transaction.hash", ["xdr_hex", "passphrase"], [], (a) => {
      const tx = S.TransactionBuilder.fromXdr(...envelope(a));
      return { value: hex(tx.hash()) };
    }],
    "memo.text_roundtrip": ["Memo.fromXdrObject", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "Memo");
      const m = S.Memo.fromXdrObject(decode(T, b, name));
      const v = m.value;
      const held = v instanceof Uint8Array ? v : typeof v === "string" ? new TextEncoder().encode(v) : new TextEncoder().encode(String(v ?? ""));
      const back = (m.type === "text" ? S.Memo.text(v) : new S.Memo(m.type, v)).toXdrObject().toXdr();
      return { value: hex(held), ...xdrOut(xdr.Memo, back) };
    }],
    "address.to_strkey": ["encodeMuxedAccountToAddress", ["xdr_hex"], ["xdr_type"], (a) => {
      const tn = "xdr_type" in a ? str(a, "xdr_type") : "MuxedAccount";
      if (tn !== "MuxedAccount" && tn !== "AccountId") throw new ArgError(`xdr_type: want MuxedAccount or AccountId, not ${tn}`);
      const { T, bytes: b, name } = xdrArg(a, tn);
      const v = decode(T, b, name);
      if (name === "MuxedAccount") return strkeyOut(S.encodeMuxedAccountToAddress(v));
      return strkeyOut(S.StrKey.encodeEd25519PublicKey(v.value()));
    }],
    "address.from_sc_address": ["Address.fromScAddress", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "ScAddress");
      return strkeyOut(S.Address.fromScAddress(decode(T, b, name)).toString());
    }],
    "signer_key.to_strkey": ["SignerKey.encodeSignerKey", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "SignerKey");
      const text = S.SignerKey.encodeSignerKey(decode(T, b, name));
      try {
        S.SignerKey.decodeAddress(text);
      } catch (e) {
        if (isFault(e)) throw e;
        return new Result("diverge", reason("own_output_rejected", e, "SignerKey.encodeSignerKey"), { api: { value: text, self_decode: "rejected" } });
      }
      return { value: text, self_decode: "accepted" };
    }],
    "operation.object_roundtrip": ["Operation.fromXdrObject", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "Operation");
      const o = S.Operation.fromXdrObject(decode(T, b, name));
      const build = S.Operation[o.type];
      if (typeof build !== "function") return new Result("n_a", { code: "type_not_generated", message: `no Operation.${o.type} builder` });
      const back = build.call(S.Operation, o).toXdr();
      return { value: bytesEqual(back, b), ...xdrOut(xdr.Operation, back) };
    }],
    "xdr.custom_union_encode": ["js-xdr union", ["switch_on", "cases", "discriminant"], ["value"], (a) => customUnion(jsxdr, a)],
    "asset.from_operation": ["Asset.fromOperation", ["xdr_hex"], [], (a) => {
      const { T, bytes: b, name } = xdrArg(a, "Asset");
      const as = S.Asset.fromOperation(decode(T, b, name));
      const v = { type: as.getAssetType(), code: as.getCode() };
      if (as.getIssuer()) v.issuer = as.getIssuer();
      return { value: v };
    }],
  };

  return {
    ops: Object.keys(OPS).sort(),
    // Throws ArgError for a request the driver cannot understand.
    run(op, args) {
      const o = OPS[op];
      if (!o) return new Result("n_a", { code: "op_not_supported", message: `api op ${op} is not implemented for the v17 API` });
      argNames(op, args, o[1], o[2]);
      for (const [name, kinds] of Object.entries(argTypes[op] ?? {})) {
        const k = tagKind(args[name]);
        if (k && !kinds.has(k)) {
          return new Result("n_a", { code: "argument_type_not_accepted", message: `the SDK declares ${name} as ${[...kinds].join(" | ")}; a ${k} cannot be passed`, entry_point: o[0] });
        }
      }
      try {
        const r = o[3](args);
        if (r instanceof Result) return r;
        if (r.self_decode === "rejected") {
          return new Result("diverge", { code: "own_output_rejected", message: "the SDK's own decoder refuses its output", entry_point: o[0] }, { api: r });
        }
        return new Result("ok", undefined, { api: r });
      } catch (e) {
        if (isFault(e) || e instanceof ArgError) throw e;
        if (e.decodeEntryPoint) return new Result("reject", reason(decodeCode(e), e, e.decodeEntryPoint));
        const code = op.startsWith("strkey.") ? "other" : objectCode(e, "other");
        return new Result("reject", reason(code, e, o[0]));
      }
    },
  };
}
