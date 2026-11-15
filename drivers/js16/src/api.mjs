// L4: the SDK-neutral api operations (the manifest schema's apiOp list) mapped onto @stellar/stellar-sdk 16.x,
// and strkey texts. Arguments and results follow the canonical api vocabulary exactly, with no aliases:
//
//   bytes      {"hex": …} or {"native":"bytes","hex": …}, or a plain hex string under a name ending in _hex
//   numbers    {"native":"number"|"string"|"bigint","value":"<decimal>"}; a bare string is a native string.
//              A number is built as an application would write it (9007199254740993 is already …992 when the
//              SDK sees it); JavaScript can hold every tagged value, so nothing is value_not_representable
//   assets     "native" or "CODE:ISSUER"; IDs in results are decimal strings, hashes and pool IDs lower-case hex
//   self_decode  whenever an op produces XDR or a strkey: does the SDK's own decoder accept it ("not_checked"
//              when the SDK has no decoder for it); a rejection is outcome diverge / own_output_rejected
//
//   op                         arguments ([optional])                               value; xdr_hex
//   asset.compare              asset_a, asset_b                                     -1, 0 or 1
//   liquidity_pool.id          asset_a, asset_b, [fee=30]                           pool ID hex
//   liquidity_pool.asset       asset_a, asset_b, [fee=30]                           pool ID hex; ChangeTrustAsset
//   muxed_account.encode       account (G…), id (tagged)                            M…; MuxedAccount
//   muxed_account.decode       text (M…)                                            {account, id}
//   offer.manage_sell / _buy   offer_id (tagged), [selling=native],                 offer ID read back; Operation
//                              [buying=USD:GA7Q…VSGZ], [amount="1"], [price="1"]
//   scval.from_native          value (JSON, tagged leaves), [type]                  map keys "<arm>:<text>" or the
//                                                                                   single key; ScVal
//   scval.sort_map             keys ("u32:10", "bytes:0a", "symbol:a", "string:b", {"xdr_hex"})
//                                                                                   keys in resulting order; ScVal
//   scval.to_native            xdr_hex (ScVal)                                      {"map_entries": n} for a map,
//                                                                                   else the native value as JSON
//   scval.native_roundtrip     xdr_hex (ScVal), [type]                              bytes_preserved; the ScVal made
//   strkey.encode              type, payload_hex                                    strkey text
//   strkey.decode              text, [type]                                         payload hex
//   transaction.parse          xdr_hex (TransactionEnvelope), passphrase            {tx_hash, operations}; envelope
//   transaction.hash           xdr_hex, passphrase                                  hash hex
//   memo.text_roundtrip        xdr_hex (Memo)                                       hex of the native text's bytes;
//                                                                                   the re-encoded Memo
//   address.to_strkey          xdr_hex, [xdr_type=MuxedAccount | AccountId]         strkey
//   address.from_sc_address    xdr_hex (ScAddress)                                  strkey
//   signer_key.to_strkey       xdr_hex (SignerKey)                                  strkey
//   operation.object_roundtrip xdr_hex (Operation)                                  bytes_preserved; rebuilt Operation
//   asset.from_operation       xdr_hex (Asset)                                      {type, code, issuer}
//
// A missing or malformed argument is the request's fault, answered with a protocol error; every op listed here
// answers ok, diverge, reject or crash (or n_a where the 16.x SDK lacks the function: StrKey has no muxed-contract
// codec, and Operation has no builder for some operation types). A tagged argument whose kind the SDK's
// TypeScript declaration of that parameter does not take (read from the installed package by sdk.mjs: the
// muxed-account ID is declared a string, the offer ID number | string) is n_a/argument_type_not_accepted,
// decided before the call. xdr.custom_union_encode (switch_on, cases, discriminant, [value] → the discriminant
// read back; the encoded union) uses the js-xdr copy bundled into the SDK (config, union). xdrjson.decode and
// price.encode are not offered and not listed in describe.
//
// v16 API against v17: xdr.<Type>.fromXDR / .toXDR, unions through switch() / value(), struct fields through
// accessor methods (ScMapEntry key()), TransactionBuilder.fromXDR, Operation.fromXDRObject, Memo.fromXDRObject,
// *.toXDRObject. Bytes reach the SDK as plain Uint8Array (driver obligation 6), never Buffer; what the SDK
// returns may be a Buffer and is rendered as hex.
import { decodeCode, objectCodeOf, strkeyCode, isFault, reason, locate } from "./errors.mjs";
import { hex, fromHex, u8, toBase64, jsonable, bytesEqual } from "./util.mjs";

const DEFAULT_ISSUER = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

/** A run outcome. */
export class Result {
  constructor(outcome, rsn, actual) {
    this.outcome = outcome;
    this.reason = rsn;
    this.actual = actual;
  }
}
const okv = (api) => new Result("ok", undefined, { api });

/** A malformed request: answered with a protocol error, never as an SDK outcome. */
export class ArgError extends Error {}

/** Build the native JavaScript value a tagged argument stands for. */
export function nativeArg(v) {
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    if ("native" in v) {
      switch (v.native) {
        case "number":
          return Number(v.value);
        case "bigint":
          try {
            return BigInt(v.value);
          } catch {
            throw new ArgError(`not an integer: ${String(v.value).slice(0, 40)}`);
          }
        case "string":
          return String(v.value);
        case "bool":
          return v.value === true || v.value === "true";
        case "bytes":
          return hexBytes(v.hex ?? v.value);
      }
      throw new ArgError(`unknown native tag ${v.native}`);
    }
    if (Object.keys(v).length === 1 && "hex" in v) return hexBytes(v.hex);
  }
  return v;
}

function hexBytes(h) {
  if (typeof h !== "string" || !/^([0-9a-fA-F]{2})*$/.test(h)) throw new ArgError(`not a hex string: ${String(h).slice(0, 40)}`);
  return fromHex(h);
}

/** Decode tagged values anywhere inside a JSON value (for scval.from_native). */
function nativeDeep(v) {
  const n = nativeArg(v);
  if (n !== v) return n;
  if (Array.isArray(v)) return v.map(nativeDeep);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, nativeDeep(x)]));
  return v;
}

function need(args, name) {
  if (!(name in args)) throw new ArgError(`argument ${name} is required`);
  return nativeArg(args[name]);
}

/** A string argument. */
function text(args, name) {
  const v = need(args, name);
  if (typeof v !== "string") throw new ArgError(`argument ${name} must be a string`);
  return v;
}

/** A bytes argument: {"hex"}, {"native":"bytes"} or, under a name ending in _hex, a plain hex string. */
function bytesArg(args, name) {
  const v = need(args, name);
  if (v instanceof Uint8Array) return v;
  if (typeof v === "string" && name.endsWith("_hex")) return hexBytes(v);
  throw new ArgError(`argument ${name} must be bytes`);
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

/** The strkey type an application would pick from a text's first letter. */
function typeOfText(t) {
  // A non-ASCII first character is folded to its low byte, so look-alike letters still reach a decoder (which
  // must refuse them).
  const c = String.fromCharCode(String(t).charCodeAt(0) & 0xff).toUpperCase();
  return BY_LETTER[c] ?? "account";
}

// The 16.x StrKey has no muxed-contract (W…) codec: the SDK has no API for it, which is n_a, not a refusal.
const absent = (S, fn) => new Result("n_a", { code: "type_not_generated", message: `no StrKey.${fn} in this version` });

/** Strkey text → payload (the strkey entry kind, and strkey.decode). */
export function strkeyDecode(S, t, declared) {
  const type = declared ?? typeOfText(t);
  const names = STRKEY[type];
  if (!names) throw new ArgError(`unknown strkey type ${type}`);
  const fn = S.StrKey[names[1]];
  if (typeof fn !== "function") return absent(S, names[1]);
  try {
    return okv({ value: hex(fn.call(S.StrKey, t)) });
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("reject", reason(strkeyCode(e), e, `StrKey.${names[1]}`));
  }
}

// The nativeToScVal type hint that names an ScVal's own arm, for the arms where JavaScript's native type alone
// does not decide it on the way back.
const SCALAR_HINTS = {
  scvString: "string", scvSymbol: "symbol", scvU32: "u32", scvI32: "i32", scvU64: "u64", scvI64: "i64",
  scvU128: "u128", scvI128: "i128", scvU256: "u256", scvI256: "i256", scvTimepoint: "timepoint",
  scvDuration: "duration", scvBytes: "bytes",
};
export const scalarHint = (sv) => SCALAR_HINTS[sv.switch().name];

/** The kind a tagged argument passes (number, string, bigint), or undefined for anything else. */
function tagKind(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
  return ["number", "string", "bigint"].includes(v.native) ? v.native : undefined;
}

// js-xdr 4 schema builders for xdr.custom_union_encode, by XDR type name.
const SWITCH_TYPES = { int: "int", "unsigned int": "uint", hyper: "hyper", "unsigned hyper": "uhyper", float: "float", double: "double", bool: "bool" };

/**
 * xdr.custom_union_encode on js-xdr 4 (the copy bundled into the SDK): define union U over switch_on with the
 * given cases through config(), encode the selected discriminant (and value), decode it back with the same type.
 */
function customUnion(config, a) {
  const typeOf = (x, name, what) => {
    if (typeof name !== "string" || !Object.hasOwn(SWITCH_TYPES, name)) throw new ArgError(`${what}: ${JSON.stringify(name)} is not one of ${Object.keys(SWITCH_TYPES).join(", ")}`);
    return x[SWITCH_TYPES[name]]();
  };
  if (!Array.isArray(a.cases) || a.cases.length === 0) throw new ArgError("cases: want a non-empty list");
  const specs = a.cases.map((c, i) => {
    if (c === null || typeof c !== "object" || Object.keys(c).sort().join(",") !== "arm,discriminant") throw new ArgError(`cases[${i}]: want {"discriminant", "arm"}`);
    if (!tagKind(c.discriminant)) throw new ArgError(`cases[${i}].discriminant: want a tagged number`);
    if (c.arm !== "void" && !Object.hasOwn(SWITCH_TYPES, c.arm)) throw new ArgError(`cases[${i}].arm: ${JSON.stringify(c.arm)} is not void or an XDR type name`);
    return { name: `c${i}`, disc: nativeArg(c.discriminant), arm: c.arm === "void" ? null : c.arm };
  });
  if (!tagKind(a.discriminant)) throw new ArgError("discriminant: want a tagged number");
  if (!("switch_on" in a) || !Object.hasOwn(SWITCH_TYPES, a.switch_on)) throw new ArgError(`switch_on: ${JSON.stringify(a.switch_on)} is not one of ${Object.keys(SWITCH_TYPES).join(", ")}`);
  const disc = nativeArg(a.discriminant);
  let U;
  try {
    U = config((x) => {
      const arms = {};
      for (const c of specs) if (c.arm !== null) arms[c.name] = typeOf(x, c.arm, `arm ${c.name}`);
      x.union("U", { switchOn: typeOf(x, a.switch_on, "switch_on"), switchName: "type", switches: specs.map((c) => [c.disc, c.arm === null ? x.void() : c.name]), arms });
    }).U;
  } catch (e) {
    if (isFault(e) || e instanceof ArgError) throw e;
    return new Result("reject", reason(objectCodeOf(e, "other"), e, "js-xdr config"));
  }
  let b;
  try {
    b = u8(U.toXDR(new U(disc, "value" in a ? nativeArg(a.value) : undefined)));
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("reject", reason(objectCodeOf(e, "other"), e, "js-xdr Union.toXDR"));
  }
  let back;
  try {
    back = U.fromXDR(b);
  } catch (e) {
    if (isFault(e)) throw e;
    return new Result("diverge", reason("own_output_rejected", e, "js-xdr Union.fromXDR"), { api: { xdr_hex: hex(b), self_decode: "rejected" } });
  }
  return { value: String(back.switch()), xdr_hex: hex(b), self_decode: "accepted" };
}

export function makeAPI(S, { argTypes = {}, xdrConfig } = {}) {
  const { xdr } = S;
  const XdrReader = S.cereal.XdrReader;

  const asset = (args, name) => {
    const a = text(args, name);
    if (a === "native") return S.Asset.native();
    const i = a.lastIndexOf(":");
    if (i < 0) throw new ArgError(`argument ${name}: want native or CODE:ISSUER`);
    return new S.Asset(a.slice(0, i), a.slice(i + 1));
  };
  const optAsset = (args, name, dflt) => (name in args ? asset(args, name) : asset({ [name]: dflt }, name));
  const fee = (args) => ("fee" in args ? Number(nativeArg(args.fee)) : S.LiquidityPoolFeeV18);
  const xdrArg = (args, typeName) => ({ T: xdr[typeName], bytes: bytesArg(args, "xdr_hex"), name: typeName });
  // The decode step of an op is the XDR layer, not the API under test: a refusal there is reported with the
  // decode reason and entry point.
  const decode = (T, bytes, name) => {
    try {
      return T.fromXDR(bytes);
    } catch (e) {
      if (isFault(e)) throw e;
      throw Object.assign(e, { decodeEntryPoint: `xdr.${name}.fromXDR`, decodeCode: decodeCode(e, () => locate(T, bytes, XdrReader)) });
    }
  };
  const keyText = (sv) => {
    const t = sv.switch().name.replace(/^scv/, "").toLowerCase();
    let v = sv.value();
    if (t === "bytes") v = hex(v.toBytes ? v.toBytes() : v);
    else if (v instanceof Uint8Array) v = hex(v);
    else v = v && v.toString ? v.toString() : String(v);
    return `${t}:${v}`;
  };
  const mkKey = (spec) => {
    if (spec && typeof spec === "object" && "xdr_hex" in spec) return xdr.ScVal.fromXDR(bytesArg(spec, "xdr_hex"));
    if (typeof spec !== "string" || !spec.includes(":")) throw new ArgError(`map key ${JSON.stringify(spec)}: want "<arm>:<text>"`);
    const i = spec.indexOf(":");
    const [t, v] = [spec.slice(0, i), spec.slice(i + 1)];
    switch (t) {
      case "u32":
        return xdr.ScVal.scvU32(Number(v));
      case "i32":
        return xdr.ScVal.scvI32(Number(v));
      case "bytes":
        return xdr.ScVal.scvBytes(hexBytes(v)); // a plain Uint8Array: a Buffer would hide the byte-key ordering defect
      case "symbol":
        return xdr.ScVal.scvSymbol(v);
      case "string":
        return xdr.ScVal.scvString(v);
      default:
        return S.nativeToScVal(v, { type: t });
    }
  };
  const mapKeys = (sv) => (sv.switch().name === "scvMap" ? sv.value().map((e) => keyText(e.key())) : keyText(sv));
  const selfDecode = (T, bytes) => {
    try {
      T.fromXDR(bytes);
      return "accepted";
    } catch (e) {
      if (isFault(e)) throw e;
      return "rejected";
    }
  };
  const selfStrkey = (t) => {
    const fn = S.StrKey[STRKEY[typeOfText(t)][1]];
    if (typeof fn !== "function") return "not_checked";
    try {
      fn.call(S.StrKey, t);
      return "accepted";
    } catch (e) {
      if (isFault(e)) throw e;
      return "rejected";
    }
  };
  const strkeyResult = (t) => ({ value: t, self_decode: selfStrkey(t) });

  const offer = (args, buy) => {
    const p = {
      selling: optAsset(args, "selling", "native"),
      buying: optAsset(args, "buying", `USD:${DEFAULT_ISSUER}`),
      price: String(nativeArg(args.price ?? "1")),
      offerId: need(args, "offer_id"),
    };
    const amount = String(nativeArg(args.amount ?? "1"));
    if (buy) p.buyAmount = amount;
    else p.amount = amount;
    const ep = buy ? "Operation.manageBuyOffer" : "Operation.manageSellOffer";
    let op;
    try {
      op = buy ? S.Operation.manageBuyOffer(p) : S.Operation.manageSellOffer(p);
    } catch (e) {
      if (isFault(e)) throw e;
      return new Result("reject", reason(objectCodeOf(e, "other"), e, ep));
    }
    const bytes = u8(op.toXDR());
    let back;
    try {
      back = S.Operation.fromXDRObject(xdr.Operation.fromXDR(bytes));
    } catch (e) {
      if (isFault(e)) throw e;
      return new Result("diverge", reason("own_output_rejected", e, "Operation.fromXDRObject"), { api: { xdr_hex: hex(bytes), self_decode: "rejected" } });
    }
    return { value: String(back.offerId), xdr_hex: hex(bytes), self_decode: "accepted" };
  };

  // op → [entry point, fn(args) → api result object or Result]
  const OPS = {
    "asset.compare": ["Asset.compare", (a) => ({ value: S.Asset.compare(asset(a, "asset_a"), asset(a, "asset_b")) })],
    "liquidity_pool.id": ["getLiquidityPoolId", (a) => ({
      value: hex(S.getLiquidityPoolId("constant_product", { assetA: asset(a, "asset_a"), assetB: asset(a, "asset_b"), fee: fee(a) })),
    })],
    "liquidity_pool.asset": ["LiquidityPoolAsset", (a) => {
      const lpa = new S.LiquidityPoolAsset(asset(a, "asset_a"), asset(a, "asset_b"), fee(a));
      const bytes = u8(lpa.toXDRObject().toXDR());
      return { value: hex(S.getLiquidityPoolId("constant_product", lpa.getLiquidityPoolParameters())), xdr_hex: hex(bytes), self_decode: selfDecode(xdr.ChangeTrustAsset, bytes) };
    }],
    "muxed_account.encode": ["MuxedAccount", (a) => {
      const m = new S.MuxedAccount(new S.Account(text(a, "account"), "0"), need(a, "id"));
      const bytes = u8(m.toXDRObject().toXDR());
      const self = selfDecode(xdr.MuxedAccount, bytes) === "accepted" ? selfStrkey(m.accountId()) : "rejected";
      return { value: m.accountId(), xdr_hex: hex(bytes), self_decode: self };
    }],
    "muxed_account.decode": ["MuxedAccount.fromAddress", (a) => {
      const m = S.MuxedAccount.fromAddress(text(a, "text"), "0");
      return { value: { account: m.baseAccount().accountId(), id: String(m.id()) } };
    }],
    "offer.manage_sell": ["Operation.manageSellOffer", (a) => offer(a, false)],
    "offer.manage_buy": ["Operation.manageBuyOffer", (a) => offer(a, true)],
    "scval.from_native": ["nativeToScVal", (a) => {
      const opts = "type" in a ? { type: a.type } : undefined;
      const sv = S.nativeToScVal(nativeDeep(need(a, "value")), opts);
      const bytes = u8(sv.toXDR());
      return { value: mapKeys(sv), xdr_hex: hex(bytes), self_decode: selfDecode(xdr.ScVal, bytes) };
    }],
    "scval.sort_map": ["scvSortedMap", (a) => {
      const keys = a.keys;
      if (!Array.isArray(keys)) throw new ArgError("argument keys must be a list");
      const sv = S.scvSortedMap(keys.map((k) => new xdr.ScMapEntry({ key: mkKey(k), val: xdr.ScVal.scvVoid() })));
      const bytes = u8(sv.toXDR());
      return { value: mapKeys(sv), xdr_hex: hex(bytes), self_decode: selfDecode(xdr.ScVal, bytes) };
    }],
    "scval.to_native": ["scValToNative", (a) => {
      const { T, bytes, name } = xdrArg(a, "ScVal");
      const sv = decode(T, bytes, name);
      const n = S.scValToNative(sv);
      if (sv.switch().name === "scvMap") return { value: { map_entries: n instanceof Map ? n.size : Object.keys(n ?? {}).length } };
      return { value: jsonable(n) };
    }],
    "scval.native_roundtrip": ["scValToNative + nativeToScVal", (a) => {
      const { T, bytes, name } = xdrArg(a, "ScVal");
      const sv = decode(T, bytes, name);
      const n = S.scValToNative(sv);
      const hint = "type" in a ? a.type : scalarHint(sv);
      const back = u8((hint ? S.nativeToScVal(n, { type: hint }) : S.nativeToScVal(n)).toXDR());
      return { value: bytesEqual(back, bytes), xdr_hex: hex(back), self_decode: selfDecode(xdr.ScVal, back) };
    }],
    "strkey.encode": ["StrKey.encode*", (a) => {
      const type = text(a, "type");
      const names = STRKEY[type];
      if (!names) throw new ArgError(`unknown strkey type ${type}`);
      const payload = bytesArg(a, "payload_hex");
      const enc = S.StrKey[names[0]];
      const dec = S.StrKey[names[1]];
      if (typeof enc !== "function") return absent(S, names[0]);
      let t;
      try {
        t = enc.call(S.StrKey, payload);
      } catch (e) {
        if (isFault(e)) throw e;
        return new Result("reject", reason(objectCodeOf(e, "strkey_payload"), e, `StrKey.${names[0]}`));
      }
      let back;
      try {
        back = dec.call(S.StrKey, t);
      } catch (e) {
        if (isFault(e)) throw e;
        return new Result("diverge", reason("own_output_rejected", e, `StrKey.${names[0]}`), { api: { value: t, self_decode: "rejected" } });
      }
      if (!bytesEqual(back, payload)) {
        return new Result("diverge", { code: "own_output_rejected", message: `StrKey.${names[1]} returned ${hex(back)}`, entry_point: `StrKey.${names[0]}` }, { api: { value: t, self_decode: "rejected" } });
      }
      return { value: t, self_decode: "accepted" };
    }],
    "strkey.decode": ["StrKey.decode*", (a) => {
      const type = "type" in a ? text(a, "type") : undefined;
      return strkeyDecode(S, text(a, "text"), type);
    }],
    "transaction.parse": ["TransactionBuilder.fromXDR", (a) => {
      const env = toBase64(bytesArg(a, "xdr_hex"));
      const tx = S.TransactionBuilder.fromXDR(env, text(a, "passphrase"));
      const ops = tx.innerTransaction ? tx.innerTransaction.operations : tx.operations;
      const back = u8(tx.toEnvelope().toXDR());
      return { value: { tx_hash: hex(tx.hash()), operations: ops.length }, xdr_hex: hex(back), self_decode: selfDecode(xdr.TransactionEnvelope, back) };
    }],
    "transaction.hash": ["Transaction.hash", (a) => {
      const env = toBase64(bytesArg(a, "xdr_hex"));
      const tx = S.TransactionBuilder.fromXDR(env, text(a, "passphrase"));
      return { value: hex(tx.hash()) };
    }],
    "memo.text_roundtrip": ["Memo.fromXDRObject", (a) => {
      const { T, bytes, name } = xdrArg(a, "Memo");
      const m = S.Memo.fromXDRObject(decode(T, bytes, name));
      const native = typeof m.value === "string" ? u8(Buffer.from(m.value, "utf8")) : u8(m.value);
      const back = u8(S.Memo.text(m.value).toXDRObject().toXDR());
      return { value: hex(native), xdr_hex: hex(back), self_decode: selfDecode(xdr.Memo, back) };
    }],
    "address.to_strkey": ["encodeMuxedAccountToAddress", (a) => {
      const type = "xdr_type" in a ? text(a, "xdr_type") : "MuxedAccount";
      if (type !== "MuxedAccount" && type !== "AccountId") throw new ArgError(`argument xdr_type: want MuxedAccount or AccountId, not ${type}`);
      const { T, bytes, name } = xdrArg(a, type);
      const v = decode(T, bytes, name);
      if (type === "MuxedAccount") return strkeyResult(S.encodeMuxedAccountToAddress(v));
      return strkeyResult(S.StrKey.encodeEd25519PublicKey(v.value()));
    }],
    "address.from_sc_address": ["Address.fromScAddress", (a) => {
      const { T, bytes, name } = xdrArg(a, "ScAddress");
      return strkeyResult(S.Address.fromScAddress(decode(T, bytes, name)).toString());
    }],
    "signer_key.to_strkey": ["SignerKey.encodeSignerKey", (a) => {
      const { T, bytes, name } = xdrArg(a, "SignerKey");
      const t = S.SignerKey.encodeSignerKey(decode(T, bytes, name));
      let self = "accepted";
      try {
        S.SignerKey.decodeAddress(t);
      } catch (e) {
        if (isFault(e)) throw e;
        self = "rejected";
      }
      return { value: t, self_decode: self };
    }],
    "operation.object_roundtrip": ["Operation.fromXDRObject", (a) => {
      const { T, bytes, name } = xdrArg(a, "Operation");
      const o = S.Operation.fromXDRObject(decode(T, bytes, name));
      const build = S.Operation[o.type];
      if (typeof build !== "function") return new Result("n_a", { code: "no_object_layer", message: `no Operation.${o.type} builder` });
      const back = u8(build.call(S.Operation, o).toXDR());
      return { value: bytesEqual(back, bytes), xdr_hex: hex(back), self_decode: selfDecode(xdr.Operation, back) };
    }],
    "asset.from_operation": ["Asset.fromOperation", (a) => {
      const { T, bytes, name } = xdrArg(a, "Asset");
      const as = S.Asset.fromOperation(decode(T, bytes, name));
      const v = { type: as.getAssetType(), code: as.getCode() };
      if (as.getIssuer()) v.issuer = as.getIssuer();
      return { value: v };
    }],
  };
  if (typeof xdrConfig === "function") {
    OPS["xdr.custom_union_encode"] = ["js-xdr config union", (a) => customUnion(xdrConfig, a)];
  }

  return {
    ops: Object.keys(OPS).sort(),
    has: (op) => Object.hasOwn(OPS, op),
    /** Run an op; throws ArgError for a malformed request. */
    run(op, args) {
      const o = OPS[op];
      if (!o) return new Result("n_a", { code: "op_not_supported", message: `api op ${op} is not offered for the v16 API` });
      if (args === null || typeof args !== "object" || Array.isArray(args)) throw new ArgError(`${op}: args must be an object`);
      for (const [name, kinds] of Object.entries(argTypes[op] ?? {})) {
        const k = tagKind(args[name]);
        if (k && !kinds.has(k)) {
          return new Result("n_a", { code: "argument_type_not_accepted", message: `the SDK declares ${name} as ${[...kinds].join(" | ")}; a ${k} cannot be passed`, entry_point: o[0] });
        }
      }
      try {
        const r = o[1](args);
        if (r instanceof Result) return r;
        if (r.self_decode === "rejected") return new Result("diverge", { code: "own_output_rejected", entry_point: o[0] }, { api: r });
        return okv(r);
      } catch (e) {
        if (isFault(e) || e instanceof ArgError) throw e;
        if (e.decodeEntryPoint) return new Result("reject", reason(e.decodeCode, e, e.decodeEntryPoint));
        const code = op.startsWith("strkey.") ? "other" : objectCodeOf(e, "other");
        return new Result("reject", reason(code, e, o[0]));
      }
    },
  };
}
