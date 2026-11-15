// The L2 neutral value projection for the v16 API generation: a decoded value rendered as the SEP-51 XDR-JSON
// value the corpus oracle (stellar-xdr, whose output is each entry's `decoded` sidecar) emits, compared by value.
// The rules are those of the v17 driver (drivers/js/src/project.mjs), implemented here and not taken from the
// SDK's JSON helpers:
//
//   struct field   snake_case of the field name (word boundaries at lower→upper and at the end of an acronym)
//   enum member    the member name without the enum's common prefix, snake_case
//   union arm      the discriminant's enum member name as above; "v<N>" for integer discriminants; a void arm is
//                  the bare name, any other arm an object with that single key
//   64-bit ints    decimal strings; 128/256-bit parts as one decimal string; opaque as lower-case hex;
//   string<>       printable ASCII as is, \0 \t \n \r \\ and \xNN for every other byte, from the raw bytes
//   strkey types   AccountId/NodeId/PublicKey G…, MuxedAccount G…/M…, SignerKey G…/T…/X…/P…, ScAddress
//                  G…/C…/M…/B…/L…/W…, ContractId C…, PoolId L…, ClaimableBalanceId B…, asset codes as text
//
// It walks the SDK's decoded @stellar/js-xdr 4 value (struct `_attributes`, union `switch()`/`value()`, enum
// members, Hyper/UnsignedHyper objects, Buffers) against the SDK's own schema as recorded by schema.mjs, so it
// renders exactly what the SDK decoded, with the typedef names js-xdr 4 itself forgets.
//
// What differs from v17 is where names come from. js-xdr 4 keeps only the camel-case member names
// (SC_ADDRESS_TYPE_ACCOUNT is `scAddressTypeAccount`), not the XDR names whose common underscore-terminated prefix
// the oracle strips. A word boundary of the camel-case name is an underscore of the XDR name except where the XDR
// name changes case without one (txSUCCESS, opINNER, IPv4) or a word is a bare number (BINARY_FUSE_FILTER_8_BIT);
// those enums are listed in PREFIX with the prefix the XDR names give.
//
// project(value, desc, schema) renders a whole value; pinpoint(value, desc, schema, pointer) renders the value at
// a JSON Pointer into the projection without rendering anything else.
import { encode, u64be, concat } from "./strkey.mjs";
import { hex, snake } from "./util.mjs";

const HEX = "0123456789abcdef";

/** Escaped rendering of string bytes. */
export function escapeBytes(bytes) {
  let out = "";
  for (const b of bytes) {
    if (b === 0) out += "\\0";
    else if (b === 9) out += "\\t";
    else if (b === 10) out += "\\n";
    else if (b === 13) out += "\\r";
    else if (b === 92) out += "\\\\";
    else if (b >= 32 && b <= 126) out += String.fromCharCode(b);
    else out += "\\x" + HEX[b >> 4] + HEX[b & 15];
  }
  return out;
}

/** Decode a JSON Pointer into reference tokens. */
export function pointerTokens(pointer) {
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) throw new Error(`not a JSON Pointer: ${pointer}`);
  return pointer
    .slice(1)
    .split("/")
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/** Enums whose XDR prefix the camel-case words do not show (see above). */
const PREFIX = {
  TransactionResultCode: "", // txSUCCESS, txFAILED, …
  OperationResultCode: "", // opINNER, opBAD_AUTH, …
  IpAddrType: "", // IPv4, IPv6
  BinaryFuseFilterType: "binaryFuseFilter", // BINARY_FUSE_FILTER_8_BIT, …
};

// The v16 generator inflected some XDR names: `txs` became `txes` and one array field went singular. The
// projection uses the XDR names (TransactionSet.txs, LedgerCloseMetaBatch.ledgerCloseMetas, …).
const FIELD_NAMES = {
  "TransactionSet.txes": "txs",
  "TxSetComponentTxsMaybeDiscountedFee.txes": "txs",
  "FreezeBypassTxsDelta.addTxes": "addTxs",
  "FreezeBypassTxsDelta.removeTxes": "removeTxs",
  "LedgerCloseMetaBatch.ledgerCloseMeta": "ledgerCloseMetas",
};
const MEMBER_NAMES = {
  transactionEventStageBeforeAllTxes: "transactionEventStageBeforeAllTxs",
  transactionEventStageAfterAllTxes: "transactionEventStageAfterAllTxs",
  configSettingFreezeBypassTxes: "configSettingFreezeBypassTxs",
};
/** The projection key of a struct field. */
const fieldKey = (def, f) => snake(FIELD_NAMES[`${def.name}.${f}`] ?? f);

/** Variant names: an underscore before every upper-case letter but the first (serde's snake_case). */
function variantSnake(name) {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    if (i > 0 && ch >= "A" && ch <= "Z") out += "_";
    out += ch.toLowerCase();
  }
  return out;
}

const words = (n) => n.match(/[A-Z]?[^A-Z]*/g).filter(Boolean);

function commonPrefix(members) {
  if (members.length < 2) return "";
  const ws = members.map(words);
  let k = 0;
  while (ws.every((w) => w.length > k + 1) && new Set(ws.map((w) => w[k])).size === 1) k++;
  return ws[0].slice(0, k).join("");
}

const enumNameCache = new WeakMap();

/** Projection name of an enum member by value: the common prefix stripped, then snake_case. */
export function enumName(def, value) {
  let names = enumNameCache.get(def);
  if (!names) {
    names = new Map();
    const members = def.members.map(([m]) => MEMBER_NAMES[m] ?? m);
    const prefix = def.name in PREFIX ? PREFIX[def.name] : commonPrefix(members);
    for (const [js, v] of def.members) {
      const m = MEMBER_NAMES[js] ?? js;
      let stripped = prefix && m.startsWith(prefix) && m.length > prefix.length ? m.slice(prefix.length) : m;
      // A stripped name may not start with a digit: the prefix's first letter is kept (as the oracle does).
      if (stripped !== m && stripped[0] >= "0" && stripped[0] <= "9") stripped = prefix[0] + stripped;
      names.set(v, variantSnake(stripped[0].toUpperCase() + stripped.slice(1)));
    }
    enumNameCache.set(def, names);
  }
  return names.get(value);
}

/** The bytes of a decoded opaque or string value. */
function bytesOf(v) {
  if (typeof v === "string") return new Uint8Array(Buffer.from(v, "utf8"));
  return v;
}

/** A decoded union: its arm and the case name the projection uses. */
function unionCase(value, u, schema) {
  const sw = value.switch();
  const { def: swDef } = schema.resolve(u.switchOn);
  let key;
  let name;
  if (swDef.kind === "enum") {
    key = sw.name;
    name = enumName(swDef, sw.value);
  } else if (swDef.kind === "bool") {
    key = sw;
    name = String(sw);
  } else {
    key = sw;
    name = `v${sw}`;
  }
  const arm = schema.arm(u, key);
  if (!arm) throw new Error(`${u.name}: no case for discriminant ${key}`);
  const disc = typeof sw === "object" ? sw.value : sw;
  const payloadDesc = arm.desc.kind === "void" ? null : arm.desc;
  return { name, disc, payload: payloadDesc ? value.value() : undefined, payloadDesc };
}

const resolved = (schema, desc) => schema.resolve(desc).def;
const field = (rec, f) => rec._attributes[f];

function fieldOf(rec, def, schema, kind, length) {
  for (const [f, d] of def.fields) {
    const r = resolved(schema, d);
    if (r.kind === kind && (length === undefined || r.length === length)) return field(rec, f);
  }
  throw new Error(`${def.name}: no ${kind} field`);
}

const big = (v) => BigInt(typeof v === "object" ? v.toString() : v);

function intParts(rec, def, schema) {
  let acc = 0n;
  let bits = 0;
  for (const [f] of def.fields) {
    acc = (acc << 64n) | BigInt.asUintN(64, big(field(rec, f)));
    bits += 64;
  }
  const signed = resolved(schema, def.fields[0][1]).kind === "hyper";
  return (signed ? BigInt.asIntN(bits, acc) : acc).toString();
}

function trimZeros(bytes, min) {
  let end = bytes.length;
  while (end > min && bytes[end - 1] === 0) end--;
  return bytes.subarray(0, end);
}

function muxed(rec, def, schema) {
  return encode("M", concat(fieldOf(rec, def, schema, "opaque", 32), u64be(big(fieldOf(rec, def, schema, "uhyper")))));
}

function signedPayload(rec, def, schema) {
  const key = fieldOf(rec, def, schema, "opaque", 32);
  const payload = fieldOf(rec, def, schema, "varOpaque");
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, payload.length, false);
  const pad = new Uint8Array((4 - (payload.length % 4)) % 4);
  return encode("P", concat(key, len, payload, pad));
}

// Types rendered as one string, by any name on their typedef chain. Each returns the string, or undefined to
// fall back to the generic walk.
const SPECIAL = {
  PublicKey(v, d, s) {
    const u = unionCase(v, d, s);
    return u.payloadDesc && resolved(s, u.payloadDesc).kind === "opaque" ? encode("G", u.payload) : undefined;
  },
  MuxedAccount(v, d, s) {
    const u = unionCase(v, d, s);
    if (!u.payloadDesc) return undefined;
    const p = resolved(s, u.payloadDesc);
    if (p.kind === "opaque") return encode("G", u.payload);
    if (p.kind === "struct") return muxed(u.payload, p, s);
    return undefined;
  },
  MuxedAccountMed25519: (v, d, s) => muxed(v, d, s),
  MuxedEd25519Account: (v, d, s) => muxed(v, d, s),
  MuxedContract: (v, d, s) => encode("W", concat(fieldOf(v, d, s, "opaque", 32), u64be(big(fieldOf(v, d, s, "uhyper"))))),
  SignerKey(v, d, s) {
    const u = unionCase(v, d, s);
    const letter = { 0: "G", 1: "T", 2: "X" }[u.disc];
    const p = u.payloadDesc && resolved(s, u.payloadDesc);
    if (letter && p?.kind === "opaque") return encode(letter, u.payload);
    if (u.disc === 3 && p?.kind === "struct") return signedPayload(u.payload, p, s);
    return undefined;
  },
  ScAddress(v, d, s) {
    const u = unionCase(v, d, s);
    return u.payloadDesc ? project(u.payload, u.payloadDesc, s) : undefined;
  },
  ClaimableBalanceId(v, d, s) {
    const u = unionCase(v, d, s);
    if (!u.payloadDesc || resolved(s, u.payloadDesc).kind !== "opaque") return undefined;
    return encode("B", concat(Uint8Array.of(u.disc), u.payload));
  },
  PoolId: (v) => encode("L", v),
  ContractId: (v) => encode("C", v),
  AssetCode4: (v) => escapeBytes(trimZeros(v, 0)),
  AssetCode12: (v) => escapeBytes(trimZeros(v, 5)),
  AssetCode(v, d, s) {
    const u = unionCase(v, d, s);
    return u.payloadDesc ? project(u.payload, u.payloadDesc, s) : undefined;
  },
  SignerKeyEd25519SignedPayload: (v, d, s) => signedPayload(v, d, s),
};
for (const n of ["Int128Parts", "UInt128Parts", "Uint128Parts", "Int256Parts", "UInt256Parts", "Uint256Parts"]) {
  SPECIAL[n] = (v, d, s) => intParts(v, d, s);
}

const specialOf = (names) => names.find((n) => SPECIAL[n]);

/** The projection of a whole value. */
export function project(value, desc, schema) {
  const { def, names } = schema.resolve(desc);
  const sp = specialOf(names);
  if (sp) {
    const r = SPECIAL[sp](value, def, schema);
    if (r !== undefined) return r;
  }
  switch (def.kind) {
    case "bool":
    case "int":
    case "uint":
    case "float":
    case "double":
      return value;
    case "hyper":
    case "uhyper":
      return value.toString();
    case "void":
      return null;
    case "opaque":
    case "varOpaque":
      return hex(bytesOf(value));
    case "string":
      return escapeBytes(bytesOf(value));
    case "enum":
      return enumName(def, value.value);
    case "option":
      return value === undefined || value === null ? null : project(value, def.child, schema);
    case "array":
    case "varArray":
      return value.map((v) => project(v, def.child, schema));
    case "struct": {
      const out = {};
      for (const [f, d] of def.fields) out[fieldKey(def, f)] = project(field(value, f), d, schema);
      return out;
    }
    case "union": {
      const u = unionCase(value, def, schema);
      return u.payloadDesc ? { [u.name]: project(u.payload, u.payloadDesc, schema) } : u.name;
    }
  }
  throw new Error(`projection: unsupported kind ${def.kind}`);
}

/**
 * The value at a JSON Pointer into the projection: {found: true, value} or {found: false}. Only the addressed
 * part is rendered; a pointer that reaches into a value rendered as one string (a strkey, a 128-bit integer)
 * is resolved against the rendered value.
 */
export function pinpoint(value, desc, schema, pointer) {
  let tokens = pointerTokens(pointer);
  let v = value;
  let d = desc;
  while (tokens.length > 0) {
    const { def, names } = schema.resolve(d);
    if (specialOf(names)) break; // rendered as a whole below
    const t = tokens[0];
    if (def.kind === "option") {
      if (v === undefined || v === null) return { found: false };
      d = def.child;
      continue;
    }
    if (def.kind === "struct") {
      const e = def.fields.find(([f]) => fieldKey(def, f) === t);
      if (!e) return { found: false };
      v = field(v, e[0]);
      d = e[1];
    } else if (def.kind === "union") {
      const u = unionCase(v, def, schema);
      if (u.name !== t || !u.payloadDesc) return { found: false };
      v = u.payload;
      d = u.payloadDesc;
    } else if (def.kind === "array" || def.kind === "varArray") {
      if (!/^(0|[1-9][0-9]*)$/.test(t) || Number(t) >= v.length) return { found: false };
      v = v[Number(t)];
      d = def.child;
    } else break;
    tokens = tokens.slice(1);
  }
  let r = project(v, d, schema);
  for (const t of tokens) {
    if (Array.isArray(r) && /^(0|[1-9][0-9]*)$/.test(t) && Number(t) < r.length) r = r[Number(t)];
    else if (r !== null && typeof r === "object" && !Array.isArray(r) && Object.hasOwn(r, t)) r = r[t];
    else return { found: false };
  }
  return { found: true, value: r };
}
