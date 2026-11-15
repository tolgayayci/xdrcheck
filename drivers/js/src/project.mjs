// The L2 neutral value projection: a decoded value rendered as the SEP-51 XDR-JSON value the corpus oracle
// (stellar-xdr, whose output is each entry's `decoded` sidecar) emits, compared by value. It walks the SDK's decoded value in its wire form
// (`toXdrObject()`) against the SDK's own generated schema (`Type.schema`, @stellar/js-xdr 5 schema objects:
// struct entries, union cases, enum members), so it renders exactly what the SDK decoded. Names follow the
// oracle's rules, implemented here and not taken from the SDK's JSON helpers:
//
//   struct field   snake_case of the field name (word boundaries at lower→upper and at the end of an acronym)
//   enum member    the member name without the enum's common prefix (as the generator recorded it on the
//                  schema), snake_case
//   union arm      the discriminant's enum member name as above; "v<N>" for integer discriminants; a void arm is
//                  the bare name, any other arm an object with that single key
//   64-bit ints    decimal strings; 128/256-bit parts as one decimal string; opaque as lower-case hex;
//   string<>       printable ASCII as is, \0 \t \n \r \\ and \xNN for every other byte, from the raw bytes
//   strkey types   AccountId/NodeId/PublicKey G…, MuxedAccount G…/M…, SignerKey G…/T…/X…/P…, ScAddress
//                  G…/C…/M…/B…/L…/W…, ContractId C…, PoolId L…, ClaimableBalanceId B…, asset codes as text
//
// project(wire, schema) renders a whole value; pinpoint(wire, schema, pointer) renders the value at a JSON
// Pointer into the projection without rendering anything else.
import { encode, u64be, concat } from "./strkey.mjs";

const HEX = "0123456789abcdef";

export function hex(bytes) {
  let s = "";
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

/** snake_case of a camelCase or PascalCase identifier. */
export function snake(name) {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    const prev = name[i - 1] ?? "";
    const next = name[i + 1] ?? "";
    const upper = ch >= "A" && ch <= "Z";
    const prevLowerOrDigit = (prev >= "a" && prev <= "z") || (prev >= "0" && prev <= "9");
    const prevUpper = prev >= "A" && prev <= "Z";
    const nextLower = next >= "a" && next <= "z";
    if (i > 0 && upper && (prevLowerOrDigit || (prevUpper && nextLower))) out += "_";
    out += ch.toLowerCase();
  }
  return out;
}

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

const enumNameCache = new WeakMap();

/** Projection name of an enum member: the common prefix stripped, then snake_case. */
export function enumName(schema, value) {
  let names = enumNameCache.get(schema);
  if (!names) {
    names = new Map();
    const members = [...schema.nameByValue.values()];
    const prefix = memberPrefix(schema, members);
    for (const [v, m] of schema.nameByValue) {
      let stripped = prefix && m.startsWith(prefix) && m.length > prefix.length ? m.slice(prefix.length) : m;
      // A stripped name may not start with a digit: the prefix's first letter is kept (as the oracle does).
      if (stripped !== m && stripped[0] >= "0" && stripped[0] <= "9") stripped = prefix[0] + stripped;
      names.set(v, variantSnake(stripped[0].toUpperCase() + stripped.slice(1)));
    }
    enumNameCache.set(schema, names);
  }
  return names.get(value);
}

// The prefix the oracle strips: the members' common prefix up to the last underscore of the XDR names. The JS
// member names no longer carry the underscores (SC_ADDRESS_TYPE_ACCOUNT and txSUCCESS both lose them), so the
// prefix is the one the generator recorded on the schema from the XDR names (`memberPrefix`); none when absent.
function memberPrefix(schema, members) {
  const p = schema.memberPrefix;
  return typeof p === "string" && members.length > 1 && members.every((m) => m.startsWith(p)) ? p : "";
}

function unwrap(schema) {
  while (schema.kind === "lazy") schema = schema.getSchema();
  return schema;
}

function unionCase(wire, s) {
  const disc = wire[s.switchKey];
  const c = s.cases.find((x) => x.discriminant === disc);
  if (!c) throw new Error(`${s.name}: no case for discriminant ${disc}`);
  const arm = c.arm;
  const field = "schema" in arm;
  return { c, disc, payload: field ? wire[arm.name] : undefined, payloadSchema: field ? unwrap(arm.schema) : null };
}

function caseName(s, c) {
  const sw = unwrap(s.switchOn);
  if (sw.kind === "enum") return enumName(sw, c.discriminant);
  if (sw.kind === "int32" || sw.kind === "uint32") return `v${c.discriminant}`;
  if (sw.kind === "bool") return String(c.discriminant);
  return snake(c.name);
}

function fieldOf(rec, s, kind) {
  for (const [k, fs] of s.entries) if (unwrap(fs).kind === kind) return rec[k];
  throw new Error(`${s.name}: no ${kind} field`);
}

function opaqueField(rec, s, length) {
  for (const [k, fs] of s.entries) {
    const u = unwrap(fs);
    if (u.kind === "opaque" && u.length === length) return rec[k];
  }
  throw new Error(`${s.name}: no ${length}-byte field`);
}

function intParts(rec, s) {
  let acc = 0n;
  let bits = 0;
  for (const [k] of s.entries) {
    acc = (acc << 64n) | BigInt.asUintN(64, rec[k]);
    bits += 64;
  }
  const signed = unwrap(s.entries[0][1]).kind === "int64";
  return (signed ? BigInt.asIntN(bits, acc) : acc).toString();
}

function trimZeros(bytes, min) {
  let end = bytes.length;
  while (end > min && bytes[end - 1] === 0) end--;
  return bytes.subarray(0, end);
}

// Types rendered as one string. Each returns the string, or undefined to fall back to the generic walk.
const SPECIAL = {
  PublicKey(w, s) {
    const u = unionCase(w, s);
    return u.payloadSchema?.kind === "opaque" ? encode("G", u.payload) : undefined;
  },
  MuxedAccount(w, s) {
    const u = unionCase(w, s);
    if (u.payloadSchema?.kind === "opaque") return encode("G", u.payload);
    if (u.payloadSchema?.kind === "struct") return muxed(u.payload, u.payloadSchema);
    return undefined;
  },
  MuxedAccountMed25519: (w, s) => muxed(w, s),
  MuxedEd25519Account: (w, s) => muxed(w, s),
  MuxedContract(w, s) {
    return encode("W", concat(opaqueField(w, s, 32), u64be(fieldOf(w, s, "uint64"))));
  },
  SignerKey(w, s) {
    const u = unionCase(w, s);
    const letter = { 0: "G", 1: "T", 2: "X" }[u.disc];
    if (letter && u.payloadSchema?.kind === "opaque") return encode(letter, u.payload);
    if (u.disc === 3 && u.payloadSchema?.kind === "struct") return signedPayload(u.payload, u.payloadSchema);
    return undefined;
  },
  ScAddress(w, s) {
    const u = unionCase(w, s);
    if (!u.payloadSchema) return undefined;
    return project(u.payload, u.payloadSchema);
  },
  ClaimableBalanceId(w, s) {
    const u = unionCase(w, s);
    if (u.payloadSchema?.kind !== "opaque") return undefined;
    return encode("B", concat(Uint8Array.of(u.disc), u.payload));
  },
  PoolId: (w) => encode("L", w),
  ContractId: (w) => encode("C", w),
  AssetCode4: (w) => escapeBytes(trimZeros(w, 0)),
  AssetCode12: (w) => escapeBytes(trimZeros(w, 5)),
  AssetCode(w, s) {
    const u = unionCase(w, s);
    return u.payloadSchema ? project(u.payload, u.payloadSchema) : undefined;
  },
};
SPECIAL.SignerKeyEd25519SignedPayload = (w, s) => signedPayload(w, s);
for (const n of ["Int128Parts", "UInt128Parts", "Uint128Parts", "Int256Parts", "UInt256Parts", "Uint256Parts"]) {
  SPECIAL[n] = (w, s) => intParts(w, s);
}

function muxed(rec, s) {
  return encode("M", concat(opaqueField(rec, s, 32), u64be(fieldOf(rec, s, "uint64"))));
}

function signedPayload(rec, s) {
  const key = opaqueField(rec, s, 32);
  const payload = fieldOf(rec, s, "varOpaque");
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, payload.length, false);
  const pad = new Uint8Array((4 - (payload.length % 4)) % 4);
  return encode("P", concat(key, len, payload, pad));
}

/** The projection of a whole value. */
export function project(wire, schema) {
  const s = unwrap(schema);
  const special = s.name && SPECIAL[s.name];
  if (special) {
    const r = special(wire, s);
    if (r !== undefined) return r;
  }
  switch (s.kind) {
    case "bool":
    case "int32":
    case "uint32":
    case "float":
    case "double":
      return wire;
    case "int64":
    case "uint64":
      return wire.toString();
    case "void":
      return null;
    case "opaque":
    case "varOpaque":
      return hex(wire);
    case "string":
      return escapeBytes(wire instanceof Uint8Array ? wire : wire.bytes);
    case "enum":
      return enumName(s, wire);
    case "option":
      return wire === null ? null : project(wire, s.element);
    case "array":
    case "fixedArray":
      return wire.map((v) => project(v, s.element));
    case "struct": {
      const out = {};
      for (const [k, fs] of s.entries) out[snake(k)] = project(wire[k], fs);
      return out;
    }
    case "union": {
      const u = unionCase(wire, s);
      const name = caseName(s, u.c);
      return u.payloadSchema ? { [name]: project(u.payload, u.payloadSchema) } : name;
    }
  }
  throw new Error(`projection: unsupported schema kind ${s.kind}`);
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

/**
 * The value at a JSON Pointer into the projection: {found: true, value} or {found: false}. Only the addressed
 * part is rendered; a pointer that reaches into a value rendered as one string (a strkey, a 128-bit integer)
 * is resolved against the rendered value.
 */
export function pinpoint(wire, schema, pointer) {
  let tokens = pointerTokens(pointer);
  let w = wire;
  let s = unwrap(schema);
  while (tokens.length > 0) {
    if (s.name && SPECIAL[s.name]) break; // rendered as a whole below
    const t = tokens[0];
    if (s.kind === "option") {
      if (w === null) return { found: false };
      s = unwrap(s.element);
      continue;
    }
    if (s.kind === "struct") {
      const e = s.entries.find(([k]) => snake(k) === t);
      if (!e) return { found: false };
      w = w[e[0]];
      s = unwrap(e[1]);
    } else if (s.kind === "union") {
      const u = unionCase(w, s);
      if (caseName(s, u.c) !== t || !u.payloadSchema) return { found: false };
      w = u.payload;
      s = u.payloadSchema;
    } else if (s.kind === "array" || s.kind === "fixedArray") {
      if (!/^(0|[1-9][0-9]*)$/.test(t) || Number(t) >= w.length) return { found: false };
      w = w[Number(t)];
      s = unwrap(s.element);
    } else {
      break;
    }
    tokens = tokens.slice(1);
  }
  let v = project(w, s);
  for (const t of tokens) {
    if (Array.isArray(v) && /^(0|[1-9][0-9]*)$/.test(t) && Number(t) < v.length) v = v[Number(t)];
    else if (v !== null && typeof v === "object" && !Array.isArray(v) && Object.hasOwn(v, t)) v = v[t];
    else return { found: false };
  }
  return { found: true, value: v };
}
