// Small helpers shared by the levels.
import { createHash } from "node:crypto";
import { trim } from "./errors.mjs";

const HEX = "0123456789abcdef";

/** Lower-case hex of a byte array. */
export function hex(bytes) {
  let s = "";
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

export const sha256 = (b) => createHash("sha256").update(b).digest("hex");

export const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Lower- or upper-case hex → a plain Uint8Array (never a Buffer). */
export function fromHex(h) {
  if (typeof h !== "string" || !/^([0-9a-fA-F]{2})*$/.test(h)) throw new TypeError(`not a hex string: ${String(h).slice(0, 40)}`);
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
}

/** A plain Uint8Array view of a Buffer (or any byte array). */
export const u8 = (b) => new Uint8Array(b.buffer, b.byteOffset, b.byteLength);

export const toBase64 = (b) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64");

/** snake_case of a camelCase or PascalCase identifier (word boundaries at lower→upper and at an acronym's end). */
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

/** A JSON-safe rendering of a native value: BigInt as decimal, bytes as hex, Map as entry pairs. */
export function jsonable(x, seen = new Set()) {
  if (typeof x === "bigint") return x.toString();
  if (x === undefined) return "undefined";
  if (x instanceof Uint8Array) return hex(x);
  if (x instanceof Map) return [...x].map(([k, v]) => [jsonable(k, seen), jsonable(v, seen)]);
  if (x && typeof x === "object") {
    if (seen.has(x)) return "[cycle]";
    seen.add(x);
    if (Array.isArray(x)) return x.map((v) => jsonable(v, seen));
    if (x.constructor !== Object && typeof x.toString === "function" && x.toString !== Object.prototype.toString) return x.toString();
    return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, jsonable(v, seen)]));
  }
  return x;
}

/** A short rendering for the report (at most 300 characters). */
export const summary = (n) => trim(JSON.stringify(jsonable(n)) ?? String(n), 300);

/** The native type's name: typeof for primitives, the constructor's name for objects. */
export function nativeType(n) {
  if (n === null) return "null";
  if (typeof n !== "object") return typeof n;
  return n.constructor?.name ?? "object";
}
