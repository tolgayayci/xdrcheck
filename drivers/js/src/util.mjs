// Small helpers shared by the levels.
import { createHash } from "node:crypto";
import { hex } from "./project.mjs";
import { trim } from "./errors.mjs";

export { hex };

export const sha256 = (b) => createHash("sha256").update(b).digest("hex");

export const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Lower- or upper-case hex → a plain Uint8Array (never a Buffer). */
export function fromHex(h) {
  if (typeof h !== "string" || !/^([0-9a-fA-F]{2})*$/.test(h)) throw new TypeError(`not a hex string: ${String(h).slice(0, 40)}`);
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
}

export const toBase64 = (b) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64");

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

// The nativeToScVal type hint that names an ScVal's own arm, for the arms where JavaScript's native type alone
// does not decide it on the way back.
const SCALAR_HINTS = {
  scvString: "string", scvSymbol: "symbol", scvU32: "u32", scvI32: "i32", scvU64: "u64", scvI64: "i64",
  scvU128: "u128", scvI128: "i128", scvU256: "u256", scvI256: "i256", scvTimepoint: "timepoint",
  scvDuration: "duration", scvBytes: "bytes",
};
export const scalarHint = (sv) => SCALAR_HINTS[sv.type];
