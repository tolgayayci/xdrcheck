// The SDK's XDR schema with its type names, as the v16 generation declares it.
//
// @stellar/js-xdr 4 resolves every reference when the SDK loads: a typedef becomes the very object it names, so
// at run time `xdr.PoolId === xdr.ContractId === xdr.Hash` (one opaque[32] instance) and `xdr.AssetCode4` is
// indistinguishable from `xdr.Thresholds`. The L2 projection needs those names (a PoolId renders as an L… strkey,
// a Hash as hex), so this module re-runs the SDK's own generated definition callback (the argument of `config(…)`
// in lib/esm/base/generated/curr_generated.js) against a recording builder that keeps every reference by name.
// recordSchema() then checks the recording against the live classes, so a mismatch fails at start-up instead of
// producing a wrong projection.
//
// A descriptor is one of
//   {kind: "ref", name}                                   a named type (typedef, struct, union or enum)
//   {kind: "int" | "uint" | "hyper" | "uhyper" | "bool" | "void" | "float" | "double" | "quadruple"}
//   {kind: "opaque", length} {kind: "varOpaque", max} {kind: "string", max}
//   {kind: "array", child, length} {kind: "varArray", child, max} {kind: "option", child}
// and a definition (defs.get(name)) one of
//   {kind: "typedef", name, type}  {kind: "struct", name, fields: [[field, descriptor]…]}
//   {kind: "enum", name, members: [[jsName, value]…]}
//   {kind: "union", name, switchOn: descriptor, switches: [[member name or number, arm name | null (void)]…],
//    arms: {arm: descriptor}, defaultArm: descriptor | undefined}
import { readFileSync } from "node:fs";
import { join } from "node:path";

const GENERATED = "lib/esm/base/generated/curr_generated.js";
const VOID = Object.freeze({ kind: "void" });

class Recorder {
  constructor() {
    this.defs = new Map();
  }
  define(name, d) {
    this.defs.set(name, { name, ...d });
  }
  typedef(name, type) {
    this.define(name, { kind: "typedef", type });
  }
  struct(name, fields) {
    this.define(name, { kind: "struct", fields: fields.map(([f, t]) => [f, t]) });
  }
  enum(name, members) {
    this.define(name, { kind: "enum", members: Object.entries(members) });
  }
  union(name, cfg) {
    this.define(name, {
      kind: "union",
      switchOn: cfg.switchOn,
      switches: cfg.switches.map(([k, arm]) => [k, typeof arm === "string" ? arm : null]),
      arms: { ...(cfg.arms ?? {}) },
      defaultArm: cfg.defaultArm,
    });
  }
  const() {}
  lookup(name) {
    return { kind: "ref", name };
  }
  option(child) {
    return { kind: "option", child };
  }
  array(child, length) {
    return { kind: "array", child, length };
  }
  varArray(child, max) {
    return { kind: "varArray", child, max };
  }
  opaque(length) {
    return { kind: "opaque", length };
  }
  varOpaque(max) {
    return { kind: "varOpaque", max };
  }
  string(max) {
    return { kind: "string", max };
  }
  void() {
    return VOID;
  }
}
for (const k of ["int", "uint", "hyper", "uhyper", "bool", "float", "double", "quadruple"]) {
  Recorder.prototype[k] = () => ({ kind: k });
}

/** The recorded schema of the SDK installed at pkgDir, checked against its live xdr namespace. */
export function recordSchema(pkgDir, xdr) {
  const src = readFileSync(join(pkgDir, GENERATED), "utf8");
  const start = src.indexOf("config((xdr) =>");
  const end = src.lastIndexOf("});");
  if (start < 0 || end < start) throw new Error(`${GENERATED}: no config((xdr) => …) definition block`);
  const define = new Function(`return ${src.slice(start + "config(".length, end + 1)};`)();
  const rec = new Recorder();
  define(rec);
  const schema = new Schema(rec.defs);
  schema.verify(xdr);
  return schema;
}

export class Schema {
  constructor(defs) {
    this.defs = defs;
  }

  /** Follow references and typedefs: {def, names} where names are every name passed on the way. */
  resolve(desc) {
    const names = [];
    let d = desc;
    for (;;) {
      if (d.kind === "ref") {
        names.push(d.name);
        d = this.defs.get(d.name);
        if (!d) throw new Error(`schema: undefined type ${names.at(-1)}`);
      } else if (d.kind === "typedef") {
        d = d.type;
      } else return { def: d, names };
    }
  }

  /** The arm of a union for a switch key (enum member name or number): {name, desc} or undefined. */
  arm(u, key) {
    const s = u.switches.find(([k]) => k === key);
    if (s) return s[1] === null ? { name: null, desc: VOID } : { name: s[1], desc: u.arms[s[1]] };
    if (u.defaultArm) return { name: null, desc: u.defaultArm };
    return undefined;
  }

  // The recording must describe the classes the SDK actually decodes with: every struct's field names, every
  // union's switch table and every enum's members.
  verify(xdr) {
    let n = 0;
    for (const d of this.defs.values()) {
      const T = xdr[d.name];
      if (d.kind === "struct") {
        const live = T?._fields?.map(([f]) => f).join(",");
        if (live !== d.fields.map(([f]) => f).join(",")) throw new Error(`schema: struct ${d.name} differs from the SDK's`);
      } else if (d.kind === "union") {
        if (!T?._switches || T._switches.size !== d.switches.length) throw new Error(`schema: union ${d.name} differs from the SDK's`);
      } else if (d.kind === "enum") {
        const live = Object.entries(T?._members ?? {}).map(([k, v]) => `${k}=${v.value}`).join(",");
        if (live !== d.members.map(([k, v]) => `${k}=${v}`).join(",")) throw new Error(`schema: enum ${d.name} differs from the SDK's`);
      } else continue;
      n++;
    }
    if (n === 0) throw new Error("schema: nothing recorded");
  }
}
