// The spec level: the SDK's contract-spec reader on a Wasm module (contract.Spec.fromWasm) or on a bare
// SCSpecEntry stream (new contract.Spec(bytes)), and its entries in the neutral rendering of
// docs/conformance-protocol.md (spec level). Everything is read from the SDK's own objects (the v17 generated
// types: `type` tags and plain fields); the driver never decodes the bytes itself.

const TYPE_NAMES = {
  Val: "val", Bool: "bool", Void: "void", Error: "error", U32: "u32", I32: "i32", U64: "u64", I64: "i64",
  Timepoint: "timepoint", Duration: "duration", U128: "u128", I128: "i128", U256: "u256", I256: "i256",
  Bytes: "bytes", String: "string", Symbol: "symbol", Address: "address", MuxedAddress: "muxed_address",
};

const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// A name's text: the string when its bytes are UTF-8, else SEP-51 escaped (\xNN for every other byte).
export function nameText(x) {
  const b = x?.bytes instanceof Uint8Array ? x.bytes : typeof x === "string" ? new TextEncoder().encode(x) : Uint8Array.from(x ?? []);
  try {
    return strict.decode(b);
  } catch {
    let s = "";
    for (const c of b) s += c >= 0x20 && c < 0x7f && c !== 0x5c ? String.fromCharCode(c) : "\\x" + c.toString(16).padStart(2, "0");
    return s;
  }
}

function tag(x) {
  // "scSpecTypeU32" -> "U32"
  return String(x?.type ?? "").replace(/^scSpecType/, "");
}

export function typeText(t) {
  const k = tag(t);
  if (TYPE_NAMES[k]) return TYPE_NAMES[k];
  switch (k) {
    case "Option":
      return `option<${typeText(t.option.valueType)}>`;
    case "Result":
      return `result<${typeText(t.result.okType)},${typeText(t.result.errorType)}>`;
    case "Vec":
      return `vec<${typeText(t.vec.elementType)}>`;
    case "Map":
      return `map<${typeText(t.map.keyType)},${typeText(t.map.valueType)}>`;
    case "Tuple":
      return `tuple<${t.tuple.valueTypes.map(typeText).join(",")}>`;
    case "BytesN":
      return `bytes_n<${t.bytesN.n}>`;
    case "Udt":
      return `udt:${nameText(t.udt.name)}`;
  }
  throw new Error(`unknown SCSpecTypeDef ${t?.type}`);
}

const arg = (name, type) => ({ name: nameText(name), type });

export function entryFact(e) {
  switch (e.type) {
    case "scSpecEntryFunctionV0": {
      const f = e.functionV0;
      return { kind: "function", name: nameText(f.name), args: f.inputs.map((i) => arg(i.name, typeText(i.type))), outputs: f.outputs.map(typeText) };
    }
    case "scSpecEntryUdtStructV0": {
      const s = e.udtStructV0;
      return { kind: "struct", name: nameText(s.name), args: s.fields.map((f) => arg(f.name, typeText(f.type))) };
    }
    case "scSpecEntryUdtUnionV0": {
      const u = e.udtUnionV0;
      return {
        kind: "union", name: nameText(u.name),
        args: u.cases.map((c) => (c.type === "scSpecUdtUnionCaseVoidV0"
          ? arg(c.voidCase.name, "void")
          : arg(c.tupleCase.name, `tuple<${c.tupleCase.type.map(typeText).join(",")}>`))),
      };
    }
    case "scSpecEntryUdtEnumV0":
    case "scSpecEntryUdtErrorEnumV0": {
      const u = e.udtEnumV0 ?? e.udtErrorEnumV0;
      return { kind: e.type === "scSpecEntryUdtEnumV0" ? "enum" : "error_enum", name: nameText(u.name), args: u.cases.map((c) => arg(c.name, `=${c.value}`)) };
    }
    case "scSpecEntryEventV0": {
      const ev = e.eventV0;
      const loc = (l) => (l.name === "scSpecEventParamLocationTopicList" ? "topic_list" : "data");
      return { kind: "event", name: nameText(ev.name), args: ev.params.map((p) => arg(p.name, `${typeText(p.type)}@${loc(p.location)}`)) };
    }
  }
  throw new Error(`unknown SCSpecEntry ${e?.type}`);
}

// Read the input with the SDK's reader; returns { entryPoint, entries } or throws what the SDK threw.
export function readSpec(S, bytes, container) {
  if (container === "wasm") {
    return { entryPoint: "contract.Spec.fromWasm", spec: S.contract.Spec.fromWasm(bytes) };
  }
  return { entryPoint: "new contract.Spec(stream)", spec: new S.contract.Spec(bytes) };
}
