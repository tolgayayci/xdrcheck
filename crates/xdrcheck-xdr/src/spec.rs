//! Contract-spec reader: the `contractspecv0` Wasm custom sections of a contract and the stream
//! of `SCSpecEntry` values they hold (SEP-48), read from the bytes alone.
//!
//! This is the corpus's own reader for `spec` entries: the expected facts of every such entry
//! (section count, the ordered entry list, whether the stream ends cleanly) are computed here and
//! never taken from a spec reader under test. Section framing follows the WebAssembly binary format
//! (magic, version 1, then `id ‖ size(LEB128 u32) ‖ payload` sections; a custom section's payload
//! starts with its name as `len(LEB128) ‖ UTF-8 bytes`). Section names are compared as raw bytes.
//! The entry stream is decoded by the oracle (`stellar-xdr`), one `ScSpecEntry` after another
//! with no frame, under the Soroban host's default depth and a length budget of the stream's size.
//!
//! Entry facts are a neutral rendering every conformance driver produces the same way
//! (`docs/conformance-protocol.md`, spec level): `kind` (`function`, `struct`, `union`, `enum`,
//! `error_enum`, `event`), `name`, `args` (function inputs, struct fields, union cases, enum
//! cases, event params, each `{name, type}`) and, for a function, `outputs`. Types are written
//! `u32`, `option<T>`, `result<T,E>`, `vec<T>`, `map<K,V>`, `tuple<A,B>`, `bytes_n<N>`,
//! `udt:<name>`; a union case's type is `void` or `tuple<…>`, an enum case's `=<value>`, an event
//! param's `<type>@<location>` (`topic_list`, `data`). Names are text when they are UTF-8 and
//! otherwise SEP-51 escaped (`\xNN`).
use serde_json::{json, Value};
use stellar_xdr::{
    Limited, Limits, ReadXdr, ScSpecEntry, ScSpecEventParamLocationV0, ScSpecTypeDef,
    ScSpecUdtUnionCaseV0, WriteXdr,
};

/// The custom section that holds a contract's interface.
pub const SPEC_SECTION: &[u8] = b"contractspecv0";

/// Depth budget for the entry stream: the Soroban host's default XDR depth.
pub const SPEC_DEPTH: u32 = 500;

/// One custom section of a Wasm module: its name and where its payload (after the name) lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSection {
    pub name: Vec<u8>,
    pub offset: usize,
    pub len: usize,
}

fn leb_u32(b: &[u8], mut i: usize, limit: usize) -> Result<(u32, usize), String> {
    let mut r: u64 = 0;
    for shift in (0..35).step_by(7) {
        if i >= limit {
            return Err("truncated LEB128 value".into());
        }
        let x = b[i];
        i += 1;
        r |= u64::from(x & 0x7f) << shift;
        if x & 0x80 == 0 {
            return u32::try_from(r)
                .map(|v| (v, i))
                .map_err(|_| "LEB128 value exceeds u32".into());
        }
    }
    Err("LEB128 value is longer than 5 bytes".into())
}

/// Every custom section of a Wasm module, in module order. Fails on a module that is not Wasm
/// version 1 or whose section framing is broken (a section running past the end of the module).
pub fn custom_sections(wasm: &[u8]) -> Result<Vec<CustomSection>, String> {
    if wasm.len() < 8 || &wasm[..4] != b"\0asm" {
        return Err("not a Wasm module (bad magic)".into());
    }
    if wasm[4..8] != [1, 0, 0, 0] {
        return Err("unsupported Wasm version".into());
    }
    let mut out = Vec::new();
    let mut i = 8;
    while i < wasm.len() {
        let id = wasm[i];
        let (size, j) = leb_u32(wasm, i + 1, wasm.len())?;
        let end = j
            .checked_add(size as usize)
            .filter(|&e| e <= wasm.len())
            .ok_or("a section runs past the end of the module")?;
        if id == 0 {
            let (n, k) = leb_u32(wasm, j, end)?;
            let name_end = k
                .checked_add(n as usize)
                .filter(|&e| e <= end)
                .ok_or("a custom section name runs past its section")?;
            out.push(CustomSection {
                name: wasm[k..name_end].to_vec(),
                offset: name_end,
                len: end - name_end,
            });
        }
        i = end;
    }
    Ok(out)
}

/// How a spec blob holds its entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// A Wasm module; the entries are in its `contractspecv0` custom sections.
    Wasm,
    /// A bare `SCSpecEntry` stream.
    Stream,
}

impl Container {
    pub fn parse(s: &str) -> Option<Container> {
        match s {
            "wasm" => Some(Container::Wasm),
            "xdr-stream" => Some(Container::Stream),
            _ => None,
        }
    }
}

/// What the bytes say.
#[derive(Debug, Clone, PartialEq)]
pub struct SpecFacts {
    /// `contractspecv0` sections (Wasm only).
    pub sections: Option<usize>,
    /// Every whole entry decoded, in order, across all spec sections.
    pub entries: Vec<ScSpecEntry>,
    /// Every section's bytes decode to whole entries with nothing left over.
    pub clean_end: bool,
    /// Why the stream (or the module) does not end cleanly.
    pub error: Option<String>,
    /// Where each decoded entry's bytes lie in the blob: (offset, length).
    pub spans: Vec<(usize, usize)>,
}

/// Decode one stream: whole entries until the bytes end or an entry fails.
fn read_stream(
    b: &[u8],
    base: usize,
    out: &mut Vec<ScSpecEntry>,
    spans: &mut Vec<(usize, usize)>,
) -> Result<(), String> {
    let mut pos = 0;
    while pos < b.len() {
        let rest = &b[pos..];
        let mut r = Limited::new(
            std::io::Cursor::new(rest),
            Limits {
                depth: SPEC_DEPTH,
                len: b.len(),
            },
        );
        match ScSpecEntry::read_xdr(&mut r) {
            Ok(e) => {
                let used = r.inner.position() as usize;
                out.push(e);
                spans.push((base + pos, used));
                pos += used;
            }
            Err(e) => {
                return Err(format!(
                    "entry {} at byte {} of the stream: {e}",
                    out.len(),
                    pos
                ))
            }
        }
    }
    Ok(())
}

/// Read a spec blob.
pub fn read(blob: &[u8], container: Container) -> SpecFacts {
    let mut f = SpecFacts {
        sections: None,
        entries: Vec::new(),
        clean_end: true,
        error: None,
        spans: Vec::new(),
    };
    match container {
        Container::Stream => {
            if let Err(e) = read_stream(blob, 0, &mut f.entries, &mut f.spans) {
                f.clean_end = false;
                f.error = Some(e);
            }
        }
        Container::Wasm => match custom_sections(blob) {
            Err(e) => {
                f.clean_end = false;
                f.error = Some(e);
                f.sections = Some(0);
            }
            Ok(all) => {
                let spec: Vec<&CustomSection> =
                    all.iter().filter(|s| s.name == SPEC_SECTION).collect();
                f.sections = Some(spec.len());
                for (n, s) in spec.iter().enumerate() {
                    let b = &blob[s.offset..s.offset + s.len];
                    if let Err(e) = read_stream(b, s.offset, &mut f.entries, &mut f.spans) {
                        f.clean_end = false;
                        f.error = Some(format!("section {n}: {e}"));
                        break;
                    }
                }
            }
        },
    }
    f
}

/// The payloads of a Wasm module's `contractspecv0` sections, as (offset, length).
pub fn spec_sections(wasm: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    Ok(custom_sections(wasm)?
        .into_iter()
        .filter(|s| s.name == SPEC_SECTION)
        .map(|s| (s.offset, s.len))
        .collect())
}

/// Text of a spec name: the string when it is UTF-8, else SEP-51 escaped.
pub fn name_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b
            .iter()
            .map(|&c| {
                if (0x20..0x7f).contains(&c) && c != b'\\' {
                    (c as char).to_string()
                } else {
                    format!("\\x{c:02x}")
                }
            })
            .collect(),
    }
}

/// The neutral text of a type.
pub fn type_text(t: &ScSpecTypeDef) -> String {
    use ScSpecTypeDef as T;
    match t {
        T::Val => "val".into(),
        T::Bool => "bool".into(),
        T::Void => "void".into(),
        T::Error => "error".into(),
        T::U32 => "u32".into(),
        T::I32 => "i32".into(),
        T::U64 => "u64".into(),
        T::I64 => "i64".into(),
        T::Timepoint => "timepoint".into(),
        T::Duration => "duration".into(),
        T::U128 => "u128".into(),
        T::I128 => "i128".into(),
        T::U256 => "u256".into(),
        T::I256 => "i256".into(),
        T::Bytes => "bytes".into(),
        T::String => "string".into(),
        T::Symbol => "symbol".into(),
        T::Address => "address".into(),
        T::MuxedAddress => "muxed_address".into(),
        T::Option(o) => format!("option<{}>", type_text(&o.value_type)),
        T::Result(r) => format!(
            "result<{},{}>",
            type_text(&r.ok_type),
            type_text(&r.error_type)
        ),
        T::Vec(v) => format!("vec<{}>", type_text(&v.element_type)),
        T::Map(m) => format!(
            "map<{},{}>",
            type_text(&m.key_type),
            type_text(&m.value_type)
        ),
        T::Tuple(t) => format!(
            "tuple<{}>",
            t.value_types
                .iter()
                .map(type_text)
                .collect::<Vec<_>>()
                .join(",")
        ),
        T::BytesN(b) => format!("bytes_n<{}>", b.n),
        T::Udt(u) => format!("udt:{}", name_text(u.name.as_slice())),
    }
}

fn arg(name: &[u8], ty: String) -> Value {
    json!({"name": name_text(name), "type": ty})
}

/// The neutral facts of one entry.
pub fn entry_fact(e: &ScSpecEntry) -> Value {
    match e {
        ScSpecEntry::FunctionV0(f) => json!({
            "kind": "function",
            "name": name_text(f.name.0.as_slice()),
            "args": f.inputs.iter().map(|i| arg(i.name.as_slice(), type_text(&i.type_))).collect::<Vec<_>>(),
            "outputs": f.outputs.iter().map(type_text).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtStructV0(s) => json!({
            "kind": "struct",
            "name": name_text(s.name.as_slice()),
            "args": s.fields.iter().map(|f| arg(f.name.as_slice(), type_text(&f.type_))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtUnionV0(u) => json!({
            "kind": "union",
            "name": name_text(u.name.as_slice()),
            "args": u.cases.iter().map(|c| match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => arg(v.name.as_slice(), "void".into()),
                ScSpecUdtUnionCaseV0::TupleV0(t) => arg(
                    t.name.as_slice(),
                    format!("tuple<{}>", t.type_.iter().map(type_text).collect::<Vec<_>>().join(",")),
                ),
            }).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtEnumV0(u) => json!({
            "kind": "enum",
            "name": name_text(u.name.as_slice()),
            "args": u.cases.iter().map(|c| arg(c.name.as_slice(), format!("={}", c.value))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::UdtErrorEnumV0(u) => json!({
            "kind": "error_enum",
            "name": name_text(u.name.as_slice()),
            "args": u.cases.iter().map(|c| arg(c.name.as_slice(), format!("={}", c.value))).collect::<Vec<_>>(),
        }),
        ScSpecEntry::EventV0(ev) => json!({
            "kind": "event",
            "name": name_text(ev.name.as_slice()),
            "args": ev.params.iter().map(|p| arg(
                p.name.as_slice(),
                format!("{}@{}", type_text(&p.type_), match p.location {
                    ScSpecEventParamLocationV0::Data => "data",
                    ScSpecEventParamLocationV0::TopicList => "topic_list",
                }),
            )).collect::<Vec<_>>(),
        }),
    }
}

/// The `expect.spec` block for a blob: `sections` (Wasm only), `entries`, `clean_end`.
pub fn expect_block(f: &SpecFacts) -> Value {
    let mut m = serde_json::Map::new();
    if let Some(n) = f.sections {
        m.insert("sections".into(), json!(n));
    }
    m.insert(
        "entries".into(),
        Value::Array(f.entries.iter().map(entry_fact).collect()),
    );
    m.insert("clean_end".into(), json!(f.clean_end));
    Value::Object(m)
}

/// Encode entries as a stream (no frame between them).
pub fn encode_stream(entries: &[ScSpecEntry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for e in entries {
        out.extend(e.to_xdr(Limits::none()).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn leb_bytes(mut n: u32) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            v.push(b);
            return v;
        }
        v.push(b | 0x80);
    }
}

/// A minimal Wasm module (header only) followed by one custom section per `(name, payload)`.
pub fn wasm_with_sections(sections: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut w = b"\0asm\x01\0\0\0".to_vec();
    for (name, payload) in sections {
        let mut body = leb_bytes(name.len() as u32);
        body.extend_from_slice(name);
        body.extend_from_slice(payload);
        w.push(0);
        w.extend(leb_bytes(body.len() as u32));
        w.extend(body);
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{ScSpecFunctionInputV0, ScSpecFunctionV0, ScSymbol, StringM, VecM};

    fn func(name: &str, input: ScSpecTypeDef) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: ScSymbol(name.try_into().unwrap()),
            inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: "a".try_into().unwrap(),
                type_: input,
            }])
            .unwrap(),
            outputs: VecM::try_from(vec![ScSpecTypeDef::Bool]).unwrap(),
        })
    }

    #[test]
    fn sections_and_stream() {
        let s = encode_stream(&[
            func("f", ScSpecTypeDef::U32),
            func("g", ScSpecTypeDef::I128),
        ])
        .unwrap();
        let w = wasm_with_sections(&[(b"other", b"xyz"), (SPEC_SECTION, &s)]);
        let f = read(&w, Container::Wasm);
        assert_eq!(f.sections, Some(1));
        assert!(f.clean_end);
        assert_eq!(f.entries.len(), 2);
        assert_eq!(
            entry_fact(&f.entries[1]),
            json!({"kind":"function","name":"g","args":[{"name":"a","type":"i128"}],"outputs":["bool"]})
        );
        let (off, len) = f.spans[0];
        assert_eq!(&w[off..off + len], &s[..len]);
        // A truncated stream keeps the whole entries before the cut and does not end cleanly.
        let t = read(&s[..s.len() - 3], Container::Stream);
        assert_eq!((t.entries.len(), t.clean_end), (1, false));
        // Two sections are both read; the count says so.
        let two = wasm_with_sections(&[(SPEC_SECTION, &s), (SPEC_SECTION, &s)]);
        let f2 = read(&two, Container::Wasm);
        assert_eq!(
            (f2.sections, f2.entries.len(), f2.clean_end),
            (Some(2), 4, true)
        );
    }

    #[test]
    fn broken_framing() {
        assert!(custom_sections(b"\0asm\x01\0\0\0\0\x05\x01").is_err());
        assert!(custom_sections(b"nope").is_err());
        assert_eq!(read(b"\0asm\x01\0\0\0", Container::Wasm).sections, Some(0));
    }
}
