//! `wasm-post`: the post-build step for the test contracts.
//!
//! soroban-sdk 29 always builds with "spec shaking v2": every non-function
//! spec entry (types, events) is written to `contractspecv0`, and a 14-byte
//! marker (`SpEcV1` + first 8 bytes of the entry's XDR sha256) is left in the
//! data section for each entry the code really uses. A build system must then
//! drop the entries without a marker; normally `stellar contract build` does
//! that. This tool does the same filtering with the marker functions from
//! `soroban-spec` 29.0.1 (the implementation that ships with the SDK), so the
//! build depends only on pinned crates.
//!
//! Commands:
//! - `wasm-post shake <in.wasm> <out.wasm>`: write a copy whose
//!   `contractspecv0` keeps functions and marked entries only. Every other
//!   byte is copied unchanged.
//! - `wasm-post info <file.wasm>`: print a JSON object with the env interface
//!   version, the contract meta, the spec function names and the number of
//!   spec entries.
use std::{collections::HashSet, fs, io::Cursor, process::ExitCode};

use sha2::{Digest, Sha256};
use soroban_spec::shaking;
use stellar_xdr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry, ScSpecEntry, WriteXdr};

const SPEC: &str = "contractspecv0";
const META: &str = "contractmetav0";
const ENV_META: &str = "contractenvmetav0";

/// One top-level wasm section: id, the offset range of the whole section
/// (header included) and, for custom sections, the name and payload.
struct Section<'a> {
    id: u8,
    raw: &'a [u8],
    custom: Option<(&'a str, &'a [u8])>,
}

fn read_leb_u32(b: &[u8], pos: &mut usize) -> Result<u32, String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos).ok_or("truncated LEB128")?;
        *pos += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 28 {
            return Err("LEB128 too long".into());
        }
    }
}

fn write_leb_u32(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn sections(wasm: &[u8]) -> Result<Vec<Section<'_>>, String> {
    if wasm.len() < 8 || &wasm[0..4] != b"\0asm" {
        return Err("not a wasm module".into());
    }
    let mut pos = 8;
    let mut out = Vec::new();
    while pos < wasm.len() {
        let start = pos;
        let id = wasm[pos];
        pos += 1;
        let size = read_leb_u32(wasm, &mut pos)? as usize;
        let body_start = pos;
        let end = body_start
            .checked_add(size)
            .ok_or("section size overflow")?;
        if end > wasm.len() {
            return Err("section runs past the end of the file".into());
        }
        let custom = if id == 0 {
            let mut p = body_start;
            let name_len = read_leb_u32(wasm, &mut p)? as usize;
            let name = std::str::from_utf8(&wasm[p..p + name_len])
                .map_err(|_| "custom section name is not UTF-8")?;
            Some((name, &wasm[p + name_len..end]))
        } else {
            None
        };
        out.push(Section {
            id,
            raw: &wasm[start..end],
            custom,
        });
        pos = end;
    }
    Ok(out)
}

fn custom<'a>(secs: &'a [Section<'a>], name: &str) -> Vec<&'a [u8]> {
    secs.iter()
        .filter_map(|s| s.custom.filter(|(n, _)| *n == name).map(|(_, d)| d))
        .collect()
}

fn read_all<T: ReadXdr>(data: &[u8]) -> Result<Vec<T>, String> {
    let limits = Limits {
        depth: 500,
        len: data.len(),
    };
    T::read_xdr_iter(&mut Limited::new(Cursor::new(data), limits))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("decoding custom section: {e}"))
}

fn spec_entries(secs: &[Section<'_>]) -> Result<Vec<ScSpecEntry>, String> {
    let specs = custom(secs, SPEC);
    if specs.len() != 1 {
        return Err(format!(
            "expected one {SPEC} section, found {}",
            specs.len()
        ));
    }
    read_all(specs[0])
}

fn meta_entries(secs: &[Section<'_>]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for data in custom(secs, META) {
        for e in read_all::<ScMetaEntry>(data)? {
            let ScMetaEntry::ScMetaV0(v) = e;
            out.push((
                String::from_utf8_lossy(v.key.as_slice()).into_owned(),
                String::from_utf8_lossy(v.val.as_slice()).into_owned(),
            ));
        }
    }
    Ok(out)
}

fn shake(wasm: &[u8]) -> Result<(Vec<u8>, usize, usize), String> {
    let secs = sections(wasm)?;
    let meta = meta_entries(&secs)?;
    let version = meta
        .iter()
        .find(|(k, _)| k == shaking::META_KEY)
        .map(|(_, v)| v.as_str());
    if version != Some(shaking::META_VALUE_V2) {
        return Err(format!(
            "contract meta {} is {version:?}, expected \"{}\"",
            shaking::META_KEY,
            shaking::META_VALUE_V2
        ));
    }
    let markers: HashSet<shaking::Marker> = shaking::find_all(wasm);
    let entries = spec_entries(&secs)?;
    let before = entries.len();
    let mut kept = Vec::new();
    for e in entries {
        let xdr = e
            .to_xdr(Limits::none())
            .map_err(|err| format!("encoding spec entry: {err}"))?;
        let keep = matches!(e, ScSpecEntry::FunctionV0(_))
            || markers.contains(&shaking::generate_marker_for_xdr(&xdr));
        if keep {
            kept.extend_from_slice(&xdr);
        }
    }
    let after_count = {
        let k: Vec<ScSpecEntry> = read_all(&kept)?;
        k.len()
    };
    let mut out = wasm[..8].to_vec();
    for s in &secs {
        match s.custom {
            Some((name, _)) if name == SPEC => {
                let mut body = Vec::new();
                write_leb_u32(&mut body, name.len() as u32);
                body.extend_from_slice(name.as_bytes());
                body.extend_from_slice(&kept);
                out.push(s.id);
                write_leb_u32(&mut out, body.len() as u32);
                out.extend_from_slice(&body);
            }
            _ => out.extend_from_slice(s.raw),
        }
    }
    Ok((out, before, after_count))
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn info(wasm: &[u8]) -> Result<String, String> {
    let secs = sections(wasm)?;
    let env = custom(&secs, ENV_META);
    if env.len() != 1 {
        return Err(format!(
            "expected one {ENV_META} section, found {}",
            env.len()
        ));
    }
    let mut protocol = None;
    for e in read_all::<ScEnvMetaEntry>(env[0])? {
        let ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(v) = e;
        protocol = Some((v.protocol, v.pre_release));
    }
    let (proto, pre) = protocol.ok_or("no interface version in env meta")?;
    let entries = spec_entries(&secs)?;
    let functions: Vec<String> = entries
        .iter()
        .filter_map(|e| match e {
            ScSpecEntry::FunctionV0(f) => Some(json_str(&f.name.to_utf8_string_lossy())),
            _ => None,
        })
        .collect();
    let meta: Vec<String> = meta_entries(&secs)?
        .iter()
        .map(|(k, v)| format!("{}: {}", json_str(k), json_str(v)))
        .collect();
    let sha = hex(&Sha256::digest(wasm));
    Ok(format!(
        "{{\"wasm_sha256\": \"{sha}\", \"wasm_bytes\": {}, \"interface_version\": {{\"protocol\": {proto}, \"pre_release\": {pre}}}, \"contract_meta\": {{{}}}, \"spec_entries\": {}, \"functions\": [{}]}}",
        wasm.len(),
        meta.join(", "),
        entries.len(),
        functions.join(", ")
    ))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, input, output] if cmd == "shake" => {
            let wasm = fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            let (out, before, after) = shake(&wasm)?;
            fs::write(output, &out).map_err(|e| format!("{output}: {e}"))?;
            eprintln!("wasm-post: {input}: spec entries {before} -> {after}");
            Ok(())
        }
        [cmd, input] if cmd == "info" => {
            let wasm = fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            println!("{}", info(&wasm)?);
            Ok(())
        }
        _ => Err("usage: wasm-post shake <in.wasm> <out.wasm> | wasm-post info <file.wasm>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wasm-post: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb_round_trip() {
        for v in [0u32, 1, 127, 128, 300, 16_383, 16_384, u32::MAX] {
            let mut b = Vec::new();
            write_leb_u32(&mut b, v);
            let mut p = 0;
            assert_eq!(read_leb_u32(&b, &mut p).unwrap(), v);
            assert_eq!(p, b.len());
        }
    }

    #[test]
    fn rejects_non_wasm() {
        assert!(sections(b"not wasm").is_err());
    }
}
