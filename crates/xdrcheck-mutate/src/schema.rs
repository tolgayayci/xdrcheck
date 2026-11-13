//! The XDR schema the mutator walks: the pinned `stellar-xdr` crate's own definitions file
//! (`xdr-definitions-json/xdr.json`), committed here with the source text dropped
//! (`schema/xdr-definitions.json`; its `origin_sha256` is the hash of the file it was cut from).
//!
//! Every definition is a struct, an enum, a union or a typedef; every type expression is one of the
//! RFC 4506 forms. Constants are already folded into sizes by the generator. Names are the `.x`
//! names (`SCVal`, `AccountID`); [`Schema::lookup`] also accepts the Rust spelling (`ScVal`).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// The committed definitions file.
pub const DEFINITIONS: &str = include_str!("../schema/xdr-definitions.json");

/// "No declared maximum" for variable-length types.
pub const UNBOUNDED: u32 = u32::MAX;

/// A type expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    Int,
    UInt,
    Hyper,
    UHyper,
    Bool,
    OpaqueFixed(u32),
    OpaqueVar(u32),
    Str(u32),
    Array(Box<Ty>, u32),
    VarArray(Box<Ty>, u32),
    Optional(Box<Ty>),
    Ref(String),
}

/// One arm of a union.
#[derive(Debug, Clone)]
pub struct Arm {
    /// Case values (the discriminant's numeric value) with their enum member names when the
    /// discriminant is an enum.
    pub cases: Vec<(i32, Option<String>)>,
    /// The arm's field name; `None` for a void arm.
    pub name: Option<String>,
    /// The arm's type; `None` for a void arm.
    pub ty: Option<Ty>,
}

/// A named definition.
#[derive(Debug, Clone)]
pub enum Def {
    Struct(Vec<(String, Ty)>),
    Enum(Vec<(String, i32)>),
    Union { disc: Ty, arms: Vec<Arm> },
    Typedef(Ty),
}

/// The loaded schema.
#[derive(Debug)]
pub struct Schema {
    defs: HashMap<String, Def>,
    folded: HashMap<String, String>,
    /// SHA-256 of the definitions file the committed copy was cut from.
    pub origin_sha256: String,
}

/// What a type expression is once every typedef is followed.
#[derive(Debug, Clone, Copy)]
pub enum Shape<'a> {
    Prim(&'a Ty),
    Struct(&'a [(String, Ty)]),
    Enum(&'a [(String, i32)]),
    Union(&'a Ty, &'a [Arm]),
}

impl Schema {
    /// The committed schema.
    pub fn load() -> Result<Schema> {
        Self::parse(DEFINITIONS)
    }

    /// Parse a definitions document (the committed shape: `{origin_sha256, definitions: [...]}`).
    pub fn parse(text: &str) -> Result<Schema> {
        let doc: Value = serde_json::from_str(text).context("XDR definitions are not JSON")?;
        let mut defs = HashMap::new();
        let mut folded = HashMap::new();
        for d in doc["definitions"]
            .as_array()
            .ok_or_else(|| anyhow!("no definitions"))?
        {
            let name = d["name"]
                .as_str()
                .ok_or_else(|| anyhow!("definition without a name"))?;
            let def = match d["kind"].as_str() {
                Some("struct") => Def::Struct(
                    d["fields"]
                        .as_array()
                        .ok_or_else(|| anyhow!("{name}: no fields"))?
                        .iter()
                        .map(|f| {
                            Ok((
                                f["name"].as_str().unwrap_or("").to_string(),
                                ty(&f["type"])?,
                            ))
                        })
                        .collect::<Result<_>>()?,
                ),
                Some("enum") => Def::Enum(
                    d["members"]
                        .as_array()
                        .ok_or_else(|| anyhow!("{name}: no members"))?
                        .iter()
                        .map(|m| {
                            Ok((
                                m["name"].as_str().unwrap_or("").to_string(),
                                m["value"]
                                    .as_i64()
                                    .ok_or_else(|| anyhow!("{name}: member value"))?
                                    as i32,
                            ))
                        })
                        .collect::<Result<_>>()?,
                ),
                Some("union") => Def::Union {
                    disc: ty(&d["discriminant"]["type"])?,
                    arms: d["arms"]
                        .as_array()
                        .ok_or_else(|| anyhow!("{name}: no arms"))?
                        .iter()
                        .map(|a| {
                            let cases = a["cases"]
                                .as_array()
                                .ok_or_else(|| anyhow!("{name}: arm without cases"))?
                                .iter()
                                .map(|c| {
                                    Ok((
                                        c["value"]
                                            .as_i64()
                                            .ok_or_else(|| anyhow!("{name}: case value"))?
                                            as i32,
                                        c["name"].as_str().map(str::to_string),
                                    ))
                                })
                                .collect::<Result<_>>()?;
                            let t = if a["type"].is_null() {
                                None
                            } else {
                                Some(ty(&a["type"])?)
                            };
                            Ok(Arm {
                                cases,
                                name: a["name"].as_str().map(str::to_string),
                                ty: t,
                            })
                        })
                        .collect::<Result<_>>()?,
                },
                Some("typedef") => Def::Typedef(ty(&d["type"])?),
                other => bail!("{name}: unknown definition kind {other:?}"),
            };
            if defs.insert(name.to_string(), def).is_some() {
                bail!("{name} is defined twice");
            }
            if let Some(prev) = folded.insert(fold(name), name.to_string()) {
                bail!("{name} and {prev} differ only in case");
            }
        }
        Ok(Schema {
            defs,
            folded,
            origin_sha256: doc["origin_sha256"].as_str().unwrap_or("").to_string(),
        })
    }

    /// The definition of a name (`.x` spelling or Rust spelling).
    pub fn lookup(&self, name: &str) -> Option<(&str, &Def)> {
        if let Some((k, d)) = self.defs.get_key_value(name) {
            return Some((k.as_str(), d));
        }
        let k = self.folded.get(&fold(name))?;
        self.defs
            .get_key_value(k.as_str())
            .map(|(k, d)| (k.as_str(), d))
    }

    /// Follow typedefs to the shape, returning the last name met on the way (the most specific
    /// named type, e.g. `SCSymbol` for `string<32>`), if any.
    pub fn shape<'a>(&'a self, t: &'a Ty) -> Result<(Shape<'a>, Option<&'a str>)> {
        let mut cur = t;
        let mut name: Option<&'a str> = None;
        for _ in 0..64 {
            match cur {
                Ty::Ref(n) => {
                    let (k, d) = self.lookup(n).ok_or_else(|| anyhow!("unknown type {n}"))?;
                    if name.is_none() {
                        name = Some(k);
                    }
                    match d {
                        Def::Typedef(inner) => cur = inner,
                        Def::Struct(f) => return Ok((Shape::Struct(f), name)),
                        Def::Enum(m) => return Ok((Shape::Enum(m), name)),
                        Def::Union { disc, arms } => return Ok((Shape::Union(disc, arms), name)),
                    }
                }
                other => return Ok((Shape::Prim(other), name)),
            }
        }
        bail!("typedef chain too long")
    }

    /// Enum members of a discriminant type, when it is an enum.
    pub fn enum_members<'a>(&'a self, t: &'a Ty) -> Option<&'a [(String, i32)]> {
        match self.shape(t).ok()?.0 {
            Shape::Enum(m) => Some(m),
            _ => None,
        }
    }

    /// Whether the definition names a type.
    pub fn has(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }
}

fn fold(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn size(v: &Value) -> u32 {
    v.as_u64()
        .map(|n| n.min(UNBOUNDED as u64) as u32)
        .unwrap_or(UNBOUNDED)
}

fn ty(v: &Value) -> Result<Ty> {
    Ok(match v["kind"].as_str() {
        Some("int") => Ty::Int,
        Some("unsigned_int") => Ty::UInt,
        Some("hyper") => Ty::Hyper,
        Some("unsigned_hyper") => Ty::UHyper,
        Some("bool") => Ty::Bool,
        Some("opaque_fixed") => Ty::OpaqueFixed(size(&v["size"])),
        Some("opaque_var") => Ty::OpaqueVar(size(&v["max_size"])),
        Some("string") => Ty::Str(size(&v["max_size"])),
        Some("array") => Ty::Array(Box::new(ty(&v["element"])?), size(&v["count"])),
        Some("var_array") => Ty::VarArray(Box::new(ty(&v["element"])?), size(&v["max_count"])),
        Some("optional") => Ty::Optional(Box::new(ty(&v["element"])?)),
        Some("ref") => Ty::Ref(
            v["name"]
                .as_str()
                .ok_or_else(|| anyhow!("ref without a name"))?
                .to_string(),
        ),
        other => bail!("unknown type kind {other:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_resolves_rust_spelling() {
        let s = Schema::load().unwrap();
        assert!(s.lookup("ScVal").is_some());
        assert!(s.lookup("LedgerCloseMeta").is_some());
        let sym = Ty::Ref("SCSymbol".into());
        let (shape, name) = s.shape(&sym).unwrap();
        assert!(matches!(shape, Shape::Prim(Ty::Str(32))));
        assert_eq!(name, Some("SCSymbol"));
    }

    /// The committed copy is cut from the definitions of the pinned crate: when the crate's own
    /// file is in the local registry, its hash matches the recorded origin.
    #[test]
    fn origin_matches_the_pinned_crate_when_present() {
        let s = Schema::load().unwrap();
        let home = std::env::var("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| std::path::Path::new(&h).join(".cargo")));
        let Ok(home) = home else { return };
        let Ok(rd) = std::fs::read_dir(home.join("registry/src")) else {
            return;
        };
        for d in rd.flatten() {
            let f = d
                .path()
                .join("stellar-xdr-30.0.0/xdr-definitions-json/xdr.json");
            if let Ok(bytes) = std::fs::read(&f) {
                assert_eq!(
                    xdrcheck_xdr::sha256_hex(&bytes),
                    s.origin_sha256,
                    "{}",
                    f.display()
                );
            }
        }
    }
}
