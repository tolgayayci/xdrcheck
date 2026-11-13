//! A schema-driven XDR value tree with byte offsets.
//!
//! [`decode`] reads bytes of a named type into a [`Node`] tree, strictly (RFC 4506: booleans and
//! optional flags 0 or 1, enum values declared, union arms declared, zero padding, lengths within
//! their declared maximum and within the input, no trailing bytes). Every node keeps the byte
//! range `[off, end)` it was read from, so a wire-level mutation can be applied at the exact
//! offset of a typed value. [`encode`] writes a (possibly mutated) tree back. [`sites`] lists
//! every node with its value path (`/v1/txProcessing/0/result/...`), the most specific named type
//! at that place, and its byte range: the path-to-byte-offset map.
//!
//! Paths use the `.x` field and arm names. A void union arm is named by its case
//! (`SCV_VOID`); an optional is transparent in the path. The tree is recursive: build, walk and
//! drop deep trees on a large stack ([`xdrcheck_xdr::with_stack`]).

use anyhow::{anyhow, bail, Result};

use crate::schema::{Schema, Shape, Ty};

/// A value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V {
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    /// The raw word (0 or 1 when decoded strictly).
    Bool(u32),
    Enum(i32),
    /// Fixed or variable opaque, or a string.
    Bytes(Vec<u8>),
    /// Fixed or variable array.
    List(Vec<Node>),
    Struct(Vec<Node>),
    /// Discriminant value and the arm's value (`None` for a void arm).
    Union(i32, Option<Box<Node>>),
    Opt(Option<Box<Node>>),
}

/// A value and the bytes it was read from (`off..end`, padding included). Nodes built by a
/// mutation carry `0..0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub v: V,
    pub off: u32,
    pub end: u32,
}

impl Node {
    pub fn new(v: V) -> Node {
        Node { v, off: 0, end: 0 }
    }

    /// The child at one location step.
    pub fn child_mut(&mut self, step: u32) -> Option<&mut Node> {
        match &mut self.v {
            V::Struct(f) | V::List(f) => f.get_mut(step as usize),
            V::Union(_, Some(a)) | V::Opt(Some(a)) if step == 0 => Some(a),
            _ => None,
        }
    }

    pub fn child(&self, step: u32) -> Option<&Node> {
        match &self.v {
            V::Struct(f) | V::List(f) => f.get(step as usize),
            V::Union(_, Some(a)) | V::Opt(Some(a)) if step == 0 => Some(a),
            _ => None,
        }
    }

    /// The node at a location (a list of child steps from this node).
    pub fn at_mut(&mut self, loc: &[u32]) -> Option<&mut Node> {
        let mut cur = self;
        for s in loc {
            cur = cur.child_mut(*s)?;
        }
        Some(cur)
    }

    pub fn at(&self, loc: &[u32]) -> Option<&Node> {
        let mut cur = self;
        for s in loc {
            cur = cur.child(*s)?;
        }
        Some(cur)
    }
}

/// Maximum nesting the tree reader follows; deeper input is refused (the oracle's own depth limit
/// is far below what a value of this depth costs).
pub const MAX_DEPTH: u32 = 20_000;

struct Dec<'a> {
    b: &'a [u8],
    pos: usize,
    s: &'a Schema,
    depth: u32,
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() - self.pos < n {
            bail!(
                "input ends at {} while reading {n} bytes at {}",
                self.b.len(),
                self.pos
            );
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn pad(&mut self, n: usize) -> Result<()> {
        let p = (4 - n % 4) % 4;
        if self.take(p)?.iter().any(|b| *b != 0) {
            bail!("non-zero padding at {}", self.pos - p);
        }
        Ok(())
    }
    fn len(&mut self, max: u32) -> Result<usize> {
        let n = self.u32()?;
        if n > max {
            bail!(
                "length {n} above the declared maximum {max} at {}",
                self.pos - 4
            );
        }
        if n as usize > self.b.len() - self.pos {
            bail!("length {n} above the remaining input at {}", self.pos - 4);
        }
        Ok(n as usize)
    }

    fn node(&mut self, t: &Ty) -> Result<Node> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            bail!("nesting deeper than {MAX_DEPTH}");
        }
        let off = self.pos as u32;
        let v = self.value(t)?;
        self.depth -= 1;
        Ok(Node {
            v,
            off,
            end: self.pos as u32,
        })
    }

    fn value(&mut self, t: &Ty) -> Result<V> {
        let (shape, name) = self.s.shape(t)?;
        Ok(match shape {
            Shape::Prim(p) => match p {
                Ty::Int => V::I32(self.u32()? as i32),
                Ty::UInt => V::U32(self.u32()?),
                Ty::Hyper => V::I64(self.u64()? as i64),
                Ty::UHyper => V::U64(self.u64()?),
                Ty::Bool => {
                    let w = self.u32()?;
                    if w > 1 {
                        bail!("bool {w} at {}", self.pos - 4);
                    }
                    V::Bool(w)
                }
                Ty::OpaqueFixed(n) => {
                    let b = self.take(*n as usize)?.to_vec();
                    self.pad(*n as usize)?;
                    V::Bytes(b)
                }
                Ty::OpaqueVar(max) | Ty::Str(max) => {
                    let n = self.len(*max)?;
                    let b = self.take(n)?.to_vec();
                    self.pad(n)?;
                    V::Bytes(b)
                }
                Ty::Array(e, n) => V::List((0..*n).map(|_| self.node(e)).collect::<Result<_>>()?),
                Ty::VarArray(e, max) => {
                    let n = self.len(*max)?;
                    V::List((0..n).map(|_| self.node(e)).collect::<Result<_>>()?)
                }
                Ty::Optional(e) => match self.u32()? {
                    0 => V::Opt(None),
                    1 => V::Opt(Some(Box::new(self.node(e)?))),
                    f => bail!("optional flag {f} at {}", self.pos - 4),
                },
                Ty::Ref(_) => unreachable!("shape follows references"),
            },
            Shape::Struct(fields) => V::Struct(
                fields
                    .iter()
                    .map(|(_, ft)| self.node(ft))
                    .collect::<Result<_>>()?,
            ),
            Shape::Enum(members) => {
                let v = self.u32()? as i32;
                if !members.iter().any(|(_, m)| *m == v) {
                    bail!(
                        "{} value {v} not declared at {}",
                        name.unwrap_or("enum"),
                        self.pos - 4
                    );
                }
                V::Enum(v)
            }
            Shape::Union(disc, arms) => {
                let at = self.pos;
                let d = self.u32()? as i32;
                if let Some(m) = self.s.enum_members(disc) {
                    if !m.iter().any(|(_, x)| *x == d) {
                        bail!(
                            "{} discriminant {d} not declared at {at}",
                            name.unwrap_or("union")
                        );
                    }
                }
                let arm = arms
                    .iter()
                    .find(|a| a.cases.iter().any(|(c, _)| *c == d))
                    .ok_or_else(|| {
                        anyhow!("{} has no arm for {d} at {at}", name.unwrap_or("union"))
                    })?;
                let inner = match &arm.ty {
                    Some(at) => Some(Box::new(self.node(at)?)),
                    None => None,
                };
                V::Union(d, inner)
            }
        })
    }
}

/// Decode `bytes` as one value of type `t`, strictly, with no trailing bytes.
pub fn decode(s: &Schema, t: &Ty, bytes: &[u8]) -> Result<Node> {
    let mut d = Dec {
        b: bytes,
        pos: 0,
        s,
        depth: 0,
    };
    let n = d.node(t)?;
    if d.pos != bytes.len() {
        bail!("{} trailing bytes", bytes.len() - d.pos);
    }
    Ok(n)
}

/// Decode a value of the named type.
pub fn decode_named(s: &Schema, type_name: &str, bytes: &[u8]) -> Result<Node> {
    let (k, _) = s
        .lookup(type_name)
        .ok_or_else(|| anyhow!("unknown XDR type {type_name}"))?;
    decode(s, &Ty::Ref(k.to_string()), bytes)
}

fn put_pad(out: &mut Vec<u8>, n: usize) {
    out.extend(std::iter::repeat_n(0u8, (4 - n % 4) % 4));
}

/// Encode a tree as type `t`. Shapes that do not match the type are an error (a mutation bug).
pub fn encode(s: &Schema, t: &Ty, n: &Node) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    enc(s, t, n, &mut out)?;
    Ok(out)
}

fn enc(s: &Schema, t: &Ty, n: &Node, out: &mut Vec<u8>) -> Result<()> {
    let (shape, _) = s.shape(t)?;
    match (shape, &n.v) {
        (Shape::Prim(Ty::Int), V::I32(x)) => out.extend(x.to_be_bytes()),
        (Shape::Prim(Ty::UInt), V::U32(x)) => out.extend(x.to_be_bytes()),
        (Shape::Prim(Ty::Hyper), V::I64(x)) => out.extend(x.to_be_bytes()),
        (Shape::Prim(Ty::UHyper), V::U64(x)) => out.extend(x.to_be_bytes()),
        (Shape::Prim(Ty::Bool), V::Bool(x)) => out.extend(x.to_be_bytes()),
        (Shape::Prim(Ty::OpaqueFixed(k)), V::Bytes(b)) => {
            if b.len() != *k as usize {
                bail!("fixed opaque of {k} bytes holds {}", b.len());
            }
            out.extend(b);
            put_pad(out, b.len());
        }
        (Shape::Prim(Ty::OpaqueVar(_) | Ty::Str(_)), V::Bytes(b)) => {
            out.extend((b.len() as u32).to_be_bytes());
            out.extend(b);
            put_pad(out, b.len());
        }
        (Shape::Prim(Ty::Array(e, k)), V::List(items)) => {
            if items.len() != *k as usize {
                bail!("fixed array of {k} holds {}", items.len());
            }
            for i in items {
                enc(s, e, i, out)?;
            }
        }
        (Shape::Prim(Ty::VarArray(e, _)), V::List(items)) => {
            out.extend((items.len() as u32).to_be_bytes());
            for i in items {
                enc(s, e, i, out)?;
            }
        }
        (Shape::Prim(Ty::Optional(e)), V::Opt(o)) => match o {
            None => out.extend(0u32.to_be_bytes()),
            Some(i) => {
                out.extend(1u32.to_be_bytes());
                enc(s, e, i, out)?;
            }
        },
        (Shape::Struct(fields), V::Struct(vals)) => {
            if fields.len() != vals.len() {
                bail!("struct of {} fields holds {}", fields.len(), vals.len());
            }
            for ((_, ft), v) in fields.iter().zip(vals) {
                enc(s, ft, v, out)?;
            }
        }
        (Shape::Enum(_), V::Enum(x)) => out.extend(x.to_be_bytes()),
        (Shape::Union(_, arms), V::Union(d, inner)) => {
            out.extend(d.to_be_bytes());
            let arm = arms
                .iter()
                .find(|a| a.cases.iter().any(|(c, _)| c == d))
                .ok_or_else(|| anyhow!("union has no arm for {d}"))?;
            match (&arm.ty, inner) {
                (None, None) => {}
                (Some(at), Some(i)) => enc(s, at, i, out)?,
                _ => bail!("union arm {d}: payload does not match the arm"),
            }
        }
        (sh, v) => bail!("value {} does not fit type {sh:?}", kind(v)),
    }
    Ok(())
}

fn kind(v: &V) -> &'static str {
    match v {
        V::I32(_) => "int",
        V::U32(_) => "unsigned int",
        V::I64(_) => "hyper",
        V::U64(_) => "unsigned hyper",
        V::Bool(_) => "bool",
        V::Enum(_) => "enum",
        V::Bytes(_) => "bytes",
        V::List(_) => "list",
        V::Struct(_) => "struct",
        V::Union(..) => "union",
        V::Opt(_) => "optional",
    }
}

/// The smallest valid value of a type: zeros, empty variable-length values, absent optionals, and
/// for a union its void arm if it has one, else its first arm.
pub fn minimal(s: &Schema, t: &Ty) -> Result<Node> {
    minimal_at(s, t, 0)
}

fn minimal_at(s: &Schema, t: &Ty, depth: u32) -> Result<Node> {
    if depth > 256 {
        bail!("no finite minimal value");
    }
    let (shape, _) = s.shape(t)?;
    Ok(Node::new(match shape {
        Shape::Prim(p) => match p {
            Ty::Int => V::I32(0),
            Ty::UInt => V::U32(0),
            Ty::Hyper => V::I64(0),
            Ty::UHyper => V::U64(0),
            Ty::Bool => V::Bool(0),
            Ty::OpaqueFixed(n) => V::Bytes(vec![0; *n as usize]),
            Ty::OpaqueVar(_) | Ty::Str(_) => V::Bytes(Vec::new()),
            Ty::Array(e, n) => V::List(
                (0..*n)
                    .map(|_| minimal_at(s, e, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Ty::VarArray(..) => V::List(Vec::new()),
            Ty::Optional(_) => V::Opt(None),
            Ty::Ref(_) => unreachable!(),
        },
        Shape::Struct(fields) => V::Struct(
            fields
                .iter()
                .map(|(_, ft)| minimal_at(s, ft, depth + 1))
                .collect::<Result<_>>()?,
        ),
        Shape::Enum(m) => V::Enum(m.first().map(|x| x.1).unwrap_or(0)),
        Shape::Union(_, arms) => {
            let arm = arms
                .iter()
                .find(|a| a.ty.is_none())
                .or(arms.first())
                .ok_or_else(|| anyhow!("union without arms"))?;
            let inner = match &arm.ty {
                Some(at) => Some(Box::new(minimal_at(s, at, depth + 1)?)),
                None => None,
            };
            V::Union(arm.cases[0].0, inner)
        }
    }))
}

/// One node of a tree, as the mutators see it.
#[derive(Debug, Clone)]
pub struct Site {
    /// Child steps from the root.
    pub loc: Vec<u32>,
    /// Value path: `/` and the field, index or arm names.
    pub path: String,
    /// The type expression at this place.
    pub ty: Ty,
    /// The most specific named type at this place (the first reference met), if any.
    pub type_name: Option<String>,
    /// Name of the struct field or union arm this node fills (`None` at the root and for list
    /// elements).
    pub field: Option<String>,
    pub off: u32,
    pub end: u32,
}

impl Site {
    /// The path with every index replaced by `*`, for signatures.
    pub fn type_path(&self) -> String {
        generalise(&self.path)
    }
}

/// A value path with every list index replaced by `*`.
pub fn generalise(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                "*"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Every node of the tree, parents before children, with locations, paths, types and offsets.
pub fn sites(s: &Schema, root_ty: &Ty, root: &Node) -> Result<Vec<Site>> {
    let mut out = Vec::new();
    let mut loc = Vec::new();
    walk(s, root_ty, root, &mut loc, String::new(), None, &mut out)?;
    Ok(out)
}

fn walk(
    s: &Schema,
    t: &Ty,
    n: &Node,
    loc: &mut Vec<u32>,
    path: String,
    field: Option<String>,
    out: &mut Vec<Site>,
) -> Result<()> {
    let (shape, name) = s.shape(t)?;
    out.push(Site {
        loc: loc.clone(),
        path: if path.is_empty() {
            "/".into()
        } else {
            path.clone()
        },
        ty: t.clone(),
        type_name: name.map(str::to_string),
        field: field.clone(),
        off: n.off,
        end: n.end,
    });
    let mut child =
        |ct: &Ty, cn: &Node, step: u32, seg: &str, fname: Option<String>, out: &mut Vec<Site>| {
            loc.push(step);
            let r = walk(s, ct, cn, loc, format!("{path}/{seg}"), fname, out);
            loc.pop();
            r
        };
    match (shape, &n.v) {
        (Shape::Prim(Ty::Array(e, _) | Ty::VarArray(e, _)), V::List(items)) => {
            for (i, it) in items.iter().enumerate() {
                child(e, it, i as u32, &i.to_string(), None, out)?;
            }
        }
        (Shape::Prim(Ty::Optional(e)), V::Opt(Some(inner))) => {
            // Transparent in the path: the element sits where the optional is.
            loc.push(0);
            let r = walk(s, e, inner, loc, path.clone(), field, out);
            loc.pop();
            r?;
        }
        (Shape::Struct(fields), V::Struct(vals)) => {
            for (i, ((fname, ft), v)) in fields.iter().zip(vals).enumerate() {
                child(ft, v, i as u32, fname, Some(fname.clone()), out)?;
            }
        }
        (Shape::Union(_, arms), V::Union(d, Some(inner))) => {
            if let Some(arm) = arms.iter().find(|a| a.cases.iter().any(|(c, _)| c == d)) {
                if let (Some(at), Some(an)) = (&arm.ty, &arm.name) {
                    child(at, inner, 0, an, Some(an.clone()), out)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// The type expression at a location, following the tree's union arms.
pub fn type_at(s: &Schema, root_ty: &Ty, root: &Node, loc: &[u32]) -> Result<Ty> {
    let mut t = root_ty.clone();
    let mut n = root;
    for step in loc {
        let (shape, _) = s.shape(&t)?;
        t = match (shape, &n.v) {
            (Shape::Prim(Ty::Array(e, _) | Ty::VarArray(e, _)), V::List(_)) => (**e).clone(),
            (Shape::Prim(Ty::Optional(e)), V::Opt(Some(_))) => (**e).clone(),
            (Shape::Struct(fields), V::Struct(_)) => fields
                .get(*step as usize)
                .ok_or_else(|| anyhow!("no field {step}"))?
                .1
                .clone(),
            (Shape::Union(_, arms), V::Union(d, Some(_))) => arms
                .iter()
                .find(|a| a.cases.iter().any(|(c, _)| c == d))
                .and_then(|a| a.ty.clone())
                .ok_or_else(|| anyhow!("no arm for {d}"))?,
            _ => bail!("location step {step} does not exist"),
        };
        n = n
            .child(*step)
            .ok_or_else(|| anyhow!("location step {step} does not exist"))?;
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scval_roundtrip_and_offsets() {
        let s = Schema::load().unwrap();
        // SCV_VEC (16), present, 2 elements: SCV_U32 7, SCV_SYMBOL "ab".
        let bytes = hex::decode(
            "00000010000000010000000200000003000000070000000f000000026162 0000".replace(' ', ""),
        )
        .unwrap();
        let n = decode_named(&s, "ScVal", &bytes).unwrap();
        let t = Ty::Ref("SCVal".into());
        assert_eq!(encode(&s, &t, &n).unwrap(), bytes);
        let sites = sites(&s, &t, &n).unwrap();
        let sym = sites.iter().find(|x| x.path == "/vec/1/sym").unwrap();
        assert_eq!((sym.off, sym.end), (24, 32));
        assert_eq!(sym.type_name.as_deref(), Some("SCSymbol"));
        assert_eq!(generalise("/vec/1/sym"), "/vec/*/sym");
        assert!(decode_named(&s, "ScVal", &[0, 0, 0, 0, 0, 0, 0, 2]).is_err());
    }
}
