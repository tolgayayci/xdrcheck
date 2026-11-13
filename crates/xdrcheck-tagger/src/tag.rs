//! Dangerous-value tags of one ledger, transaction by transaction.
//!
//! The transaction index is the position in the ledger's `tx_processing` (apply order, 0-based),
//! the index the scan uses. Paths name the field without element indexes, so one path is one
//! field of the XDR, whatever vector element held it.
use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountEntry, AccountId, Asset, AssetCode, ChangeTrustAsset, ClaimAtom, ContractEvent,
    ContractEventBody, ContractExecutable, ContractIdPreimage, FeeBumpTransactionInnerTx,
    GeneralizedTransactionSet, Hash, HashIdPreimage, HashIdPreimageContractId,
    InnerTransactionResultResult, Int128Parts, Int256Parts, LedgerCloseMeta, LedgerEntry,
    LedgerEntryChange, LedgerEntryData, LedgerEntryExt, LedgerKey, Limits, Memo, MuxedAccount,
    Operation, OperationBody, OperationResult, OperationResultTr, Preconditions, PublicKey,
    ScAddress, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    Transaction, TransactionEnvelope, TransactionMeta, TransactionPhase, TransactionResultResult,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, TrustLineAsset,
    TxSetComponent, UInt128Parts, UInt256Parts, Uint256, WriteXdr,
};

pub const TWO53: u64 = 1 << 53;
pub const TWO62: i64 = 1 << 62;
pub const TWO63: u64 = 1 << 63;
/// ScVal nesting depth from which a row is written (the histogram counts every depth).
pub const DEPTH_ROW: u32 = 8;
/// Authorized-invocation depth from which a row is written.
pub const AUTH_DEPTH_ROW: u32 = 4;
/// ScVec / ScMap length from which a row is written.
pub const LONG_SC: usize = 1000;

/// One hit before collapsing: tag, path, value; `mag` orders numeric values (bit length, digits).
pub struct Hit {
    pub tag: String,
    pub path: String,
    pub value: String,
    pub mag: (u32, String),
}

/// Per-transaction result.
pub struct TxTags {
    pub tx: u32,
    pub hash: String,
    pub hits: Vec<Hit>,
}

/// Facts about contracts gathered from one ledger (merged across the run).
#[derive(Default)]
pub struct Evidence {
    /// contract strkey -> asset string; proven Stellar Asset Contracts
    pub sac: BTreeMap<String, String>,
    /// (kind, depth) -> count
    pub depth: BTreeMap<(String, u32), u64>,
}

pub struct Net {
    pub id: [u8; 32],
}

impl Net {
    pub fn new(passphrase: &str) -> Net {
        Net {
            id: Sha256::digest(passphrase.as_bytes()).into(),
        }
    }
    /// The contract id of an asset's Stellar Asset Contract.
    pub fn sac_id(&self, a: &Asset) -> [u8; 32] {
        let p = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(self.id),
            contract_id_preimage: ContractIdPreimage::Asset(a.clone()),
        });
        Sha256::digest(p.to_xdr(Limits::none()).unwrap()).into()
    }
    fn tx_hash(&self, e: &TransactionEnvelope) -> [u8; 32] {
        let tagged = match e {
            TransactionEnvelope::TxV0(v) => {
                let t = &v.tx;
                TransactionSignaturePayloadTaggedTransaction::Tx(Transaction {
                    source_account: MuxedAccount::Ed25519(t.source_account_ed25519.clone()),
                    fee: t.fee,
                    seq_num: t.seq_num.clone(),
                    cond: match &t.time_bounds {
                        Some(b) => Preconditions::Time(b.clone()),
                        None => Preconditions::None,
                    },
                    memo: t.memo.clone(),
                    operations: t.operations.clone(),
                    ext: stellar_xdr::TransactionExt::V0,
                })
            }
            TransactionEnvelope::Tx(v) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(v.tx.clone())
            }
            TransactionEnvelope::TxFeeBump(v) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(v.tx.clone())
            }
        };
        let p = TransactionSignaturePayload {
            network_id: Hash(self.id),
            tagged_transaction: tagged,
        };
        Sha256::digest(p.to_xdr(Limits::none()).unwrap()).into()
    }
}

/// `native` or `CODE:ISSUER` as an asset.
pub fn parse_asset(s: &[u8]) -> Option<Asset> {
    let s = std::str::from_utf8(s).ok()?;
    if s == "native" {
        return Some(Asset::Native);
    }
    let (code, issuer) = s.split_once(':')?;
    let pk = stellar_strkey::ed25519::PublicKey::from_string(issuer).ok()?;
    let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
    let b = code.as_bytes();
    if b.is_empty() || b.len() > 12 {
        return None;
    }
    if b.len() <= 4 {
        let mut c = [0u8; 4];
        c[..b.len()].copy_from_slice(b);
        Some(Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(c),
            issuer,
        }))
    } else {
        let mut c = [0u8; 12];
        c[..b.len()].copy_from_slice(b);
        Some(Asset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
            asset_code: stellar_xdr::AssetCode12(c),
            issuer,
        }))
    }
}

pub fn contract_str(b: &[u8; 32]) -> String {
    format!("{}", stellar_strkey::Contract(*b))
}
fn account_str(a: &AccountId) -> String {
    let PublicKey::PublicKeyTypeEd25519(Uint256(b)) = &a.0;
    format!("{}", stellar_strkey::ed25519::PublicKey(*b))
}
fn account_key(a: &AccountId) -> [u8; 32] {
    let PublicKey::PublicKeyTypeEd25519(Uint256(b)) = &a.0;
    *b
}
fn muxed_key(m: &MuxedAccount) -> [u8; 32] {
    match m {
        MuxedAccount::Ed25519(Uint256(b)) => *b,
        MuxedAccount::MuxedEd25519(x) => x.ed25519.0,
    }
}

// ---------- numbers ----------

/// Decimal of a 256-bit magnitude given as big-endian 64-bit words.
fn dec_words(w: [u64; 4]) -> String {
    let mut w = w;
    if w.iter().all(|x| *x == 0) {
        return "0".into();
    }
    let mut parts: Vec<u64> = Vec::new();
    const BASE: u128 = 10_000_000_000_000_000_000; // 1e19
    while w.iter().any(|x| *x != 0) {
        let mut rem: u128 = 0;
        for x in w.iter_mut() {
            let cur = (rem << 64) | *x as u128;
            *x = (cur / BASE) as u64;
            rem = cur % BASE;
        }
        parts.push(rem as u64);
    }
    let mut s = parts.last().unwrap().to_string();
    for p in parts.iter().rev().skip(1) {
        s.push_str(&format!("{p:019}"));
    }
    s
}

fn bitlen(w: [u64; 4]) -> u32 {
    for (i, x) in w.iter().enumerate() {
        if *x != 0 {
            return (3 - i as u32) * 64 + 64 - x.leading_zeros();
        }
    }
    0
}

/// (negative, magnitude words) of a two's-complement 256-bit value.
fn neg256(w: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 1u128;
    for i in (0..4).rev() {
        let v = (!w[i]) as u128 + carry;
        out[i] = v as u64;
        carry = v >> 64;
    }
    out
}

fn wide(kind: &str, w: [u64; 4], signed: bool) -> Option<(String, (u32, String))> {
    let neg = signed && (w[0] >> 63) == 1;
    let m = if neg { neg256(w) } else { w };
    let bl = bitlen(m);
    // |v| >= 2^63
    if bl < 64 {
        return None;
    }
    let d = dec_words(m);
    let s = if neg { format!("-{d}") } else { d.clone() };
    Some((format!("{kind}={s}"), (bl, d)))
}

fn i128_words(p: &Int128Parts) -> [u64; 4] {
    let ext = if p.hi < 0 { u64::MAX } else { 0 };
    [ext, ext, p.hi as u64, p.lo]
}
fn u128_words(p: &UInt128Parts) -> [u64; 4] {
    [0, 0, p.hi, p.lo]
}
fn i256_words(p: &Int256Parts) -> [u64; 4] {
    [p.hi_hi as u64, p.hi_lo, p.lo_hi, p.lo_lo]
}
fn u256_words(p: &UInt256Parts) -> [u64; 4] {
    [p.hi_hi, p.hi_lo, p.lo_hi, p.lo_lo]
}

fn mag_u64(v: u64) -> (u32, String) {
    (64 - v.leading_zeros(), v.to_string())
}

// ---------- text ----------

/// Classes of bytes read as text: nul, nonutf8, ctrl, nonascii.
fn text_classes(b: &[u8]) -> Vec<&'static str> {
    let mut f = Vec::new();
    if b.contains(&0) {
        f.push("nul");
    }
    let utf8 = std::str::from_utf8(b).is_ok();
    if !utf8 {
        f.push("nonutf8");
    }
    if b.iter().any(|c| *c != 0 && (*c < 0x20 || *c == 0x7f)) {
        f.push("ctrl");
    }
    if utf8 && b.iter().any(|c| *c >= 0x80) {
        f.push("nonascii");
    }
    f
}

fn text_value(b: &[u8]) -> String {
    let h = hex::encode(&b[..b.len().min(96)]);
    let s: String = String::from_utf8_lossy(&b[..b.len().min(48)])
        .chars()
        .map(|c| if c.is_control() || c == '\t' { '.' } else { c })
        .collect();
    format!("len={};hex={h};text={s}", b.len())
}

fn sym_name(b: &[u8]) -> String {
    let s: String = b
        .iter()
        .take(24)
        .map(|c| {
            if c.is_ascii_alphanumeric() || *c == b'_' {
                *c as char
            } else {
                '?'
            }
        })
        .collect();
    if s.is_empty() {
        "-".into()
    } else {
        s
    }
}

// ---------- the walker ----------

pub struct Tagger<'n> {
    pub net: &'n Net,
    hits: Vec<Hit>,
    pub ev: Evidence,
    /// max ScVal depth seen in the current walk
    depth_max: u32,
}

const SAC_FNS: [&str; 5] = ["transfer", "mint", "burn", "clawback", "approve"];

impl<'n> Tagger<'n> {
    pub fn new(net: &'n Net) -> Tagger<'n> {
        Tagger {
            net,
            hits: Vec::new(),
            ev: Evidence::default(),
            depth_max: 0,
        }
    }

    fn hit(
        &mut self,
        tag: impl Into<String>,
        path: impl Into<String>,
        value: String,
        mag: (u32, String),
    ) {
        self.hits.push(Hit {
            tag: tag.into(),
            path: path.into(),
            value,
            mag,
        });
    }

    fn u64_band(&mut self, prefix: &str, path: &str, v: u64) {
        if v >= TWO63 {
            self.hit(format!("{prefix}>=2^63"), path, v.to_string(), mag_u64(v));
        } else if v >= TWO53 {
            self.hit(format!("{prefix}>=2^53"), path, v.to_string(), mag_u64(v));
        }
    }

    /// int64 amount rules; `zero` = whether 0 is tagged at this field.
    fn amount(&mut self, path: &str, v: i64, zero: bool) {
        let m = || {
            (
                64 - v.unsigned_abs().leading_zeros(),
                v.unsigned_abs().to_string(),
            )
        };
        if v == i64::MAX {
            self.hit("i64=max", path, v.to_string(), m());
        } else if v >= TWO62 {
            self.hit("i64>=2^62", path, v.to_string(), m());
        } else if v < 0 {
            self.hit("i64<0", path, v.to_string(), m());
        } else if v == 0 && zero {
            self.hit("i64=0", path, "0".into(), (0, "0".into()));
        }
    }

    fn negative(&mut self, path: &str, v: i64) {
        if v < 0 {
            self.hit(
                "i64<0",
                path,
                v.to_string(),
                (64, v.unsigned_abs().to_string()),
            );
        }
    }

    fn text(&mut self, path: &str, b: &[u8], max: Option<usize>) {
        for c in text_classes(b) {
            self.hit(
                format!("text:{c}"),
                path,
                text_value(b),
                (b.len() as u32, String::new()),
            );
        }
        if let Some(m) = max {
            if b.len() == m {
                self.hit(
                    "text:maxlen",
                    path,
                    text_value(b),
                    (b.len() as u32, String::new()),
                );
            }
        }
    }

    /// Ledger-entry and op-body text that core restricts to printable ASCII.
    fn printable(&mut self, path: &str, b: &[u8], max: usize) {
        if b.iter().any(|c| *c < 0x20 || *c > 0x7e) {
            self.hit(
                "text:nonprintable",
                path,
                text_value(b),
                (b.len() as u32, String::new()),
            );
        }
        self.text(path, b, Some(max));
    }

    fn code(&mut self, path: &str, b: &[u8], n4: bool) {
        let (mut zeros, mut cnt, mut bad) = (false, 0, Vec::new());
        for c in b {
            if *c == 0 {
                zeros = true;
            } else if zeros {
                if !bad.contains(&"inner_nul") {
                    bad.push("inner_nul");
                }
            } else if c.is_ascii_alphanumeric() {
                cnt += 1;
            } else if *c >= 0x80 {
                if !bad.contains(&"nonascii") {
                    bad.push("nonascii");
                }
            } else if !bad.contains(&"nonalnum") {
                bad.push("nonalnum");
            }
        }
        if cnt == 0 || (!n4 && cnt < 5) {
            bad.push("short");
        }
        for t in bad {
            self.hit(
                format!("asset_code:{t}"),
                path,
                text_value(b),
                (0, String::new()),
            );
        }
    }

    fn asset(&mut self, path: &str, a: &Asset) {
        match a {
            Asset::CreditAlphanum4(x) => self.code(path, x.asset_code.as_slice(), true),
            Asset::CreditAlphanum12(x) => self.code(path, x.asset_code.as_slice(), false),
            Asset::Native => {}
        }
    }
    fn tl_asset(&mut self, path: &str, a: &TrustLineAsset) {
        match a {
            TrustLineAsset::CreditAlphanum4(x) => self.code(path, x.asset_code.as_slice(), true),
            TrustLineAsset::CreditAlphanum12(x) => self.code(path, x.asset_code.as_slice(), false),
            _ => {}
        }
    }

    fn muxed(&mut self, path: &str, m: &MuxedAccount) {
        if let MuxedAccount::MuxedEd25519(x) = m {
            self.u64_band("muxed_id", path, x.id);
        }
    }

    // ----- ScVal -----

    fn scval(&mut self, v: &ScVal, loc: &str, depth: u32) {
        self.depth_max = self.depth_max.max(depth);
        match v {
            ScVal::U64(x) => self.u64_band("scv_u64", &format!("{loc}:u64"), *x),
            ScVal::Timepoint(x) => self.u64_band("scv_u64", &format!("{loc}:timepoint"), x.0),
            ScVal::Duration(x) => self.u64_band("scv_u64", &format!("{loc}:duration"), x.0),
            ScVal::I128(p) => self.wide(loc, "i128", i128_words(p), true),
            ScVal::U128(p) => self.wide(loc, "u128", u128_words(p), false),
            ScVal::I256(p) => self.wide(loc, "i256", i256_words(p), true),
            ScVal::U256(p) => self.wide(loc, "u256", u256_words(p), false),
            ScVal::String(s) => {
                let b = s.as_vec();
                for c in text_classes(b) {
                    self.hit(
                        format!("text:{c}"),
                        format!("{loc}:scstring"),
                        text_value(b),
                        (b.len() as u32, String::new()),
                    );
                }
            }
            ScVal::Symbol(s) => {
                let b = s.as_vec();
                if b.iter().any(|c| !(c.is_ascii_alphanumeric() || *c == b'_')) {
                    self.hit(
                        "symbol:badchar",
                        format!("{loc}:symbol"),
                        text_value(b),
                        (0, String::new()),
                    );
                }
                if b.len() == 32 {
                    self.hit(
                        "symbol:maxlen",
                        format!("{loc}:symbol"),
                        text_value(b),
                        (0, String::new()),
                    );
                }
            }
            ScVal::Vec(Some(xs)) => {
                if xs.len() >= LONG_SC {
                    self.hit(
                        "scvec:len>=1000",
                        loc,
                        xs.len().to_string(),
                        (xs.len() as u32, String::new()),
                    );
                }
                for x in xs.iter() {
                    self.scval(x, loc, depth + 1);
                }
            }
            ScVal::Map(Some(m)) => {
                if m.len() >= LONG_SC {
                    self.hit(
                        "scmap:len>=1000",
                        loc,
                        m.len().to_string(),
                        (m.len() as u32, String::new()),
                    );
                }
                let mut dup = false;
                let mut uns = false;
                for w in m.windows(2) {
                    match w[0].key.cmp(&w[1].key) {
                        std::cmp::Ordering::Equal => dup = true,
                        std::cmp::Ordering::Greater => uns = true,
                        _ => {}
                    }
                }
                if dup {
                    self.hit(
                        "scmap:dup_key",
                        loc,
                        format!("len={}", m.len()),
                        (0, String::new()),
                    );
                }
                if uns {
                    self.hit(
                        "scmap:unsorted",
                        loc,
                        format!("len={}", m.len()),
                        (0, String::new()),
                    );
                }
                for e in m.iter() {
                    self.scval(&e.key, loc, depth + 1);
                    self.scval(&e.val, loc, depth + 1);
                }
            }
            ScVal::Address(ScAddress::MuxedAccount(x)) => {
                self.u64_band("muxed_id", &format!("{loc}:scaddress"), x.id)
            }
            ScVal::ContractInstance(i) => {
                if let Some(st) = &i.storage {
                    let l = format!("{loc}:instance");
                    for e in st.iter() {
                        self.scval(&e.key, &l, depth + 1);
                        self.scval(&e.val, &l, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    fn wide(&mut self, loc: &str, kind: &str, w: [u64; 4], signed: bool) {
        if let Some((v, m)) = wide(kind, w, signed) {
            self.hit("int>=2^63", format!("{loc}:{kind}"), v, m);
        }
    }

    /// Walk a root ScVal and record its depth (histogram per kind; a row from DEPTH_ROW).
    fn scval_root(&mut self, v: &ScVal, loc: &str, kind: &str) {
        self.depth_max = 0;
        self.scval(v, loc, 1);
        let d = self.depth_max;
        *self.ev.depth.entry((kind.to_string(), d)).or_default() += 1;
        if d >= DEPTH_ROW {
            self.hit("scval_depth", loc, d.to_string(), (d, String::new()));
        }
    }

    fn auth_inv(&mut self, inv: &SorobanAuthorizedInvocation, depth: u32, max: &mut u32) {
        *max = (*max).max(depth);
        match &inv.function {
            SorobanAuthorizedFunction::ContractFn(a) => {
                for x in a.args.iter() {
                    self.scval_root(x, "auth:args", "auth_args");
                }
            }
            SorobanAuthorizedFunction::CreateContractHostFn(c) => {
                self.preimage(&c.contract_id_preimage)
            }
            SorobanAuthorizedFunction::CreateContractV2HostFn(c) => {
                self.preimage(&c.contract_id_preimage);
                for x in c.constructor_args.iter() {
                    self.scval_root(x, "auth:ctor_args", "auth_args");
                }
            }
        }
        for s in inv.sub_invocations.iter() {
            self.auth_inv(s, depth + 1, max);
        }
    }

    fn preimage(&mut self, p: &ContractIdPreimage) {
        if let ContractIdPreimage::Asset(a) = p {
            let id = self.net.sac_id(a);
            self.ev.sac.insert(contract_str(&id), asset_string(a));
        }
    }

    // ----- envelope -----

    fn envelope(
        &mut self,
        e: &TransactionEnvelope,
        parties: &mut BTreeSet<[u8; 32]>,
    ) -> Vec<Operation> {
        match e {
            TransactionEnvelope::TxV0(v) => {
                let t = &v.tx;
                parties.insert(t.source_account_ed25519.0);
                self.seq("tx.seqNum", t.seq_num.0);
                if let Some(b) = &t.time_bounds {
                    self.time_bounds("tx.timeBounds", b.min_time.0, b.max_time.0);
                }
                self.memo(&t.memo, "v0");
                self.vec_max("tx.operations", t.operations.len(), 100);
                self.vec_max("tx.signatures", v.signatures.len(), 20);
                t.operations.to_vec()
            }
            TransactionEnvelope::Tx(v) => {
                self.tx_body(&v.tx, "tx", parties);
                self.vec_max("tx.signatures", v.signatures.len(), 20);
                v.tx.operations.to_vec()
            }
            TransactionEnvelope::TxFeeBump(f) => {
                self.muxed("feeBump.feeSource", &f.tx.fee_source);
                parties.insert(muxed_key(&f.tx.fee_source));
                self.amount("feeBump.fee", f.tx.fee, false);
                self.vec_max("feeBump.signatures", f.signatures.len(), 20);
                let FeeBumpTransactionInnerTx::Tx(inner) = &f.tx.inner_tx;
                self.tx_body(&inner.tx, "tx", parties);
                self.vec_max("tx.signatures", inner.signatures.len(), 20);
                inner.tx.operations.to_vec()
            }
        }
    }

    fn vec_max(&mut self, path: &str, n: usize, max: usize) {
        if n == max {
            self.hit("len=max", path, n.to_string(), (n as u32, String::new()));
        }
    }

    fn seq(&mut self, path: &str, v: i64) {
        // Sequence numbers above 2^53 are the norm (ledger << 32); only the int64 edges are tagged.
        self.amount(path, v, false);
    }

    fn time_bounds(&mut self, path: &str, min: u64, max: u64) {
        self.u64_band("u64", &format!("{path}.minTime"), min);
        self.u64_band("u64", &format!("{path}.maxTime"), max);
        if max != 0 && max < min {
            self.hit(
                "maxTime<minTime",
                path,
                format!("min={min};max={max}"),
                mag_u64(min),
            );
        }
    }

    fn memo(&mut self, m: &Memo, env: &str) {
        match m {
            Memo::Text(t) => self.text(&format!("memo.text@{env}"), t.as_vec(), Some(28)),
            Memo::Id(i) => self.u64_band("memo_id", "memo.id", *i),
            _ => {}
        }
    }

    fn tx_body(&mut self, t: &Transaction, p: &str, parties: &mut BTreeSet<[u8; 32]>) {
        self.muxed(&format!("{p}.sourceAccount"), &t.source_account);
        parties.insert(muxed_key(&t.source_account));
        self.seq(&format!("{p}.seqNum"), t.seq_num.0);
        match &t.cond {
            Preconditions::Time(b) => {
                self.time_bounds(&format!("{p}.cond.time"), b.min_time.0, b.max_time.0)
            }
            Preconditions::V2(c) => {
                if let Some(b) = &c.time_bounds {
                    self.time_bounds(
                        &format!("{p}.cond.v2.timeBounds"),
                        b.min_time.0,
                        b.max_time.0,
                    );
                }
                if let Some(l) = &c.ledger_bounds {
                    if l.max_ledger != 0 && l.max_ledger < l.min_ledger {
                        self.hit(
                            "maxLedger<minLedger",
                            format!("{p}.cond.v2.ledgerBounds"),
                            format!("min={};max={}", l.min_ledger, l.max_ledger),
                            mag_u64(l.min_ledger as u64),
                        );
                    }
                }
                if let Some(s) = &c.min_seq_num {
                    self.seq(&format!("{p}.cond.v2.minSeqNum"), s.0);
                }
                self.u64_band("u64", &format!("{p}.cond.v2.minSeqAge"), c.min_seq_age.0);
                if c.min_seq_ledger_gap >= 1 << 31 {
                    self.hit(
                        "u32>=2^31",
                        format!("{p}.cond.v2.minSeqLedgerGap"),
                        c.min_seq_ledger_gap.to_string(),
                        mag_u64(c.min_seq_ledger_gap as u64),
                    );
                }
                self.vec_max(
                    &format!("{p}.cond.v2.extraSigners"),
                    c.extra_signers.len(),
                    2,
                );
            }
            Preconditions::None => {}
        }
        self.memo(&t.memo, "tx");
        self.vec_max(&format!("{p}.operations"), t.operations.len(), 100);
    }

    fn op_body(&mut self, op: &Operation, parties: &mut BTreeSet<[u8; 32]>) {
        if let Some(s) = &op.source_account {
            self.muxed("op.sourceAccount", s);
            parties.insert(muxed_key(s));
        }
        let p = |s: &str| format!("op.{s}");
        match &op.body {
            OperationBody::CreateAccount(o) => {
                parties.insert(account_key(&o.destination));
                self.amount(
                    &p("CREATE_ACCOUNT.startingBalance"),
                    o.starting_balance,
                    true,
                );
            }
            OperationBody::Payment(o) => {
                parties.insert(muxed_key(&o.destination));
                self.muxed(&p("PAYMENT.destination"), &o.destination);
                self.amount(&p("PAYMENT.amount"), o.amount, true);
                self.asset(&p("PAYMENT.asset"), &o.asset);
            }
            OperationBody::PathPaymentStrictReceive(o) => {
                parties.insert(muxed_key(&o.destination));
                self.muxed(
                    &p("PATH_PAYMENT_STRICT_RECEIVE.destination"),
                    &o.destination,
                );
                self.amount(&p("PATH_PAYMENT_STRICT_RECEIVE.sendMax"), o.send_max, true);
                self.amount(
                    &p("PATH_PAYMENT_STRICT_RECEIVE.destAmount"),
                    o.dest_amount,
                    true,
                );
                self.asset(&p("PATH_PAYMENT_STRICT_RECEIVE.sendAsset"), &o.send_asset);
                self.asset(&p("PATH_PAYMENT_STRICT_RECEIVE.destAsset"), &o.dest_asset);
                for a in o.path.iter() {
                    self.asset(&p("PATH_PAYMENT_STRICT_RECEIVE.path"), a);
                }
                self.vec_max(&p("PATH_PAYMENT_STRICT_RECEIVE.path"), o.path.len(), 5);
            }
            OperationBody::PathPaymentStrictSend(o) => {
                parties.insert(muxed_key(&o.destination));
                self.muxed(&p("PATH_PAYMENT_STRICT_SEND.destination"), &o.destination);
                self.amount(
                    &p("PATH_PAYMENT_STRICT_SEND.sendAmount"),
                    o.send_amount,
                    true,
                );
                self.amount(&p("PATH_PAYMENT_STRICT_SEND.destMin"), o.dest_min, true);
                self.asset(&p("PATH_PAYMENT_STRICT_SEND.sendAsset"), &o.send_asset);
                self.asset(&p("PATH_PAYMENT_STRICT_SEND.destAsset"), &o.dest_asset);
                for a in o.path.iter() {
                    self.asset(&p("PATH_PAYMENT_STRICT_SEND.path"), a);
                }
                self.vec_max(&p("PATH_PAYMENT_STRICT_SEND.path"), o.path.len(), 5);
            }
            OperationBody::ManageSellOffer(o) => {
                // amount 0 deletes an offer: not tagged
                self.amount(&p("MANAGE_SELL_OFFER.amount"), o.amount, false);
                self.offer_id(&p("MANAGE_SELL_OFFER.offerID"), o.offer_id);
                self.asset(&p("MANAGE_SELL_OFFER.selling"), &o.selling);
                self.asset(&p("MANAGE_SELL_OFFER.buying"), &o.buying);
            }
            OperationBody::ManageBuyOffer(o) => {
                self.amount(&p("MANAGE_BUY_OFFER.buyAmount"), o.buy_amount, false);
                self.offer_id(&p("MANAGE_BUY_OFFER.offerID"), o.offer_id);
                self.asset(&p("MANAGE_BUY_OFFER.selling"), &o.selling);
                self.asset(&p("MANAGE_BUY_OFFER.buying"), &o.buying);
            }
            OperationBody::CreatePassiveSellOffer(o) => {
                self.amount(&p("CREATE_PASSIVE_SELL_OFFER.amount"), o.amount, true);
                self.asset(&p("CREATE_PASSIVE_SELL_OFFER.selling"), &o.selling);
                self.asset(&p("CREATE_PASSIVE_SELL_OFFER.buying"), &o.buying);
            }
            OperationBody::SetOptions(o) => {
                if let Some(a) = &o.inflation_dest {
                    parties.insert(account_key(a));
                }
                for (n, w) in [
                    ("masterWeight", o.master_weight),
                    ("lowThreshold", o.low_threshold),
                    ("medThreshold", o.med_threshold),
                    ("highThreshold", o.high_threshold),
                ] {
                    if let Some(w) = w {
                        if w > 255 {
                            self.hit(
                                "weight>255",
                                p(&format!("SET_OPTIONS.{n}")),
                                w.to_string(),
                                mag_u64(w as u64),
                            );
                        }
                    }
                }
                if let Some(s) = &o.signer {
                    if s.weight > 255 {
                        self.hit(
                            "weight>255",
                            p("SET_OPTIONS.signer.weight"),
                            s.weight.to_string(),
                            mag_u64(s.weight as u64),
                        );
                    }
                }
                if let Some(h) = &o.home_domain {
                    self.printable(&p("SET_OPTIONS.homeDomain"), h.as_vec(), 32);
                }
            }
            OperationBody::ChangeTrust(o) => {
                // limit 0 removes a trustline and int64 max is the usual "no limit": only < 0
                self.negative(&p("CHANGE_TRUST.limit"), o.limit);
                match &o.line {
                    ChangeTrustAsset::CreditAlphanum4(x) => {
                        self.code(&p("CHANGE_TRUST.line"), x.asset_code.as_slice(), true)
                    }
                    ChangeTrustAsset::CreditAlphanum12(x) => {
                        self.code(&p("CHANGE_TRUST.line"), x.asset_code.as_slice(), false)
                    }
                    ChangeTrustAsset::PoolShare(
                        stellar_xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(c),
                    ) => {
                        self.asset(&p("CHANGE_TRUST.line.pool"), &c.asset_a);
                        self.asset(&p("CHANGE_TRUST.line.pool"), &c.asset_b);
                    }
                    ChangeTrustAsset::Native => {}
                }
            }
            OperationBody::AllowTrust(o) => {
                parties.insert(account_key(&o.trustor));
                match &o.asset {
                    AssetCode::CreditAlphanum4(c) => {
                        self.code(&p("ALLOW_TRUST.asset"), c.as_slice(), true)
                    }
                    AssetCode::CreditAlphanum12(c) => {
                        self.code(&p("ALLOW_TRUST.asset"), c.as_slice(), false)
                    }
                }
            }
            OperationBody::AccountMerge(d) => {
                parties.insert(muxed_key(d));
                self.muxed(&p("ACCOUNT_MERGE.destination"), d);
            }
            OperationBody::ManageData(o) => {
                self.printable(&p("MANAGE_DATA.dataName"), o.data_name.as_vec(), 64);
            }
            OperationBody::BumpSequence(o) => self.seq(&p("BUMP_SEQUENCE.bumpTo"), o.bump_to.0),
            OperationBody::CreateClaimableBalance(o) => {
                self.amount(&p("CREATE_CLAIMABLE_BALANCE.amount"), o.amount, true);
                self.asset(&p("CREATE_CLAIMABLE_BALANCE.asset"), &o.asset);
                self.vec_max(
                    &p("CREATE_CLAIMABLE_BALANCE.claimants"),
                    o.claimants.len(),
                    10,
                );
                for c in o.claimants.iter() {
                    let stellar_xdr::Claimant::ClaimantTypeV0(c) = c;
                    parties.insert(account_key(&c.destination));
                }
            }
            OperationBody::BeginSponsoringFutureReserves(o) => {
                parties.insert(account_key(&o.sponsored_id));
            }
            OperationBody::RevokeSponsorship(o) => match o {
                stellar_xdr::RevokeSponsorshipOp::LedgerEntry(k) => {
                    if let Some(a) = key_owner(k) {
                        parties.insert(a);
                    }
                }
                stellar_xdr::RevokeSponsorshipOp::Signer(s) => {
                    parties.insert(account_key(&s.account_id));
                }
            },
            OperationBody::Clawback(o) => {
                parties.insert(muxed_key(&o.from));
                self.muxed(&p("CLAWBACK.from"), &o.from);
                self.amount(&p("CLAWBACK.amount"), o.amount, true);
                self.asset(&p("CLAWBACK.asset"), &o.asset);
            }
            OperationBody::SetTrustLineFlags(o) => {
                parties.insert(account_key(&o.trustor));
                self.asset(&p("SET_TRUST_LINE_FLAGS.asset"), &o.asset);
            }
            OperationBody::LiquidityPoolDeposit(o) => {
                self.amount(
                    &p("LIQUIDITY_POOL_DEPOSIT.maxAmountA"),
                    o.max_amount_a,
                    true,
                );
                self.amount(
                    &p("LIQUIDITY_POOL_DEPOSIT.maxAmountB"),
                    o.max_amount_b,
                    true,
                );
            }
            OperationBody::LiquidityPoolWithdraw(o) => {
                self.amount(&p("LIQUIDITY_POOL_WITHDRAW.amount"), o.amount, true);
                self.amount(
                    &p("LIQUIDITY_POOL_WITHDRAW.minAmountA"),
                    o.min_amount_a,
                    false,
                );
                self.amount(
                    &p("LIQUIDITY_POOL_WITHDRAW.minAmountB"),
                    o.min_amount_b,
                    false,
                );
            }
            OperationBody::InvokeHostFunction(o) => {
                match &o.host_function {
                    stellar_xdr::HostFunction::InvokeContract(a) => {
                        collect_sc_accounts(&a.args, parties);
                        for x in a.args.iter() {
                            self.scval_root(x, "args", "args");
                        }
                    }
                    stellar_xdr::HostFunction::CreateContract(c) => {
                        self.preimage(&c.contract_id_preimage)
                    }
                    stellar_xdr::HostFunction::CreateContractV2(c) => {
                        self.preimage(&c.contract_id_preimage);
                        for x in c.constructor_args.iter() {
                            self.scval_root(x, "ctor_args", "args");
                        }
                    }
                    stellar_xdr::HostFunction::UploadContractWasm(_) => {}
                }
                for a in o.auth.iter() {
                    if let SorobanCredentials::Address(c) = &a.credentials {
                        if let ScAddress::Account(x) = &c.address {
                            parties.insert(account_key(x));
                        }
                    }
                    let mut max = 0;
                    self.auth_inv(&a.root_invocation, 1, &mut max);
                    *self
                        .ev
                        .depth
                        .entry(("auth_invocation".into(), max))
                        .or_default() += 1;
                    if max >= AUTH_DEPTH_ROW {
                        self.hit(
                            "auth_depth",
                            "auth.rootInvocation",
                            max.to_string(),
                            (max, String::new()),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn offer_id(&mut self, path: &str, v: i64) {
        if v < 0 {
            self.hit("i64<0", path, v.to_string(), (64, v.to_string()));
        } else {
            self.u64_band("offer_id", path, v as u64);
        }
    }

    // ----- results -----

    fn op_result(
        &mut self,
        i: usize,
        op: &OperationBody,
        r: &OperationResult,
        parties: &mut BTreeSet<[u8; 32]>,
    ) -> bool {
        let OperationResult::OpInner(tr) = r else {
            return false;
        };
        let _ = i;
        let mut atoms = |s: &mut Self, path: &str, xs: &[ClaimAtom], zero_hop: bool| {
            for a in xs {
                let (seller, sold, bought) = match a {
                    ClaimAtom::V0(x) => (Some(x.seller_ed25519.0), x.amount_sold, x.amount_bought),
                    ClaimAtom::OrderBook(x) => (
                        Some(account_key(&x.seller_id)),
                        x.amount_sold,
                        x.amount_bought,
                    ),
                    ClaimAtom::LiquidityPool(x) => (None, x.amount_sold, x.amount_bought),
                };
                if let Some(k) = seller {
                    parties.insert(k);
                }
                if zero_hop && (sold == 0 || bought == 0) {
                    s.hit(
                        "path_zero_hop",
                        path,
                        format!("sold={sold};bought={bought}"),
                        (0, String::new()),
                    );
                }
                s.amount(&format!("{path}.amountSold"), sold, false);
                s.amount(&format!("{path}.amountBought"), bought, false);
            }
        };

        match (op, tr) {
            (
                _,
                OperationResultTr::PathPaymentStrictReceive(
                    stellar_xdr::PathPaymentStrictReceiveResult::Success(s),
                ),
            ) => {
                atoms(
                    self,
                    "opres.PATH_PAYMENT_STRICT_RECEIVE.offers",
                    &s.offers,
                    true,
                );
                true
            }
            (
                _,
                OperationResultTr::PathPaymentStrictSend(
                    stellar_xdr::PathPaymentStrictSendResult::Success(s),
                ),
            ) => {
                atoms(
                    self,
                    "opres.PATH_PAYMENT_STRICT_SEND.offers",
                    &s.offers,
                    true,
                );
                true
            }
            (
                _,
                OperationResultTr::ManageSellOffer(stellar_xdr::ManageSellOfferResult::Success(s)),
            )
            | (
                _,
                OperationResultTr::CreatePassiveSellOffer(
                    stellar_xdr::ManageSellOfferResult::Success(s),
                ),
            ) => {
                atoms(
                    self,
                    "opres.MANAGE_OFFER.offersClaimed",
                    &s.offers_claimed,
                    false,
                );
                true
            }
            (
                _,
                OperationResultTr::ManageBuyOffer(stellar_xdr::ManageBuyOfferResult::Success(s)),
            ) => {
                atoms(
                    self,
                    "opres.MANAGE_OFFER.offersClaimed",
                    &s.offers_claimed,
                    false,
                );
                true
            }
            (
                _,
                OperationResultTr::LiquidityPoolDeposit(
                    stellar_xdr::LiquidityPoolDepositResult::Success,
                ),
            ) => true,
            (
                _,
                OperationResultTr::LiquidityPoolWithdraw(
                    stellar_xdr::LiquidityPoolWithdrawResult::Success,
                ),
            ) => true,
            _ => false,
        }
    }

    // ----- entries -----

    fn entry(&mut self, e: &LedgerEntry, w: &str) {
        let p = |s: &str| format!("{w}.{s}");
        match &e.data {
            LedgerEntryData::Account(a) => self.account(a, w),
            LedgerEntryData::Trustline(t) => {
                self.amount(&p("TRUSTLINE.balance"), t.balance, false);
                self.negative(&p("TRUSTLINE.limit"), t.limit);
                self.tl_asset(&p("TRUSTLINE.asset"), &t.asset);
            }
            LedgerEntryData::Offer(o) => {
                self.amount(&p("OFFER.amount"), o.amount, false);
                self.offer_id(&p("OFFER.offerID"), o.offer_id);
                self.asset(&p("OFFER.selling"), &o.selling);
                self.asset(&p("OFFER.buying"), &o.buying);
            }
            LedgerEntryData::Data(d) => {
                self.printable(&p("DATA.dataName"), d.data_name.as_vec(), 64)
            }
            LedgerEntryData::ClaimableBalance(c) => {
                self.amount(&p("CLAIMABLE_BALANCE.amount"), c.amount, false);
                self.asset(&p("CLAIMABLE_BALANCE.asset"), &c.asset);
            }
            LedgerEntryData::LiquidityPool(l) => {
                let stellar_xdr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(c) = &l.body;
                self.amount(&p("LIQUIDITY_POOL.reserveA"), c.reserve_a, false);
                self.amount(&p("LIQUIDITY_POOL.reserveB"), c.reserve_b, false);
                self.amount(
                    &p("LIQUIDITY_POOL.totalPoolShares"),
                    c.total_pool_shares,
                    false,
                );
            }
            LedgerEntryData::ContractData(cd) => {
                let con = match &cd.contract {
                    ScAddress::Contract(c) => contract_str(&c.0 .0),
                    _ => "-".into(),
                };
                if let ScVal::ContractInstance(i) = &cd.val {
                    if matches!(i.executable, ContractExecutable::StellarAsset) {
                        // only the host creates these; the asset is checked against the id at merge
                        self.ev.sac.entry(con.clone()).or_insert_with(|| "?".into());
                        if let ScAddress::Contract(c) = &cd.contract {
                            if let Some(a) = instance_asset(i) {
                                if self.net.sac_id(&a) == c.0 .0 {
                                    self.ev.sac.insert(con.clone(), asset_string(&a));
                                }
                            }
                        }
                    }
                }
                let balance = matches!(&cd.key, ScVal::Vec(Some(v)) if v.len() == 2 && matches!(&v[0], ScVal::Symbol(s) if s.as_vec() == b"Balance"));
                let loc = if balance { "cdata:Balance" } else { "cdata" };
                self.scval_root(&cd.key, &format!("{loc}:key"), "cdata");
                let n0 = self.hits.len();
                self.scval_root(&cd.val, &format!("{loc}:val"), "cdata");
                if balance {
                    // a candidate: SAC or custom contract is decided at merge
                    let mut best: Option<(String, (u32, String))> = None;
                    for h in &self.hits[n0..] {
                        if h.tag == "int>=2^63" && best.as_ref().is_none_or(|b| h.mag > b.1) {
                            best = Some((h.value.clone(), h.mag.clone()));
                        }
                    }
                    if let Some((v, m)) = best {
                        self.hit(
                            "balance_candidate",
                            format!("{w}.CONTRACT_DATA.Balance"),
                            format!("contract={con};{v}"),
                            m,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn account(&mut self, a: &AccountEntry, w: &str) {
        self.amount(&format!("{w}.ACCOUNT.balance"), a.balance, false);
        self.printable(
            &format!("{w}.ACCOUNT.homeDomain"),
            a.home_domain.as_vec(),
            32,
        );
        for s in a.signers.iter() {
            if s.weight > 255 {
                self.hit(
                    "weight>255",
                    format!("{w}.ACCOUNT.signers.weight"),
                    s.weight.to_string(),
                    mag_u64(s.weight as u64),
                );
            }
        }
        self.vec_max(&format!("{w}.ACCOUNT.signers"), a.signers.len(), 20);
    }

    // ----- events -----

    fn event(&mut self, ev: &ContractEvent, kind: &str) {
        let ContractEventBody::V0(b) = &ev.body;
        let con = ev.contract_id.as_ref().map(|c| c.0 .0);
        let fn_ = match b.topics.first() {
            Some(ScVal::Symbol(s)) => sym_name(s.as_vec()),
            _ => "-".into(),
        };
        let loc = format!("{kind}:{fn_}");
        if kind != "diag" && SAC_FNS.contains(&fn_.as_str()) {
            if let Some(c) = con {
                let asset = match b.topics.last() {
                    Some(ScVal::String(s)) if b.topics.len() >= 2 => Some(s.as_vec().clone()),
                    _ => None,
                };
                match asset.as_ref().and_then(|s| parse_asset(s).map(|a| (s, a))) {
                    Some((s, a)) => {
                        if self.net.sac_id(&a) == c {
                            self.ev
                                .sac
                                .insert(contract_str(&c), String::from_utf8_lossy(s).into());
                        } else {
                            self.hit(
                                format!("token_event:spoof_asset_topic:{fn_}"),
                                kind,
                                format!(
                                    "contract={};asset={}",
                                    contract_str(&c),
                                    String::from_utf8_lossy(s)
                                ),
                                (0, String::new()),
                            );
                        }
                    }
                    None => self.hit(
                        format!("token_event:nonsac:{fn_}"),
                        kind,
                        format!("contract={};topics={}", contract_str(&c), b.topics.len()),
                        (0, String::new()),
                    ),
                }
            }
        }
        for t in b.topics.iter() {
            self.scval_root(t, &format!("{loc}:topic"), "event");
        }
        self.scval_root(&b.data, &format!("{loc}:data"), "event");
    }
}

fn asset_string(a: &Asset) -> String {
    let code = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .trim_end_matches('\0')
            .to_string()
    };
    match a {
        Asset::Native => "native".into(),
        Asset::CreditAlphanum4(x) => format!(
            "{}:{}",
            code(x.asset_code.as_slice()),
            account_str(&x.issuer)
        ),
        Asset::CreditAlphanum12(x) => format!(
            "{}:{}",
            code(x.asset_code.as_slice()),
            account_str(&x.issuer)
        ),
    }
}

/// The asset of a SAC instance: storage key Symbol("AssetInfo") -> Vec[Symbol(kind), Map{asset_code, issuer}].
fn instance_asset(i: &stellar_xdr::ScContractInstance) -> Option<Asset> {
    let st = i.storage.as_ref()?;
    for e in st.iter() {
        if !matches!(&e.key, ScVal::Vec(Some(v)) if matches!(v.first(), Some(ScVal::Symbol(s)) if s.as_vec() == b"AssetInfo"))
        {
            continue;
        }
        let ScVal::Vec(Some(v)) = &e.val else {
            return None;
        };
        let ScVal::Symbol(kind) = v.first()? else {
            return None;
        };
        if kind.as_vec() == b"Native" {
            return Some(Asset::Native);
        }
        let ScVal::Map(Some(m)) = v.get(1)? else {
            return None;
        };
        let (mut code, mut issuer) = (None, None);
        for f in m.iter() {
            match (&f.key, &f.val) {
                (ScVal::Symbol(k), ScVal::String(s)) if k.as_vec() == b"asset_code" => {
                    code = Some(s.as_vec().clone())
                }
                (ScVal::Symbol(k), ScVal::Bytes(b)) if k.as_vec() == b"issuer" => {
                    issuer = Some(b.as_vec().clone())
                }
                _ => {}
            }
        }
        let (code, issuer) = (code?, issuer?);
        let issuer: [u8; 32] = issuer.try_into().ok()?;
        let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer)));
        let mut s = code.clone();
        while s.last() == Some(&0) {
            s.pop();
        }
        return if code.len() == 4 {
            Some(Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                asset_code: stellar_xdr::AssetCode4(code.try_into().ok()?),
                issuer,
            }))
        } else if code.len() == 12 {
            Some(Asset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
                asset_code: stellar_xdr::AssetCode12(code.try_into().ok()?),
                issuer,
            }))
        } else {
            None
        };
    }
    None
}

fn collect_sc_accounts(xs: &[ScVal], out: &mut BTreeSet<[u8; 32]>) {
    for x in xs {
        match x {
            ScVal::Address(ScAddress::Account(a)) => {
                out.insert(account_key(a));
            }
            ScVal::Address(ScAddress::MuxedAccount(m)) => {
                out.insert(m.ed25519.0);
            }
            ScVal::Vec(Some(v)) => collect_sc_accounts(v, out),
            ScVal::Map(Some(m)) => {
                for e in m.iter() {
                    collect_sc_accounts(std::slice::from_ref(&e.key), out);
                    collect_sc_accounts(std::slice::from_ref(&e.val), out);
                }
            }
            _ => {}
        }
    }
}

fn key_owner(k: &LedgerKey) -> Option<[u8; 32]> {
    match k {
        LedgerKey::Account(a) => Some(account_key(&a.account_id)),
        LedgerKey::Trustline(t) => Some(account_key(&t.account_id)),
        LedgerKey::Offer(o) => Some(account_key(&o.seller_id)),
        LedgerKey::Data(d) => Some(account_key(&d.account_id)),
        _ => None,
    }
}

fn entry_owner(e: &LedgerEntry) -> Option<([u8; 32], &'static str)> {
    match &e.data {
        LedgerEntryData::Account(a) => Some((account_key(&a.account_id), "ACCOUNT")),
        LedgerEntryData::Trustline(t) => Some((account_key(&t.account_id), "TRUSTLINE")),
        LedgerEntryData::Offer(o) => Some((account_key(&o.seller_id), "OFFER")),
        LedgerEntryData::Data(d) => Some((account_key(&d.account_id), "DATA")),
        _ => None,
    }
}

fn sponsors(e: &LedgerEntry, out: &mut BTreeSet<[u8; 32]>) {
    if let LedgerEntryExt::V1(x) = &e.ext {
        if let Some(a) = &x.sponsoring_id.0 {
            out.insert(account_key(a));
        }
    }
    if let LedgerEntryData::Account(a) = &e.data {
        if let stellar_xdr::AccountEntryExt::V1(v1) = &a.ext {
            if let stellar_xdr::AccountEntryExtensionV1Ext::V2(v2) = &v1.ext {
                for s in v2.signer_sponsoring_i_ds.iter() {
                    if let Some(a) = &s.0 {
                        out.insert(account_key(a));
                    }
                }
            }
        }
    }
}

fn change_entry(c: &LedgerEntryChange) -> Option<&LedgerEntry> {
    match c {
        LedgerEntryChange::Created(e)
        | LedgerEntryChange::Updated(e)
        | LedgerEntryChange::State(e)
        | LedgerEntryChange::Restored(e) => Some(e),
        LedgerEntryChange::Removed(_) => None,
    }
}

fn change_kind(c: &LedgerEntryChange) -> &'static str {
    match c {
        LedgerEntryChange::Created(_) => "created",
        LedgerEntryChange::Updated(_) => "updated",
        LedgerEntryChange::State(_) => "state",
        LedgerEntryChange::Restored(_) => "restored",
        LedgerEntryChange::Removed(_) => "removed",
    }
}

fn generalized(s: &GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(v) = s;
    let mut out = Vec::new();
    for ph in v.phases.iter() {
        match ph {
            TransactionPhase::V0(cs) => {
                for c in cs.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(x) = c;
                    out.extend(x.txs.iter());
                }
            }
            TransactionPhase::V1(p) => {
                for st in p.execution_stages.iter() {
                    for cl in st.0.iter() {
                        out.extend(cl.0.iter());
                    }
                }
            }
        }
    }
    out
}

/// Per transaction of a ledger: the tags. `seq` is the ledger.
pub fn ledger(t: &mut Tagger, lcm: &LedgerCloseMeta) -> anyhow::Result<(u32, Vec<TxTags>)> {
    let (seq, envs, results): (
        u32,
        Vec<&TransactionEnvelope>,
        Vec<(&stellar_xdr::TransactionResultPair, &TransactionMeta)>,
    ) = match lcm {
        LedgerCloseMeta::V0(v) => (
            v.ledger_header.header.ledger_seq,
            v.tx_set.txs.iter().collect(),
            v.tx_processing
                .iter()
                .map(|r| (&r.result, &r.tx_apply_processing))
                .collect(),
        ),
        LedgerCloseMeta::V1(v) => (
            v.ledger_header.header.ledger_seq,
            generalized(&v.tx_set),
            v.tx_processing
                .iter()
                .map(|r| (&r.result, &r.tx_apply_processing))
                .collect(),
        ),
        LedgerCloseMeta::V2(v) => (
            v.ledger_header.header.ledger_seq,
            generalized(&v.tx_set),
            v.tx_processing
                .iter()
                .map(|r| (&r.result, &r.tx_apply_processing))
                .collect(),
        ),
    };
    let mut by_hash: BTreeMap<[u8; 32], &TransactionEnvelope> = BTreeMap::new();
    for e in envs {
        by_hash.insert(t.net.tx_hash(e), e);
    }
    let mut out = Vec::with_capacity(results.len());
    for (i, (res, meta)) in results.into_iter().enumerate() {
        let env = *by_hash.get(&res.transaction_hash.0).ok_or_else(|| {
            anyhow::anyhow!(
                "ledger {seq} tx {i}: no envelope with hash {}",
                hex::encode(res.transaction_hash.0)
            )
        })?;
        t.hits.clear();
        let mut parties: BTreeSet<[u8; 32]> = BTreeSet::new();
        let ops = t.envelope(env, &mut parties);
        let mut base = parties.clone();
        // results
        let (failed, op_results): (bool, Option<&[OperationResult]>) = match &res.result.result {
            TransactionResultResult::TxSuccess(r) => (false, Some(r)),
            TransactionResultResult::TxFailed(r) => (true, Some(r)),
            TransactionResultResult::TxFeeBumpInnerSuccess(p)
            | TransactionResultResult::TxFeeBumpInnerFailed(p) => match &p.result.result {
                InnerTransactionResultResult::TxSuccess(r) => (false, Some(r)),
                InnerTransactionResultResult::TxFailed(r) => (true, Some(r)),
                _ => (true, None),
            },
            _ => (true, None),
        };
        // op-level meta
        let (op_changes, op_events, soroban_events, ret, diag, tx_events): (
            Vec<&[LedgerEntryChange]>,
            usize,
            Vec<&ContractEvent>,
            Option<&ScVal>,
            Vec<&ContractEvent>,
            Vec<&ContractEvent>,
        ) = match meta {
            TransactionMeta::V0(ops) => (
                ops.iter().map(|o| &o.changes.0[..]).collect(),
                0,
                vec![],
                None,
                vec![],
                vec![],
            ),
            TransactionMeta::V1(m) => (
                m.operations.iter().map(|o| &o.changes.0[..]).collect(),
                0,
                vec![],
                None,
                vec![],
                vec![],
            ),
            TransactionMeta::V2(m) => (
                m.operations.iter().map(|o| &o.changes.0[..]).collect(),
                0,
                vec![],
                None,
                vec![],
                vec![],
            ),
            TransactionMeta::V3(m) => {
                let (ev, ret, diag) = match &m.soroban_meta {
                    Some(s) => (
                        s.events.iter().collect::<Vec<_>>(),
                        Some(&s.return_value),
                        s.diagnostic_events
                            .iter()
                            .map(|d| &d.event)
                            .collect::<Vec<_>>(),
                    ),
                    None => (vec![], None, vec![]),
                };
                let n = ev.len();
                (
                    m.operations.iter().map(|o| &o.changes.0[..]).collect(),
                    n,
                    ev,
                    ret,
                    diag,
                    vec![],
                )
            }
            TransactionMeta::V4(m) => {
                let ev: Vec<&ContractEvent> =
                    m.operations.iter().flat_map(|o| o.events.iter()).collect();
                let n = ev.len();
                (
                    m.operations.iter().map(|o| &o.changes.0[..]).collect(),
                    n,
                    ev,
                    m.soroban_meta
                        .as_ref()
                        .and_then(|s| s.return_value.as_ref()),
                    m.diagnostic_events.iter().map(|d| &d.event).collect(),
                    m.events.iter().map(|e| &e.event).collect(),
                )
            }
        };
        if failed {
            if op_events > 0 {
                t.hit(
                    "failed_with_events",
                    "meta.events",
                    op_events.to_string(),
                    (op_events as u32, String::new()),
                );
            }
            let n: usize = op_changes.iter().map(|c| c.len()).sum();
            if n > 0 {
                t.hit(
                    "failed_with_op_changes",
                    "meta.operations.changes",
                    n.to_string(),
                    (n as u32, String::new()),
                );
            }
        }
        for (oi, op) in ops.iter().enumerate() {
            let mut p = base.clone();
            t.op_body(op, &mut p);
            let succ = match op_results.and_then(|r| r.get(oi)) {
                Some(r) => t.op_result(oi, &op.body, r, &mut p),
                None => false,
            };
            let changes: &[LedgerEntryChange] = op_changes.get(oi).copied().unwrap_or(&[]);
            for c in changes {
                if let Some(e) = change_entry(c) {
                    sponsors(e, &mut p);
                }
            }
            // LP zero leg
            if succ
                && matches!(
                    op.body,
                    OperationBody::LiquidityPoolDeposit(_)
                        | OperationBody::LiquidityPoolWithdraw(_)
                )
            {
                let mut pre: Option<(i64, i64)> = None;
                for c in changes {
                    if let Some(LedgerEntryData::LiquidityPool(l)) =
                        change_entry(c).map(|e| &e.data)
                    {
                        let stellar_xdr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) =
                            &l.body;
                        match c {
                            LedgerEntryChange::State(_) => pre = Some((cp.reserve_a, cp.reserve_b)),
                            LedgerEntryChange::Updated(_) | LedgerEntryChange::Created(_) => {
                                let (a0, b0) = pre.unwrap_or((0, 0));
                                let (da, db) = (cp.reserve_a - a0, cp.reserve_b - b0);
                                if da == 0 || db == 0 {
                                    let w = if matches!(
                                        op.body,
                                        OperationBody::LiquidityPoolDeposit(_)
                                    ) {
                                        "deposit"
                                    } else {
                                        "withdraw"
                                    };
                                    t.hit(
                                        "lp_zero_leg",
                                        format!("op.LIQUIDITY_POOL_{}", w.to_uppercase()),
                                        format!("dA={da};dB={db}"),
                                        (0, String::new()),
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            // third accounts
            if !matches!(op.body, OperationBody::Inflation) {
                for c in changes {
                    if matches!(c, LedgerEntryChange::State(_)) {
                        continue;
                    }
                    let owner = match c {
                        LedgerEntryChange::Removed(k) => key_owner(k).map(|o| (o, "removed")),
                        _ => change_entry(c)
                            .and_then(entry_owner)
                            .map(|(o, _)| (o, change_kind(c))),
                    };
                    if let Some((o, k)) = owner {
                        if !p.contains(&o) {
                            let ty = match c {
                                LedgerEntryChange::Removed(k) => format!("{:?}", k.discriminant()),
                                _ => change_entry(c)
                                    .map(|e| entry_owner(e).unwrap().1.to_string())
                                    .unwrap_or_default(),
                            };
                            let opname = format!("{:?}", op.body.discriminant());
                            t.hit(
                                "third_account_change",
                                format!("op.{opname}:{ty}:{k}"),
                                format!("{}", stellar_strkey::ed25519::PublicKey(o)),
                                (0, String::new()),
                            );
                        }
                    }
                }
            }
            if oi == 0 {
                base = base.clone();
            }
        }
        // all entries in every change of the transaction
        let tx_changes: Vec<&LedgerEntryChange> = match meta {
            TransactionMeta::V0(_) => vec![],
            TransactionMeta::V1(m) => m.tx_changes.0.iter().collect(),
            TransactionMeta::V2(m) => m
                .tx_changes_before
                .0
                .iter()
                .chain(m.tx_changes_after.0.iter())
                .collect(),
            TransactionMeta::V3(m) => m
                .tx_changes_before
                .0
                .iter()
                .chain(m.tx_changes_after.0.iter())
                .collect(),
            TransactionMeta::V4(m) => m
                .tx_changes_before
                .0
                .iter()
                .chain(m.tx_changes_after.0.iter())
                .collect(),
        };
        for c in op_changes.iter().flat_map(|c| c.iter()).chain(tx_changes) {
            if matches!(c, LedgerEntryChange::State(_)) {
                continue;
            }
            if let Some(e) = change_entry(c) {
                t.entry(e, "entry");
            }
        }
        for e in soroban_events {
            t.event(e, "ev");
        }
        for e in tx_events {
            t.event(e, "txev");
        }
        for e in diag {
            if !matches!(e.type_, stellar_xdr::ContractEventType::Contract) {
                t.event(e, "diag");
            }
        }
        if let Some(r) = ret {
            t.scval_root(r, "return", "return");
        }
        out.push(TxTags {
            tx: i as u32,
            hash: hex::encode(res.transaction_hash.0),
            hits: std::mem::take(&mut t.hits),
        });
    }
    Ok((seq, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_of_wide_values() {
        assert_eq!(dec_words([0, 0, 0, 0]), "0");
        assert_eq!(dec_words([0, 0, 0, u64::MAX]), "18446744073709551615");
        assert_eq!(dec_words([0, 0, 1, 0]), "18446744073709551616");
        assert_eq!(
            dec_words([u64::MAX; 4]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        // i128 -2^127
        let w = i128_words(&Int128Parts {
            hi: i64::MIN,
            lo: 0,
        });
        assert_eq!(
            wide("i128", w, true).unwrap().0,
            "i128=-170141183460469231731687303715884105728"
        );
        // below 2^63: no tag; 2^63 exactly: tagged
        assert!(wide("u128", [0, 0, 0, (1 << 63) - 1], false).is_none());
        assert_eq!(
            wide("u128", [0, 0, 0, 1 << 63], false).unwrap().0,
            "u128=9223372036854775808"
        );
        assert!(wide(
            "i128",
            i128_words(&Int128Parts {
                hi: -1,
                lo: u64::MAX
            }),
            true
        )
        .is_none());
    }

    #[test]
    fn text_classes_of_bytes() {
        assert!(text_classes(b"plain").is_empty());
        assert_eq!(text_classes(b"a\0b"), vec!["nul"]);
        assert_eq!(text_classes(&[0xd1]), vec!["nonutf8"]);
        assert_eq!(text_classes(b"\x01x"), vec!["ctrl"]);
        assert_eq!(text_classes("é".as_bytes()), vec!["nonascii"]);
    }

    #[test]
    fn asset_strings_and_sac_ids() {
        let net = Net::new("Test SDF Network ; September 2015");
        assert_eq!(parse_asset(b"native"), Some(Asset::Native));
        let issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let a = parse_asset(format!("USDC:{issuer}").as_bytes()).unwrap();
        assert!(matches!(a, Asset::CreditAlphanum4(_)));
        assert_eq!(asset_string(&a), format!("USDC:{issuer}"));
        assert!(parse_asset(b"USDC").is_none());
        assert!(parse_asset(b"TOOLONGASSETCODE:x").is_none());
        // the id depends on the network and on the asset
        assert_ne!(net.sac_id(&a), net.sac_id(&Asset::Native));
        assert_ne!(net.sac_id(&a), Net::new(PUB).sac_id(&a));
    }

    const PUB: &str = "Public Global Stellar Network ; September 2015";

    #[test]
    fn asset_code_rules() {
        let net = Net::new(PUB);
        let mut t = Tagger::new(&net);
        t.code("c", b"AB\0C", true);
        t.code("c", b"US$\0", true);
        t.code("c", b"ABCD", true);
        t.code("c", b"AB\0\0\0\0\0\0\0\0\0\0", false);
        let tags: Vec<&str> = t.hits.iter().map(|h| h.tag.as_str()).collect();
        assert_eq!(
            tags,
            vec![
                "asset_code:inner_nul",
                "asset_code:nonalnum",
                "asset_code:short"
            ]
        );
    }

    #[test]
    fn map_order_and_depth() {
        let net = Net::new(PUB);
        let mut t = Tagger::new(&net);
        let e = |k: u32| stellar_xdr::ScMapEntry {
            key: ScVal::U32(k),
            val: ScVal::Void,
        };
        let m = ScVal::Map(Some(stellar_xdr::ScMap(
            vec![e(2), e(1), e(1)].try_into().unwrap(),
        )));
        let mut v = m.clone();
        for _ in 0..9 {
            v = ScVal::Vec(Some(stellar_xdr::ScVec(vec![v].try_into().unwrap())));
        }
        t.scval_root(&v, "args", "args");
        let tags: Vec<(&str, &str)> = t
            .hits
            .iter()
            .map(|h| (h.tag.as_str(), h.value.as_str()))
            .collect();
        assert!(tags.contains(&("scmap:dup_key", "len=3")));
        assert!(tags.contains(&("scmap:unsorted", "len=3")));
        assert!(tags.contains(&("scval_depth", "11")));
    }
}
