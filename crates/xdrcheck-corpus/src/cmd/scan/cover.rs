//! `scan cover-stream`: greedy example covers of a whole run, per level, with memory bounded by the
//! number of distinct ids (never by the number of transactions or units).
//!
//! A first-fit greedy over a fixed order of candidates selects a candidate exactly when it is the
//! first carrier, in that order, of some id (everything an earlier candidate carries is already
//! covered). So each cover is, per id, the argmin of the order key over the candidates carrying it,
//! and the number of new ids of a selected candidate is the number of ids whose argmin it is. Each
//! unit computes its local argmins; the global argmin is their minimum, which does not depend on the
//! order in which units are folded: units run in parallel, and a checkpoint of the folded state makes
//! the job resumable.
//!
//! Ids per level: the component ids of `scan ablate` / `census` (the same projection), or, at level
//! `TOK`, the tokens themselves (id = sha256("xcc.token/v1\n" + token)[..16]), which makes the token
//! cover. Transaction covers use the transaction-level kinds (A E F M O R); ledger covers add the
//! ledger component (L).
//!
//! Orders (the key, smallest first):
//! - tx, ascending: (ledger, stored tx shape id, first apply index of that shape in the ledger): the
//!   order of `scan slice-cover`, so the two agree line for line. Within a ledger this follows the
//!   shape id, not the apply index; the ledgers and the counts per ledger of new ids do not depend on it.
//! - tx, rarest first: (smallest census occurrence among the transaction's ids, then the ascending key).
//! - ledger, ascending: ledger. It selects the first ledger of every id, so its size equals the number
//!   of distinct first ledgers in the census (checked).
//! - ledger, rarest first: (smallest census occurrence among the ledger's ids, ledger).
//!
//! Occurrences for the rarest-first keys come from the census (`--census`: transactions holding a
//! component id; ledgers for an `L` id) and, for `TOK`, from `token-census` (`--token-occ`).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};

use super::report::{self, level, Comp, RunData};
use super::shape::Id;
use super::tokens::token_id;
use super::units::{self, check_manifest, Unit, ZOut, ERA};

#[derive(clap::Args, Debug)]
pub struct CoverStreamArgs {
    /// Merged run directory (read only)
    #[arg(long)]
    pub run: PathBuf,
    /// Output directory
    #[arg(long)]
    pub out: PathBuf,
    /// Census directory of the same run (`census-merge` output): occurrences for the rarest-first
    /// orders and the first-ledger baseline; without it only the ascending covers are made
    #[arg(long)]
    pub census: Option<PathBuf>,
    /// `tokens.tsv.zst` of `token-census` on the same run: occurrences for the rarest-first token cover
    #[arg(long)]
    pub token_occ: Option<PathBuf>,
    /// Levels, comma-separated: G0 G1 G2 G3 TOK
    #[arg(long, default_value = "G0,G1,G2,G3")]
    pub levels: String,
    /// File with unit directory names (one per line); default: every unit of the run
    #[arg(long)]
    pub units_from: Option<PathBuf>,
    /// Accept units that do not follow each other (a partial view)
    #[arg(long)]
    pub allow_gaps: bool,
    /// Units read in parallel
    #[arg(long, default_value_t = 4)]
    pub jobs: usize,
    /// Seconds between checkpoints of the folded state (0 = none)
    #[arg(long, default_value_t = 900)]
    pub checkpoint_secs: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lv {
    G(&'static str),
    Tok,
}

impl Lv {
    fn name(&self) -> &'static str {
        match self {
            Lv::G(n) => n,
            Lv::Tok => "TOK",
        }
    }
}

fn parse_levels(s: &str) -> Result<Vec<Lv>> {
    let mut v = Vec::new();
    for x in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        v.push(match x {
            "G0" => Lv::G("G0"),
            "G1" => Lv::G("G1"),
            "G2" => Lv::G("G2"),
            "G3" => Lv::G("G3"),
            "TOK" => Lv::Tok,
            _ => bail!("{x}: not a level (G0 G1 G2 G3 TOK)"),
        });
    }
    ensure!(!v.is_empty(), "no levels");
    Ok(v)
}

const NO_ID: Id = [0xff; 16];

/// Per id: the smallest key of each of the four orders among its carriers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Best {
    /// (ledger, tx shape, apply index)
    tx: (u32, Id, u16),
    /// (occurrence, ledger, tx shape, apply index)
    txr: (u64, u32, Id, u16),
    led: u32,
    /// (occurrence, ledger)
    ledr: (u64, u32),
}

const REC: usize = 16 + 22 + 30 + 4 + 12;

impl Best {
    const NONE: Best = Best {
        tx: (u32::MAX, NO_ID, u16::MAX),
        txr: (u64::MAX, u32::MAX, NO_ID, u16::MAX),
        led: u32::MAX,
        ledr: (u64::MAX, u32::MAX),
    };
    fn absorb(&mut self, o: &Best) {
        self.tx = self.tx.min(o.tx);
        self.txr = self.txr.min(o.txr);
        self.led = self.led.min(o.led);
        self.ledr = self.ledr.min(o.ledr);
    }
    fn has_tx(&self) -> bool {
        self.tx.0 != u32::MAX
    }
    fn put(&self, id: &Id, b: &mut Vec<u8>) {
        b.extend_from_slice(id);
        b.extend_from_slice(&self.tx.0.to_le_bytes());
        b.extend_from_slice(&self.tx.1);
        b.extend_from_slice(&self.tx.2.to_le_bytes());
        b.extend_from_slice(&self.txr.0.to_le_bytes());
        b.extend_from_slice(&self.txr.1.to_le_bytes());
        b.extend_from_slice(&self.txr.2);
        b.extend_from_slice(&self.txr.3.to_le_bytes());
        b.extend_from_slice(&self.led.to_le_bytes());
        b.extend_from_slice(&self.ledr.0.to_le_bytes());
        b.extend_from_slice(&self.ledr.1.to_le_bytes());
    }
    fn get(b: &[u8; REC]) -> (Id, Best) {
        let u16_at = |i: usize| u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let id16 = |i: usize| -> Id { b[i..i + 16].try_into().unwrap() };
        (
            id16(0),
            Best {
                tx: (u32_at(16), id16(20), u16_at(36)),
                txr: (u64_at(38), u32_at(46), id16(50), u16_at(66)),
                led: u32_at(68),
                ledr: (u64_at(72), u32_at(80)),
            },
        )
    }
}

/// Occurrence of every id the rarest-first keys need.
struct Occ {
    map: HashMap<Id, u64>,
    /// levels whose ids are all in `map`
    levels: BTreeSet<&'static str>,
}

impl Occ {
    fn get(&self, lv: Lv, id: &Id) -> Result<u64> {
        if !self.levels.contains(lv.name()) {
            return Ok(0);
        }
        self.map.get(id).copied().with_context(|| {
            format!(
                "{} id {} has no occurrence in the census (census of another run?)",
                lv.name(),
                hex::encode(id)
            )
        })
    }
}

/// Census first-ledger baseline per level: (distinct first ledgers of the tx-level ids, of all ids).
type Baseline = BTreeMap<&'static str, (usize, usize)>;

fn load_occ(a: &CoverStreamArgs, levels: &[Lv]) -> Result<(Occ, Baseline)> {
    let mut occ = Occ {
        map: HashMap::new(),
        levels: BTreeSet::new(),
    };
    let mut base = Baseline::new();
    if let Some(dir) = &a.census {
        for lv in levels {
            let Lv::G(name) = lv else { continue };
            let (mut tx, mut all) = (BTreeSet::new(), BTreeSet::new());
            for k in units::COMP_KINDS {
                units::each_census(dir, name, k, |id, o, first, _| {
                    occ.map.insert(id, o);
                    if k != 'L' {
                        tx.insert(first);
                    }
                    all.insert(first);
                    Ok(())
                })?;
            }
            base.insert(name, (tx.len(), all.len()));
            occ.levels.insert(name);
        }
    }
    if let Some(f) = &a.token_occ {
        if levels.contains(&Lv::Tok) {
            units::each_tsv_zst(f, |c| {
                ensure!(c.len() >= 6, "short line");
                occ.map.insert(units::unhex16(c[0])?, c[5].parse()?);
                Ok(())
            })?;
            occ.levels.insert("TOK");
        }
    }
    Ok((occ, base))
}

/// One level of one unit: local ids and their argmins.
struct Local {
    ids: Vec<Id>,
    best: Vec<Best>,
}

fn intern(map: &mut HashMap<Id, u32>, ids: &mut Vec<Id>, id: Id) -> u32 {
    *map.entry(id).or_insert_with(|| {
        ids.push(id);
        (ids.len() - 1) as u32
    })
}

fn unit_locals(dir: &Path, levels: &[Lv], occ: &Occ) -> Result<Vec<Local>> {
    check_manifest(dir)?;
    let name = dir.file_name().unwrap().to_string_lossy().to_string();
    let mut d = RunData::default();
    for r in report::rows(&dir.join("components.parquet"))? {
        let i = report::id(&r[0]);
        ensure!(
            d.comps.insert(i, report::comp_of_row(&r)).is_none(),
            "{name}: component {} twice",
            hex::encode(i)
        );
    }
    for r in report::rows(&dir.join("tx_shapes.parquet"))? {
        let i = report::id(&r[0]);
        ensure!(
            d.shapes.insert(i, report::shape_of_row(&r)).is_none(),
            "{name}: tx shape {} twice",
            hex::encode(i)
        );
    }
    let mut comp_list: Vec<Id> = d.comps.keys().copied().collect();
    comp_list.sort();
    let cix: HashMap<Id, u32> = comp_list
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, i as u32))
        .collect();
    let mut shape_list: Vec<Id> = d.shapes.keys().copied().collect();
    shape_list.sort();
    let six: HashMap<Id, u32> = shape_list
        .iter()
        .enumerate()
        .map(|(i, s)| (*s, i as u32))
        .collect();
    let mut shape_comps: Vec<Vec<u32>> = Vec::with_capacity(shape_list.len());
    for s in &shape_list {
        let mut v = Vec::new();
        for c in d.shapes[s].comps() {
            v.push(*cix.get(c).with_context(|| {
                format!(
                    "{name}: tx shape {} references component {} not in the unit",
                    hex::encode(s),
                    hex::encode(c)
                )
            })?);
        }
        v.sort();
        v.dedup();
        shape_comps.push(v);
    }
    // (ledger, L component)
    let mut ledgers: Vec<(u32, u32)> = Vec::new();
    for r in report::rows(&dir.join("ledgers.parquet"))? {
        let seq = report::int(&r[0]) as u32;
        let l = report::id(&r[15]);
        let c = *cix
            .get(&l)
            .with_context(|| format!("{name}: ledger {seq} component not in the unit"))?;
        ledgers.push((seq, c));
    }
    ledgers.sort();
    let lix: HashMap<u32, usize> = ledgers
        .iter()
        .enumerate()
        .map(|(i, (s, _))| (*s, i))
        .collect();
    ensure!(lix.len() == ledgers.len(), "{name}: a ledger twice");
    // (ledger index, shape, first apply index)
    let mut occs: Vec<(u32, u32, u16)> = Vec::new();
    for r in report::rows(&dir.join("occurrences.parquet"))? {
        let seq = report::int(&r[0]) as u32;
        let s = *six
            .get(&report::id(&r[1]))
            .with_context(|| format!("{name}: occurrence of a tx shape not in the unit"))?;
        let ix = report::bytes(&r[3]);
        ensure!(ix.len() >= 2, "{name}: occurrence without an apply index");
        let li = *lix
            .get(&seq)
            .with_context(|| format!("{name}: occurrence in ledger {seq} without a ledger row"))?;
        occs.push((li as u32, s, u16::from_be_bytes([ix[0], ix[1]])));
    }
    // First occurrence of each shape by (ledger, apply index).
    let mut sfirst = vec![(u32::MAX, u16::MAX); shape_list.len()];
    for &(li, s, ix) in &occs {
        let k = (ledgers[li as usize].0, ix);
        if k < sfirst[s as usize] {
            sfirst[s as usize] = k;
        }
    }
    ensure!(
        sfirst.iter().all(|x| x.0 != u32::MAX),
        "{name}: a tx shape without occurrence"
    );
    let comps: Vec<&Comp> = comp_list.iter().map(|c| &d.comps[c]).collect();
    let mut out = Vec::with_capacity(levels.len());
    for &lv in levels {
        let mut map: HashMap<Id, u32> = HashMap::new();
        let mut ids: Vec<Id> = Vec::new();
        // component -> local ids
        let mut comp_l: Vec<Vec<u32>> = Vec::with_capacity(comps.len());
        match lv {
            Lv::G(n) => {
                let v = level(n);
                let tag = report::view_tag(&v);
                for c in &comps {
                    comp_l.push(vec![intern(
                        &mut map,
                        &mut ids,
                        report::project_comp(&tag, &v, c),
                    )]);
                }
            }
            Lv::Tok => {
                let mut tl: HashMap<&str, u32> = HashMap::new();
                for c in &comps {
                    let mut v: Vec<u32> = c
                        .tokens
                        .iter()
                        .map(|t| {
                            *tl.entry(t.as_str())
                                .or_insert_with(|| intern(&mut map, &mut ids, token_id(t)))
                        })
                        .collect();
                    v.sort();
                    v.dedup();
                    comp_l.push(v);
                }
            }
        }
        let occ_of: Vec<u64> = ids.iter().map(|i| occ.get(lv, i)).collect::<Result<_>>()?;
        // Shape -> ids (flat) and its smallest occurrence.
        let ns = shape_list.len();
        let mut stamp = vec![u32::MAX; ids.len()];
        let mut sh_off = Vec::with_capacity(ns + 1);
        let mut sh_ids: Vec<u32> = Vec::new();
        let mut sh_min = vec![u64::MAX; ns];
        for (s, cs) in shape_comps.iter().enumerate() {
            sh_off.push(sh_ids.len());
            for c in cs {
                for &i in &comp_l[*c as usize] {
                    if stamp[i as usize] != s as u32 {
                        stamp[i as usize] = s as u32;
                        sh_ids.push(i);
                        sh_min[s] = sh_min[s].min(occ_of[i as usize]);
                    }
                }
            }
        }
        sh_off.push(sh_ids.len());
        // Ledger key: smallest occurrence among the ledger's ids.
        let mut lkey: Vec<u64> = ledgers
            .iter()
            .map(|(_, c)| {
                comp_l[*c as usize]
                    .iter()
                    .map(|i| occ_of[*i as usize])
                    .min()
                    .unwrap_or(u64::MAX)
            })
            .collect();
        for &(li, s, _) in &occs {
            lkey[li as usize] = lkey[li as usize].min(sh_min[s as usize]);
        }
        // Per shape: its best ledger in the rarest-first ledger order.
        let mut sled = vec![(u64::MAX, u32::MAX); ns];
        for &(li, s, _) in &occs {
            let k = (lkey[li as usize], ledgers[li as usize].0);
            if k < sled[s as usize] {
                sled[s as usize] = k;
            }
        }
        let mut best = vec![Best::NONE; ids.len()];
        for s in 0..ns {
            let (seq, ix) = sfirst[s];
            let sid = shape_list[s];
            let cand = Best {
                tx: (seq, sid, ix),
                txr: (sh_min[s], seq, sid, ix),
                led: seq,
                ledr: sled[s],
            };
            for &i in &sh_ids[sh_off[s]..sh_off[s + 1]] {
                best[i as usize].absorb(&cand);
            }
        }
        for (li, &(seq, c)) in ledgers.iter().enumerate() {
            let cand = Best {
                led: seq,
                ledr: (lkey[li], seq),
                ..Best::NONE
            };
            for &i in &comp_l[c as usize] {
                best[i as usize].absorb(&cand);
            }
        }
        out.push(Local { ids, best });
    }
    Ok(out)
}

struct State {
    levels: Vec<HashMap<Id, Best>>,
    done: BTreeSet<String>,
}

const CK_MAGIC: &[u8; 8] = b"XCCCOV01";

fn fingerprint(a: &CoverStreamArgs, levels: &[Lv]) -> Result<String> {
    let mut f = format!(
        "levels={}",
        levels
            .iter()
            .map(|l| l.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    if let Some(c) = &a.census {
        let s = fs::read(c.join("summary.tsv"))?;
        f.push_str(&format!(";census={}", xdrcheck_xdr::sha256_hex(&s)));
    }
    if let Some(t) = &a.token_occ {
        f.push_str(&format!(";tokens={}", fs::metadata(t)?.len()));
    }
    f.push_str(&format!(";run={}", a.run.display()));
    Ok(f)
}

fn save_checkpoint(path: &Path, fp: &str, st: &State) -> Result<()> {
    let f = File::create(units::tmp_of(path))?;
    let mut enc = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, f), 1)?;
    enc.write_all(CK_MAGIC)?;
    let w64 =
        |e: &mut zstd::Encoder<'static, BufWriter<File>>, x: u64| e.write_all(&x.to_le_bytes());
    w64(&mut enc, fp.len() as u64)?;
    enc.write_all(fp.as_bytes())?;
    w64(&mut enc, st.done.len() as u64)?;
    for d in &st.done {
        w64(&mut enc, d.len() as u64)?;
        enc.write_all(d.as_bytes())?;
    }
    let mut b = Vec::with_capacity(REC * 4096);
    for m in &st.levels {
        w64(&mut enc, m.len() as u64)?;
        for (id, best) in m {
            best.put(id, &mut b);
            if b.len() >= REC * 4096 {
                enc.write_all(&b)?;
                b.clear();
            }
        }
        enc.write_all(&b)?;
        b.clear();
    }
    let f = enc.finish()?.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    drop(f);
    fs::rename(units::tmp_of(path), path)?;
    Ok(())
}

fn load_checkpoint(path: &Path, fp: &str, nlevels: usize) -> Result<Option<State>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut r = BufReader::with_capacity(1 << 20, zstd::Decoder::new(File::open(path)?)?);
    let mut m = [0u8; 8];
    r.read_exact(&mut m)?;
    ensure!(&m == CK_MAGIC, "{}: not a cover checkpoint", path.display());
    let r64 = |r: &mut dyn Read| -> Result<u64> {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    };
    let rs = |r: &mut dyn Read, n: u64| -> Result<String> {
        let mut b = vec![0u8; n as usize];
        r.read_exact(&mut b)?;
        Ok(String::from_utf8(b)?)
    };
    let n = r64(&mut r)?;
    let old = rs(&mut r, n)?;
    ensure!(
        old == fp,
        "{}: the checkpoint is of another job ({old}); remove it to start over",
        path.display()
    );
    let mut st = State {
        levels: Vec::new(),
        done: BTreeSet::new(),
    };
    for _ in 0..r64(&mut r)? {
        let n = r64(&mut r)?;
        st.done.insert(rs(&mut r, n)?);
    }
    for _ in 0..nlevels {
        let n = r64(&mut r)? as usize;
        let mut m = HashMap::with_capacity(n);
        let mut b = [0u8; REC];
        for _ in 0..n {
            r.read_exact(&mut b)?;
            let (id, best) = Best::get(&b);
            m.insert(id, best);
        }
        st.levels.push(m);
    }
    Ok(Some(st))
}

pub fn run(a: CoverStreamArgs) -> Result<()> {
    let t0 = Instant::now();
    let levels = parse_levels(&a.levels)?;
    let list = units::list(&a.run, a.units_from.as_deref(), a.allow_gaps)?;
    fs::create_dir_all(&a.out)?;
    let (occ, base) = load_occ(&a, &levels)?;
    eprintln!(
        "cover-stream: {} units, levels {}, rarest-first for {:?}, {} occurrences loaded ({:.0} s)",
        list.len(),
        a.levels,
        occ.levels,
        occ.map.len(),
        t0.elapsed().as_secs_f64()
    );
    let fp = fingerprint(&a, &levels)?;
    let ck = a.out.join("cover-stream.checkpoint");
    let st = match load_checkpoint(&ck, &fp, levels.len())? {
        Some(s) => {
            eprintln!("resuming: {} units already folded", s.done.len());
            s
        }
        None => State {
            levels: vec![HashMap::new(); levels.len()],
            done: BTreeSet::new(),
        },
    };
    let todo: Vec<&Unit> = list
        .iter()
        .filter(|u| !st.done.contains(&u.name()))
        .collect();
    let st = Mutex::new(st);
    let last_ck = Mutex::new(Instant::now());
    let n_done = AtomicUsize::new(0);
    units::par_each(&todo, a.jobs, |_, u| {
        let loc = unit_locals(&u.dir, &levels, &occ)?;
        let mut g = st.lock().unwrap();
        for (k, l) in loc.iter().enumerate() {
            let m = &mut g.levels[k];
            for (id, b) in l.ids.iter().zip(&l.best) {
                m.entry(*id).or_insert(Best::NONE).absorb(b);
            }
        }
        g.done.insert(u.name());
        let k = n_done.fetch_add(1, Ordering::SeqCst) + 1;
        if k.is_multiple_of(500) || k == todo.len() {
            let sizes: Vec<usize> = g.levels.iter().map(|m| m.len()).collect();
            eprintln!(
                "[{k}/{}] ids per level {sizes:?} ({:.0} s)",
                todo.len(),
                t0.elapsed().as_secs_f64()
            );
        }
        if a.checkpoint_secs > 0 {
            let mut lc = last_ck.lock().unwrap();
            if lc.elapsed().as_secs() >= a.checkpoint_secs && k < todo.len() {
                let t = Instant::now();
                save_checkpoint(&ck, &fp, &g)?;
                eprintln!("checkpoint written in {:.1} s", t.elapsed().as_secs_f64());
                *lc = Instant::now();
            }
        }
        Ok(())
    })?;
    let st = st.into_inner().unwrap();
    if a.checkpoint_secs > 0 && !todo.is_empty() {
        save_checkpoint(&ck, &fp, &st)?;
    }
    eprintln!(
        "fold done ({:.0} s); writing covers",
        t0.elapsed().as_secs_f64()
    );
    report(&a, &levels, &occ, &base, &st)?;
    eprintln!("cover-stream: done in {:.0} s", t0.elapsed().as_secs_f64());
    Ok(())
}

#[derive(Default)]
struct Sizes {
    tx: usize,
    tx_ledgers: usize,
    ledgers: usize,
    era_tx: BTreeMap<u32, usize>,
    era_tx_ledgers: BTreeMap<u32, usize>,
    era_ledgers: BTreeMap<u32, usize>,
}

fn report(
    a: &CoverStreamArgs,
    levels: &[Lv],
    occ: &Occ,
    base: &Baseline,
    st: &State,
) -> Result<()> {
    let mut summary = String::from(
        "level\torder\tids_tx\tids_all\ttx_selected\ttx_distinct_ledgers\tledgers_selected\tbaseline_first_ledgers_tx\tbaseline_first_ledgers_all\tcheck\n",
    );
    let mut eras_out: Vec<(String, String, &'static str, BTreeMap<u32, usize>)> = Vec::new();
    let mut all_eras: BTreeSet<u32> = BTreeSet::new();
    for (k, lv) in levels.iter().enumerate() {
        let m = &st.levels[k];
        let ids_all = m.len();
        let ids_tx = m.values().filter(|b| b.has_tx()).count();
        let rare = occ.levels.contains(lv.name());
        for order in ["asc", "rare"] {
            if order == "rare" && !rare {
                continue;
            }
            // tx carrier (ledger, apply index) -> (new ids, key occurrence)
            let mut txc: BTreeMap<(u32, u16), (u64, u64)> = BTreeMap::new();
            let mut lc: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
            for b in m.values() {
                if b.has_tx() {
                    let (key, o) = if order == "asc" {
                        ((b.tx.0, b.tx.2), 0)
                    } else {
                        ((b.txr.1, b.txr.3), b.txr.0)
                    };
                    let e = txc.entry(key).or_insert((0, o));
                    e.0 += 1;
                }
                let (key, o) = if order == "asc" {
                    (b.led, 0)
                } else {
                    (b.ledr.1, b.ledr.0)
                };
                let e = lc.entry(key).or_insert((0, o));
                e.0 += 1;
            }
            let sfx = if order == "asc" { "" } else { "-rare" };
            let mut w = ZOut::create(
                a.out.join(format!("cover-{}-tx{sfx}.tsv.zst", lv.name())),
                if order == "asc" {
                    "ledger\ttx_index\tnew_ids"
                } else {
                    "ledger\ttx_index\tnew_ids\tkey_occurrence"
                },
            )?;
            let mut sz = Sizes::default();
            let mut tx_ledgers: BTreeSet<u32> = BTreeSet::new();
            for ((seq, ix), (n, o)) in &txc {
                if order == "asc" {
                    writeln!(w.enc, "{seq}\t{ix}\t{n}")?;
                } else {
                    writeln!(w.enc, "{seq}\t{ix}\t{n}\t{o}")?;
                }
                *sz.era_tx.entry(seq / ERA).or_default() += 1;
                if tx_ledgers.insert(*seq) {
                    *sz.era_tx_ledgers.entry(seq / ERA).or_default() += 1;
                }
            }
            w.finish()?;
            sz.tx = txc.len();
            sz.tx_ledgers = tx_ledgers.len();
            let mut w = ZOut::create(
                a.out
                    .join(format!("cover-{}-ledgers{sfx}.tsv.zst", lv.name())),
                if order == "asc" {
                    "ledger\tnew_ids"
                } else {
                    "ledger\tnew_ids\tkey_occurrence"
                },
            )?;
            for (seq, (n, o)) in &lc {
                if order == "asc" {
                    writeln!(w.enc, "{seq}\t{n}")?;
                } else {
                    writeln!(w.enc, "{seq}\t{n}\t{o}")?;
                }
                *sz.era_ledgers.entry(seq / ERA).or_default() += 1;
            }
            w.finish()?;
            sz.ledgers = lc.len();
            let (bt, ba) = match lv {
                Lv::G(n) => base
                    .get(n)
                    .map(|(t, a)| (t.to_string(), a.to_string()))
                    .unwrap_or(("-".into(), "-".into())),
                Lv::Tok => ("-".into(), "-".into()),
            };
            let check = if order == "asc" && bt != "-" {
                if bt == sz.tx_ledgers.to_string() && ba == sz.ledgers.to_string() {
                    "baseline-equal"
                } else {
                    "BASELINE-DIFFERS"
                }
            } else {
                "-"
            };
            writeln!(
                summary,
                "{}\t{order}\t{ids_tx}\t{ids_all}\t{}\t{}\t{}\t{bt}\t{ba}\t{check}",
                lv.name(),
                sz.tx,
                sz.tx_ledgers,
                sz.ledgers
            )?;
            for (what, e) in [
                ("tx_selected", &sz.era_tx),
                ("tx_distinct_ledgers", &sz.era_tx_ledgers),
                ("ledgers_selected", &sz.era_ledgers),
            ] {
                all_eras.extend(e.keys().copied());
                eras_out.push((lv.name().into(), order.into(), what, e.clone()));
            }
        }
    }
    let mut eras = String::from("level\torder\tmeasure");
    for e in &all_eras {
        write!(
            eras,
            "\t{}M-{}M",
            e * (ERA / 1_000_000),
            (e + 1) * (ERA / 1_000_000)
        )?;
    }
    eras.push('\n');
    for (l, o, what, m) in &eras_out {
        write!(eras, "{l}\t{o}\t{what}")?;
        for e in &all_eras {
            write!(eras, "\t{}", m.get(e).copied().unwrap_or(0))?;
        }
        eras.push('\n');
    }
    units::write_atomic(&a.out.join("cover-summary.tsv"), summary.as_bytes())?;
    units::write_atomic(&a.out.join("cover-eras.tsv"), eras.as_bytes())?;
    print!("{summary}\n{eras}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_round_trip_and_min() {
        let mut a = Best::NONE;
        let b = Best {
            tx: (5, [1; 16], 3),
            txr: (7, 5, [1; 16], 3),
            led: 5,
            ledr: (2, 9),
        };
        a.absorb(&b);
        let mut c = b;
        c.tx = (5, [0; 16], 9);
        c.ledr = (2, 8);
        a.absorb(&c);
        assert_eq!(a.tx, (5, [0; 16], 9));
        assert_eq!(a.ledr, (2, 8));
        let mut v = Vec::new();
        a.put(&[4; 16], &mut v);
        assert_eq!(v.len(), REC);
        let (id, back) = Best::get(&v[..].try_into().unwrap());
        assert_eq!(id, [4; 16]);
        assert_eq!(back, a);
    }
}
