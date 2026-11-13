//! `scan token-census`: the G3 tokens of a whole run, per token and per token class.
//!
//! Units are read in parallel; each G3 component (id as in the census) is taken once, from the
//! first unit that reaches it, so memory depends on the number of distinct components and tokens,
//! never on the run. Occurrences and ledger ranges of a component come from the census G3 files.
//!
//! Outputs (in `--out`):
//! - `tokens.tsv.zst`: token id (sha256("xcc.token/v1\n" + token)[..16], the ids of
//!   `cover-stream --levels TOK`), kind, class, token, distinct G3 components carrying it, occurrences
//!   (sum of those components' census occurrences: transactions; ledgers for `L` components), first
//!   and last ledger, kinds of the carrying components.
//! - `token-classes.tsv`: per (kind, class): distinct tokens, components carrying at least one, per
//!   component kind, singleton components (census occurrence 1) carrying one, and singleton components
//!   whose rarest token is in the class (rarest = fewest carrying components, then fewest occurrences,
//!   then token text).
//! - `token-steps.tsv`: for the `O` components, each projection step (G0→G1, G1→G2, G2→G3) and each
//!   (kind, class) the step adds: distinct ids at the lower view plus that class alone (`add_alone`)
//!   and at the upper view minus that class alone (`drop_alone`). Distinct counts use a 64-bit hash of
//!   the kept token set, so the level rows must equal the census (checked).
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::report::{self, level, Comp};
use super::shape::Id;
use super::units::{self, check_manifest, ZOut, COMP_KINDS};

#[derive(clap::Args, Debug)]
pub struct TokenCensusArgs {
    /// Merged run directory (read only)
    #[arg(long)]
    pub run: PathBuf,
    /// Output directory
    #[arg(long)]
    pub out: PathBuf,
    /// Census directory of the same run (`census-merge` output)
    #[arg(long)]
    pub census: PathBuf,
    /// File with unit directory names (one per line); default: every unit of the run
    #[arg(long)]
    pub units_from: Option<PathBuf>,
    /// Accept units that do not follow each other (a partial view)
    #[arg(long)]
    pub allow_gaps: bool,
    /// Units read in parallel
    #[arg(long, default_value_t = 4)]
    pub jobs: usize,
    /// Stop when the run holds more distinct tokens than this (memory guard)
    #[arg(long, default_value_t = 20_000_000)]
    pub max_tokens: usize,
}

/// Stable id of a token (the `TOK` level of `cover-stream`).
pub fn token_id(t: &str) -> Id {
    let mut h = Sha256::new();
    h.update(b"xcc.token/v1\n");
    h.update(t.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

fn kind_bit(k: char) -> u8 {
    COMP_KINDS
        .iter()
        .position(|x| *x == k)
        .map(|i| 1u8 << i)
        .unwrap_or(0)
}

/// (kind, class) of a token `K|class|rest`.
fn class_of(t: &str) -> (&str, &str) {
    let mut it = t.splitn(3, '|');
    (it.next().unwrap_or(""), it.next().unwrap_or(""))
}

fn mix(h: u64, x: u64) -> u64 {
    // splitmix64 finaliser over the running value
    let mut z = (h ^ x).wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[derive(Clone, Copy)]
struct TokStat {
    comps: u64,
    occ: u64,
    first: u32,
    last: u32,
    kinds: u8,
}

struct State {
    seen: HashSet<Id>,
    tok: HashMap<String, u32>,
    texts: Vec<String>,
    hash: Vec<u64>,
    stat: Vec<TokStat>,
    tclass: Vec<u16>,
    classes: Vec<(String, String)>,
    class_ix: HashMap<(String, String), u16>,
    /// per class: components carrying >= 1 token, per component kind
    class_comps: Vec<[u64; 7]>,
    /// per class: singleton components carrying >= 1 token
    class_single: Vec<u64>,
    comps_by_kind: [u64; 7],
    /// O components: hash of the T tokens, then (class, hash of that class's tokens) runs
    o_t: Vec<u64>,
    o_off: Vec<u32>,
    o_class: Vec<u16>,
    o_hash: Vec<u64>,
    spool: Option<zstd::Encoder<'static, BufWriter<File>>>,
    singletons: u64,
}

impl State {
    fn intern(&mut self, t: &str) -> u32 {
        if let Some(i) = self.tok.get(t) {
            return *i;
        }
        let i = self.texts.len() as u32;
        let (k, c) = class_of(t);
        let key = (k.to_string(), c.to_string());
        let ci = match self.class_ix.get(&key) {
            Some(x) => *x,
            None => {
                let x = self.classes.len() as u16;
                self.classes.push(key.clone());
                self.class_ix.insert(key, x);
                self.class_comps.push([0; 7]);
                self.class_single.push(0);
                x
            }
        };
        self.tok.insert(t.to_string(), i);
        self.texts.push(t.to_string());
        let h = Sha256::digest(t.as_bytes());
        self.hash
            .push(u64::from_le_bytes(h[..8].try_into().unwrap()));
        self.stat.push(TokStat {
            comps: 0,
            occ: 0,
            first: u32::MAX,
            last: 0,
            kinds: 0,
        });
        self.tclass.push(ci);
        i
    }
}

pub fn run(a: TokenCensusArgs) -> Result<()> {
    let t0 = Instant::now();
    let list = units::list(&a.run, a.units_from.as_deref(), a.allow_gaps)?;
    fs::create_dir_all(&a.out)?;
    // G3 component id -> (occurrences, first, last)
    let mut cen: HashMap<Id, (u64, u32, u32)> = HashMap::new();
    let mut census_o = [0usize; 4];
    for (li, l) in ["G0", "G1", "G2", "G3"].iter().enumerate() {
        for k in COMP_KINDS {
            if *l != "G3" && k != 'O' {
                continue;
            }
            units::each_census(&a.census, l, k, |id, o, f, la| {
                if *l == "G3" {
                    cen.insert(id, (o, f, la));
                }
                if k == 'O' {
                    census_o[li] += 1;
                }
                Ok(())
            })?;
        }
    }
    eprintln!(
        "token-census: {} units, {} G3 components in the census ({:.0} s)",
        list.len(),
        cen.len(),
        t0.elapsed().as_secs_f64()
    );
    let spool_path = a.out.join("singletons.spool");
    let st = Mutex::new(State {
        seen: HashSet::new(),
        tok: HashMap::new(),
        texts: Vec::new(),
        hash: Vec::new(),
        stat: Vec::new(),
        tclass: Vec::new(),
        classes: Vec::new(),
        class_ix: HashMap::new(),
        class_comps: Vec::new(),
        class_single: Vec::new(),
        comps_by_kind: [0; 7],
        o_t: Vec::new(),
        o_off: vec![0],
        o_class: Vec::new(),
        o_hash: Vec::new(),
        spool: Some(zstd::Encoder::new(
            BufWriter::with_capacity(1 << 20, File::create(&spool_path)?),
            1,
        )?),
        singletons: 0,
    });
    let g3 = level("G3");
    let tag = report::view_tag(&g3);
    let n_done = AtomicUsize::new(0);
    units::par_each(&list, a.jobs, |_, u| {
        check_manifest(&u.dir)?;
        let mut comps: Vec<(Id, Comp)> = Vec::new();
        for r in report::rows(&u.dir.join("components.parquet"))? {
            let c = report::comp_of_row(&r);
            comps.push((report::project_comp(&tag, &g3, &c), c));
        }
        // Components not taken yet (checked again under the lock when folding).
        let fresh: Vec<usize> = {
            let g = st.lock().unwrap();
            (0..comps.len())
                .filter(|i| !g.seen.contains(&comps[*i].0))
                .collect()
        };
        let mut g = st.lock().unwrap();
        let g = &mut *g;
        for i in fresh {
            let (id, c) = &comps[i];
            if !g.seen.insert(*id) {
                continue;
            }
            let (occ, first, last) = *cen.get(id).with_context(|| {
                format!(
                    "{}: component {} not in the census (census of another run?)",
                    u.name(),
                    hex::encode(id)
                )
            })?;
            let kb = kind_bit(c.kind);
            let ki = kb.trailing_zeros() as usize;
            ensure!(kb != 0, "{}: component kind {}", u.name(), c.kind);
            g.comps_by_kind[ki] += 1;
            let mut idx: Vec<u32> = c.tokens.iter().map(|t| g.intern(t)).collect();
            idx.sort();
            idx.dedup();
            ensure!(
                g.texts.len() <= a.max_tokens,
                "more than {} distinct tokens",
                a.max_tokens
            );
            let mut cls: Vec<u16> = Vec::new();
            for &t in &idx {
                let s = &mut g.stat[t as usize];
                s.comps += 1;
                s.occ += occ;
                s.first = s.first.min(first);
                s.last = s.last.max(last);
                s.kinds |= kb;
                cls.push(g.tclass[t as usize]);
            }
            cls.sort();
            cls.dedup();
            for &c in &cls {
                g.class_comps[c as usize][ki] += 1;
                if occ == 1 {
                    g.class_single[c as usize] += 1;
                }
            }
            if c.kind == 'O' {
                // Sorted (class, token hash) pairs; T classes fold into one T hash.
                let mut pairs: Vec<(u16, u64)> = Vec::with_capacity(idx.len());
                let mut th: Vec<u64> = Vec::new();
                for &t in &idx {
                    let ci = g.tclass[t as usize];
                    if g.classes[ci as usize].0 == "T" {
                        th.push(g.hash[t as usize]);
                    } else {
                        pairs.push((ci, g.hash[t as usize]));
                    }
                }
                th.sort_unstable();
                pairs.sort_unstable();
                g.o_t.push(th.iter().fold(0x5458_4343, |h, x| mix(h, *x)));
                let mut j = 0;
                while j < pairs.len() {
                    let ci = pairs[j].0;
                    let mut h = 0x4f43_4c53 ^ ci as u64;
                    while j < pairs.len() && pairs[j].0 == ci {
                        h = mix(h, pairs[j].1);
                        j += 1;
                    }
                    g.o_class.push(ci);
                    g.o_hash.push(h);
                }
                let n = g.o_class.len() as u32;
                g.o_off.push(n);
            }
            if occ == 1 {
                g.singletons += 1;
                let sp = g.spool.as_mut().unwrap();
                sp.write_all(&[ki as u8])?;
                sp.write_all(&(idx.len() as u32).to_le_bytes())?;
                for t in &idx {
                    sp.write_all(&t.to_le_bytes())?;
                }
            }
        }
        let k = n_done.fetch_add(1, Ordering::SeqCst) + 1;
        if k.is_multiple_of(1000) || k == list.len() {
            eprintln!(
                "[{k}/{}] components {}, tokens {} ({:.0} s)",
                list.len(),
                g.seen.len(),
                g.texts.len(),
                t0.elapsed().as_secs_f64()
            );
        }
        Ok(())
    })?;
    let mut g = st.into_inner().unwrap();
    ensure!(
        g.seen.len() == cen.len(),
        "the run holds {} G3 components, the census {}",
        g.seen.len(),
        cen.len()
    );
    g.spool.take().unwrap().finish()?.flush()?;
    drop(cen);

    // tokens.tsv.zst, sorted by (kind, class, token)
    let mut order: Vec<u32> = (0..g.texts.len() as u32).collect();
    order.sort_by(|x, y| {
        let (a, b) = (&g.texts[*x as usize], &g.texts[*y as usize]);
        class_of(a).cmp(&class_of(b)).then(a.cmp(b))
    });
    let mut w = ZOut::create(
        a.out.join("tokens.tsv.zst"),
        "token_id\tkind\tclass\ttoken\tcomponents\toccurrences\tfirst_ledger\tlast_ledger\tcomponent_kinds",
    )?;
    for &t in &order {
        let s = g.stat[t as usize];
        let text = &g.texts[t as usize];
        ensure!(
            !text.contains('\t') && !text.contains('\n'),
            "token with a tab or newline: {text:?}"
        );
        let (k, c) = class_of(text);
        let kinds: String = COMP_KINDS
            .iter()
            .enumerate()
            .filter(|(i, _)| s.kinds & (1 << i) != 0)
            .map(|(_, k)| *k)
            .collect();
        writeln!(
            w.enc,
            "{}\t{k}\t{c}\t{text}\t{}\t{}\t{}\t{}\t{kinds}",
            hex::encode(token_id(text)),
            s.comps,
            s.occ,
            s.first,
            s.last
        )?;
    }
    w.finish()?;
    eprintln!("tokens written ({:.0} s)", t0.elapsed().as_secs_f64());

    // Singletons by the class of their rarest token (second pass over the spool).
    let nclass = g.classes.len();
    let mut by_rarest = vec![0u64; nclass];
    {
        let mut r =
            BufReader::with_capacity(1 << 20, zstd::Decoder::new(File::open(&spool_path)?)?);
        let mut n_read = 0u64;
        let mut head = [0u8; 5];
        loop {
            match r.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let n = u32::from_le_bytes(head[1..5].try_into().unwrap()) as usize;
            let mut b = vec![0u8; 4 * n];
            r.read_exact(&mut b)?;
            let rarest = b
                .chunks(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .min_by(|x, y| {
                    let (sx, sy) = (&g.stat[*x as usize], &g.stat[*y as usize]);
                    (sx.comps, sx.occ, &g.texts[*x as usize]).cmp(&(
                        sy.comps,
                        sy.occ,
                        &g.texts[*y as usize],
                    ))
                });
            if let Some(t) = rarest {
                by_rarest[g.tclass[t as usize] as usize] += 1;
            }
            n_read += 1;
        }
        ensure!(n_read == g.singletons, "singleton spool truncated");
    }
    fs::remove_file(&spool_path)?;

    // token-classes.tsv
    let mut per_class_tokens = vec![0u64; nclass];
    let mut per_class_one = vec![0u64; nclass];
    for (t, c) in g.tclass.iter().enumerate() {
        per_class_tokens[*c as usize] += 1;
        per_class_one[*c as usize] += (g.stat[t].comps == 1) as u64;
    }
    let mut cls: Vec<usize> = (0..nclass).collect();
    cls.sort_by(|x, y| g.classes[*x].cmp(&g.classes[*y]));
    let mut t =
        String::from("kind\tclass\tdistinct_tokens\ttokens_in_one_component\tcomponents_carrying");
    for k in COMP_KINDS {
        write!(t, "\tcarrying_{k}")?;
    }
    t.push_str("\tsingleton_components_carrying\tsingletons_by_rarest_token\n");
    for &c in &cls {
        let cc = g.class_comps[c];
        write!(
            t,
            "{}\t{}\t{}\t{}\t{}",
            g.classes[c].0,
            g.classes[c].1,
            per_class_tokens[c],
            per_class_one[c],
            cc.iter().sum::<u64>()
        )?;
        for x in cc {
            write!(t, "\t{x}")?;
        }
        writeln!(t, "\t{}\t{}", g.class_single[c], by_rarest[c])?;
    }
    write!(
        t,
        "all\tall\t{}\t{}\t{}",
        g.texts.len(),
        per_class_one.iter().sum::<u64>(),
        g.seen.len()
    )?;
    for x in g.comps_by_kind {
        write!(t, "\t{x}")?;
    }
    writeln!(t, "\t{}\t{}", g.singletons, by_rarest.iter().sum::<u64>())?;
    units::write_atomic(&a.out.join("token-classes.tsv"), t.as_bytes())?;

    // token-steps.tsv: projection-step attribution over the O components.
    let n_o = g.o_t.len();
    let distinct = |keep: &dyn Fn(u16) -> bool| -> usize {
        let mut v: Vec<u64> = Vec::with_capacity(n_o);
        for i in 0..n_o {
            let mut h = g.o_t[i];
            for j in g.o_off[i] as usize..g.o_off[i + 1] as usize {
                if keep(g.o_class[j]) {
                    h = mix(h, g.o_hash[j]);
                }
            }
            v.push(h);
        }
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    let views: [(&str, &[&str]); 4] = [
        ("G0", &[]),
        ("G1", &["A", "O", "E"]),
        ("G2", &["A", "O", "E", "L", "V", "S", "K", "X"]),
        ("G3", &["A", "O", "E", "L", "V", "S", "K", "X", "D", "R"]),
    ];
    let kind_of = |c: u16| g.classes[c as usize].0.as_str();
    let mut lv_n = [0usize; 4];
    let mut s = String::from("step\tkind\tclass\tlower\tupper\tlower_plus_class\tupper_minus_class\tadd_alone\tdrop_alone\tg3_minus_class\n");
    for (i, (name, ks)) in views.iter().enumerate() {
        lv_n[i] = distinct(&|c| ks.contains(&kind_of(c)));
        let ok = if lv_n[i] == census_o[i] {
            "census-equal"
        } else {
            "CENSUS-DIFFERS"
        };
        writeln!(
            s,
            "{name}\t-\t-\t-\t{}\t-\t-\t-\t-\t-\t{ok} (census {})",
            lv_n[i], census_o[i]
        )?;
    }
    for i in 0..3 {
        let (lo, hi) = (views[i].1, views[i + 1].1);
        let step = format!("{}->{}", views[i].0, views[i + 1].0);
        writeln!(
            s,
            "{step}\tall\tall\t{}\t{}\t-\t-\t{}\t{}\t-",
            lv_n[i],
            lv_n[i + 1],
            lv_n[i + 1] - lv_n[i],
            lv_n[i + 1] - lv_n[i]
        )?;
        let mut added: Vec<u16> = (0..nclass as u16)
            .filter(|c| hi.contains(&kind_of(*c)) && !lo.contains(&kind_of(*c)))
            .collect();
        added.sort_by(|x, y| g.classes[*x as usize].cmp(&g.classes[*y as usize]));
        for c in added {
            let plus = distinct(&|x| lo.contains(&kind_of(x)) || x == c);
            let minus = distinct(&|x| hi.contains(&kind_of(x)) && x != c);
            let g3m = if i == 2 {
                minus
            } else {
                distinct(&|x| views[3].1.contains(&kind_of(x)) && x != c)
            };
            writeln!(
                s,
                "{step}\t{}\t{}\t{}\t{}\t{plus}\t{minus}\t{}\t{}\t{g3m}",
                g.classes[c as usize].0,
                g.classes[c as usize].1,
                lv_n[i],
                lv_n[i + 1],
                plus as i64 - lv_n[i] as i64,
                lv_n[i + 1] as i64 - minus as i64
            )?;
        }
    }
    units::write_atomic(&a.out.join("token-steps.tsv"), s.as_bytes())?;
    print!("{t}\n{s}");
    if lv_n != census_o {
        bail!("O distinct counts {lv_n:?} differ from the census {census_o:?}");
    }
    eprintln!("token-census: done in {:.0} s", t0.elapsed().as_secs_f64());
    Ok(())
}
