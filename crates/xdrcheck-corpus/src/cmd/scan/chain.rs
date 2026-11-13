//! `scan chain-check`: every ledger of a run in ledger order, holding only the previous row: the
//! header-hash chain (`prev_hash` = previous `header_hash`, across unit boundaries too), gaps and
//! duplicates in the sequence, and per (writer core, protocol applied, LCM arm) the ledgers whose
//! invariant bits are off (metadata match, tx-set hash, result hash: the table `scan format` prints).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{ensure, Result};
use parquet::record::Field;

use super::report::{bytes, int, rows};
use super::store::inv;
use super::units::{self, check_manifest, Unit};

#[derive(clap::Args, Debug)]
pub struct ChainCheckArgs {
    /// Merged run directory (read only)
    #[arg(long)]
    pub run: PathBuf,
    /// Output directory (chain-groups.tsv, chain-summary.txt)
    #[arg(long)]
    pub out: PathBuf,
    /// File with unit directory names (one per line); default: every unit of the run
    #[arg(long)]
    pub units_from: Option<PathBuf>,
    /// Accept units that do not follow each other (a partial view)
    #[arg(long)]
    pub allow_gaps: bool,
    /// Units read in parallel
    #[arg(long, default_value_t = 4)]
    pub jobs: usize,
}

const EXAMPLES: usize = 20;
/// Invariant bits reported, in column order.
const BITS: [(u32, &str); 3] = [
    (inv::META_MATCHES, "meta_mismatch"),
    (inv::TX_SET_HASH_OK, "tx_set_hash_fail"),
    (inv::RESULT_HASH_OK, "result_hash_fail"),
];

struct Row {
    seq: u32,
    hh: Vec<u8>,
    prev: Vec<u8>,
    applied: u32,
    arm: u32,
    txs: u64,
    inv: u32,
    md5: Option<bool>,
    core: String,
}

struct UnitRows {
    rows: Vec<Row>,
    refused: Vec<u32>,
}

fn load(u: &Unit) -> Result<UnitRows> {
    check_manifest(&u.dir)?;
    let prov = xdrcheck_xdr::batch::decompress_bounded(
        &fs::read(u.dir.join("provenance.jsonl.zst"))?,
        1 << 30,
    )?;
    let mut core: HashMap<u32, String> = HashMap::new();
    for l in prov.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_slice(l)?;
        if let Some(s) = v["seq"].as_u64() {
            let c = v["core_version"].as_str().unwrap_or("?");
            core.insert(s as u32, c.split(" (").next().unwrap_or(c).to_string());
        }
    }
    let mut out = Vec::new();
    for r in rows(&u.dir.join("ledgers.parquet"))? {
        let seq = int(&r[0]) as u32;
        ensure!(
            (u.first..=u.last).contains(&seq),
            "{}: ledger {seq} outside the unit's range",
            u.name()
        );
        out.push(Row {
            seq,
            hh: bytes(&r[10]),
            prev: bytes(&r[11]),
            applied: int(&r[8]) as u32,
            arm: int(&r[9]) as u32,
            txs: int(&r[12]) as u64,
            inv: int(&r[16]) as u32,
            md5: match &r[5] {
                Field::Bool(b) => Some(*b),
                _ => None,
            },
            core: core.get(&seq).cloned().unwrap_or_else(|| "?".into()),
        });
    }
    out.sort_by_key(|r| r.seq);
    let mut refused = Vec::new();
    let rp = u.dir.join("refusals.parquet");
    if rp.exists() {
        for r in rows(&rp)? {
            refused.push(int(&r[0]) as u32);
        }
    }
    let m: serde_json::Value = serde_json::from_slice(&fs::read(u.dir.join("MANIFEST.json"))?)?;
    ensure!(
        m["refusals"].as_u64().unwrap_or(0) == refused.len() as u64,
        "{}: manifest refusals differ from refusals.parquet",
        u.name()
    );
    Ok(UnitRows { rows: out, refused })
}

#[derive(Default)]
struct Group {
    ledgers: u64,
    txs: u64,
    off: [u64; 3],
    ex: [Vec<u32>; 3],
    md5_false: u64,
    md5_none: u64,
    first: u32,
    last: u32,
}

pub fn run(a: ChainCheckArgs) -> Result<ExitCode> {
    let t0 = Instant::now();
    let list = units::list(&a.run, a.units_from.as_deref(), a.allow_gaps)?;
    fs::create_dir_all(&a.out)?;
    eprintln!("chain-check: {} units, {} jobs", list.len(), a.jobs);
    let mut prev: Option<(u32, Vec<u8>)> = None;
    let mut open_end: Option<(u32, String)> = None;
    let (mut ledgers, mut txs, mut links, mut boundary_links) = (0u64, 0u64, 0u64, 0u64);
    let (mut mismatch, mut dups) = (0u64, 0u64);
    let mut mismatch_ex: Vec<u32> = Vec::new();
    let mut dup_ex: Vec<u32> = Vec::new();
    // missing ranges [from, to]
    let mut gaps: Vec<(u32, u32)> = Vec::new();
    let mut refused: BTreeSet<u32> = BTreeSet::new();
    let mut groups: BTreeMap<(String, u32, u32), Group> = BTreeMap::new();
    let mut done = 0usize;
    units::par_ordered(&list, a.jobs, 4 * a.jobs.max(1), load, |i, ur| {
        refused.extend(ur.refused.iter().copied());
        let mut first_in_unit = true;
        for r in ur.rows {
            match &prev {
                None => open_end = Some((r.seq, hex::encode(&r.prev))),
                Some((ps, ph)) => {
                    if r.seq <= *ps {
                        dups += 1;
                        if dup_ex.len() < EXAMPLES {
                            dup_ex.push(r.seq);
                        }
                    } else if r.seq == ps + 1 {
                        links += 1;
                        boundary_links += first_in_unit as u64;
                        if r.prev != *ph {
                            mismatch += 1;
                            if mismatch_ex.len() < EXAMPLES {
                                mismatch_ex.push(r.seq);
                            }
                        }
                    } else {
                        gaps.push((ps + 1, r.seq - 1));
                    }
                }
            }
            first_in_unit = false;
            ledgers += 1;
            txs += r.txs;
            let g = groups.entry((r.core, r.applied, r.arm)).or_default();
            if g.ledgers == 0 {
                g.first = r.seq;
            }
            g.ledgers += 1;
            g.txs += r.txs;
            g.last = r.seq;
            for (k, (bit, _)) in BITS.iter().enumerate() {
                if r.inv & bit == 0 {
                    g.off[k] += 1;
                    if g.ex[k].len() < EXAMPLES {
                        g.ex[k].push(r.seq);
                    }
                }
            }
            g.md5_false += (r.md5 == Some(false)) as u64;
            g.md5_none += r.md5.is_none() as u64;
            prev = Some((r.seq, r.hh));
        }
        done += 1;
        if done.is_multiple_of(2000) || done == list.len() {
            eprintln!(
                "[{done}/{}] {} ({:.0} s)",
                list.len(),
                list[i].name(),
                t0.elapsed().as_secs_f64()
            );
        }
        Ok(())
    })?;
    let missing: u64 = gaps.iter().map(|(a, b)| (b - a + 1) as u64).sum();
    let unexplained: u64 = gaps
        .iter()
        .map(|(a, b)| (*a..=*b).filter(|s| !refused.contains(s)).count() as u64)
        .sum();
    let mut t =
        String::from("core\tprotocol_applied\tlcm_arm\tledgers\ttxs\tfirst_ledger\tlast_ledger");
    for (_, n) in BITS {
        t.push_str(&format!("\t{n}"));
    }
    t.push_str("\tmd5_etag_fail\tno_etag");
    for (_, n) in BITS {
        t.push_str(&format!("\t{n}_first{EXAMPLES}"));
    }
    t.push('\n');
    for ((core, p, arm), g) in &groups {
        t.push_str(&format!(
            "{core}\t{p}\tv{arm}\t{}\t{}\t{}\t{}",
            g.ledgers, g.txs, g.first, g.last
        ));
        for k in 0..3 {
            t.push_str(&format!("\t{}", g.off[k]));
        }
        t.push_str(&format!("\t{}\t{}", g.md5_false, g.md5_none));
        for k in 0..3 {
            let v: Vec<String> = g.ex[k].iter().map(|s| s.to_string()).collect();
            t.push_str(&format!(
                "\t{}",
                if v.is_empty() {
                    "-".into()
                } else {
                    v.join(",")
                }
            ));
        }
        t.push('\n');
    }
    units::write_atomic(&a.out.join("chain-groups.tsv"), t.as_bytes())?;
    let mut s = String::new();
    let (lo, hi) = (list[0].first, list.last().unwrap().last);
    writeln!(s, "units\t{}", list.len())?;
    writeln!(s, "unit_range\t{lo}-{hi}")?;
    writeln!(s, "ledgers\t{ledgers}")?;
    writeln!(s, "transactions\t{txs}")?;
    writeln!(s, "refusals\t{}", refused.len())?;
    writeln!(s, "hash_links_checked\t{links}")?;
    writeln!(s, "hash_links_across_units\t{boundary_links}")?;
    writeln!(s, "hash_mismatches\t{mismatch}")?;
    writeln!(s, "hash_mismatch_first{EXAMPLES}\t{mismatch_ex:?}")?;
    writeln!(s, "duplicates_or_out_of_order\t{dups}")?;
    writeln!(s, "duplicate_first{EXAMPLES}\t{dup_ex:?}")?;
    writeln!(s, "gaps\t{}", gaps.len())?;
    writeln!(s, "missing_ledgers\t{missing}")?;
    writeln!(s, "missing_not_refused\t{unexplained}")?;
    writeln!(
        s,
        "gap_first{EXAMPLES}\t{:?}",
        gaps.iter().take(EXAMPLES).collect::<Vec<_>>()
    )?;
    if let Some((seq, ph)) = &open_end {
        writeln!(
            s,
            "open_end\tledger {seq}: prev_hash {ph} (ledger {} is not in the run)",
            seq - 1
        )?;
    }
    writeln!(s, "seconds\t{:.0}", t0.elapsed().as_secs_f64())?;
    units::write_atomic(&a.out.join("chain-summary.txt"), s.as_bytes())?;
    print!("{s}");
    println!();
    print!("{t}");
    let bad = mismatch > 0 || dups > 0 || (!a.allow_gaps && unexplained > 0);
    Ok(if bad {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
