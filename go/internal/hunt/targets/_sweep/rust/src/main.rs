// Rust sweep: the kit's rust target (rs-stellar-xdr) over a list of ledgers, and the reference cut.
// usage:
//   sweep run LIST_TSV ROOT OUT_DIR
//     LIST_TSV rows: seq<TAB>path (absolute, or relative to ROOT) of a zstd LedgerCloseMetaBatch.
//     Checks: codec (decode / re-encode bytes equal), extract (transactions in apply order), json-roundtrip (serde
//     JSON self round trip of envelope, result pair, meta). Writes OUT_DIR/txs/<seq>.jsonl.zst (one row per
//     transaction: seq, idx, hash, env/pair/meta base64, env_json/pair_json/meta_json), OUT_DIR/rows.jsonl (one
//     JSON row per failure), OUT_DIR/stats.jsonl. Resumable: ledgers in OUT_DIR/done.txt are skipped.
//     env SWEEP_PASSPHRASE (default pubnet), SWEEP_VERSION (the version label of the rows).
//   sweep perturb JSONL_ZST N SEED
//     seeded control: N changes of the reference JSON, each must be flagged by the JSON -> XDR re-encode.
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{BufRead, Read, Write};
use std::time::Instant;
use stellar_xdr::*;

const PKG: &str = "stellar-xdr";

fn pass() -> String { std::env::var("SWEEP_PASSPHRASE").unwrap_or_else(|_| "Public Global Stellar Network ; September 2015".into()) }
fn ver() -> String { std::env::var("SWEEP_VERSION").unwrap_or_else(|_| "unknown".into()) }

fn env_hash(env: &TransactionEnvelope, net: [u8; 32]) -> [u8; 32] {
    let tagged = match env {
        TransactionEnvelope::TxV0(e) => {
            let t = &e.tx;
            TransactionSignaturePayloadTaggedTransaction::Tx(Transaction {
                source_account: MuxedAccount::Ed25519(t.source_account_ed25519.clone()),
                fee: t.fee,
                seq_num: t.seq_num.clone(),
                cond: match &t.time_bounds { None => Preconditions::None, Some(tb) => Preconditions::Time(tb.clone()) },
                memo: t.memo.clone(),
                operations: t.operations.clone(),
                ext: TransactionExt::V0,
            })
        }
        TransactionEnvelope::Tx(e) => TransactionSignaturePayloadTaggedTransaction::Tx(e.tx.clone()),
        TransactionEnvelope::TxFeeBump(e) => TransactionSignaturePayloadTaggedTransaction::TxFeeBump(e.tx.clone()),
    };
    let p = TransactionSignaturePayload { network_id: Hash(net), tagged_transaction: tagged };
    Sha256::digest(p.to_xdr(Limits::none()).unwrap()).into()
}

fn gen_envs(g: &GeneralizedTransactionSet, out: &mut Vec<TransactionEnvelope>) {
    let GeneralizedTransactionSet::V1(s) = g;
    for ph in s.phases.iter() {
        match ph {
            TransactionPhase::V0(comps) => for c in comps.iter() {
                let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = c;
                out.extend(c.txs.iter().cloned());
            },
            TransactionPhase::V1(p) => for st in p.execution_stages.iter() { for cl in st.0.iter() { out.extend(cl.0.iter().cloned()); } },
        }
    }
}

// Err = (class, detail)
fn rt<T>(v: &T, bytes: &[u8]) -> Result<serde_json::Value, (String, String)>
where T: serde::Serialize + serde::de::DeserializeOwned + WriteXdr {
    let j = serde_json::to_value(v).map_err(|e| ("to_json-error".to_string(), format!("to_json: {e}")))?;
    let back: T = serde_json::from_value(j.clone()).map_err(|e| (format!("from_json-error:{}", strip(&e.to_string())), format!("from_json: {e}")))?;
    let b2 = back.to_xdr(Limits::none()).map_err(|e| ("re-encode-error".to_string(), format!("re-encode: {e}")))?;
    if b2 != bytes { return Err(("bytes-changed".into(), "json round trip changed bytes".into())); }
    Ok(j)
}

// remove numbers and quoted literals from a message to build a stable class
fn strip(s: &str) -> String {
    let mut o = String::new();
    let mut in_q = false;
    let mut last_n = false;
    for c in s.chars() {
        if c == '`' || c == '"' { if !in_q { o.push_str("<s>"); } in_q = !in_q; continue; }
        if in_q { continue; }
        if c.is_ascii_digit() { if !last_n { o.push('N'); } last_n = true; continue; }
        last_n = false;
        o.push(c);
    }
    o.chars().take(120).collect::<String>().replace(['\t', '\n'], " ")
}

fn read_zst(path: &str) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut d = zstd::stream::read::Decoder::new(f)?;
    let mut v = Vec::new();
    d.read_to_end(&mut v)?;
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
fn stats_line(fin: bool, nled: u64, ntx: u64, nfail: u64, nskip: u64, bytes_out: u64, tr: f64, ta: f64, te: f64, tj: f64, tw: f64, wall: f64) -> String {
    serde_json::json!({"final": fin, "pkg": PKG, "version": ver(), "pid": std::process::id(), "ledgers": nled, "txs": ntx, "failures": nfail, "skipped_done": nskip,
        "jsonl_zst_bytes": bytes_out, "cpu_s": {"read_zstd": tr, "codec": ta, "extract": te, "json_roundtrip": tj, "write_zstd": tw}, "wall_s": wall, "peak_rss_mb": vm_hwm_mb()}).to_string()
}

fn fail(buf: &mut Vec<String>, check: &str, seq: u32, idx: i64, hash: &str, class: &str, detail: &str) {
    let d: String = detail.replace(['\t', '\n'], " ").chars().take(400).collect();
    buf.push(serde_json::json!({"check": check, "class": class, "ledger": seq, "tx": idx, "hash": hash, "op": "", "op_type": "", "detail": d}).to_string());
}

fn empty_txs(outd: &str, seq: u32) {
    let p = format!("{outd}/txs/{seq}.jsonl.zst");
    let e = zstd::stream::write::Encoder::new(std::fs::File::create(format!("{p}.tmp")).unwrap(), 3).unwrap();
    e.finish().unwrap();
    std::fs::rename(format!("{p}.tmp"), p).unwrap();
}

fn vm_hwm_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1)).and_then(|k| k.parse::<f64>().ok())).map(|k| k / 1024.0).unwrap_or(0.0)
}

fn run(a: &[String]) {
    let (list, kept, outd) = (&a[2], &a[3], &a[4]);
    std::fs::create_dir_all(format!("{outd}/txs")).unwrap();
    let net: [u8; 32] = Sha256::digest(pass().as_bytes()).into();
    let done: HashSet<u32> = std::fs::read_to_string(format!("{outd}/done.txt")).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect();
    let open_app = |p: &str| std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
    let mut rows = open_app(&format!("{outd}/rows.jsonl"));
    let mut donef = open_app(&format!("{outd}/done.txt"));
    let mut statf = open_app(&format!("{outd}/stats.jsonl"));
    let (mut t_read, mut t_a, mut t_ext, mut t_json, mut t_write) = (0f64, 0f64, 0f64, 0f64, 0f64);
    let (mut nled, mut ntx, mut nfail, mut nskip, mut bytes_out) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let t0 = Instant::now();
    let mut buf: Vec<String> = Vec::new();
    let inflight = format!("{outd}/inflight");
    let mut done = done;
    if let Ok(s) = std::fs::read_to_string(&inflight) {
        if let Ok(q) = s.trim().parse::<u32>() {
            if !done.contains(&q) {
                fail(&mut buf, "run", q, -1, "", "crash-on-ledger", "previous run died on this ledger; skipped");
                for l in buf.drain(..) { writeln!(rows, "{l}").unwrap(); }
                empty_txs(outd, q);
                writeln!(donef, "{q}").unwrap();
                done.insert(q);
            }
        }
    }
    let f = std::fs::File::open(list).unwrap();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.unwrap();
        let c: Vec<&str> = line.split('\t').collect();
        let Ok(seq0) = c[0].parse::<u32>() else { continue };
        if done.contains(&seq0) { nskip += 1; continue; }
        std::fs::write(&inflight, seq0.to_string()).unwrap();
        let with_json = true;
        let t = Instant::now();
        let raw = match read_zst(&if c[1].starts_with('/') { c[1].to_string() } else { format!("{kept}/{}", c[1]) }) {
            Ok(r) => r,
            Err(e) => { fail(&mut buf, "read", seq0, -1, "", "read-error", &format!("{e}")); nfail += 1; for l in buf.drain(..) { writeln!(rows, "{l}").unwrap(); } empty_txs(outd, seq0); writeln!(donef, "{seq0}").unwrap(); continue; }
        };
        t_read += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let batch = match LedgerCloseMetaBatch::from_xdr(&raw, Limits::none()) {
            Ok(b) => b,
            Err(e) => { fail(&mut buf, "codec", seq0, -1, "", &format!("decode-error:{}", strip(&e.to_string())), &format!("decode: {e}")); nfail += 1;
                for l in buf.drain(..) { writeln!(rows, "{l}").unwrap(); } empty_txs(outd, seq0); writeln!(donef, "{seq0}").unwrap(); continue; }
        };
        if batch.to_xdr(Limits::none()).unwrap() != raw { fail(&mut buf, "codec", seq0, -1, "", "re-encode-differs", "re-encode differs"); nfail += 1; }
        t_a += t.elapsed().as_secs_f64();
        let tmp = format!("{outd}/txs/{seq0}.jsonl.zst.tmp");
        let mut enc = zstd::stream::write::Encoder::new(std::io::BufWriter::new(std::fs::File::create(&tmp).unwrap()), 3).unwrap();
        for lcm in batch.ledger_close_metas.iter() {
            nled += 1;
            let t = Instant::now();
            let mut envs = Vec::new();
            let (seq, procs): (u32, Vec<(&TransactionResultPair, &TransactionMeta)>) = match lcm {
                LedgerCloseMeta::V0(v) => { envs.extend(v.tx_set.txs.iter().cloned());
                    (v.ledger_header.header.ledger_seq, v.tx_processing.iter().map(|p| (&p.result, &p.tx_apply_processing)).collect()) }
                LedgerCloseMeta::V1(v) => { gen_envs(&v.tx_set, &mut envs);
                    (v.ledger_header.header.ledger_seq, v.tx_processing.iter().map(|p| (&p.result, &p.tx_apply_processing)).collect()) }
                LedgerCloseMeta::V2(v) => { gen_envs(&v.tx_set, &mut envs);
                    (v.ledger_header.header.ledger_seq, v.tx_processing.iter().map(|p| (&p.result, &p.tx_apply_processing)).collect()) }
            };
            let by_hash: std::collections::HashMap<[u8; 32], &TransactionEnvelope> = envs.iter().map(|e| (env_hash(e, net), e)).collect();
            if envs.len() != procs.len() { fail(&mut buf, "extract", seq, -1, "", "txset-count-differs", &format!("txset {} envelopes, txProcessing {}", envs.len(), procs.len())); nfail += 1; }
            t_ext += t.elapsed().as_secs_f64();
            for (i, (pair, meta)) in procs.iter().enumerate() {
                ntx += 1;
                let h = hex::encode(pair.transaction_hash.0);
                let Some(env) = by_hash.get(&pair.transaction_hash.0) else { fail(&mut buf, "extract", seq, i as i64, &h, "no-envelope-for-hash", "no envelope with the recorded hash"); nfail += 1; continue; };
                let t = Instant::now();
                let (eb, pb, mb) = (env.to_xdr(Limits::none()).unwrap(), pair.to_xdr(Limits::none()).unwrap(), meta.to_xdr(Limits::none()).unwrap());
                t_ext += t.elapsed().as_secs_f64();
                let t = Instant::now();
                let mut js = Vec::new();
                for (name, r) in [("TransactionEnvelope", rt(*env, &eb)), ("TransactionResultPair", rt(*pair, &pb)), ("TransactionMeta", rt(*meta, &mb))] {
                    match r { Ok(j) => js.push(j), Err((cl, d)) => { fail(&mut buf, "json-roundtrip", seq, i as i64, &h, &format!("{name}:{cl}"), &format!("{name}: {d}")); nfail += 1; js.push(serde_json::Value::Null); } }
                }
                t_json += t.elapsed().as_secs_f64();
                let t = Instant::now();
                use base64::Engine as _;
                let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
                let row = if with_json {
                    serde_json::json!({"seq": seq, "idx": i, "hash": h, "env": b64(&eb), "pair": b64(&pb), "meta": b64(&mb),
                        "env_json": js[0], "pair_json": js[1], "meta_json": js[2]})
                } else {
                    serde_json::json!({"seq": seq, "idx": i, "hash": h, "env": b64(&eb), "pair": b64(&pb), "meta": b64(&mb)})
                };
                serde_json::to_writer(&mut enc, &row).unwrap();
                enc.write_all(b"\n").unwrap();
                t_write += t.elapsed().as_secs_f64();
            }
        }
        let t = Instant::now();
        enc.finish().unwrap().flush().unwrap();
        let fin = format!("{outd}/txs/{seq0}.jsonl.zst");
        std::fs::rename(&tmp, &fin).unwrap();
        bytes_out += std::fs::metadata(&fin).map(|m| m.len()).unwrap_or(0);
        t_write += t.elapsed().as_secs_f64();
        for l in buf.drain(..) { writeln!(rows, "{l}").unwrap(); }
        rows.flush().unwrap();
        writeln!(donef, "{seq0}").unwrap();
        if nled % 200 == 0 { writeln!(statf, "{}", stats_line(false, nled, ntx, nfail, nskip, bytes_out, t_read, t_a, t_ext, t_json, t_write, t0.elapsed().as_secs_f64())).unwrap(); }
    }
    let s = stats_line(true, nled, ntx, nfail, nskip, bytes_out, t_read, t_a, t_ext, t_json, t_write, t0.elapsed().as_secs_f64());
    writeln!(statf, "{s}").unwrap();
    println!("{s}");
}

// small deterministic PRNG (xorshift64*)
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { self.0 ^= self.0 >> 12; self.0 ^= self.0 << 25; self.0 ^= self.0 >> 27; self.0.wrapping_mul(0x2545F4914F6CDD1D) } }

fn leaves(v: &serde_json::Value, path: &mut Vec<serde_json::Value>, out: &mut Vec<Vec<serde_json::Value>>) {
    match v {
        serde_json::Value::Object(m) => for (k, x) in m { path.push(serde_json::Value::String(k.clone())); leaves(x, path, out); path.pop(); },
        serde_json::Value::Array(a) => for (i, x) in a.iter().enumerate() { path.push(serde_json::Value::from(i)); leaves(x, path, out); path.pop(); },
        serde_json::Value::Null => {}
        _ => out.push(path.clone()),
    }
}
fn at<'a>(v: &'a mut serde_json::Value, p: &[serde_json::Value]) -> &'a mut serde_json::Value {
    let mut cur = v;
    for k in p { cur = match k { serde_json::Value::String(s) => cur.get_mut(s.as_str()).unwrap(), _ => cur.get_mut(k.as_u64().unwrap() as usize).unwrap() }; }
    cur
}
// mutate a leaf: numbers ^1, numeric strings ^1, hex strings change the first nibble, other strings change the last
// character, booleans negate
fn mutate(x: &mut serde_json::Value) -> String {
    use serde_json::Value as V;
    let before = x.to_string();
    *x = match x.clone() {
        V::Bool(b) => V::Bool(!b),
        V::Number(n) => if let Some(u) = n.as_u64() { V::from(u ^ 1) } else if let Some(i) = n.as_i64() { V::from(i ^ 1) } else { V::from(n.as_f64().unwrap() + 1.0) },
        V::String(s) => {
            if let Ok(i) = s.parse::<i128>() { V::String((i ^ 1).to_string()) }
            else if !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) { let mut c: Vec<char> = s.chars().collect(); c[0] = if c[0] == '0' { '1' } else { '0' }; V::String(c.into_iter().collect()) }
            else { let mut c: Vec<char> = s.chars().collect(); if let Some(l) = c.last_mut() { *l = if *l == 'A' { 'B' } else { 'A' }; } else { c.push('A'); } V::String(c.into_iter().collect()) }
        }
        o => o,
    };
    format!("{before} -> {x}")
}

fn perturb(a: &[String]) {
    let (path, n, seed) = (&a[2], a[3].parse::<usize>().unwrap(), a[4].parse::<u64>().unwrap());
    let rows: Vec<serde_json::Value> = String::from_utf8(read_zst(path).unwrap()).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let mut rng = Rng(seed | 1);
    let mut used = HashSet::new();
    let (mut flagged, mut tried) = (0, 0);
    while tried < n {
        let r = (rng.next() % rows.len() as u64) as usize;
        let o = (rng.next() % 3) as usize;
        if !used.insert((r, o)) { continue; }
        let (jk, bk) = [("env_json", "env"), ("pair_json", "pair"), ("meta_json", "meta")][o];
        let mut j = rows[r][jk].clone();
        let mut ls = Vec::new();
        leaves(&j, &mut Vec::new(), &mut ls);
        if ls.is_empty() { continue; }
        let p = ls[(rng.next() % ls.len() as u64) as usize].clone();
        let what = mutate(at(&mut j, &p));
        use base64::Engine as _;
        let orig = base64::engine::general_purpose::STANDARD.decode(rows[r][bk].as_str().unwrap()).unwrap();
        let res: Result<Vec<u8>, String> = match o {
            0 => serde_json::from_value::<TransactionEnvelope>(j).map_err(|e| e.to_string()).and_then(|v| v.to_xdr(Limits::none()).map_err(|e| e.to_string())),
            1 => serde_json::from_value::<TransactionResultPair>(j).map_err(|e| e.to_string()).and_then(|v| v.to_xdr(Limits::none()).map_err(|e| e.to_string())),
            _ => serde_json::from_value::<TransactionMeta>(j).map_err(|e| e.to_string()).and_then(|v| v.to_xdr(Limits::none()).map_err(|e| e.to_string())),
        };
        let hit = match &res { Err(_) => true, Ok(b) => *b != orig };
        tried += 1;
        if hit { flagged += 1; }
        let ps: Vec<String> = p.iter().map(|x| x.to_string().trim_matches('"').to_string()).collect();
        println!("{}\t{}\t{}\t{}\t{}\t{}", rows[r]["idx"], jk, ps.join("."), what.chars().take(120).collect::<String>(), if hit { "flagged" } else { "MISSED" },
            match &res { Err(e) => format!("error: {}", e.chars().take(80).collect::<String>()), Ok(_) => "bytes".into() });
    }
    println!("TOTAL\t{flagged} of {tried} flagged");
}


// ---- fields (xcheck): what the crate states about each transaction of the reference cut, as JSONL.
// usage: sweep fields LIST_TSV TXS_DIR OUT_JSONL. Hash from the crate's TransactionEnvelope::hash, strkeys from its
// Display impls; amounts are stroops written as 7-decimal text (our formatting), assets as CODE:ISSUER.
fn amt(v: i64) -> String { let s = if v < 0 { "-" } else { "" }; let a = v.unsigned_abs(); format!("{s}{}.{:07}", a / 10_000_000, a % 10_000_000) }
fn code(b: &[u8]) -> String { let n = b.iter().rposition(|c| *c != 0).map(|i| i + 1).unwrap_or(0); String::from_utf8_lossy(&b[..n]).into_owned() }
fn asset_s(a: &Asset) -> String {
    match a {
        Asset::Native => "native".into(),
        Asset::CreditAlphanum4(x) => format!("{}:{}", code(&x.asset_code.0), x.issuer),
        Asset::CreditAlphanum12(x) => format!("{}:{}", code(&x.asset_code.0), x.issuer),
    }
}
fn xhex<T: WriteXdr>(v: &T) -> String { hex::encode(v.to_xdr(Limits::none()).unwrap_or_default()) }
fn op_fields(op: &Operation) -> serde_json::Value {
    use serde_json::json;
    let mut o = serde_json::Map::new();
    o.insert("type".into(), json!(op.body.name()));
    if let Some(s) = &op.source_account { o.insert("source".into(), json!(s.to_string())); }
    let mut put = |k: &str, v: serde_json::Value| { o.insert(k.into(), v); };
    match &op.body {
        OperationBody::CreateAccount(x) => { put("destination", json!(x.destination.to_string())); put("amount", json!(amt(x.starting_balance))); }
        OperationBody::Payment(x) => { put("destination", json!(x.destination.to_string())); put("amount", json!(amt(x.amount))); put("asset", json!(asset_s(&x.asset))); }
        OperationBody::PathPaymentStrictReceive(x) => { put("destination", json!(x.destination.to_string())); put("send_asset", json!(asset_s(&x.send_asset))); put("send_max", json!(amt(x.send_max))); put("dest_asset", json!(asset_s(&x.dest_asset))); put("dest_amount", json!(amt(x.dest_amount))); }
        OperationBody::PathPaymentStrictSend(x) => { put("destination", json!(x.destination.to_string())); put("send_asset", json!(asset_s(&x.send_asset))); put("send_amount", json!(amt(x.send_amount))); put("dest_asset", json!(asset_s(&x.dest_asset))); put("dest_min", json!(amt(x.dest_min))); }
        OperationBody::ManageSellOffer(x) => { put("selling", json!(asset_s(&x.selling))); put("buying", json!(asset_s(&x.buying))); put("amount", json!(amt(x.amount))); put("price", json!(format!("{}/{}", x.price.n, x.price.d))); put("offer_id", json!(x.offer_id.to_string())); }
        OperationBody::ManageBuyOffer(x) => { put("selling", json!(asset_s(&x.selling))); put("buying", json!(asset_s(&x.buying))); put("amount", json!(amt(x.buy_amount))); put("price", json!(format!("{}/{}", x.price.n, x.price.d))); put("offer_id", json!(x.offer_id.to_string())); }
        OperationBody::CreatePassiveSellOffer(x) => { put("selling", json!(asset_s(&x.selling))); put("buying", json!(asset_s(&x.buying))); put("amount", json!(amt(x.amount))); put("price", json!(format!("{}/{}", x.price.n, x.price.d))); }
        OperationBody::ChangeTrust(x) => {
            match &x.line { ChangeTrustAsset::Native => put("asset", json!("native")), ChangeTrustAsset::CreditAlphanum4(a) => put("asset", json!(format!("{}:{}", code(&a.asset_code.0), a.issuer))), ChangeTrustAsset::CreditAlphanum12(a) => put("asset", json!(format!("{}:{}", code(&a.asset_code.0), a.issuer))), ChangeTrustAsset::PoolShare(_) => {} }
            put("limit", json!(amt(x.limit)));
        }
        OperationBody::SetOptions(x) => {
            if let Some(v) = &x.inflation_dest { put("inflation_dest", json!(v.to_string())); }
            for (k, v) in [("set_flags", x.set_flags), ("clear_flags", x.clear_flags), ("master_weight", x.master_weight), ("low_threshold", x.low_threshold), ("med_threshold", x.med_threshold), ("high_threshold", x.high_threshold)] { if let Some(v) = v { put(k, json!(v.to_string())); } }
            if let Some(h) = &x.home_domain { put("home_domain", json!(String::from_utf8_lossy(h.as_slice()).into_owned())); }
            if let Some(sg) = &x.signer { put("signer_key", json!(sg.key.to_string())); put("signer_weight", json!(sg.weight.to_string())); }
        }
        OperationBody::AllowTrust(x) => { put("trustor", json!(x.trustor.to_string())); }
        OperationBody::AccountMerge(d) => { put("destination", json!(d.to_string())); }
        OperationBody::ManageData(x) => { put("name", json!(String::from_utf8_lossy(x.data_name.as_slice()).into_owned())); put("data_value", x.data_value.as_ref().map(|v| json!(hex::encode(v.as_slice()))).unwrap_or(serde_json::Value::Null)); }
        OperationBody::BumpSequence(x) => { put("bump_to", json!(x.bump_to.0.to_string())); }
        OperationBody::ClaimClaimableBalance(x) => { put("balance_id", json!(xhex(&x.balance_id))); }
        OperationBody::ClawbackClaimableBalance(x) => { put("balance_id", json!(xhex(&x.balance_id))); }
        OperationBody::BeginSponsoringFutureReserves(x) => { put("sponsored_id", json!(x.sponsored_id.to_string())); }
        OperationBody::Clawback(x) => { put("from", json!(x.from.to_string())); put("amount", json!(amt(x.amount))); put("asset", json!(asset_s(&x.asset))); }
        OperationBody::SetTrustLineFlags(x) => { put("trustor", json!(x.trustor.to_string())); put("asset", json!(asset_s(&x.asset))); }
        OperationBody::LiquidityPoolDeposit(x) => { put("liquidity_pool_id", json!(hex::encode(x.liquidity_pool_id.0 .0))); }
        OperationBody::LiquidityPoolWithdraw(x) => { put("liquidity_pool_id", json!(hex::encode(x.liquidity_pool_id.0 .0))); put("amount", json!(amt(x.amount))); }
        _ => {}
    }
    serde_json::Value::Object(o)
}
fn tx_fields(env: &TransactionEnvelope, pair: &str, net: [u8; 32]) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::json;
    let mut row = serde_json::Map::new();
    match env.hash(net) { Ok(h) => { row.insert("hash".into(), json!(hex::encode(h))); } Err(e) => { row.insert("error".into(), json!(format!("hash: {e}"))); return row; } }
    let (src, fee, seq, cond, memo, ops): (String, String, i64, Preconditions, &Memo, &[Operation]) = match env {
        TransactionEnvelope::TxV0(e) => {
            let t = &e.tx;
            (MuxedAccount::Ed25519(t.source_account_ed25519.clone()).to_string(), t.fee.to_string(), t.seq_num.0,
             match &t.time_bounds { None => Preconditions::None, Some(tb) => Preconditions::Time(tb.clone()) }, &t.memo, t.operations.as_slice())
        }
        TransactionEnvelope::Tx(e) => { let t = &e.tx; (t.source_account.to_string(), t.fee.to_string(), t.seq_num.0, t.cond.clone(), &t.memo, t.operations.as_slice()) }
        TransactionEnvelope::TxFeeBump(e) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &e.tx.inner_tx;
            row.insert("fee_source".into(), json!(e.tx.fee_source.to_string()));
            if let Ok(h) = inner.hash(net) { row.insert("inner_hash".into(), json!(hex::encode(h))); }
            let t = &inner.tx;
            (t.source_account.to_string(), e.tx.fee.to_string(), t.seq_num.0, t.cond.clone(), &t.memo, t.operations.as_slice())
        }
    };
    row.insert("source".into(), json!(src));
    row.insert("fee".into(), json!(fee));
    row.insert("seq".into(), json!(seq.to_string()));
    row.insert("op_count".into(), json!(ops.len()));
    row.insert("memo".into(), match memo {
        Memo::None => json!({"type": "none"}),
        Memo::Text(t) => json!({"type": "text", "value": String::from_utf8_lossy(t.as_slice()).into_owned()}),
        Memo::Id(i) => json!({"type": "id", "value": i.to_string()}),
        Memo::Hash(h) => json!({"type": "hash", "value": hex::encode(h.0)}),
        Memo::Return(h) => json!({"type": "return", "value": hex::encode(h.0)}),
    });
    let (tb, v2) = match &cond { Preconditions::None => (None, None), Preconditions::Time(t) => (Some(t.clone()), None), Preconditions::V2(v) => (v.time_bounds.clone(), Some(v.clone())) };
    row.insert("time_bounds".into(), match tb { Some(t) if t.min_time.0 != 0 || t.max_time.0 != 0 => json!({"min": t.min_time.0.to_string(), "max": t.max_time.0.to_string()}), _ => serde_json::Value::Null });
    if let Some(v) = v2 {
        if let Some(lb) = &v.ledger_bounds { row.insert("ledger_bounds".into(), json!(format!("{}-{}", lb.min_ledger, lb.max_ledger))); }
        if let Some(m) = &v.min_seq_num { row.insert("min_seq_num".into(), json!(m.0.to_string())); }
        row.insert("min_seq_age".into(), json!(v.min_seq_age.0.to_string()));
        row.insert("min_seq_ledger_gap".into(), json!(v.min_seq_ledger_gap.to_string()));
        if !v.extra_signers.is_empty() { row.insert("extra_signers".into(), json!(v.extra_signers.iter().map(|k| k.to_string()).collect::<Vec<_>>())); }
    }
    row.insert("operations".into(), serde_json::Value::Array(ops.iter().map(op_fields).collect()));
    match TransactionResultPair::from_xdr_base64(pair, Limits::none()) {
        Ok(p) => { row.insert("fee_charged".into(), json!(p.result.fee_charged.to_string())); }
        Err(e) => { row.insert("fee_charged".into(), json!(format!("error: {e}"))); }
    }
    row
}
fn fields(a: &[String]) {
    let (list, txs, out) = (&a[2], &a[3], &a[4]);
    let net: [u8; 32] = Sha256::digest(pass().as_bytes()).into();
    let mut w = std::io::BufWriter::new(std::fs::File::create(out).expect("create out"));
    for line in std::fs::read_to_string(list).expect("list").lines() {
        let seq = line.split('\t').next().unwrap_or("");
        if seq.is_empty() || !seq.bytes().all(|c| c.is_ascii_digit()) { continue; }
        let raw = read_zst(&format!("{txs}/{seq}.jsonl.zst")).unwrap_or_default();
        for l in String::from_utf8_lossy(&raw).lines() {
            if l.trim().is_empty() { continue; }
            let r: serde_json::Value = serde_json::from_str(l).expect("cut row");
            let mut row = match TransactionEnvelope::from_xdr_base64(r["env"].as_str().unwrap_or(""), Limits::none()) {
                Ok(env) => tx_fields(&env, r["pair"].as_str().unwrap_or(""), net),
                Err(e) => { let mut m = serde_json::Map::new(); m.insert("error".into(), serde_json::json!(format!("decode: {e}"))); m }
            };
            if row.get("error").is_none() {
                // sha256 (12 hex) of the serde JSON (sorted keys, compact) of envelope, result pair and meta
                fn jd<T: ReadXdr + serde::Serialize>(b: &str) -> serde_json::Value {
                    match T::from_xdr_base64(b, Limits::none()) {
                        Ok(v) => match serde_json::to_value(&v) { Ok(j) => serde_json::json!(hex::encode(&Sha256::digest(j.to_string().as_bytes())[..6])), Err(e) => serde_json::json!(format!("error: {e}")) },
                        Err(e) => serde_json::json!(format!("error: {e}")),
                    }
                }
                row.insert("json".into(), serde_json::json!({"env": jd::<TransactionEnvelope>(r["env"].as_str().unwrap_or("")), "pair": jd::<TransactionResultPair>(r["pair"].as_str().unwrap_or("")), "meta": jd::<TransactionMeta>(r["meta"].as_str().unwrap_or(""))}));
            }
            row.insert("ledger".into(), r["seq"].clone());
            row.insert("tx".into(), r["idx"].clone());
            writeln!(w, "{}", serde_json::Value::Object(row)).expect("write");
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("run") => run(&a),
        Some("perturb") => perturb(&a),
        Some("fields") => fields(&a),
        _ => { eprintln!("usage: sweep run LIST_TSV KEPT_DIR OUT_DIR | sweep perturb JSONL_ZST N SEED"); std::process::exit(2); }
    }
}
