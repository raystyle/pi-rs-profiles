#!/usr/bin/env rust-script
//! name: duphost_probe
//! description: 双 Host 表达探针(重复头表达前置判) - 单条 TCP/TLS 连接上发一份携带两条调用方自定义头行(--h1/--h2,典型即两个 Host 头)的原始请求,读完整响应并判定边缘如何处置重复头:rejected-400(400 且文本言 duplicate)/ first-wins / second-wins(恰一个值被回显)/ both-reflected(两值都被回显;仅在经 {REFLECT} 令牌嵌入 --reflect 金丝雀时才判此型,短值不会假阳)/ other(附原始响应头与体前 400 字节)。--repeat N 换新连接复打并报告判定稳定性,作为 ambiguous-request 缓存投毒的前置测试:客户端到底能不能表达两个 Host,边缘留哪个。
//! version: 1.0.0
//! args: <url> --h1 'Host: a' --h2 'Host: b' [--path /] [--reflect STR] [--repeat N] [--read-ms N] [--selftest]
//! keywords: 漏洞猎手套件, duplicate-host, host-header, 双头, 重复头, 表达探针, ambiguous-request, cache-poisoning, prior, first-wins, second-wins
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const SLICE_MS: u64 = 1500;
const REFLECT_TOKEN: &str = "{REFLECT}";

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn connect(host: &str, port: u16, tls: bool) -> Result<Box<dyn ReadWrite>, String> {
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(SLICE_MS)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
    if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls init: {e}"))?;
        Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        Ok(Box::new(tcp))
    }
}

/// Read until EOF or until `window_ms` has elapsed, collecting everything.
/// Non-timeout IO errors surface as Err instead of masquerading as EOF.
fn read_window<S: Read>(s: &mut S, window_ms: u64) -> Result<(Vec<u8>, bool), String> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    let start = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok((out, true)),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if start.elapsed() >= Duration::from_millis(window_ms) {
                    return Ok((out, false));
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
        if start.elapsed() >= Duration::from_millis(window_ms) {
            return Ok((out, false));
        }
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn substitute(s: &str, marker: &str) -> String {
    s.replace(REFLECT_TOKEN, marker)
}

/// Split a `--hN 'Name: Value'` spec at the first colon.
fn parse_header(spec: &str) -> Result<(String, String), String> {
    let (name, value) = spec.split_once(':').ok_or_else(|| format!("header spec '{spec}' lacks a colon"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return Err(format!("header spec '{spec}' has an empty name"));
    }
    if name.contains('\r') || name.contains('\n') || value.contains('\r') || value.contains('\n') {
        return Err(format!("header spec '{spec}' must not contain CR/LF"));
    }
    Ok((name.to_string(), value.to_string()))
}

fn build_request(path: &str, n1: &str, v1: &str, n2: &str, v2: &str) -> Result<String, String> {
    if path.contains('\r') || path.contains('\n') || path.contains(' ') {
        return Err(format!("path '{path}' must not contain CR/LF/spaces (it would split the request line)"));
    }
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    Ok(format!("GET {path} HTTP/1.1\r\n{n1}: {v1}\r\n{n2}: {v2}\r\nConnection: close\r\n\r\n"))
}

fn status_line_of(text: &str) -> String {
    text.lines().find(|l| l.starts_with("HTTP/")).unwrap_or("<no status line>").trim().to_string()
}

fn status_code_of(text: &str) -> Option<u16> {
    text.lines()
        .find(|l| l.starts_with("HTTP/"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
}

/// Split a raw response into head (status line + headers) and the first
/// `body_max` body bytes, both lossy strings.
fn head_body(raw: &[u8], head_max: usize, body_max: usize) -> (String, String) {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let (head, body) = match sep {
        Some(p) => (&raw[..p], &raw[p..]),
        None => (raw, &[][..]),
    };
    let head_len = head.len().min(head_max);
    let body_len = body.len().min(body_max);
    (
        String::from_utf8_lossy(&head[..head_len]).to_string(),
        String::from_utf8_lossy(&body[..body_len]).to_string(),
    )
}

/// Five-class verdict. `canary` means a --reflect marker was embedded in the
/// request, so a both-values match is trustworthy.
fn classify(raw: &[u8], n1: &str, n2: &str, canary: bool) -> (String, String) {
    let text = String::from_utf8_lossy(raw);
    if status_code_of(&text) == Some(400) && text.to_lowercase().contains("duplicate") {
        return ("rejected-400".to_string(), format!("edge refused the duplicate: {}", status_line_of(&text)));
    }
    if n1.is_empty() || n2.is_empty() || n1 == n2 {
        return ("other".to_string(), "header values are empty or identical; first/second cannot be distinguished".to_string());
    }
    let hit1 = text.contains(n1);
    let hit2 = text.contains(n2);
    let (verdict, mut note) = match (hit1, hit2) {
        (true, true) => {
            if canary {
                ("both-reflected", "both values reflected; the canary confirms the endpoint echoes input".to_string())
            } else {
                ("other", "both values matched but no --reflect canary is embedded; re-run with --reflect and the {REFLECT} token to confirm both-reflected".to_string())
            }
        }
        (true, false) => ("first-wins", format!("only the first value '{n1}' was reflected")),
        (false, true) => ("second-wins", format!("only the second value '{n2}' was reflected")),
        (false, false) => ("other", "neither value reflected; the endpoint does not echo input - re-run against a reflecting endpoint with --reflect".to_string()),
    };
    if !canary && (verdict == "first-wins" || verdict == "second-wins") {
        note.push_str("; no --reflect canary, so short values can false-positive");
    }
    (verdict.to_string(), note)
}

#[allow(clippy::too_many_arguments)]
fn probe_once(n: usize, host: &str, port: u16, tls: bool, request: &str, n1: &str, n2: &str, canary: bool, read_ms: u64) -> Result<Value, String> {
    let mut stream = connect(host, port, tls)?;
    let t = Instant::now();
    stream.write_all(request.as_bytes()).map_err(|e| format!("send request: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    let (raw, eof) = read_window(&mut stream, read_ms)?;
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (verdict, note) = classify(&raw, n1, n2, canary);
    let (head, body_head) = head_body(&raw, 2000, 400);
    Ok(json!({
        "attempt": n,
        "status": status_code_of(&text),
        "status_line": status_line_of(&text),
        "verdict": verdict,
        "note": note,
        "canary": canary,
        "elapsed_ms": elapsed_ms,
        "bytes": raw.len(),
        "eof": eof,
        "response_head": head,
        "body_head": body_head,
    }))
}

fn next_hint(verdict: &str) -> String {
    match verdict {
        "rejected-400" => "the edge refuses duplicates - this ambiguous-Host vector is closed; pivot to casing/whitespace ambiguity or absolute-URI tricks".to_string(),
        "first-wins" | "second-wins" => "the client CAN express two Hosts and the winner is known - proceed to ambiguous-request cache poisoning probes with this precedence".to_string(),
        "both-reflected" => "both values reach the application - compare edge-vs-backend Host selection for cache-key confusion".to_string(),
        "mixed" => "verdicts differ across repeats; raise --repeat and --read-ms before trusting any poison attempt".to_string(),
        _ => "inspect response_head/body_head; if nothing reflected, re-run against a reflecting endpoint with --reflect and the {REFLECT} token".to_string(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }

    let mut url = String::new();
    let mut h1 = String::new();
    let mut h2 = String::new();
    let mut path = String::from("/");
    let mut reflect: Option<String> = None;
    let mut repeat: usize = 1;
    let mut read_ms: u64 = 8000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--h1" => { i += 1; if let Some(v) = args.get(i) { h1 = v.clone(); } }
            "--h2" => { i += 1; if let Some(v) = args.get(i) { h2 = v.clone(); } }
            "--path" => { i += 1; if let Some(v) = args.get(i) { path = v.clone(); } }
            "--reflect" => { i += 1; if let Some(v) = args.get(i) { reflect = Some(v.clone()); } }
            "--repeat" => { i += 1; repeat = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(repeat); }
            "--read-ms" => { i += 1; read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms); }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() || h1.is_empty() || h2.is_empty() {
        pi_rust_lib::report::failure("duphost_probe", "usage", "duphost_probe <url> --h1 'Host: a' --h2 'Host: b' [--path /] [--reflect STR] [--repeat N]");
        std::process::exit(2);
    }

    let marker = reflect.clone().unwrap_or_default();
    let parsed = match Url::parse(&url) {
        Ok(u) => u,
        Err(e) => {
            pi_rust_lib::report::failure("duphost_probe", &format!("parse url: {e}"), "give a full http(s):// url");
            std::process::exit(2);
        }
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        pi_rust_lib::report::failure("duphost_probe", "url has no host", "give a full http(s)://host url");
        std::process::exit(2);
    }
    let tls = parsed.scheme() == "https";
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });

    let (n1, v1) = match parse_header(&substitute(&h1, &marker)) {
        Ok(x) => x,
        Err(e) => {
            pi_rust_lib::report::failure("duphost_probe", &e, "header specs look like 'Host: value'");
            std::process::exit(2);
        }
    };
    let (n2, v2) = match parse_header(&substitute(&h2, &marker)) {
        Ok(x) => x,
        Err(e) => {
            pi_rust_lib::report::failure("duphost_probe", &e, "header specs look like 'Host: value'");
            std::process::exit(2);
        }
    };
    let path_final = substitute(&path, &marker);

    let canary = !marker.is_empty() && (path_final.contains(&marker) || v1.contains(&marker) || v2.contains(&marker));
    if !marker.is_empty() && !canary {
        pi_rust_lib::report::failure(
            "duphost_probe",
            "--reflect marker is not embedded anywhere",
            "embed the marker in --path/--h1/--h2 with the {REFLECT} token so both-reflected cannot false-positive",
        );
        std::process::exit(2);
    }

    let request = match build_request(&path_final, &n1, &v1, &n2, &v2) {
        Ok(r) => r,
        Err(e) => {
            pi_rust_lib::report::failure("duphost_probe", &e, "fix --path or the header specs");
            std::process::exit(2);
        }
    };
    let mut attempts: Vec<Value> = Vec::new();
    for n in 1..=repeat.max(1) {
        match probe_once(n, &host, port, tls, &request, &v1, &v2, canary, read_ms) {
            Ok(v) => attempts.push(v),
            Err(e) => {
                pi_rust_lib::report::failure("duphost_probe", &format!("attempt {n}: {e}"), "check host/port, scheme, and that the target speaks plain HTTP/1.1");
                std::process::exit(1);
            }
        }
    }
    let verdicts: Vec<&str> = attempts.iter().filter_map(|a| a["verdict"].as_str()).collect();
    let stable = !verdicts.is_empty() && verdicts.iter().all(|v| *v == verdicts[0]);
    let overall = if stable { verdicts[0].to_string() } else { "mixed".to_string() };
    let next = next_hint(&overall);
    pi_rust_lib::report::success(
        "duphost_probe",
        json!({
            "url": url,
            "host": host,
            "port": port,
            "tls": tls,
            "request": {
                "path": path_final,
                "h1": format!("{n1}: {v1}"),
                "h2": format!("{n2}: {v2}"),
                "reflect_marker": reflect,
                "wire": request,
            },
            "attempts": attempts,
            "stable": stable,
            "verdict": overall,
        }),
        &next,
    )
    .unwrap_or(());
}

/// Accept one connection on 127.0.0.1, record the raw request, answer with the
/// canned response, close. Returns the port and the captured request buffer.
fn mock_once(response: &'static [u8]) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock listener");
    let port = listener.local_addr().expect("mock addr").port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_millis(2000)));
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match s.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if contains_subslice(&buf, b"\r\n\r\n") || buf.len() > 65536 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            *sink.lock().expect("lock captured") = buf;
            let _ = s.write_all(response);
            let _ = s.flush();
        }
    });
    (port, captured)
}

/// Run one selftest scenario: the probe fires at the local mock, then the
/// verdict and the wire shape the mock recorded are checked.
fn scenario(name: &str, response: &'static [u8], h1: &str, h2: &str, path: &str, reflect: Option<&str>, expected: &str) -> Value {
    let (port, captured) = mock_once(response);
    let marker = reflect.unwrap_or("");
    let h1r = substitute(h1, marker);
    let h2r = substitute(h2, marker);
    let path_r = substitute(path, marker);
    let specs = parse_header(&h1r).and_then(|a| parse_header(&h2r).map(|b| (a, b)));
    let out = match specs {
        Ok(((n1, v1), (n2, v2))) => {
            let canary = !marker.is_empty() && (path_r.contains(marker) || v1.contains(marker) || v2.contains(marker));
            let request = match build_request(&path_r, &n1, &v1, &n2, &v2) {
                Ok(r) => r,
                Err(e) => return json!({"scenario": name, "expected": expected, "error": e, "pass": false}),
            };
            probe_once(1, "127.0.0.1", port, false, &request, &v1, &v2, canary, 4000).map(|v| {
                let got = captured.lock().expect("lock captured").clone();
                let got_text = String::from_utf8_lossy(&got).to_string();
                let line1 = format!("{n1}: {v1}");
                let line2 = format!("{n2}: {v2}");
                let order_ok = match (got_text.find(&line1), got_text.find(&line2)) {
                    (Some(a), Some(b)) => a < b,
                    _ => false,
                };
                let want_path = if path_r.starts_with('/') { path_r.clone() } else { format!("/{path_r}") };
                let path_ok = got_text.starts_with(&format!("GET {want_path} HTTP/1.1"));
                let head_ok = v["response_head"].as_str().map(|h| h.starts_with("HTTP/1.1")).unwrap_or(false);
                (v, order_ok && path_ok && head_ok)
            })
        }
        Err(e) => Err(e),
    };
    match out {
        Ok((v, shape_ok)) => {
            let verdict = v["verdict"].as_str().unwrap_or("").to_string();
            let pass = verdict == expected && shape_ok;
            json!({"scenario": name, "expected": expected, "got": verdict, "wire_and_shape_ok": shape_ok, "pass": pass})
        }
        Err(e) => json!({"scenario": name, "expected": expected, "error": e, "pass": false}),
    }
}

fn selftest() {
    let scenarios = vec![
        scenario(
            "reject-400-duplicate",
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDuplicate Host header detected",
            "Host: alpha.example", "Host: beta.example", "/", None, "rejected-400",
        ),
        scenario(
            "first-wins",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nserved by alpha.example only",
            "Host: alpha.example", "Host: beta.example", "/", None, "first-wins",
        ),
        scenario(
            "second-wins",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nvhost beta.example answered",
            "Host: alpha.example", "Host: beta.example", "/", None, "second-wins",
        ),
        scenario(
            "both-reflected-canary",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsaw zzq9-a.example and zzq9-b.example",
            "Host: {REFLECT}-a.example", "Host: {REFLECT}-b.example", "/", Some("zzq9"), "both-reflected",
        ),
        scenario(
            "both-matched-without-canary-gated",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsaw alpha.example and beta.example",
            "Host: alpha.example", "Host: beta.example", "/", None, "other",
        ),
        scenario(
            "no-reflection",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ngeneric landing page",
            "Host: alpha.example", "Host: beta.example", "/", None, "other",
        ),
    ];
    let ok = scenarios.iter().all(|s| s["pass"].as_bool().unwrap_or(false));
    let data = json!({"selftest": if ok { "ok" } else { "fail" }, "scenarios": scenarios});
    if ok {
        pi_rust_lib::report::success("duphost_probe", data, "selftest passed; against real targets embed a --reflect canary via {REFLECT} for a trustworthy both-reflected").unwrap_or(());
        std::process::exit(0);
    }
    pi_rust_lib::report::failure("duphost_probe", "selftest failed", "inspect the scenarios array for the failing case");
    std::process::exit(1);
}
