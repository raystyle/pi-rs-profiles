#!/usr/bin/env rust-script
//! name: burp_interp
//! description: 拦截代理语义重放件 - 读入原始请求文件(--req,含请求行/头/体,{HOST} 令牌替换为目标主机),按固定序改写(先 --drop-header/--set-header 结构改头,再并入 --jar 同主机 cookie(同名 jar 优先),再 --set-body 换体并重算 Content-Length,最后 --replace 'OLD=>NEW' 对整份序列化请求做原文手术且不再回改 Content-Length),随后作为客户端向目标直连重放,回读响应状态行、全部响应头、体长与体预览,--follow 时按 30x+Location 跟踪至多 5 跳并给出整链;注意:这是客户端侧重放拦截语义(截获→改写→重放→回读),不是 TLS 终止代理;供 essential 扫描题对与 h2-bypass 复用
//! version: 1.0.0
//! args: <url> --req FILE [--set-header 'K: V']... [--drop-header K]... [--replace 'OLD=>NEW']... [--set-body STR] [--jar PATH] [--follow] [--read-ms N] [--preview N] [--selftest]
//! keywords: 漏洞猎手套件, burp, intercept, replay, repeater, rewrite, proxy-semantics, cookie-jar, follow
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

const SLICE_MS: u64 = 3000;
const MAX_FOLLOW: usize = 5;
const REWRITE_CAP: usize = 20_000;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

type Jar = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Default)]
struct Cfg {
    url: String,
    req: String,
    set_headers: Vec<(String, String)>,
    drop_headers: Vec<String>,
    replaces: Vec<(String, String)>,
    set_body: Option<String>,
    jar_path: Option<String>,
    follow: bool,
    read_ms: u64,
    preview: usize,
}

struct Request {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    eof: bool,
    elapsed_ms: u64,
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn connect(host: &str, port: u16, tls: bool) -> Result<Box<dyn ReadWrite>, String> {
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
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

fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    for needle in [b"\r\n\r\n".as_slice(), b"\n\n".as_slice()] {
        if let Some(p) = raw.windows(needle.len()).position(|w| w == needle) {
            return (&raw[..p], &raw[p + needle.len()..]);
        }
    }
    (raw, &[][..])
}

fn find_sub(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn parse_request(raw: &[u8]) -> Result<Request, String> {
    let (head, body) = split_head(raw);
    let text = String::from_utf8_lossy(head);
    let sep = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines = text.split(sep);
    let line = lines.next().unwrap_or("").trim().to_string();
    if line.is_empty() {
        return Err("request file has no request line".to_string());
    }
    let mut headers = Vec::new();
    for l in lines {
        let l = l.trim_end_matches('\r');
        if l.is_empty() {
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Request { line, headers, body: body.to_vec() })
}

fn serialize(req: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(req.line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (k, v) in &req.headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn drop_header(req: &mut Request, name: &str) -> bool {
    let before = req.headers.len();
    req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    before != req.headers.len()
}

fn set_header(req: &mut Request, name: &str, value: &str) {
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case(name) {
            h.0 = name.to_string();
            h.1 = value.to_string();
            return;
        }
    }
    req.headers.push((name.to_string(), value.to_string()));
}

fn split_cookie(raw: &str) -> Option<(String, String)> {
    let first = raw.split(';').next()?.trim();
    let (k, v) = first.split_once('=')?;
    Some((k.trim().to_string(), v.trim().to_string()))
}

fn parse_cookie_header(value: &str) -> Vec<(String, String)> {
    value.split(';').filter_map(split_cookie).collect()
}

fn jar_pairs(jar: &Jar, host: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (h, cookies) in jar {
        if host == h || host.ends_with(&format!(".{h}")) || h.ends_with(host) {
            for (k, v) in cookies {
                out.push((k.clone(), v.clone()));
            }
        }
    }
    out
}

/// Jar wins on a name conflict: it is the live session store, the file is a
/// stale capture. Returns the cookie names the jar contributed.
fn merge_jar_cookies(req: &mut Request, jar: &Jar, host: &str) -> Vec<String> {
    let pairs = jar_pairs(jar, host);
    if pairs.is_empty() {
        return Vec::new();
    }
    let mut merged: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| parse_cookie_header(v))
        .collect();
    req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
    let mut touched = Vec::new();
    for (k, v) in pairs {
        if let Some(idx) = merged.iter().position(|(n, _)| *n == k) {
            merged[idx].1 = v;
        } else {
            merged.push((k.clone(), v));
        }
        touched.push(k);
    }
    let value = merged.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    if !value.is_empty() {
        req.headers.push(("Cookie".to_string(), value));
    }
    touched
}

fn apply_setcookies(jar: &mut Jar, host: &str, pairs: &[(String, String)]) -> bool {
    if pairs.is_empty() {
        return false;
    }
    let key = jar
        .keys()
        .find(|h| **h == host || host.ends_with(&format!(".{h}")) || h.ends_with(host))
        .cloned()
        .unwrap_or_else(|| host.to_string());
    let entry = jar.entry(key).or_default();
    for (k, v) in pairs {
        entry.insert(k.clone(), v.clone());
    }
    true
}

fn load_jar(path: &str) -> Jar {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| pi_rust_lib::serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| match v {
            Value::Object(hosts) => Some(
                hosts
                    .into_iter()
                    .map(|(h, c)| {
                        let map = c
                            .as_object()
                            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                            .unwrap_or_default();
                        (h, map)
                    })
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

fn save_jar(path: &str, jar: &Jar) -> bool {
    match pi_rust_lib::serde_json::to_string(jar) {
        Ok(text) => std::fs::write(path, text).is_ok(),
        Err(_) => false,
    }
}

fn response_complete(buf: &[u8]) -> bool {
    if !find_sub(buf, b"\r\n\r\n") {
        return false;
    }
    let (head, body) = split_head(buf);
    let text = String::from_utf8_lossy(head);
    if !text.starts_with("HTTP/") {
        return false;
    }
    let mut cl: Option<usize> = None;
    let mut chunked = false;
    for l in text.split("\r\n").skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("content-length") {
                cl = v.trim().parse().ok();
            }
            if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    if chunked {
        return body.starts_with(b"0\r\n\r\n") || find_sub(body, b"\r\n0\r\n\r\n");
    }
    if let Some(n) = cl {
        return body.len() >= n;
    }
    false
}

fn read_response<S: Read>(s: &mut S, window_ms: u64) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    let start = Instant::now();
    let mut last = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                last = Instant::now();
                if response_complete(&out) {
                    return (out, false);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if !out.is_empty() && last.elapsed() >= Duration::from_millis(900) {
                    return (out, false);
                }
                if start.elapsed() >= Duration::from_millis(window_ms) {
                    return (out, false);
                }
            }
            Err(_) => return (out, true),
        }
        if start.elapsed() >= Duration::from_millis(window_ms) {
            return (out, false);
        }
    }
}

fn parse_response(raw: &[u8], eof: bool, elapsed_ms: u64) -> Response {
    let (head, body) = split_head(raw);
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Response { status, reason, headers, body: body.to_vec(), eof, elapsed_ms }
}

fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos >= body.len() {
            return None;
        }
        let rel = body[pos..].windows(2).position(|w| w == b"\r\n")?;
        let size_txt = String::from_utf8_lossy(&body[pos..pos + rel]).into_owned();
        let size_str = size_txt.split(';').next()?.trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        pos += rel + 2;
        if size == 0 {
            return Some(out);
        }
        if pos + size > body.len() {
            return None;
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if body.len() >= pos + 2 && &body[pos..pos + 2] == b"\r\n" {
            pos += 2;
        }
    }
}

fn send_and_read(host: &str, port: u16, tls: bool, bytes: &[u8], read_ms: u64) -> Result<Response, String> {
    let mut stream = connect(host, port, tls)?;
    stream.write_all(bytes).map_err(|e| format!("send: {e}"))?;
    let _ = stream.flush();
    let t = Instant::now();
    let (raw, eof) = read_response(&mut stream, read_ms);
    if raw.is_empty() && !eof {
        return Err(format!("no response within {read_ms}ms"));
    }
    Ok(parse_response(&raw, eof, t.elapsed().as_millis() as u64))
}

fn hop_value(url: &str, resp: &Response, preview: usize) -> Value {
    let chunked = header_value(&resp.headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let decoded = if chunked { decode_chunked(&resp.body).unwrap_or_else(|| resp.body.clone()) } else { resp.body.clone() };
    json!({
        "url": url,
        "status": resp.status,
        "reason": resp.reason,
        "location": header_value(&resp.headers, "location").unwrap_or(""),
        "headers": resp.headers.iter().map(|(k, v)| json!({"name": k, "value": v})).collect::<Vec<_>>(),
        "set_cookies": resp.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.clone()).collect::<Vec<_>>(),
        "chunked": chunked,
        "body_bytes": decoded.len(),
        "body_bytes_raw": resp.body.len(),
        "body_preview": String::from_utf8_lossy(&decoded).chars().take(preview).collect::<String>(),
        "eof": resp.eof,
        "elapsed_ms": resp.elapsed_ms,
    })
}

fn run(cfg: &Cfg) -> Result<Value, String> {
    let parsed = Url::parse(&cfg.url).map_err(|e| format!("bad url {}: {e}", cfg.url))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme {scheme}; want http or https"));
    }
    let host = parsed.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        return Err("url has no host".to_string());
    }
    let tls = scheme == "https";
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });

    let raw = std::fs::read(&cfg.req).map_err(|e| format!("read --req {}: {e}", cfg.req))?;
    let text = String::from_utf8_lossy(&raw).replace("{HOST}", &host);
    let mut req = parse_request(text.as_bytes())?;

    let mut jar: Jar = cfg.jar_path.as_deref().map(load_jar).unwrap_or_default();

    // 1. structural header rules
    let mut dropped: Vec<String> = Vec::new();
    for name in &cfg.drop_headers {
        if drop_header(&mut req, name) {
            dropped.push(name.clone());
        }
    }
    let mut set: Vec<String> = Vec::new();
    for (k, v) in &cfg.set_headers {
        set_header(&mut req, k, v);
        set.push(k.clone());
    }

    // 2. jar cookies (an explicit Cookie drop wins over the jar)
    let cookie_dropped = cfg.drop_headers.iter().any(|d| d.eq_ignore_ascii_case("cookie"));
    let jar_merged = if cookie_dropped { Vec::new() } else { merge_jar_cookies(&mut req, &jar, &host) };

    // 3. body swap, with the Burp-default Content-Length recompute
    let cl_dropped = cfg.drop_headers.iter().any(|d| d.eq_ignore_ascii_case("content-length"));
    if let Some(b) = &cfg.set_body {
        req.body = unescape(b).into_bytes();
        let cl = req.body.len().to_string();
        if !cl_dropped {
            set_header(&mut req, "Content-Length", &cl);
        }
    }

    // 4. raw replaces on the serialized request; no fixups afterwards
    let mut wire = serialize(&req);
    let mut replaced: Vec<Value> = Vec::new();
    for (old, new) in &cfg.replaces {
        let text = String::from_utf8_lossy(&wire).into_owned();
        let occurrences = text.matches(old.as_str()).count();
        wire = text.replace(old.as_str(), new).into_bytes();
        replaced.push(json!({"old": old, "new": new, "occurrences": occurrences}));
    }

    let (wire_head, wire_body) = split_head(&wire);
    let orig_method = String::from_utf8_lossy(wire_head)
        .split("\r\n")
        .next()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("GET")
        .to_string();
    let orig_body = wire_body.to_vec();
    let orig_ctype = header_value(&req.headers, "content-type").map(String::from);

    let started = Instant::now();
    let mut final_resp = send_and_read(&host, port, tls, &wire, cfg.read_ms)?;
    let set0: Vec<(String, String)> = final_resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| split_cookie(v))
        .collect();
    apply_setcookies(&mut jar, &host, &set0);

    let mut current_url = cfg.url.clone();
    let mut chain: Vec<Value> = Vec::new();
    let mut hops = 0usize;
    if cfg.follow {
        chain.push(hop_value(&current_url, &final_resp, cfg.preview));
        loop {
            let loc = header_value(&final_resp.headers, "location").unwrap_or("").to_string();
            let redirect = matches!(final_resp.status, 301 | 302 | 303 | 307 | 308);
            if !redirect || loc.is_empty() || hops >= MAX_FOLLOW {
                break;
            }
            let base = Url::parse(&current_url).map_err(|e| format!("bad current url {current_url}: {e}"))?;
            let next = base.join(&loc).map_err(|e| format!("bad redirect target {loc}: {e}"))?;
            let nhost = next.host_str().unwrap_or("").to_string();
            if nhost.is_empty() {
                break;
            }
            let ntls = next.scheme() == "https";
            let nport = next.port().unwrap_or(if ntls { 443 } else { 80 });
            let keep = matches!(final_resp.status, 307 | 308);
            let (method, body) = if keep { (orig_method.clone(), orig_body.clone()) } else { ("GET".to_string(), Vec::new()) };
            let path = if next.path().is_empty() { "/" } else { next.path() };
            let target = match next.query() {
                Some(q) => format!("{path}?{q}"),
                None => path.to_string(),
            };
            let host_hdr = if (ntls && nport == 443) || (!ntls && nport == 80) { nhost.clone() } else { format!("{nhost}:{nport}") };
            let mut freq = Request { line: format!("{method} {target} HTTP/1.1"), headers: Vec::new(), body };
            freq.headers.push(("Host".to_string(), host_hdr));
            merge_jar_cookies(&mut freq, &jar, &nhost);
            if !freq.body.is_empty() {
                if let Some(ct) = &orig_ctype {
                    set_header(&mut freq, "Content-Type", ct);
                }
                let cl = freq.body.len().to_string();
                set_header(&mut freq, "Content-Length", &cl);
            }
            let fwire = serialize(&freq);
            let resp = send_and_read(&nhost, nport, ntls, &fwire, cfg.read_ms)?;
            let sets: Vec<(String, String)> = resp
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                .filter_map(|(_, v)| split_cookie(v))
                .collect();
            apply_setcookies(&mut jar, &nhost, &sets);
            current_url = next.to_string();
            chain.push(hop_value(&current_url, &resp, cfg.preview));
            final_resp = resp;
            hops += 1;
        }
    }

    let jar_updated = match cfg.jar_path.as_deref() {
        Some(p) => save_jar(p, &jar),
        None => false,
    };

    let rw_text = String::from_utf8_lossy(&wire).into_owned();
    let rw_truncated = rw_text.chars().count() > REWRITE_CAP;
    let rw_out: String = rw_text.chars().take(REWRITE_CAP).collect();

    Ok(json!({
        "url": cfg.url,
        "tls": tls,
        "note": "client-side replay of intercept semantics (intercept -> rewrite -> replay -> read); not a TLS-terminating proxy",
        "rewritten_request": rw_out,
        "rewritten_bytes": wire.len(),
        "rewritten_truncated": rw_truncated,
        "rules_applied": {
            "dropped_headers": dropped,
            "set_headers": set,
            "jar_cookies": jar_merged,
            "body_set": cfg.set_body.is_some(),
            "replaces": replaced,
        },
        "response": hop_value(&current_url, &final_resp, cfg.preview),
        "chain": if cfg.follow { Value::Array(chain) } else { Value::Null },
        "followed": hops,
        "jar_updated": jar_updated,
        "total_elapsed_ms": started.elapsed().as_millis() as u64,
    }))
}

fn arg(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut cfg = Cfg { read_ms: 10_000, preview: 900, ..Default::default() };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--req" => { i += 1; cfg.req = arg(&args, i); }
            "--set-header" => {
                i += 1;
                match arg(&args, i).split_once(':') {
                    Some((k, v)) if !k.trim().is_empty() => cfg.set_headers.push((k.trim().to_string(), v.trim().to_string())),
                    _ => {
                        pi_rust_lib::report::failure("burp_interp", "bad --set-header, want 'K: V'", "quote the pair: --set-header 'X-Scan: 1'");
                        std::process::exit(2);
                    }
                }
            }
            "--drop-header" => { i += 1; cfg.drop_headers.push(arg(&args, i)); }
            "--replace" => {
                i += 1;
                match arg(&args, i).split_once("=>") {
                    Some((o, n)) if !o.is_empty() => cfg.replaces.push((o.to_string(), n.to_string())),
                    _ => {
                        pi_rust_lib::report::failure("burp_interp", "bad --replace, want 'OLD=>NEW' with non-empty OLD", "quote the pair: --replace 'http=>https'");
                        std::process::exit(2);
                    }
                }
            }
            "--set-body" => { i += 1; cfg.set_body = Some(arg(&args, i)); }
            "--jar" => { i += 1; cfg.jar_path = Some(arg(&args, i)); }
            "--follow" => cfg.follow = true,
            "--read-ms" => { i += 1; cfg.read_ms = arg(&args, i).parse().unwrap_or(10_000); }
            "--preview" => { i += 1; cfg.preview = arg(&args, i).parse().unwrap_or(900); }
            other if !other.starts_with("--") && cfg.url.is_empty() => cfg.url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if cfg.url.is_empty() || cfg.req.is_empty() {
        pi_rust_lib::report::failure("burp_interp", "usage", "burp_interp <url> --req FILE [--set-header 'K: V']... [--drop-header K]... [--replace 'OLD=>NEW']... [--set-body STR] [--jar PATH] [--follow]");
        std::process::exit(2);
    }
    match run(&cfg) {
        Ok(v) => pi_rust_lib::report::success(
            "burp_interp",
            v,
            "data.rewritten_request is the exact wire text sent; data.response is the final hop and data.chain the redirect chain under --follow; the --jar file now holds the session for the next replay",
        )
        .unwrap_or(()),
        Err(e) => {
            pi_rust_lib::report::failure("burp_interp", &e, "check the url scheme/host, the --req path, and rule syntax ('K: V' / 'OLD=>NEW')");
            std::process::exit(1);
        }
    }
}

// ---- selftest ----

fn mock_complete(buf: &[u8]) -> bool {
    if !find_sub(buf, b"\r\n\r\n") {
        return false;
    }
    let (head, body) = split_head(buf);
    let text = String::from_utf8_lossy(head);
    let mut cl = 0usize;
    for l in text.split("\r\n").skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                cl = v.trim().parse().unwrap_or(0);
            }
        }
    }
    body.len() >= cl
}

fn mock_read(stream: &mut TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if mock_complete(&buf) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn selftest() {
    let parsed = parse_request(b"POST /p HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\nxy");
    let parse_ok = parsed
        .as_ref()
        .map(|r| r.line == "POST /p HTTP/1.1" && r.headers.len() == 2 && r.body == b"xy")
        .unwrap_or(false);
    let mut r = parsed.unwrap_or(Request { line: String::new(), headers: Vec::new(), body: Vec::new() });
    let drop_ok = drop_header(&mut r, "x-a") && !r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-a"));
    set_header(&mut r, "x-a", "2");
    set_header(&mut r, "X-A", "3");
    let set_ok = r.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("x-a")).count() == 1 && header_value(&r.headers, "x-a") == Some("3");
    let rep_ok = "a=>b=>c".split_once("=>") == Some(("a", "b=>c"));
    let mut jar_u: Jar = BTreeMap::new();
    jar_u.insert("h.example".to_string(), [("session".to_string(), "new".to_string())].into_iter().collect());
    let merge_ok = match parse_request(b"GET / HTTP/1.1\r\nHost: h.example\r\nCookie: session=old; a=1\r\n\r\n") {
        Ok(mut r3) => {
            let touched = merge_jar_cookies(&mut r3, &jar_u, "h.example");
            header_value(&r3.headers, "cookie") == Some("session=new; a=1") && touched == vec!["session".to_string()]
        }
        Err(_) => false,
    };
    let chunk_ok = decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n".as_slice()) == Some(b"Wikipedia".to_vec());
    let complete_ok = response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        && !response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi");

    // Live replay against a 127.0.0.1 mock: rewrite -> replay -> 302 -> follow -> jar.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().expect("mock addr").port();
    let server = std::thread::spawn(move || {
        let mut second = String::new();
        listener.set_nonblocking(true).ok();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut hop = 0;
        while hop < 2 && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(4000)));
                    let got = mock_read(&mut s);
                    if hop == 0 {
                        let ok = got.starts_with("POST /submit2 ")
                            && got.contains("X-New: yes")
                            && !got.contains("X-Old")
                            && got.contains("Content-Length: 3")
                            && got.ends_with("abc");
                        let marker = if ok { "rewrite-ok" } else { "rewrite-bad" };
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: /final\r\nSet-Cookie: sid=abc; Path=/\r\nX-Rewrite: {marker}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = s.write_all(resp.as_bytes());
                    } else {
                        let cookie_ok = got.contains("sid=abc");
                        second = got;
                        let body = "hello final";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Cookie-Ok: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            cookie_ok,
                            body
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    hop += 1;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(15)),
                Err(_) => break,
            }
        }
        second
    });

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let req_path = dir.join(format!("burp_interp_selftest_{pid}.req"));
    let jar_path = dir.join(format!("burp_interp_selftest_{pid}.jar"));
    let _ = std::fs::remove_file(&jar_path);
    let wrote = std::fs::write(&req_path, "POST /submit HTTP/1.1\r\nHost: {HOST}\r\nX-Old: 1\r\nContent-Length: 4\r\n\r\njunk").is_ok();

    let cfg = Cfg {
        url: format!("http://127.0.0.1:{port}/"),
        req: req_path.to_string_lossy().to_string(),
        set_headers: vec![("X-New".to_string(), "yes".to_string())],
        drop_headers: vec!["X-Old".to_string()],
        replaces: vec![("submit".to_string(), "submit2".to_string())],
        set_body: Some("abc".to_string()),
        jar_path: Some(jar_path.to_string_lossy().to_string()),
        follow: true,
        read_ms: 4_000,
        preview: 200,
    };
    let outcome = run(&cfg);
    let second = server.join().unwrap_or_default();

    let mut integ = false;
    let mut final_status = Value::Null;
    if let Ok(d) = &outcome {
        final_status = d["response"]["status"].clone();
        let hdr_has = |hop: &Value, name: &str, val: &str| {
            hop["headers"]
                .as_array()
                .map(|hs| {
                    hs.iter().any(|h| {
                        h["name"].as_str().unwrap_or("").eq_ignore_ascii_case(name) && h["value"].as_str().unwrap_or("").contains(val)
                    })
                })
                .unwrap_or(false)
        };
        let rw = d["rewritten_request"].as_str().unwrap_or("");
        let chain_len = d["chain"].as_array().map(|c| c.len()).unwrap_or(0);
        let hop0_ok = chain_len >= 1 && hdr_has(&d["chain"][0], "x-rewrite", "rewrite-ok");
        let final_ok = d["response"]["status"].as_u64() == Some(200)
            && d["response"]["body_preview"].as_str().unwrap_or("") == "hello final"
            && hdr_has(&d["response"], "x-cookie-ok", "true");
        let jar_txt = std::fs::read_to_string(&jar_path).unwrap_or_default();
        integ = wrote
            && rw.contains("POST /submit2 ")
            && rw.contains("X-New: yes")
            && !rw.contains("X-Old")
            && rw.contains("Content-Length: 3")
            && rw.ends_with("abc")
            && d["followed"].as_u64() == Some(1)
            && chain_len == 2
            && hop0_ok
            && final_ok
            && second.starts_with("GET /final ")
            && second.contains("sid=abc")
            && jar_txt.contains("\"sid\"")
            && jar_txt.contains("abc");
    }

    let _ = std::fs::remove_file(&req_path);
    let _ = std::fs::remove_file(&jar_path);

    let receipt = parse_ok && drop_ok && set_ok && rep_ok && merge_ok && chunk_ok && complete_ok && integ;
    let data = json!({
        "selftest": if receipt { "ok" } else { "fail" },
        "parse": parse_ok,
        "drop_header": drop_ok,
        "set_header": set_ok,
        "replace_split": rep_ok,
        "jar_merge": merge_ok,
        "chunked_decode": chunk_ok,
        "response_complete": complete_ok,
        "mock_replay_follow_jar": integ,
        "mock_port": port,
        "final_status": final_status,
    });
    if receipt {
        pi_rust_lib::report::success("burp_interp", data, "selftest passed against a 127.0.0.1 mock; run against the real target with --req and rewrite rules").expect("report");
    } else {
        pi_rust_lib::report::failure("burp_interp", &format!("selftest failed: {data}"), "inspect the failing assertion flags");
        std::process::exit(1);
    }
}
