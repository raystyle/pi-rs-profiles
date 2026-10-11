#!/usr/bin/env rust-script
//! name: targeted_scan
//! description: 定向注入点扫描器 - 请求模板文件(--req,内含 {HOST} 占位与恰好一个 §INJ§ 注入点标记,可在请求行/头/体)×载荷表(--payload 重复或 --payloads-file 每行一个,# 注释与空行跳过,--max 硬帽)逐载荷渲染实发:替换占位后自动重算 Content-Length(注入改变体长时丢弃全部旧 CL 写入唯一新值,模板无 CL 而有体则补;模板携带 Transfer-Encoding 时帧面原样不碰,注入点落在 CL 行内则拒绝),按 --rate-ms 节流逐发射,收 status/体字节数(chunked 解码后)/耗时 ms,与基线(--baseline 指定,缺省首载荷先射作基线)对比分桶:状态翻转(status != baseline)、长度越带(|len-base| > base×--len-tol-pct%)、耗时尾部(> 成功行中位数×--time-factor 且 > 基线×同倍),同因同值归簇;个别载荷网络错记 error 行不中断,基线首射连不上则整件 failure。补 burp_interp 单发重放与 raw_matrix 手工帧矩阵之间的扫描位:给模板给表即出异常簇。
//! version: 1.0.0
//! args: <url> --req FILE [--payload V]... [--payloads-file FILE] [--baseline V] [--rate-ms N] [--len-tol-pct N] [--time-factor F] [--max N] [--read-ms N] [--selftest]
//! keywords: 漏洞猎手套件, targeted-scan, 定向扫描, injection-point, 注入点, payload-table, 载荷表, baseline-diff, anomaly-cluster, status-flip, length-band, timing-tail, auto-content-length
//!
//! ```cargo
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! url = "2"
//! ```

use pi_rust_lib::serde_json::{json, Value};
use pi_rust_lib::timeout;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

const SLICE_MS: u64 = 1500;
/// Injection-point marker inside the --req template; exactly one is required.
const INJ: &str = "§INJ§";

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn arg(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_default()
}

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

/// Payload table from a wordlist file body: one per line, blanks and `#`
/// comments skipped, only the trailing CR stripped.
fn parse_payload_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Template gates, all checked before anything goes on the wire: exactly one
/// injection marker, a header/body split, and the marker must not sit on a
/// Content-Length line (the auto-CL rewrite would silently eat the payload).
fn validate_template(tpl: &str) -> Result<(), String> {
    let n = tpl.matches(INJ).count();
    if n == 0 {
        return Err("template has no injection marker (need exactly one §INJ§)".to_string());
    }
    if n > 1 {
        return Err(format!("template has {n} injection markers; exactly one §INJ§ is required"));
    }
    let head = match tpl.split_once("\r\n\r\n").or_else(|| tpl.split_once("\n\n")) {
        Some((h, _)) => h,
        None => return Err("template has no header/body separator (need a blank line after the headers)".to_string()),
    };
    for l in head.split('\n') {
        let l = l.trim_end_matches('\r');
        if !l.contains(INJ) {
            continue;
        }
        if let Some((k, _)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return Err("the injection marker sits on the Content-Length line; auto Content-Length would drop the payload - move the marker to another header value or the body".to_string());
            }
        }
    }
    Ok(())
}

struct Rendered {
    wire: String,
    cl_mode: &'static str,
}

/// Render one fireable request: substitute {HOST} and the injection marker,
/// then repair framing. Content-Length is recomputed from the post-substitution
/// body: every stale CL line is dropped and one canonical line is written when
/// a body exists or the template carried CL at all. A template carrying
/// Transfer-Encoding keeps its exact head - that framing is deliberate.
fn render(tpl: &str, host: &str, payload: &str) -> Result<Rendered, String> {
    let sub = tpl.replace("{HOST}", host).replace(INJ, payload);
    let (head, body) = match sub.split_once("\r\n\r\n").or_else(|| sub.split_once("\n\n")) {
        Some((h, b)) => (h, b),
        None => return Err("template has no header/body separator (need a blank line after the headers)".to_string()),
    };
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
    let request_line = lines.next().unwrap_or("").trim().to_string();
    if request_line.is_empty() {
        return Err("template has no request line".to_string());
    }
    let hdrs: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    let has_te = hdrs
        .iter()
        .any(|l| l.split_once(':').map(|(k, _)| k.trim().eq_ignore_ascii_case("transfer-encoding")).unwrap_or(false));
    let mut wire = request_line;
    wire.push_str("\r\n");
    let cl_mode;
    if has_te {
        for l in &hdrs {
            wire.push_str(l);
            wire.push_str("\r\n");
        }
        cl_mode = "untouched-te";
    } else {
        let mut had_cl = false;
        for l in &hdrs {
            let is_cl = l.split_once(':').map(|(k, _)| k.trim().eq_ignore_ascii_case("content-length")).unwrap_or(false);
            if is_cl {
                had_cl = true;
                continue;
            }
            wire.push_str(l);
            wire.push_str("\r\n");
        }
        if !body.is_empty() || had_cl {
            wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
            cl_mode = if had_cl { "recomputed" } else { "added" };
        } else {
            cl_mode = "none";
        }
    }
    wire.push_str("\r\n");
    wire.push_str(body);
    Ok(Rendered { wire, cl_mode })
}

struct Fired {
    status: u16,
    len: usize,
    time_ms: u64,
    error: String,
}

/// One exchange: connect, write the rendered wire, read the response window.
/// Errors ride inside the struct so one dead payload never aborts the table.
fn fire(host: &str, port: u16, tls: bool, wire: &str, read_ms: u64) -> Fired {
    let err = |error: String| Fired { status: 0, len: 0, time_ms: 0, error };
    let mut stream = match connect(host, port, tls) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if let Err(e) = stream.write_all(wire.as_bytes()).and_then(|_| stream.flush()) {
        return err(format!("write: {e}"));
    }
    let t = Instant::now();
    let (raw, eof) = read_response(&mut stream, read_ms);
    let time_ms = t.elapsed().as_millis() as u64;
    if raw.is_empty() {
        let why = if eof { "connection closed with no response".to_string() } else { format!("no response within {read_ms}ms") };
        return Fired { status: 0, len: 0, time_ms, error: why };
    }
    let (head, body) = split_head(&raw);
    let text = String::from_utf8_lossy(head);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let chunked = text
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .any(|(k, v)| k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let len = if chunked { decode_chunked(body).map(|d| d.len()).unwrap_or(body.len()) } else { body.len() };
    Fired { status, len, time_ms, error: String::new() }
}

/// Upper median (sorted position len/2); None on an empty population.
fn median(times: &[u64]) -> Option<u64> {
    if times.is_empty() {
        return None;
    }
    let mut t = times.to_vec();
    t.sort_unstable();
    Some(t[t.len() / 2])
}

/// The three anomaly buckets, in fixed flag order: status flip, length out of
/// the baseline band, timing tail over both the row median and the baseline.
fn flags_for(baseline: &Fired, row: &Fired, median_ms: Option<u64>, tol_pct: f64, time_factor: f64) -> Vec<&'static str> {
    let mut flags: Vec<&'static str> = Vec::new();
    if row.status != baseline.status {
        flags.push("status");
    }
    let band = baseline.len as f64 * tol_pct / 100.0;
    if (row.len as f64 - baseline.len as f64).abs() > band {
        flags.push("length");
    }
    if let Some(m) = median_ms {
        if row.time_ms as f64 > m as f64 * time_factor && row.time_ms as f64 > baseline.time_ms as f64 * time_factor {
            flags.push("timing");
        }
    }
    flags
}

/// Bucket every fired row against the baseline and fold same-cause-same-value
/// rows into clusters. Pure: no IO, so --selftest drives it with synthetic rows.
fn analyze(baseline: &Fired, payloads: &[String], fired: &[Fired], tol_pct: f64, time_factor: f64) -> Value {
    let times: Vec<u64> = fired.iter().filter(|f| f.error.is_empty()).map(|f| f.time_ms).collect();
    let med = median(&times);
    let mut rows = Vec::with_capacity(fired.len());
    let mut status_clusters: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    let mut length_clusters: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut timing_payloads: Vec<String> = Vec::new();
    let mut anomalous = 0usize;
    for (p, f) in payloads.iter().zip(fired.iter()) {
        if !f.error.is_empty() {
            anomalous += 1;
            rows.push(json!({"payload": p, "error": f.error, "flags": ["error"]}));
            continue;
        }
        let flags = flags_for(baseline, f, med, tol_pct, time_factor);
        if !flags.is_empty() {
            anomalous += 1;
        }
        for fl in &flags {
            match *fl {
                "status" => status_clusters.entry(f.status).or_default().push(p.clone()),
                "length" => length_clusters.entry(f.len).or_default().push(p.clone()),
                _ => timing_payloads.push(p.clone()),
            }
        }
        rows.push(json!({"payload": p, "status": f.status, "len": f.len, "time_ms": f.time_ms, "flags": flags}));
    }
    let mut clusters = Vec::new();
    for (status, ps) in &status_clusters {
        clusters.push(json!({"kind": "status", "detail": format!("status {status} vs baseline {}", baseline.status), "payloads": ps}));
    }
    for (len, ps) in &length_clusters {
        clusters.push(json!({"kind": "length", "detail": format!("len {len} vs baseline {} (+/-{tol_pct}% band)", baseline.len), "payloads": ps}));
    }
    if !timing_payloads.is_empty() {
        clusters.push(json!({"kind": "timing", "detail": format!("time_ms > median({})x{} and > baseline({})x{}", med.unwrap_or(0), time_factor, baseline.time_ms, time_factor), "payloads": timing_payloads}));
    }
    json!({
        "median_time_ms": med,
        "rows": rows,
        "clusters": clusters,
        "summary": {"total": fired.len(), "anomalous": anomalous},
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut url = String::new();
    let mut req_file = String::new();
    let mut payloads: Vec<String> = Vec::new();
    let mut payloads_file = String::new();
    let mut baseline_arg: Option<String> = None;
    let mut rate_ms: u64 = 0;
    let mut tol_pct: f64 = 10.0;
    let mut time_factor: f64 = 3.0;
    let mut max_n: usize = 200;
    let mut read_ms: u64 = 8_000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--req" => { i += 1; req_file = arg(&args, i); }
            "--payload" => { i += 1; payloads.push(arg(&args, i)); }
            "--payloads-file" => { i += 1; payloads_file = arg(&args, i); }
            "--baseline" => { i += 1; baseline_arg = Some(arg(&args, i)); }
            "--rate-ms" => { i += 1; rate_ms = arg(&args, i).parse().unwrap_or(0); }
            "--len-tol-pct" => { i += 1; tol_pct = arg(&args, i).parse().unwrap_or(10.0); }
            "--time-factor" => { i += 1; time_factor = arg(&args, i).parse().unwrap_or(3.0); }
            "--max" => { i += 1; max_n = arg(&args, i).parse().unwrap_or(200); }
            "--read-ms" => { i += 1; read_ms = arg(&args, i).parse().unwrap_or(8_000); }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() || req_file.is_empty() {
        pi_rust_lib::report::failure("targeted_scan", "usage", "targeted_scan <url> --req FILE [--payload V]... [--payloads-file FILE] [--baseline V] [--rate-ms N] [--len-tol-pct N] [--time-factor F] [--max N]");
        std::process::exit(2);
    }
    if !payloads_file.is_empty() {
        match pi_rust_lib::read_to_string_lossy(&payloads_file) {
            Ok(text) => payloads.extend(parse_payload_lines(&text)),
            Err(e) => {
                pi_rust_lib::report::failure("targeted_scan", &e, "pass a readable --payloads-file (one payload per line)");
                std::process::exit(2);
            }
        }
    }
    if payloads.is_empty() {
        pi_rust_lib::report::failure("targeted_scan", "no payloads", "give at least one --payload V or a --payloads-file with one payload per line");
        std::process::exit(2);
    }
    if payloads.len() > max_n {
        pi_rust_lib::report::failure("targeted_scan", &format!("{} payloads exceed the --max {max_n} cap", payloads.len()), "trim the payload table or raise --max");
        std::process::exit(2);
    }
    let parsed = match Url::parse(&url) {
        Ok(u) => u,
        Err(e) => {
            pi_rust_lib::report::failure("targeted_scan", &format!("parse url: {e}"), "give a full http(s):// url");
            std::process::exit(2);
        }
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        pi_rust_lib::report::failure("targeted_scan", "url has no host", "give a full http(s)://host url");
        std::process::exit(2);
    }
    let tls = parsed.scheme() == "https";
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });

    let tpl = match pi_rust_lib::read_to_string_lossy(&req_file) {
        Ok(t) => t,
        Err(e) => {
            pi_rust_lib::report::failure("targeted_scan", &e, "pass a readable --req template file");
            std::process::exit(2);
        }
    };
    if let Err(e) = validate_template(&tpl) {
        pi_rust_lib::report::failure("targeted_scan", &e, "the template needs exactly one §INJ§ marker (request line, header, or body) plus a blank-line header/body split");
        std::process::exit(2);
    }
    let base_payload = baseline_arg.unwrap_or_else(|| payloads[0].clone());
    let base_render = match render(&tpl, &host, &base_payload) {
        Ok(r) => r,
        Err(e) => {
            pi_rust_lib::report::failure("targeted_scan", &e, "fix the --req template shape");
            std::process::exit(2);
        }
    };
    let base_fired = fire(&host, port, tls, &base_render.wire, read_ms);
    if !base_fired.error.is_empty() {
        pi_rust_lib::report::failure("targeted_scan", &format!("baseline fire failed: {}", base_fired.error), "check scheme/host/port and that the target speaks plain HTTP/1.1; every payload would fail the same way");
        std::process::exit(1);
    }

    let mut fired: Vec<Fired> = Vec::with_capacity(payloads.len());
    for p in &payloads {
        timeout::check();
        if rate_ms > 0 {
            std::thread::sleep(Duration::from_millis(rate_ms));
        }
        match render(&tpl, &host, p) {
            Ok(r) => fired.push(fire(&host, port, tls, &r.wire, read_ms)),
            Err(e) => fired.push(Fired { status: 0, len: 0, time_ms: 0, error: e }),
        }
    }

    let analysis = analyze(&base_fired, &payloads, &fired, tol_pct, time_factor);
    let anomalous = analysis["summary"]["anomalous"].as_u64().unwrap_or(0);
    let data = json!({
        "url": url,
        "host": host,
        "port": port,
        "tls": tls,
        "req_file": req_file,
        "rate_ms": rate_ms,
        "len_tol_pct": tol_pct,
        "time_factor": time_factor,
        "cl_mode": base_render.cl_mode,
        "baseline": {"payload": base_payload, "status": base_fired.status, "len": base_fired.len, "time_ms": base_fired.time_ms},
        "median_time_ms": analysis["median_time_ms"],
        "rows": analysis["rows"],
        "clusters": analysis["clusters"],
        "summary": analysis["summary"],
    });
    let next = if anomalous > 0 {
        "clusters hold the divergent payloads - re-fire one member of each cluster alone to confirm it is stable, then take the confirmed shape into burp_interp for manual follow-up"
    } else {
        "no divergence from baseline - widen the payload table, adjust --len-tol-pct/--time-factor if the target jitters, or move the §INJ§ marker to another header/parameter"
    };
    pi_rust_lib::report::success("targeted_scan", data, next).unwrap_or(());
}

// ---------------------------------------------------------------------------
// selftest: pure assertions over template validation, rendering (incl. the
// auto Content-Length repair), payload-table parsing, and the analyze
// bucketing. Fully offline - every fixture is a synthetic string.
// ---------------------------------------------------------------------------

fn check(name: &str, ok: bool, bad: &mut Vec<String>) {
    if !ok {
        bad.push(name.to_string());
    }
}

fn selftest() {
    let mut bad: Vec<String> = Vec::new();

    let tpl = "POST /submit HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nname=a&comment=§INJ§";
    match render(tpl, "example.com", "hello world") {
        Ok(r) => {
            let body = "name=a&comment=hello world";
            check("render.ok", true, &mut bad);
            check("render.host", r.wire.contains("Host: example.com\r\n"), &mut bad);
            check("render.body", r.wire.ends_with(body), &mut bad);
            check("render.cl_recomputed", r.wire.contains(&format!("Content-Length: {}\r\n", body.len())), &mut bad);
            check("render.cl_single", r.wire.matches("Content-Length:").count() == 1, &mut bad);
            check("render.cl_mode", r.cl_mode == "recomputed", &mut bad);
        }
        Err(_) => check("render.ok", false, &mut bad),
    }
    // Multibyte payload: Content-Length counts bytes, not chars.
    match render(tpl, "example.com", "héllo") {
        Ok(r) => {
            let body = "name=a&comment=héllo";
            check("render.multibyte_cl", r.wire.contains(&format!("Content-Length: {}\r\n", body.len())) && r.wire.ends_with(body), &mut bad);
        }
        Err(_) => check("render.multibyte_cl", false, &mut bad),
    }
    // No CL in the template but a body exists: CL is added.
    match render("POST /p HTTP/1.1\r\nHost: {HOST}\r\n\r\nq=§INJ§", "example.com", "abc") {
        Ok(r) => check("render.add_cl", r.wire.contains("Content-Length: 5\r\n") && r.cl_mode == "added", &mut bad),
        Err(_) => check("render.add_cl", false, &mut bad),
    }
    // GET with the marker in the request line and no body: no CL invented.
    match render("GET /?q=§INJ§ HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "example.com", "a b") {
        Ok(r) => check("render.line_inj", r.wire.starts_with("GET /?q=a b HTTP/1.1\r\n") && !r.wire.contains("Content-Length") && r.cl_mode == "none", &mut bad),
        Err(_) => check("render.line_inj", false, &mut bad),
    }
    // Transfer-Encoding in the template: the whole head ships untouched.
    match render("POST /p HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n§INJ§", "example.com", "abcdef") {
        Ok(r) => check(
            "render.te_untouched",
            r.wire.contains("Transfer-Encoding: chunked\r\n") && r.wire.contains("Content-Length: 4\r\n") && r.cl_mode == "untouched-te",
            &mut bad,
        ),
        Err(_) => check("render.te_untouched", false, &mut bad),
    }
    // LF-only template normalizes to CRLF and still recomputes CL.
    match render("POST /p HTTP/1.1\nHost: {HOST}\nContent-Length: 1\n\na=§INJ§", "example.com", "zz") {
        Ok(r) => check("render.lf_norm", r.wire.starts_with("POST /p HTTP/1.1\r\nHost: example.com\r\n") && r.wire.contains("Content-Length: 4\r\n\r\na=zz"), &mut bad),
        Err(_) => check("render.lf_norm", false, &mut bad),
    }

    check("validate.ok", validate_template(tpl).is_ok(), &mut bad);
    check("validate.none", validate_template("GET / HTTP/1.1\r\n\r\n").is_err(), &mut bad);
    check("validate.two", validate_template("GET /?a=§INJ§&b=§INJ§ HTTP/1.1\r\n\r\n").is_err(), &mut bad);
    check("validate.in_cl", validate_template("POST / HTTP/1.1\r\nContent-Length: §INJ§\r\n\r\nx").is_err(), &mut bad);
    check("validate.no_sep", validate_template("GET /§INJ§ HTTP/1.1").is_err(), &mut bad);

    check(
        "payloads.lines",
        parse_payload_lines("# comment\n\nalpha\r\nbeta\n") == vec!["alpha".to_string(), "beta".to_string()],
        &mut bad,
    );

    // Bucketing on synthetic rows: in-band, boundary, flip x2, length, tail, error.
    let baseline = Fired { status: 200, len: 1000, time_ms: 100, error: String::new() };
    let payloads: Vec<String> = ["p-inband", "p-flip", "p-flip2", "p-long", "p-slow", "p-edge", "p-err"].iter().map(|s| s.to_string()).collect();
    let fired = vec![
        Fired { status: 200, len: 1005, time_ms: 90, error: String::new() },
        Fired { status: 500, len: 1000, time_ms: 95, error: String::new() },
        Fired { status: 500, len: 998, time_ms: 100, error: String::new() },
        Fired { status: 200, len: 1200, time_ms: 105, error: String::new() },
        Fired { status: 200, len: 1000, time_ms: 1200, error: String::new() },
        Fired { status: 200, len: 1100, time_ms: 110, error: String::new() },
        Fired { status: 0, len: 0, time_ms: 0, error: "connect reset".to_string() },
    ];
    let a = analyze(&baseline, &payloads, &fired, 10.0, 3.0);
    let flags_of = |i: usize| a["rows"][i]["flags"].as_array().map(|f| f.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()).unwrap_or_default();
    check("analyze.inband", flags_of(0).is_empty(), &mut bad);
    check("analyze.status_flag", flags_of(1) == vec!["status"], &mut bad);
    check("analyze.status_flag2", flags_of(2) == vec!["status"], &mut bad);
    check("analyze.length_flag", flags_of(3) == vec!["length"], &mut bad);
    check("analyze.timing_flag", flags_of(4) == vec!["timing"], &mut bad);
    check("analyze.edge_inband", flags_of(5).is_empty(), &mut bad);
    check("analyze.error_row", flags_of(6) == vec!["error"] && a["rows"][6]["error"].as_str().is_some(), &mut bad);
    check("analyze.median", a["median_time_ms"].as_u64() == Some(105), &mut bad);
    check("analyze.summary", a["summary"]["total"].as_u64() == Some(7) && a["summary"]["anomalous"].as_u64() == Some(5), &mut bad);
    let clusters = a["clusters"].as_array().cloned().unwrap_or_default();
    let status_clusters: Vec<&Value> = clusters.iter().filter(|c| c["kind"].as_str() == Some("status")).collect();
    check(
        "analyze.status_cluster",
        status_clusters.len() == 1
            && status_clusters[0]["payloads"].as_array().map(|p| p.len()) == Some(2)
            && status_clusters[0]["detail"].as_str().map(|d| d.contains("500")).unwrap_or(false),
        &mut bad,
    );
    check(
        "analyze.length_cluster",
        clusters.iter().filter(|c| c["kind"].as_str() == Some("length")).count() == 1,
        &mut bad,
    );
    check("analyze.timing_cluster", clusters.iter().filter(|c| c["kind"].as_str() == Some("timing")).count() == 1, &mut bad);

    let ok = bad.is_empty();
    let data = json!({"selftest": if ok { "ok" } else { "fail" }, "failed_checks": bad});
    if ok {
        pi_rust_lib::report::success("targeted_scan", data, "selftest passed; give --req a template with one §INJ§ marker plus a payload table").unwrap_or(());
    } else {
        pi_rust_lib::report::failure("targeted_scan", &format!("selftest failed: {}", data["failed_checks"]), "inspect failed_checks");
    }
    std::process::exit(if ok { 0 } else { 1 });
}
