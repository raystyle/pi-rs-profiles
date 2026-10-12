#!/usr/bin/env rust-script
//! name: http_wait
//! description: Long-timeout single HTTP call - send one GET/POST with an explicit --timeout-secs for endpoints that legitimately hold the response for minutes (e.g. the academy lab launch URL, which blocks while the environment builds), optionally following redirects, sending jar cookies for the target host, and reporting every hop's status/Location/body head plus the final URL in one envelope.
//! version: 1.0.0
//! args: <url> [--method GET|POST] [--header 'K: V']... [--body STR] [--jar PATH] [--follow] [--timeout-secs 180] [--out FILE]
//! keywords: http, launch, timeout, lab, redirect, jar, cookie
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! ```
use pi_rust_lib::serde_json::{self, json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

type Jar = BTreeMap<String, BTreeMap<String, String>>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut url = String::new();
    let mut method = "GET".to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = String::new();
    let mut jar_path = String::new();
    let mut follow = false;
    let mut timeout_secs: u64 = 180;
    let mut out = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                if i < args.len() {
                    method = args[i].to_uppercase();
                }
            }
            "--header" => {
                i += 1;
                if i < args.len() {
                    if let Some((k, v)) = args[i].split_once(':') {
                        headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
            }
            "--body" => {
                i += 1;
                if i < args.len() {
                    body = args[i].clone();
                }
            }
            "--jar" => {
                i += 1;
                if i < args.len() {
                    jar_path = args[i].clone();
                }
            }
            "--follow" => follow = true,
            "--timeout-secs" => {
                i += 1;
                if i < args.len() {
                    timeout_secs = args[i].parse().unwrap_or(180);
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out = args[i].clone();
                }
            }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() {
        pi_rust_lib::report::failure(
            "http_wait",
            "usage: http_wait <url> [--method GET|POST] [--header 'K: V']... [--body STR] [--jar PATH] [--follow] [--timeout-secs N] [--out FILE]",
            "pass the URL to fetch",
        );
        std::process::exit(2);
    }
    let jar: Jar = std::fs::read_to_string(&jar_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .redirects(if follow { 10 } else { 0 })
        .build();

    let mut hops: Vec<Value> = Vec::new();
    let t0 = std::time::Instant::now();
    let mut req = agent.request(&method, &url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    // Cookies for the target host, domain-suffix matched (leading dot tolerated).
    if !jar.is_empty() {
        if let Some(host) = url.split("://").nth(1).and_then(|r| r.split('/').next()).and_then(|h| h.split(':').next()) {
            let mut pairs: Vec<String> = Vec::new();
            for (dom, cookies) in &jar {
                let d = dom.trim_start_matches('.');
                if host == d || host.ends_with(&format!(".{d}")) {
                    for (n, v) in cookies {
                        pairs.push(format!("{n}={v}"));
                    }
                }
            }
            if !pairs.is_empty() {
                req = req.set("Cookie", &pairs.join("; "));
            }
        }
    }
    let result = if body.is_empty() { req.call() } else { req.send_string(&body) };
    let (status, final_url, body_text, hops_meta) = match result {
        Ok(resp) => {
            let s = resp.status();
            let u = resp.get_url().to_string();
            let hs: Vec<(String, String)> = resp
                .headers_names()
                .into_iter()
                .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
                .collect();
            let b = resp.into_string().unwrap_or_default();
            (s, u, b, hs)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let u = resp.get_url().to_string();
            let hs: Vec<(String, String)> = resp
                .headers_names()
                .into_iter()
                .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
                .collect();
            let b = resp.into_string().unwrap_or_default();
            (code, u, b, hs)
        }
        Err(e) => {
            pi_rust_lib::report::failure(
                "http_wait",
                &format!("request failed after {:.1}s: {e}", t0.elapsed().as_secs_f64()),
                "raise --timeout-secs, or check the URL and the jar's cookies",
            );
            std::process::exit(1);
        }
    };
    let elapsed = t0.elapsed().as_secs_f64();
    let location = hops_meta
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone());
    hops.push(json!({"status": status, "url": final_url, "location": location}));
    if !out.is_empty() {
        let _ = std::fs::write(&out, &body_text);
    }
    let head: String = body_text.chars().take(400).collect();
    // Pull any academy instance anchor out of the body for convenience.
    let marker = "web-security-academy.net";
    let instances: Vec<String> = {
        let mut v = Vec::new();
        let mut idx = 0;
        while let Some(p) = body_text[idx..].find(marker) {
            let abs = idx + p;
            if let Some(s) = body_text[..abs].rfind("https://") {
                let start = s + "https://".len();
                let host = body_text[start..abs].trim_end_matches('.');
                if (16..=64).contains(&host.len()) && host.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
                    let url = format!("https://{}{}", &body_text[start..abs], marker);
                    if !v.contains(&url) {
                        v.push(url);
                    }
                }
            }
            idx = abs + marker.len();
        }
        v
    };
    pi_rust_lib::report::success(
        "http_wait",
        json!({
            "request_url": url,
            "method": method,
            "status": status,
            "final_url": final_url,
            "elapsed_secs": elapsed,
            "headers": hops_meta,
            "location": location,
            "body_len": body_text.len(),
            "body_head": head,
            "academy_instances": instances,
            "out": if out.is_empty() { Value::Null } else { Value::String(out) },
            "hops": hops,
        }),
        "if status is 3xx with --no-follow, rerun with --follow; instance anchors land in academy_instances",
    )
    .unwrap_or(());
}
