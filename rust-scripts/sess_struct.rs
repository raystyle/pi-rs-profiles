#!/usr/bin/env rust-script
//! name: sess_struct
//! description: 会话结构字节差分件 - 对形如 `label:base64payload` 的会话值(或裸 base64 令牌)解码后半段,逐枚给出字节长/hex/可打印 ascii,并对多枚做逐字节差分:标记「全稳定位」(跨样本同值 = 版本/用户常量段)、「全漂位」(跨样本全异 = 随机/MAC 段)与稳定前缀长度,供判定签名令牌的段位结构(版本头/用户标记/时戳/随机/MAC)。纯离线,不发请求。
//! version: 1.0.0
//! args: <session-or-token>... [--selftest]
//! keywords: session, token, base64, structure, diff, 会话结构, 字节差分, 令牌分析
//!
//! 用于 base64 编码的会话/签名令牌结构推断:取多枚令牌(同用户多次登录、不同用户、
//! 匿名会话)一次性喂入,稳定位与全漂位的分布把「不透明随机」与「有结构」分开。

use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};

/// Hand-rolled base64 (standard alphabet, padding tolerant, whitespace skipped)
/// so the piece carries no external crate dependency.
fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
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

fn ascii_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

/// Splits `label:payload` on the first colon; a colon-less input is treated as
/// a bare base64 token with an empty label.
fn split_parts(raw: &str) -> (String, String) {
    match raw.split_once(':') {
        Some((label, rest)) => (label.to_string(), rest.to_string()),
        None => (String::new(), raw.to_string()),
    }
}

fn analyze(inputs: &[String]) -> Value {
    let mut rows: Vec<Value> = Vec::new();
    let mut decoded: Vec<Vec<u8>> = Vec::new();
    for raw in inputs {
        let (label, b64) = split_parts(raw);
        match b64_decode(&b64) {
            Ok(bytes) => {
                rows.push(json!({
                    "input": raw,
                    "label": label,
                    "b64_len": b64.len(),
                    "len": bytes.len(),
                    "hex": pi_rust_lib::hex_encode(&bytes),
                    "ascii": ascii_of(&bytes),
                }));
                decoded.push(bytes);
            }
            Err(err) => rows.push(json!({
                "input": raw,
                "label": label,
                "b64_len": b64.len(),
                "error": err,
            })),
        }
    }

    let min_len = decoded.iter().map(|b| b.len()).min().unwrap_or(0);
    let mut positions: Vec<Value> = Vec::new();
    let mut stable_all = 0usize;
    for i in 0..min_len {
        let mut set: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
        for b in &decoded {
            set.insert(b[i]);
        }
        let distinct = set.len();
        if distinct == 1 {
            stable_all += 1;
        }
        let value_hex = if distinct == 1 {
            set.iter().next().map(|v| format!("{v:02x}")).unwrap_or_default()
        } else {
            String::new()
        };
        positions.push(json!({
            "i": i,
            "distinct": distinct,
            "stable": distinct == 1,
            "value_hex": value_hex,
        }));
    }

    // Longest stable prefix from byte 0.
    let mut prefix = 0usize;
    for p in &positions {
        if p["stable"] == Value::Bool(true) {
            prefix += 1;
        } else {
            break;
        }
    }

    json!({
        "count": inputs.len(),
        "decoded_count": decoded.len(),
        "min_len": min_len,
        "stable_positions": stable_all,
        "varying_positions": min_len.saturating_sub(stable_all),
        "stable_prefix_len": prefix,
        "tokens": rows,
        "positions": positions,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        // AQID = [1,2,3]; AQIE = [1,2,4] -> positions 0,1 stable, 2 varies.
        let synthetic = vec!["x:AQID".to_string(), "y:AQIE".to_string()];
        let v = analyze(&synthetic);
        let ok = v["stable_prefix_len"] == json!(2)
            && v["stable_positions"] == json!(2)
            && v["varying_positions"] == json!(1);
        report::success(
            "sess_struct",
            json!({"selftest": ok, "sample": v}),
            "selftest ok -> feed real tokens",
        )
        .ok();
        return;
    }

    let inputs: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    if inputs.is_empty() {
        report::failure(
            "sess_struct",
            "no inputs: pass one or more session or base64 token values",
            "e.g. sess_struct 'wiener:iGFE...' ':hZ0A...'",
        );
        return;
    }
    let value = analyze(&inputs);
    report::success(
        "sess_struct",
        value,
        "all positions varying -> opaque (encrypted/MAC); a stable prefix marks a version/user tag",
    )
    .ok();
}
