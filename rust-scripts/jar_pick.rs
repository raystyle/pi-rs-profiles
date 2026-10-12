#!/usr/bin/env rust-script
//! name: jar_pick
//! description: Cookie-jar filter and bisector - read an http_session-format jar (host -> name -> value), list its hosts/cookies with their serialized sizes, then keep or drop named cookies for chosen hosts and write a narrowed jar, so an oversized or poisoned cookie set that stalls a server can be bisected down to the working subset.
//! version: 1.0.0
//! args: <jar> [--host H]... [--keep n1,n2,...] [--drop n1,n2,...] [--out FILE] [--list]
//! keywords: jar, cookie, filter, http_session, bisect, cookie-header
use pi_rust_lib::serde_json::{self, json, Value};
use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        pi_rust_lib::report::success(
            "jar_pick",
            json!({"selftest": "ok"}),
            "run with a jar path: jar_pick <jar> --host H [--keep a,b] [--out F] [--list]",
        )
        .unwrap_or(());
        return;
    }
    let mut path = String::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut keep: Vec<String> = Vec::new();
    let mut drop: Vec<String> = Vec::new();
    let mut out = String::new();
    let mut list = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                if i < args.len() {
                    hosts.push(args[i].clone());
                }
            }
            "--keep" => {
                i += 1;
                if i < args.len() {
                    keep = args[i].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                }
            }
            "--drop" => {
                i += 1;
                if i < args.len() {
                    drop = args[i].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out = args[i].clone();
                }
            }
            "--list" => list = true,
            other if !other.starts_with("--") && path.is_empty() => path = other.to_string(),
            _ => {}
        }
        i += 1;
    }
    if path.is_empty() {
        pi_rust_lib::report::failure(
            "jar_pick",
            "usage: jar_pick <jar> [--host H]... [--keep n1,n2,...] [--drop n1,n2,...] [--out FILE] [--list]",
            "pass the jar path",
        );
        std::process::exit(2);
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            pi_rust_lib::report::failure("jar_pick", &format!("cannot read {path}: {e}"), "check the jar path");
            std::process::exit(2);
        }
    };
    let root: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            pi_rust_lib::report::failure("jar_pick", &format!("{path} is not JSON: {e}"), "expect a host -> name -> value JSON object");
            std::process::exit(2);
        }
    };
    let mut all: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    if let Some(obj) = root.as_object() {
        for (h, v) in obj {
            let mut m = BTreeMap::new();
            if let Some(co) = v.as_object() {
                for (n, cv) in co {
                    if let Some(s) = cv.as_str() {
                        m.insert(n.clone(), s.to_string());
                    }
                }
            }
            all.insert(h.clone(), m);
        }
    }
    // Per-host census with the serialized Cookie-header contribution per name.
    let mut census: Vec<Value> = Vec::new();
    for (h, m) in &all {
        let total: usize = m.iter().map(|(n, v)| n.len() + v.len() + 2).sum();
        let names: Vec<Value> = m
            .iter()
            .map(|(n, v)| json!({"name": n, "len": v.len()}))
            .collect();
        census.push(json!({"host": h, "cookies": m.len(), "cookie_header_bytes": total, "names": names}));
    }
    if list {
        pi_rust_lib::report::success(
            "jar_pick",
            json!({"jar": path, "hosts": census}),
            "rerun with --host H [--keep a,b | --drop a,b] --out FILE to write the narrowed jar",
        )
        .unwrap_or(());
        return;
    }
    let sel_hosts: Vec<String> = if hosts.is_empty() { all.keys().cloned().collect() } else { hosts.clone() };
    let mut outjar: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut kept = 0usize;
    let mut dropped = 0usize;
    let mut bytes = 0usize;
    for h in &sel_hosts {
        let Some(m) = all.get(h) else { continue };
        let mut nm = BTreeMap::new();
        for (n, v) in m {
            if !keep.is_empty() && !keep.iter().any(|k| k == n) {
                dropped += 1;
                continue;
            }
            if drop.iter().any(|k| k == n) {
                dropped += 1;
                continue;
            }
            bytes += n.len() + v.len() + 2;
            kept += 1;
            nm.insert(n.clone(), v.clone());
        }
        if !nm.is_empty() {
            outjar.insert(h.clone(), nm);
        }
    }
    if out.is_empty() {
        pi_rust_lib::report::failure("jar_pick", "no --out given", "pass --out FILE to write the narrowed jar");
        std::process::exit(2);
    }
    let body = serde_json::to_string(&outjar).unwrap_or_else(|_| "{}".to_string());
    if let Err(e) = std::fs::write(&out, &body) {
        pi_rust_lib::report::failure("jar_pick", &format!("cannot write {out}: {e}"), "pick a writable --out path");
        std::process::exit(2);
    }
    pi_rust_lib::report::success(
        "jar_pick",
        json!({
            "jar": path,
            "out": out,
            "hosts_selected": sel_hosts,
            "kept": kept,
            "dropped": dropped,
            "cookie_header_bytes": bytes,
        }),
        "point the http pieces at the written jar",
    )
    .unwrap_or(());
}
