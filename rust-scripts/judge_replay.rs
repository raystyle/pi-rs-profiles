#!/usr/bin/env rust-script
//! name: judge_replay
//! description: 判定面回放验收件 - 对给定的 practice/eval 存档清单逐档以 practice/eval/judge.py 回放该档 transcript,取 judge 判决(结构化回执优先、词表兜底),再与该档 outcome.md 的账面判决逐档比对;一个信封给出逐档 (lab,arm,run) 的 judge 判决与账面判决、是否一致,以及档级统计,供阶段自省轮的判定面生产实效验收(假阳=账面未解被 judge 判 solved,漏判=账面解出被 judge 判 0)。
//! version: 1.0.0
//! args: --case <lab>:<arm>:<run> [--case ...] | --all [--eval-dir DIR] [--python BIN] [--selftest]
//! keywords: judge, replay, verdict, acceptance, eval, archive, transcript, banner
//!
//! ```cargo
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn opt(args: &[String], key: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == key {
            return it.next().cloned();
        }
    }
    None
}

fn opt_all(args: &[String], key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == key {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

fn newest_jsonl(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".jsonl") {
            continue;
        }
        if let Ok(t) = e.metadata().and_then(|m| m.modified()) {
            if best.as_ref().map(|(bt, _)| t > *bt).unwrap_or(true) {
                best = Some((t, p));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn run_judge(py: &str, judge: &str, transcript: &str, lab: &str, arm: &str) -> Value {
    match Command::new(py)
        .arg(judge)
        .arg(transcript)
        .arg(lab)
        .arg(arm)
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            pi_rust_lib::serde_json::from_str::<Value>(&s).unwrap_or_else(|_| {
                json!({"solved": 0, "class": "parse-error", "raw": s})
            })
        }
        Err(e) => json!({"solved": 0, "class": "exec-error", "error": e.to_string()}),
    }
}

/// Recorded verdict for one arm-run, read off the lab's outcome.md line.
/// Negative forms are checked after the explicit solved=1 form so
/// "solved=0" and "not-smoke solved" land on the right sides.
fn outcome_verdict(text: &str, arm: &str, run: &str) -> (Option<bool>, String) {
    let tag = format!("{arm}-{run}");
    for line in text.lines() {
        let t = line.trim().trim_start_matches('#').trim();
        if !t.starts_with(&tag) {
            continue;
        }
        let l = line.to_lowercase();
        if l.contains("solved=1") {
            return (Some(true), line.trim().to_string());
        }
        for neg in ["solved=0", "not-solved", "unsolved", "挂死", "stuck", "未解", "未破", "未翻"] {
            if l.contains(neg) {
                return (Some(false), line.trim().to_string());
            }
        }
        if l.contains("solved") {
            return (Some(true), line.trim().to_string());
        }
        return (None, line.trim().to_string());
    }
    (None, String::new())
}

struct Case {
    lab: String,
    arm: String,
    run: String,
}

/// Enumerate every archive dir ( <lab>/<ARM>-<n>/ ) under the eval root that
/// holds a transcript.jsonl or a dated session jsonl.
fn all_cases(root: &Path) -> Vec<Case> {
    let mut out = Vec::new();
    let labs = match fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return out,
    };
    for lab_e in labs.flatten() {
        let lab_path = lab_e.path();
        if !lab_path.is_dir() {
            continue;
        }
        let lab = lab_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
        if !lab.starts_with("lab-") && !lab.starts_with("stored-") {
            continue;
        }
        let arms = match fs::read_dir(&lab_path) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for arm_e in arms.flatten() {
            let arm_path = arm_e.path();
            if !arm_path.is_dir() {
                continue;
            }
            let dir = arm_e.file_name().to_string_lossy().to_string();
            let mut parts = dir.splitn(2, '-');
            let arm = parts.next().unwrap_or("").to_string();
            let run = match parts.next() {
                Some(r) => r.split('.').next().unwrap_or("").to_string(),
                None => continue,
            };
            if arm.len() != 1 || !arm.chars().all(|c| c.is_ascii_uppercase()) || run.is_empty() {
                continue;
            }
            if !arm_path.join("transcript.jsonl").exists() && newest_jsonl(&arm_path).is_none() {
                continue;
            }
            out.push(Case { lab: lab.clone(), arm, run });
        }
    }
    out.sort_by(|a, b| {
        (a.lab.clone(), a.arm.clone(), a.run.clone())
            .cmp(&(b.lab.clone(), b.arm.clone(), b.run.clone()))
    });
    out
}

fn parse_case(s: &str) -> Option<Case> {
    let mut it = s.rsplitn(3, ':');
    let run = it.next()?.to_string();
    let arm = it.next()?.to_string();
    let lab = it.next()?.to_string();
    if lab.is_empty() || arm.is_empty() || run.is_empty() {
        return None;
    }
    Some(Case { lab, arm, run })
}

fn replay_one(py: &str, judge: &str, eval_dir: &Path, c: &Case) -> Value {
    let dir = eval_dir.join(&c.lab).join(format!("{}-{}", c.arm, c.run));
    let transcript = dir.join("transcript.jsonl");
    let transcript = if transcript.exists() {
        transcript
    } else if let Some(p) = newest_jsonl(&dir) {
        p
    } else {
        return json!({
            "lab": c.lab, "arm": c.arm, "run": c.run,
            "error": "no transcript", "judge": Value::Null, "outcome": Value::Null, "match": false,
        });
    };
    let j = run_judge(py, judge, transcript.to_string_lossy().as_ref(), &c.lab, &c.arm);
    let outcome_md = fs::read_to_string(eval_dir.join(&c.lab).join("outcome.md")).unwrap_or_default();
    let (recorded, line) = outcome_verdict(&outcome_md, &c.arm, &c.run);
    let judge_solved = j.get("solved").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
    let match_ = match recorded {
        Some(r) => r == judge_solved,
        None => false,
    };
    json!({
        "lab": c.lab,
        "arm": c.arm,
        "run": c.run,
        "transcript": transcript.to_string_lossy(),
        "judge": j,
        "outcome_solved": recorded,
        "outcome_line": line,
        "match": match_,
    })
}

fn selftest(py: &str, judge: &str) -> Result<(bool, Value), String> {
    let dir = std::env::temp_dir().join("judge_replay_selftest");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let pos = dir.join("pos.jsonl");
    let neg = dir.join("neg.jsonl");
    let pos_line = json!({
        "type": "message",
        "message": {"role": "toolResult", "toolName": "rs_execute",
            "content": [{"type": "text", "text": "{\"action\":\"banner_verdict\",\"data\":{\"solved\":true,\"class\":\"receipt\"}}"}]}
    });
    let neg_line = json!({
        "type": "message",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "终态(lab-x/A): 未解——机制未破。"}]}
    });
    fs::write(&pos, format!("{pos_line}\n")).map_err(|e| e.to_string())?;
    fs::write(&neg, format!("{neg_line}\n")).map_err(|e| e.to_string())?;
    let jp = run_judge(py, judge, pos.to_string_lossy().as_ref(), "lab-x", "A");
    let jn = run_judge(py, judge, neg.to_string_lossy().as_ref(), "lab-x", "A");
    let p = jp.get("solved").and_then(|v| v.as_i64()).unwrap_or(-1);
    let n = jn.get("solved").and_then(|v| v.as_i64()).unwrap_or(-1);
    let ok = p == 1 && n == 0;
    Ok((ok, json!({"pos": jp, "neg": jn})))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let selftest_flag = args.iter().any(|a| a == "--selftest");
    let eval_dir = PathBuf::from(opt(&args, "--eval-dir").unwrap_or_else(|| "practice/eval".to_string()));
    let py = opt(&args, "--python").unwrap_or_else(|| "python3".to_string());
    let judge = eval_dir.join("judge.py");
    if !judge.exists() {
        report::failure(
            "judge_replay",
            &format!("judge.py not found at {}", judge.display()),
            "pass --eval-dir pointing at the practice/eval checkout",
        );
        std::process::exit(2);
    }
    if selftest_flag {
        match selftest(&py, judge.to_string_lossy().as_ref()) {
            Ok((ok, detail)) => {
                let _ = report::success(
                    "judge_replay",
                    json!({"selftest": ok, "detail": detail}),
                    "rerun with --case to replay real archives",
                );
                return;
            }
            Err(e) => {
                report::failure("judge_replay", &format!("selftest error: {e}"), "check python3 and judge.py");
                std::process::exit(2);
            }
        }
    }
    let raw = opt_all(&args, "--case");
    let all = args.iter().any(|a| a == "--all");
    if raw.is_empty() && !all {
        report::failure(
            "judge_replay",
            "no --case given",
            "pass --case <lab>:<arm>:<run> (arm is the anchor arm letter, e.g. A) or --all",
        );
        std::process::exit(2);
    }
    let mut cases = Vec::new();
    if all {
        cases = all_cases(&eval_dir);
    }
    for r in &raw {
        match parse_case(r) {
            Some(c) => cases.push(c),
            None => {
                report::failure(
                    "judge_replay",
                    &format!("bad --case spec: {r}"),
                    "use <lab>:<arm>:<run>, e.g. lab-frame-buster-script:A:2", // binding-exempt: selftest fixture or usage-example name, not a runtime default that targets one lab
                );
                std::process::exit(2);
            }
        }
    }
    let mut rows = Vec::new();
    let mut mismatched_list: Vec<Value> = Vec::new();
    let (mut matched, mut unrecorded, mut solved, mut unsolved) = (0usize, 0usize, 0usize, 0usize);
    for c in &cases {
        let row = replay_one(&py, judge.to_string_lossy().as_ref(), &eval_dir, c);
        match row.get("outcome_solved") {
            None | Some(Value::Null) => unrecorded += 1,
            _ => {
                if row.get("match").and_then(|v| v.as_bool()).unwrap_or(false) {
                    matched += 1;
                } else {
                    mismatched_list.push(row.clone());
                }
            }
        }
        if row.get("judge").and_then(|j| j.get("solved")).and_then(|v| v.as_i64()).unwrap_or(0) == 1 {
            solved += 1;
        } else {
            unsolved += 1;
        }
        rows.push(row);
    }
    let total = cases.len();
    let data = json!({
        "eval_dir": eval_dir.to_string_lossy(),
        "judge": judge.to_string_lossy(),
        "total": total,
        "matched": matched,
        "mismatched": mismatched_list.len(),
        "unrecorded": unrecorded,
        "judge_solved": solved,
        "judge_unsolved": unsolved,
        "all_match": mismatched_list.is_empty(),
        "mismatch_rows": mismatched_list,
        "cases": if all { json!([]) } else { json!(rows) },
    });
    let _ = report::success(
        "judge_replay",
        data,
        "mismatch rows carry judge vs outcome_line - re-read that transcript tail before trusting the archive",
    );
}
