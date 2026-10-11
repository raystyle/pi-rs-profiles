#!/usr/bin/env rust-script
//! name: dispatch_survey
//! description: 派单形与委派实战普查件 - 遍历 practice/eval 下每一档存档( <lab>/<arm>-<n>/transcript.jsonl ),从 transcript 取该档派单词(首条 user 文本),判定其派单形(runner 形 batch-desk 标准单 / deepwater 攻坚定制单 / other)、是否带委派句(子调用计入臂预算)、是否落 lane 标签(如 lane 2-1),并统计该档 transcript 内真实 Agent 调用数( toolName":"Agent" );一个信封给出逐档行与聚合数(带委派句档数、实际委派档数、按派单形/按 lane 分组),供编排谱实战使用率验收。
//! version: 1.0.0
//! args: [--root DIR] [--lab SLUG]... [--brief] [--selftest]
//! keywords: dispatch, survey, delegation, agent, subagent, orchestration, lane, eval
//!
//! ```cargo
//! ```
use pi_rust_lib::report;
use pi_rust_lib::serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

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

/// First user message text in a pi session transcript = the dispatch prompt.
fn dispatch_of(text: &str) -> (String, usize) {
    let mut dispatch = String::new();
    for line in text.lines() {
        let obj: Value = match pi_rust_lib::serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if obj.get("type").and_then(|v| v.as_str()) != Some("message") {
            continue;
        }
        let msg = match obj.get("message") {
            Some(m) => m,
            None => continue,
        };
        if msg.get("role").and_then(|v| v.as_str()) != Some("user") {
            continue;
        }
        if let Some(blocks) = msg.get("content").and_then(|v| v.as_array()) {
            for b in blocks {
                if b.get("type").and_then(|v| v.as_str()) == Some("text") {
                    if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                        dispatch = t.to_string();
                        break;
                    }
                }
            }
        }
        if !dispatch.is_empty() {
            break;
        }
    }
    let agent_calls = text.matches("\"toolName\":\"Agent\"").count();
    (dispatch, agent_calls)
}

fn lane_of(dispatch: &str) -> Option<String> {
    let idx = dispatch.find("lane ")?;
    let rest = &dispatch[idx + 5..];
    let mut out = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_digit() || ch == '-' {
            out.push(ch);
        } else {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn form_of(dispatch: &str) -> &'static str {
    if dispatch.contains("深水攻坚") || dispatch.contains("lane ") {
        "deepwater"
    } else if dispatch.starts_with("解题评测") {
        "runner"
    } else {
        "other"
    }
}

struct Row {
    lab: String,
    arm: String,
    form: &'static str,
    lane: Option<String>,
    delegation: bool,
    agent_calls: usize,
    dispatch_head: String,
}

fn survey(root: &Path, labs_filter: &[String]) -> Vec<Row> {
    let mut rows = Vec::new();
    let labs = match fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return rows,
    };
    for lab_e in labs.flatten() {
        let lab_path = lab_e.path();
        if !lab_path.is_dir() {
            continue;
        }
        let lab = lab_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
        if !labs_filter.is_empty() && !labs_filter.iter().any(|f| lab.contains(f.as_str())) {
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
            let arm_dir = arm_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let transcript = arm_path.join("transcript.jsonl");
            if !transcript.exists() {
                continue;
            }
            let text = match fs::read_to_string(&transcript) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let (dispatch, agent_calls) = dispatch_of(&text);
            let head: String = dispatch.chars().take(80).collect();
            rows.push(Row {
                lab: lab.clone(),
                arm: arm_dir.clone(),
                form: form_of(&dispatch),
                lane: lane_of(&dispatch),
                delegation: dispatch.contains("子调用计入臂预算") || dispatch.contains("委派"),
                agent_calls,
                dispatch_head: head,
            });
        }
    }
    rows.sort_by(|a, b| (a.lab.clone(), a.arm.clone()).cmp(&(b.lab.clone(), b.arm.clone())));
    rows
}

fn selftest(root: &Path) -> (bool, Value) {
    let rows = survey(root, &[]);
    let agent_arms: Vec<String> = rows
        .iter()
        .filter(|r| r.agent_calls > 0)
        .map(|r| format!("{}/{}", r.lab, r.arm))
        .collect();
    let delegated: Vec<String> = rows
        .iter()
        .filter(|r| r.delegation)
        .map(|r| format!("{}/{}", r.lab, r.arm))
        .collect();
    let ok = !rows.is_empty() && (!agent_arms.is_empty() || !delegated.is_empty());
    (
        ok,
        json!({
            "arms": rows.len(),
            "with_delegation_clause": delegated.len(),
            "with_agent_calls": agent_arms.len(),
            "agent_arms": agent_arms,
        }),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from("practice/eval");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--root" {
            if let Some(v) = it.next() {
                root = PathBuf::from(v);
            }
        }
    }
    let labs = opt_all(&args, "--lab");
    if !root.is_dir() {
        report::failure(
            "dispatch_survey",
            &format!("root not found: {}", root.display()),
            "pass --root pointing at the practice/eval checkout",
        );
        std::process::exit(2);
    }
    if args.iter().any(|a| a == "--selftest") {
        let (ok, detail) = selftest(&root);
        let _ = report::success(
            "dispatch_survey",
            json!({"selftest": ok, "detail": detail}),
            "run without --selftest for the full per-archive table",
        );
        return;
    }
    let brief = args.iter().any(|a| a == "--brief");
    let rows = survey(&root, &labs);
    let with_delegation: Vec<Value> = rows
        .iter()
        .filter(|r| r.delegation)
        .map(|r| json!(format!("{}/{}", r.lab, r.arm)))
        .collect();
    let deepwater_rows: Vec<Value> = rows
        .iter()
        .filter(|r| r.form == "deepwater")
        .map(|r| {
            json!({
                "archive": format!("{}/{}", r.lab, r.arm),
                "lane": r.lane,
                "delegation_clause": r.delegation,
                "agent_calls": r.agent_calls,
            })
        })
        .collect();
    let with_agent: Vec<Value> = rows
        .iter()
        .filter(|r| r.agent_calls > 0)
        .map(|r| json!({"archive": format!("{}/{}", r.lab, r.arm), "form": r.form, "lane": r.lane, "agent_calls": r.agent_calls}))
        .collect();
    let deepwater: Vec<&Row> = rows.iter().filter(|r| r.form == "deepwater").collect();
    let table: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "archive": format!("{}/{}", r.lab, r.arm),
                "form": r.form,
                "lane": r.lane,
                "delegation_clause": r.delegation,
                "agent_calls": r.agent_calls,
                "dispatch_head": r.dispatch_head,
            })
        })
        .collect();
    let data = json!({
        "root": root.to_string_lossy(),
        "arms_total": rows.len(),
        "arms_with_delegation_clause": with_delegation.len(),
        "arms_with_agent_calls": with_agent.len(),
        "deepwater_form_arms": deepwater.len(),
        "deepwater_with_delegation": deepwater.iter().filter(|r| r.delegation).count(),
        "deepwater_with_agent": deepwater.iter().filter(|r| r.agent_calls > 0).count(),
        "delegation_archives": if brief { json!([]) } else { json!(with_delegation) },
        "deepwater_archives": deepwater_rows,
        "agent_archives": with_agent,
        "table": if brief { json!([]) } else { json!(table) },
    });
    let _ = report::success(
        "dispatch_survey",
        data,
        "cross-check agent_archives against their run dirs before booking an orchestration rate",
    );
}
