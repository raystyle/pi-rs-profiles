---
metadata:
  node_type: memory
name: "Deep-water lane stage self-inspection 2026-10-11"
description: "阶段自省验收：判读面样本 10/10 但全量 11/314 不一致（0cl A-3 真阳假判 + logic-flaws 三连旧锚漏判）、深水场 Agent 实际使用率 1/16（五 lane 0/13）、F3 无新尾段残迹（遗留 A-4 未收）"
last_updated: 2026-10-11T07:31:28+08:00
created: 2026-10-11T07:31:28+08:00
---

## 2026-10-11 阶段自省轮：判定面生产实效 + 编排实战复盘 + F3 收档门

**阶段定义（本轮考证）**：主台(Claude Code, glm-5.3, ~/.claude/projects/-mnt-wsl-repos-pi/2b1716ec-...jsonl)在本阶段派出两批：
- **C3b** = 压尾批 7 题（sql 3 / deser 2 / host-reset 2），本代 6 解 + phar 未解；派单形=runner(batch-desk)。
- **深水五 lane** = 五条并行车道，每条车道 = 一次 batch-desk 连滚（日志 /tmp/dw-*.log）：
  llm-trio(ipi / ai-scanner-defenses / ipi-via-ai-scan)、host(routing-ssrf / ambiguous)、
  1c(phar / pause / h2-wcp-tunnelling)、1d(frame-buster / dangling-prp / time-sensitive)、1e(h2-smuggling-crlf / h2-splitting=13 档)。
- **真深三** = 手写「深水攻坚」定制单（非 runner）：lane 2-1 h2-bypass A-3、lane 2-2 partial-construction A-4、lane 2-3 0cl A-3。

**item1 判定面（judge v3.16 = practice/eval/judge.py）**：指定样本 10/10 一致
（C3b: deser-phar A-1/A-2 + dangling A-1/A-2；深水五 lane: h2-splitting A-1..A-4 + frame-buster A-1/A-2）。
**但全量回放 314 档 = matched 251 / mismatched 11 / unrecorded 52，「零假阳零漏」不成立**：
- 真阳假判 1：0cl A-3（真深 2-3）锚文「未破｜…banner 恒 solved:false」→ judge solved=1。
  根因两条：D2 否定词表缺「未破」（有未解/未翻牌/未成…）；D3 窗内正向扫描命中臂自述里的裸子串
  「solved」（来自 `solved:false`），正向词表不辨极性。
- 锚形漏判 3：logic-flaws 三连（high-level / excessive-trust / insufficient-workflow）账面 solved、
  judge class=none —— 其 transcript 锚为旧形「终态(lab-slug):」（无 `/arm` 后缀），tag 匹配不到。
- 边界歧义 1：very-strict-csp A-1 同会话续跑进 A-2，A-1 目录 transcript 内含 A-2 腿的 receipt ⇒ judge 1 / 账面 stuck。
- 其余 6 = 账面首行陈旧（勘误行在 A-1 行之后追加）：angular-csp / llm-insecure-output /
  connection-state / proxy-page / prefilled / origin-server-normalization —— 判定面对、账面无改首行。
- 次要：judge.py docstring 仍写 v3.15（D1/D2/D3 注释已是 v3.16），版本行滞后。

**item2 编排实战**：深水场（五 lane 13 档 + 真深三 3 档 = 16 档）Agent 实际使用 1/16 ≈ 6%。
- 五 lane：13/13 派单词带委派句（runner v3.10 S4 委派句，commit 0887529），实际开火 **0/13**。
- 真深三：0/3 带委派句；实际开火 1/3（0cl A-3 派 deep-research 子代理一次）。
- 全库（305 档）：带委派句 85 档，真开火仅 3 档 —— flawed-parsing A-3(×3，编排试点)、
  prototype-pollution-browser-apis A-1(×1，唯一「带句且开火」样本，1.2%)、0cl A-3(×1，无句开火)。
- 读法：委派句不是开火的驱动；唯一在深水场开火的那档靠系统提示词路由广告 + 臂自判。

**item3 F3 收档门**：eval 仓 `git status --porcelain` 仅 2 项、全为 `??`
（grok-precedent-expert-granularity.md、lab-race-conditions-partial-construction/A-4/）；
live.txt M 数 = 0；未跟踪 dated jsonl = 0；树内 1-13 行 dated stub 全是 F1/G1(96160e6)轮扫入的旧残迹。
⇒ 本阶段无新增「commit 早于锚落盘」尾段残迹。残留同族缺口 1 项：真深 2-2 的 A-4 整目录未收
（无 transcript.jsonl、outcome.md 无 A-4 行 ⇒ 判定面与普查面双双不可见）。

**新件**（project 层，本轮铸）：`judge_replay`（--case 逐档 / --all 全库回放 + 与 outcome 比对 + selftest）、
`dispatch_survey`（派单形/委派句/Agent 调用逐档普查，--brief 省表）。两件均已入 rs_search 目录。

