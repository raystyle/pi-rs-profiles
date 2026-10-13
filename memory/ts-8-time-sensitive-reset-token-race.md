---
metadata:
  node_type: memory
name: "ts-8 time-sensitive reset token race"
description: "ts-8 solved: lab-race-conditions-exploiting-time-sensitive-vulnerabilities cracked with independent-session single-packet h2; new piece ts8_race"
last_updated: 2026-10-12T22:45:18+08:00
created: 2026-10-12T22:45:18+08:00
---

## 2026-10-12 ts-8 lab-race-conditions-exploiting-time-sensitive-vulnerabilities — SOLVED

实例 0ae1000c040be8f38154865e00a10040，verdict /tmp/ts8-verdict.json（solved:true + congrats 行）。

### 决胜几何（本轮证实）
- **每个请求独立 session（独立 phpsessionid + 该 session 的 csrf）是唯一钥匙。** 以匿名 GET /forgot-password 取 N 份 (session, csrf)，再把 1 carlos + K wiener 的 POST /forgot-password 作为 h2 stream **单包**齐发，token 立刻出现重复。
- 5 轮 CWWW 实测：round 1 三个 wiener 三枚相异；round 2 三枚全同；round 3/4/5 各两同一异。即同日历秒内多次独立 session 并发 -> token 重复率约 4/5 轮。
- 反证：上一轮"只对齐到达时刻、不换 session"为零碰撞；同 session 的请求被应用按 session 串行化，齐发到达也不会同刻生成。
- 复现出的 token 与 carlos 同一批共享：round 5 的 distinct token 为 650a1cfd… 与 63227935…（后者 ×2）；**63227935… 被服务端判 Invalid token，650a1cfd… 对 carlos 被接受** -> 同轮不同 token 分属不同时片，必须逐个试。

### 三个坑
1. **邮箱 diff 不能用位置差**：lab 邮件列表按时间倒序，新邮件是前缀；位置差分会被页面行数变化坑住（本轮它把 3 枚新邮件报成 1~2 枚，直接吞掉重复信号，导致自动收口判"零碰撞"）。正解=序列前缀差分 `after[k..].starts_with(before)`。已写成 new_rows() 并进 selftest。
2. **carlos 的活 token 只由最后一次 carlos 请求决定**：多轮连打时，早轮复现出的重复 token 已过期；必须用当轮或重跑后立即取。
3. **/admin 删除的横幅语义**：GET /admin/delete?username=carlos 返回 302 并**轮换 phpsessionid**（carlos 会话失效），横幅只在重定向目标页翻；且首次删除后 /admin 仍可能列出 carlos（"User deleted successfully!" 却仍在列），需再删一次才 is-solved。

### 收口序（已验证）
harvest N 匿名 session -> h2 单包 CWWW -> 读邮件取新 token -> 有重复则对当轮 distinct token 逐个开门（GET /forgot-password?user=carlos&token=T，form 渲染=接受）-> POST csrf/token/user/new-password-1/2（302）-> POST /login carlos（302 /my-account?id=carlos）-> GET /admin/delete?username=carlos（302 + 会话轮换）-> 横幅 is-solved。

### 新件
`ts8_race` (project, v1.0.0)：独立 session 采集 + h2 单包 CWWW/任意 layout + 邮箱新行序列差分 + 重复判定 + 自动逐候选接管；`--takeover-token T` 单发复验模式；`--selftest` 覆盖 csrf 解析/frame 构造/urlenc/新行差分四断言。

