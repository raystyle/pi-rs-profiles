---
metadata:
  node_type: memory
name: "PRS fp-1 host-header SSRF flawed-request-parsing blocked"
description: "fp-1 lab-host-header-ssrf-via-flawed-request-parsing 判 blocked：_lab 400 真因是陈旧 cookie（fresh 立即重放→200，但不改 Host 路由），前门是 academy-only host allowlist（别的实例名 504 出站 / 非 academy 403 / 语法非法 421），绝对形 URL host 本地拒且 Collaborator 零出站；11 类旁路全封"
last_updated: 2026-10-12T14:24:13+08:00
created: 2026-10-12T14:24:13+08:00
---

## fp-1 lab-host-header-ssrf-via-flawed-request-parsing — 实例内不可达（blocked）

实例 0a7f001c0318d62481a3709100ea00b9.web-security-academy.net（range_launch reused:false，jar /tmp/cj1.json；lab_id FDA35864…C7D772）。判据目标：内网 192.168.0.0/24 管理面板 → 删 carlos。**终态 blocked**：路由原语在门（academy 前门）之前被 host allowlist 封死，且绝对形 URL 方向为本地拒绝、无出站。

### 1. `_lab` 反作弊的真机制（推翻前鉴）
`_lab` 是**轮换型会话 cookie**，每条响应都新发一个，旧值立即失效。用「刚 Set-Cookie 出来的」`_lab` **立即重放** → 正确 Host 200；用 browser jar 里捞出的旧值 → 400「Too Nosy / Tampering with the _lab cookie is not required」。历史「自供 _lab 触发 400」的真因是**陈旧值**，不是反作弊墙。关键：**有效 `_lab` 不改变 Host 路由**（fresh `_lab` + `Host: 192.168.0.1` 仍 403；fresh `_lab` + 绝对形内网 URL 仍 403）⇒ 该 cookie 无杠杆价值。

### 2. 前门就是一个按 Host 路由的转发代理（allowlist = academy 实例名正则）
- `Host: <另一 academy 实例>` → **504**「Gateway Timeout (0) connecting to <host>」= 真的发起连接（本文最重要的可证事实：Host 段驱动出站路由）。
- `Host: 192.168.0.1` / `example.com` / `192.168.0.1.web-security-academy.net` → **403**「Client Error: Forbidden」（无 `_lab` Set-Cookie = 门直接拒）。
- `Host:` 语法非法（尾点、全大写、多标签、`#`）→ **421**「Invalid host」；重复头 → **400** JSON `{"error":"Duplicate header names are not allowed"}`。
- 全 /24 扫描（Host: 192.168.0.1-254）= 254/254 同一 403（判定：非按目的地路由，而是门前 allowlist）。
- 两台前门同一 ACL：`*.web-security-academy.net`（79.125.84.16 / 34.246.129.62）与 `*.h1-web-security-academy.net`（54.73.218.40 / 52.211.85.118）。

### 3. 绝对形 URL host 被本地拒绝、无出站（Collaborator 零交互）
`GET http://192.168.0.1/admin` + `Host: <实例>` → 403；指向 `*.oastify.com` 同理 403，`burp_collab` 两轮 poll `raw_count:0` ⇒ **没有发起任何出站解析/连接**，拒绝发生在门前。`Host: <另一实例>` + 绝对形内网 URL → 504（先按 Host 连接，说明门的检查在 Host 段，URL 段由下游/门前另一层拒）。

### 4. 本轮实测封死的旁路面（全部走件）
重复 Host（`lab,IP` 403 / `IP,lab` 400 JSON / `Host:`+`HOST:` 403）、userinfo（`lab@IP` 403、`IP@lab` **200 自身首页**）、fragment/query/path 夹带实例名（403）、`//192.168.0.1[/admin]` 目标（两侧都当**路径**，lab 返回 11B `"Not Found"`）、`://` 单斜杠（同样当路径）、HTTP/1.0 无 Host + 绝对形内网（403）、h2 `:authority`+额外 `host` 头（GOAWAY）、h2 `:path` 绝对形（403）、h2 头值内 CRLF（RST_STREAM）、`X-Forwarded-Host` / `Forwarded` / `X-Original-URL`（无路由效果，回落自身首页 200）、直连实例公网 IP（同一前门）。

### 5. 可复用结论
- 新题首触即用 `browser_suite` 领真 `_lab` 的路子对**本题无效**；但「`_lab` 必须取响应即时值」这条对任何 academy 题都成立（旧值一律 400 Too Nosy，极易被误判成反作弊墙）。
- academy Host 段判定三态：`*.web-security-academy.net` 的 32hex 实例名 → 放行并**按该名出站**；其它任何 host → 403；Host 语法非法 → 421。`_lab` Set-Cookie 存在与否可用来区分「门前拒」与「门后拒」。
- 件面够用：`raw_matrix`（变体矩阵）、`conn_reuse`（字节级 + 全头回读）、`abs_sweep`（Host 段 /24 扫描）、`h2_req`（h2 伪头/CRLF）、`burp_collab`（出站判定）、`chrome_cookies`（离线取 jar）。无新件需求。

