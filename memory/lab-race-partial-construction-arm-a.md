---
metadata:
  node_type: memory
name: "Lab race partial construction arm A"
description: "pc lab arm A 本代终态:未破;写侧窗口 5×NEW/3×DUP 复现,读面 login 72/72 fail、confirm 78/78 403 全 miss,错误/邮件回显面均闭 ⇒ 隔离级全 miss 实证"
last_updated: 2026-10-11T07:14:30+08:00
created: 2026-10-10T10:31:41+08:00
---

## 2026-10-10 lab-race-conditions-partial-construction (arm A) - 未解出

靶场: PHP 应用 (平台每请求约 0.25-1s, Connection: close)。目标: 绕过邮件验证拿到 ginandjuice 账号并删 carlos。终态: 未解出, carlos 未删, banner 未翻。

### 已确证的应用面
- 注册: POST /register (username/email/password/csrf, csrf 会话绑定)。username 唯一(重名报 "An account already exists with that username"), email 不唯一(同邮箱重复注册返回成功页)。
- email 校验严格: 必须合法且域为 ginandjuice.shop; 双 at、子域、exploit 域全被 "Invalid email address" 拒。
- 注册后账号不可用: 正确口令登录仍 "Invalid username or password"; 无 wiener:peter 种子。
- POST /confirm?token=X: 400 "Incorrect token: X" (未命中); token 为空串或空数组 -> 403 "Forbidden"; token 含 NUL (%00) -> 500; token[]=x -> 400 "Incorrect token: Array" (PHP 侧比较迹象, 非 PDO 绑定)。
- GET /confirm?token=X 只渲染通用 "click the button" 页, 不校验; confirm 只读 query 的 token (空 query 加 body token 仍 403)。
- /admin 与 /admin/delete 无会话时 401 "Admin interface only available if logged in as a GinAndJuice user" (门禁正常)。

### 已排除的路径(逐条实测)
- confirm 空/0/null/NULL/false/undefined/Array/32hex 及请求派生值(用户名/邮箱/csrf/口令/session id): 全部 400/403, 含 100 流单包齐发、120s 连续播撒 (570 次空 token 全 403)、同会话空 token。
- 登录面窗口: 注册期间并发登录 (单会话串行 13 次 / 驱动 60 次 / 六账号并发验证) 全失败; 同会话读 /admin 与 /my-account 全 401/302。
- 非竞态旁路全负: 注册表单 mass assignment (confirmed/verified/token) 无效; token 参数无 SQLi (LIKE/引号/反斜杠/UNION 均干净, 但 NUL 500 说明 token 进过拒 NUL 的上下文); 无 token-as-path 行为; 用 carlos 邮箱注册不覆盖种子行; 邮箱域解析绕过被挡; 实验室邮箱只显示 exploit 域收件 (空)。

### 环境事实
- 每请求约 0.25-1s (Connection: close => 每请求新 TLS), HTTP/1.1 播撒被压到约 5 次/s; h2 单连接多流廉价, 但同一包内 register 在首 => 读侧多半排其后, 窗口不可观测; 需 h2 定速放流 (pacing) 才能对齐 late 窗口。
- h2 可用 (h2_probe 200, ALPN); h2_burst 100 流约 6s 出齐响应。
- 新件: .pi-rs/rust-scripts/pcreg_race.rs (注册 + 确认播撒 + 登录面并发 + 自动复验 + /admin 删除的驱动, selftest 通过), 本题未解出, 可复用于半构造注册族。


## 2026-10-10

## 2026-10-10 lab-race-conditions-partial-construction (arm A, 真深 lane 2-2 件参调专场)

**发射钥匙(关键环境事实)**:`range_launch` 用 `~/.pi-rs/agent/lab-jar.json` 或 `chrome-jar.json` 都会落到 `login.portswigger.net`(auth0 过期,`oidc_form_submitted:false`,`instance_url:null`)。可用钥匙是 `/tmp/cj1.json`——它含新的 `portswigger.net` 会话(`.AspNetCore.CookiesC1/C2` + `SessionId` + `Authenticated_UserVerificationId`),直接 `range_launch launch-url <lab-page> --jar /tmp/cj1.json` 即出实例。旧实例 `0a6000ca…` 已 504 死掉(实例会过期),须重发。

**本代实例**:`https://0ac400ba398d36c8185d410005e000e.web-security-academy.net`(注意实际为 0ac400ba0398d36c8185d410005e000e)。


## 2026-10-10

终态: 未破(read 面全 miss 隔离级实证复判成立)。实例 0ac400ba0398d36c8185d410005e000e。

### 写侧窗口(证可达)
- h2_burst 同 session 8 流同名 `POST /register`(csrf+用户名+邮箱+口令)→ 逐流体长 **5×2636(NEW)/3×3142(DUP)**,两轮(pcwinA、pcwinC)完全复现;前 5 流全部穿过存在性检查。
- burst 后单发同名 register → DUP(3142)⇒ 已提交行对存在性检查可见;窗口内全过纯属「读在写前」的 TOCTOU,非全局去唯一约束缺失。

### 读侧双面(窗口内播撒,race_spread,class 分桶)
- login(SELECT by username):72/72 → 200 `Invalid username or password`(3801),**0×302**。确认标志门控把「行可见但未确认」掩成同一页 → login 非有效可见性 oracle。
- confirm(SELECT by token):78/78 → **403**(空 token 守卫在查询前),无其它类。
- 竞态族基线(本实例实测):register NEW=2636 / DUP=3142 / GET=3051;login GET=3724 / fail=3801 / 成功=302。

### 换维(回显面)两条均闭
- 错误页面:register 有 **username-format 档在 email/存在性/INSERT 之前短路**(`pcq'uote"<x>` → "Invalid username format",3121),不发生任何行读 → 无行回显;confirm 错误只回显入参(token[] → "Incorrect token: Array";占位符泄漏只泄查询形态)。
- 邮件/日志面:email 校验强制 `@ginandjuice.shop`(exploit 域 → "Invalid email address" 3119);exploit 收件箱只显 `@exploit-...exploit-server.net`,全空 ⇒ 令牌不可读。

### 判读
半构造行对一切非变异 oracle **不可寻址**;两候选机制(未提交事务不可见 / token 默认 NULL 不可匹)均无可见 oracle 可判,故记为隔离级全 miss。

