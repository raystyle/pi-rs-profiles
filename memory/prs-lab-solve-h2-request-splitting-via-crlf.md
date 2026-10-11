---
metadata:
  node_type: memory
name: "PRS lab solve h2 request splitting via CRLF"
description: "solved: h2 CRLF 拆分走 RQP 盈余路 — smuggled 完整请求 CL=前端尾巴 36 字节,burst 留待处理 + fresh 连接收割拿到受害者登录 302 管理员会话,删 carlos 翻横幅"
last_updated: 2026-10-12T05:51:02+08:00
created: 2026-10-12T05:51:02+08:00
---

## 终态: solved — 删 carlos 翻横幅(instance 0acd00a3…,reused)

题:lab-request-smuggling-h2-request-splitting-via-crlf-injection(HTTP/2 请求拆分 + CRLF 头注)。
题面本意是 response queue poisoning;本次按「先建盈余、再收割」的 RQP 走通。

### 走通链(判 solved 的三段证据)
1. `h2split_login --mode surplus --cl 36 --burst 10 --harvest 45`(新件,项目层)发射;
   收割段第 1 发(fresh 连接)收到 **受害者登录 302**:`Location: /my-account?id=administrator`
   + `Set-Cookie: session=MBDXFAO9XwEebvXgjyVk5yLS5eAgKtvg`。
2. `http_session get /admin --jar /tmp/h2split-jar.json` → 200,面板列 wiener + carlos。
3. `http_session get /admin/delete?username=carlos --follow` → 302→/admin,body 含
   `User deleted successfully!`,横幅 `notification-labsolved`;`banner_verdict` solved:true。

### 机制(H2 降级 + CRLF 头注的真实帧形)
- 注入点在任意 h2 头值:值 = `x\r\n\r\n<smuggled h1 request>`;外层的 `GET /` 只是载具。
- **前端在注入值之后追加固定尾巴 `\r\nVia: proxy1\r\nContent-Length: 0\r\n\r\n`(36 字节)**;
  该尾巴落在 smuggled 请求的 body 区(不是它的头)。
- 把 smuggled 请求做成**完整请求**且 `Content-Length` 恰等于 36 ⇒ 身体正好吃掉尾巴,
  后端随即把受害者的请求当作**下一条干净请求**处理 ⇒ 前端请求数比后端应答数少 1,
  受害者登录响应(302+管理员 Set-Cookie)成为**队列盈余**;此后任一被分到该上游的连接
  发请求即可拿到它。收割段用 fresh 连接是收割盈余的关键(同一 arm 连接的探针只会吃掉
  它自己那条 lod 应答)。

### 坑(都实测过)
- **hungry split-login(body 取自受害者)不解**:登录 302 会按 FIFO 配给受害者自己的请求,
  我方拿不到;`CL=H`/`H±20` 扫描无意义。
- **单条 arm 连接留不住受害者请求**:需 `--burst` 多条同时留待处理;capture 类件能捕获
  正是因为它一次 burst 多条。
- 探针留在 arm 自身连接上 → 收到的是 `POST /login` 的**登录页 200(body 3299 vs 首页 8839)**
  = 已错位但拿的是自家盈余;必须换 fresh 连接收割才能撞到受害者那条。
- capture/评论侧路不通:评论值**止于第一个 `&`**(登录体首 &),且先前 over 太小只抓到
  登录 POST 前 ~287 字节,Cookie 头在 ~720 字节处 ⇒ 抓不到受害者 Cookie。

### 件
新造 `.pi-rs/rust-scripts/h2split_login.rs`(project 层,1.0.0):`--mode surplus|hungry`、
`--cl`/`--cl-range`、`--burst`(同时 arm 多条,留待处理)、`--harvest`(窗口后 fresh 连接收割)、
`--probes`、`--check-path` 自动复验并写 jar;`--selftest` 过。先前件
(`h2split_capture`/`h2_crlf_fill`/`h2split_diag`)的 FRONTEND_TAIL 常量(23/35)均偏,
真实尾巴 36。

