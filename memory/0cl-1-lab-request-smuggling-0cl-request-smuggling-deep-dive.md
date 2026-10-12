---
metadata:
  node_type: memory
name: "0cl-1 lab-request-smuggling-0cl-request-smuggling deep dive"
description: "0.CL 题(lab-request-smuggling-0cl-request-smuggling)实测:前端自服务 /resources/*、其余路径串行转发且忽略空格 CL;后端按值等体 ⇒ 双发分叉无法成立,未解;新增调谐件 zc0cl"
last_updated: 2026-10-12T09:33:49+08:00
created: 2026-10-12T09:33:49+08:00
---

## 2026-10-11 深水专攻 0cl-1（未解，机制面收敛）

实例：`https://0ade000e037fb9db808121b6008c005a.web-security-academy.net/`（range_launch launch 4bad74c3...；reused:false）。正确题面 slug 在 `/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling`（不带 `/advanced/` 会 404；用 sitemap.xml 枚举定位）。

### 实测事实（全部走件、可复现）
1. `/post?postId=1` 把 User-Agent **未转义**回显进 `<input name="userAgent" value="...">`（`value="A"><svg onload=alert(1)>B">` 实证）⇒ 载荷面可用 `"><svg onload=alert(1)>`。
2. **前端自服务 `/resources/*`**：`/resources/images/blog.svg`、`/resources/css/labsBlog.css`、`/resources/images/avatarDefault.svg` 对带空格 CL 头的请求立即回 200。分离实验（attack1=静态、attack2=动态 `/post?postId=1`）中 attack2 被后端当**普通请求**答复（帖子页 200），证明静态 attack1 从未进入后端、后端无挂起体 ⇒ 静态 gadget 不能用于本配方。
3. **后端按值读空格 CL**：`Content-Length : N`（名与冒号间一个空格）在应用侧所有被测路由（`/`、`/post?postId=1`、`/zz-nonexistent-991`、`/image/blog/posts/25.jpg`）都**无早响应**（2.5s 内 0 字节）⇒ 后端解析该头并在等 N 字节体。
4. **前端忽略该头**：自带 8 字节体（`...Content-Length : 8\r\n\r\n12345678`）仍 0 响应 ⇒ 不是前端在等体，也不是前端把体内联消费（排除 CL.0 镜像形）。
5. **前端串行**：attack1+attack2 一次写入（pipeline）与分段写入（含 1.2–2.5s 间隔）两种，动态 gadget 下 arm 连接全程 **0 响应** ⇒ 前端等后端响应期间不把下一条客户端请求转发到同一后端连接；「第二条前 N 字节被后端当体吃掉」这一步无法发生。
6. 受害者探针（新连接 GET /）始终拿到正常首页（8264 字节），无投毒。

### 结论
派单参照系的「空格 CL 双发」0.CL 配方在该实例上结构性受阻：可分叉的一侧（后端等体）无法被喂到字节，喂字节需要「跨请求流水线到同一后端连接」，而前端不做。静态 gadget 又被前端自身接管（后端不参与）。未达成 alert 翻横幅。
若后续再攻：需要后端存在「不读体即响应」的路由（已排除 `/`、`/post`、404 路由、`/image/*`），或前端换成可流水线的层；否则应改用经前端自服务路径的 Expect 腿并单独解决「中毒后连接交还给受害者」的交付面。

### 件
新增 `zc0cl`（1.0.0，project 层，`.pi-rs/rust-scripts/zc0cl.rs`）：空格 CL 调谐/利用探针 —— 可换 attack1 方法、attack1/attack2 路径分离（`--gadget2`）、`--pipeline` 单写双发、`--cache-bust`、逐轮报 a1 早响应与 a2 响应条数、受害者探针（`--sim-victim`/`--victim-conns`），循环内点 `pi_rust_lib::timeout`。未跑 catalog regen（批外造件，避免改仓）。

