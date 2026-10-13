---
metadata:
  node_type: memory
name: "PRS sn-7 scanning-non-standard-data-structures round"
description: "sn-7 盲载荷/引爆轮:会话 cookie label 半 = integrity 500 墙,postId/quant 面全 302,website scheme 服务端强制,collab 零回调;48 件未解"
last_updated: 2026-10-12T21:46:38+08:00
created: 2026-10-12T21:46:38+08:00
---

## 2026-10-12 — lab-scanning-non-standard-data-structures(实例 0a540085048e3a6e801b126500c900ee,reused:false)

终局:未解(48 件调用后收口,banner_verdict → /tmp/sn7-verdict.json solved:false)。
题面(解块已剥离):"vulnerability ... located in a non-standard data structure; use Burp Scanner's Scan selected insertion point ... then delete carlos"。

### 唯一的非标准结构:会话 cookie `session=<username>:<token>`
- 中间件全局生效(`/`、`/post`、`/login`、`/logout`、`/admin`、`/my-account`、`/post/comment/confirmation` 全测)。
- **用户名半 = 严格相等校验**:任何改动 → 500 静态页 “Integrity violation detected”(2480 B;`GET /` 变体 2382 B,仅少 “Back to lab home” 链接)。空用户名 `:TOK`、`WIENER:TOK`、`wiener :TOK`、`xwiener:TOK`、`%00`/`%22`/`{{7*7}}`/`<script>` 一律 500 ⇒ 无前缀/大小写/trim/编码绕过。
- **token 半 = 纯查表键**:SQL(`' OR '1'='1`、`UNION`、`;`)/NoSQL/XPath/`%`/长串 全部 302 → 无注入(若有注入,`' OR '1'='1` 会返回行并触发 integrity 500,实测 302 反证)。
- 解析:先 URL 解码再切分(`wiener%3aTOK` = 200),恰需 2 段(3 段 → 302);token 每次登录新生成(非用户名派生),再次登录会作废旧 token(同一用户仅一个活会话,约数分钟即失效,重测前须重新登录)。
- 复合/重复 cookie 结构:两枚 session(两种顺序)、逗号/逗号空格分隔 → 401 或 500,无「校验用一枚、授权用另一枚」的错位。

### 其余面(均墙或惰性)
- 评论四槽 HTML 转义完整(`CMT7&lt;b&gt;`、`&quot;`),website 虽是 `href` 但服务端强制 scheme(`javascript:` → 400 `"Invalid website."`);无自动加载引爆向量。
- ACL 头绕过(X-Original-URL / X-Rewrite-URL / X-Forwarded-For / X-Custom-IP-Authorization)→ 仍 401;`/.env`、`/.git/HEAD`、`/session` 404;`/analytics` 恒 200 空体(惰性,带任何参数都不变);`/post?postId=` 非数字 → 400 `"Invalid blog post ID"`。
- 实例无 exploit server(首页 HTML 无 exploit-link);全程无 admin bot 迹象。
- 被篡改的用户名标记(MARK7)在任何后续页面都不出现 ⇒ 无存储型回显。
- burp_collab 公开轮询(oastify 载荷存进评论后)两次零交互。

### 环境/工具要点
- http_session/page_read 会剥 `<script>`;要看原始 HTML 必须 `http_dump --out`。本 app 页面除 labHeader.js 外无自有脚本(纯服务端渲染)。
- raw_matrix 自动补 `Host` 与 `Connection: close`;变体里再写 `Connection` 会 400 "Duplicate header names are not allowed"(Host 可写,写了不会重复)。
- 带 body 的 raw_matrix 变体必须自己算准 Content-Length,否则后续连接错位(实测 read timeout)。

