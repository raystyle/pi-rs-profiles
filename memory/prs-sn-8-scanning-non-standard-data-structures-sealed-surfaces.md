---
metadata:
  node_type: memory
name: "PRS sn-8 scanning-non-standard-data-structures sealed surfaces"
description: "sn-8 信道换向轮未翻牌:证明 session 按 token 查表后 label 字符串比对(label=foo+垃圾 token→302),cookie 绝对封;三线全负;指纹=Node/Express"
last_updated: 2026-10-12T23:42:15+08:00
created: 2026-10-12T23:42:15+08:00
---

## 2026-10-12 信道换向轮(42 件,未翻牌)

题:`essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures`;实例 0ae700a8…(range_launch launch-url,jar /tmp/cj1.json),目标删 carlos。终局 banner_verdict solved:false(/tmp/sn8-verdict.json)。

**决定性机制(新证)**:session 结构 `<label>:<token>`,服务端**只按 token 查会话(参数化)**,再把 label 与查到用户的用户名做**字符串比对**,不符 → 500「Integrity violation detected」(HTML 2480B)。反证:label=foo + 垃圾 token → **302 /login**(说明查表键是 token,label 根本不进查询)。因此 label 无 SQLi(语法错/UNION 2–8 列全部同一 2480B 完整性 500),token 注入全 302。cookie 绝对封。

**指纹**:Cookie 头里裸 `%`(或 `%zz`)→ 21 字节纯文本 500;`%25`→正常 → 单次 decodeURIComponent 抛 URIError ⇒ **Node/Express + cookie-parser** 栈。

**本轮三线(全负)**:
1. API 面:Accept json/xml、X-Requested-With、Content-Type:application/json 对/,/login,/my-account,/admin,/analytics,/image,/post 无 JSON/XML 表示(未知路由统一 404 `"Not Found"` JSON);OPTIONS/PUT/PATCH/DELETE/TRACE 无 Allow、无方法旁路(/my-account 的 PUT 等同 GET)。
2. 删除路由:/admin/* 全前缀 401,任何方法+体形(POST body username=carlos、path 形 /admin/delete/carlos、/admin/users/delete、/admin/delete-user)均 401;`/delete`、`/delete-user`、`/user/delete` 等 404。注意:/logout 会真杀会话,杀后测 /admin 的 401 是「未登录」,须重登再测(本轮已重登复测,仍 401)。
3. change-email:只吃 form `csrf`+`email`;JSON 体→400 Missing 'csrf';email[]→400;额外字段 isAdmin/role/admin/privilege 被忽略,重登后 /admin 仍 401(无 mass assignment)。

**其它负**:路由枚举 63+21 名全 404/401;`/post/comment`(未知端点)与 `/post/comment/confirmation` 存在,confirmation 的 postId 未校验但反射为 HTML 转义(&apos;/&quot;);/image 走路径(/image/blog/posts/N.jpg),`..`/`%2e%2e`/前缀式穿越全 404;search 为子串匹配(非 SQLi);postId 严格 int;`?__proto__[…]` 无效;oastify Collaborator 0 交互(无 SSRF/无 bot);无 `/setlang`/lang 面。

**未解缺口**:本 app 除 session cookie 外未见任何「非标准数据结构」;该结构的唯一自定部分是 label/token 二分且已封。下一轮若继续,候选:摸清 token 是否可枚举/其它 Set-Cookie(如按用户 token 的旁路端点)、或确认 lab 是否另有隐藏端点(confirmation 类已现一例)。

