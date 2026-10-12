---
metadata:
  node_type: memory
name: "PRS lab scan non-standard data structures"
description: "sn-3 lab-scanning-non-standard-data-structures 实录:会话 cookie 即「非标准数据结构」且带完整性校验(不合约 500 \"Integrity violation detected\"),注释式与引号配平式 SQL 注入全数被挡;未翻牌"
last_updated: 2026-10-12T15:50:40+08:00
created: 2026-10-12T15:50:40+08:00
---

## 题况
- lab: `using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures`,widget id `AA337200EF03F4ADB1C669E54C672A13150D20A25CEE6622930F71C424F0AFFC`,实例 `0a880015040964b880be53ed001c00f5.web-security-academy.net`,jar `/tmp/cj1.json`(wiener:peter 已登录),横幅始终 Not solved。

## 结构性发现(可复用)
- **「非标准数据结构」= session cookie 的 `<username>:<token>` 自定义格式**:URL 编码用 `%3a` 作分隔符,匿名态形如 `:<32位随机token>`;token 为随机串(匿名 cookie 每次请求都不同,故非用户名派生,无法伪造)。
- **cookie 三态**:①(用户名, token) 都合法→会话成立;②token 未知/非法→降级匿名(302 `/login` 或换新匿名 session);③token 命中但用户名不符、或用户名畸形→**500 统一页** `Integrity violation detected`(2480 字节,digest `aa136edf6af38e3e`)。该 500 是**完整性/一致性检查失败**,不是可读 SQL 报错。
- **cookie 槽位注入已封(两路都试透)**:注释式(`wiener'-- `/`#`/`wiener' OR 1=1#`)与**引号配平、无注释符**式(`wiener' OR 1=1 OR '1'='1` / `'a'='a` / `AND 1=0 OR 'a'='a`,针对多行 SQL 注释失效场景设计)全部返回同一 500;用户名换 `administrator`、空用户名 `:TOKEN` 同样 500。⇒ 该 cookie 是服务端校验的(用户名, token)二元组,非 SQL 拼接。
- **`/analytics` 是黑洞但会过会话中间件**:任意方法/参数/JSON 体均 200 空体;但带畸形 cookie 时同样 500 ⇒ 无 oracle,非注入面。
- **`id` 参数的数组形`id[]`/`id[0]`/`id[x]` 会跳过 `?id=` 的归属校验**(标量取外名 id 会 302 `/login`,数组形返回 200),但页面仍是**会话自己的**账户页(digest 与 `id=wiener` 完全一致)⇒ **无 IDOR 泄漏**,只是一个"参数被忽略"的非标准结构 quirk。
- 其它已封面复核:`postId` 严格数值(`Invalid blog post ID` 400)、`search` 子串匹配且引号转义、`email` 字段无服务端校验(任意串入库并在 /my-account 渲染)、数组形字段名被拒(`Missing parameter 'email'`)、请求头(UA/Referer/XFF/XFH/X-Marker)在 /、/post、/my-account、/admin、500 页**均无反射**。
- 路由全集(112 条路线扫描后确认):`/`、`/login`、`/logout`、`/post`、`/post/comment`(仅 POST)、`/my-account`、`/my-account/change-email`、`/admin`、`/admin/users`、`/admin/panel`、`/analytics`、`/image/<path>`、`/resources/*`;`/admin*` 三页统一 401 `Admin interface only available if logged in as an administrator`。**无隐藏端点**。

## 未解决线索(下臂起点)
- 题目要求"delete carlos"⇒ 必须拿到 admin 会话;迄今未见任何通往 admin 的路径(无 SQLi 输出面、无 IDOR、无头注入、无 token 伪造面)。
- 唯一未做的动作:**`POST /post/comment` 从未实发过**(先前臂声称"表单值面全谱",未自证),应实测 `name`/`website`/`comment` 的注入与 `website` 存储 XSS。
- `email` 无校验入库:应确认 /my-account 的 `<span id=user-email>` 是否原样输出(自 XSS),以及 admin 面板是否渲染该邮箱(若有 admin 会话则为二阶面)。
- 纠偏:实例 `reused:true`(此实例被先前臂用过,postId=1 上留有 tester 的测试评论),排场须先 `banner_verdict` 判态。

