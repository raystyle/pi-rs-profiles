---
metadata:
  node_type: memory
name: "PRS sn-2 scanning non-standard data structures round 2"
description: "sn-2 第二轮:全表单/端点/请求头面盘点与探测全部封闭,第三插入点位仍未定位"
last_updated: 2026-10-12T15:17:01+08:00
created: 2026-10-12T15:17:01+08:00
---

lab-scanning-non-standard-data-structures(essential-skills/using-burp-scanner-during-manual-testing),实例 0a880015…,wiener:peter,本轮未翻牌。

机制面(自测复核,与上轮一致)
- session cookie 值 = `username:token`(冒号分隔,用户名可为空=匿名)。token 为 base64(24 随机字节),每次登录/每请求都换,非用户名派生。
- 解析为先冒号切割:token=首个冒号之后的全部。token 不存在→302 /login 换匿名会话;token 存在但 cookie 用户名与会话属主不符→500 "Integrity violation detected"(固定 2480 字节,全局含 /admin)。未知 token 不自动建会话。JSON 形态/数组/重复 cookie/空值/JSON 体一律否。
- /my-account?id=U:无 id→显示会话用户;U 与会话用户名精确相等→200;否则→302 /login(不是 403)。?id[]=U、重复 id 均被忽略或取末值,无绕过。id 值含引号/注释不产生 SQL 错误(比较在查询前,纯字符串)。
- 全表单面:login(csrf/username/password)=参数化(wiener'-- - 返回 200 无效);search=LIKE 且参数化(% 与 ' OR '1'='1 不改变结果数,仅字面反射);postId=严格整数(1' / 1.0 / 0x1 均 400 "Invalid blog post ID");change-email(csrf 会话绑定,过期 400 "Invalid CSRF token",email 正常存储)。csrf 与 session token 同类(32 位随机)。
- comment(csrf/postId/comment/name/email/website):postId 同样严格整数;渲染时 comment/name/website 全部 HTML 转义(&lt;b&gt;、&quot;),无存储 XSS;website 进 href 属性但已转义;POST 后 302 到 /post/comment/confirmation?postId=N(该页忽略 postId 值)。
- 端点盘:56 条路径枚举仅 /admin、/admin/users、/admin/roles、/admin/delete 存在(全 401),余 404 JSON "Not Found";/logout 302(会毁会话,枚举时注意);/image?filename= 404(无 path-traversal 腿)。
- 请求头面:header_fuzz 24 头零反射零长度差;X-Original-URL / X-Forwarded-For / 额外 admin 类 cookie 均不翻 /admin 401。
- /admin?id=administrator、/admin/delete?username=carlos&id=administrator 均 401。

结论:第三插入点位仍未定位;表单/查询/头/端点四面对已识别槽位全部封闭;唯一非标准结构仍是 session cookie,其完整性闸把双槽锁死。

