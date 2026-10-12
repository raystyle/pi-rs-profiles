---
metadata:
  node_type: memory
name: "PRS lab sn-4 scanning non-standard data structures probing round"
description: "sn-4 scanning-non-standard-data-structures: 两线实测均无差分,应用全面编码/绑定/整数校验,会话 cookie user:token 有 integrity 守卫"
last_updated: 2026-10-12T16:32:44+08:00
created: 2026-10-12T16:32:44+08:00
---

- 题:PortSwigger "Scanning non-standard data structures"(essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures),lab_id AA337200EF03F4ADB1C669E54C672A13150D20A25CEE6622930F71C424F0AFFC;实例 0ae3002504d8809c80116c300028002f.web-security-academy.net(reused:false),登录 wiener:peter,jar /tmp/cj1.json;目标=删 carlos,未翻横幅。
- 应用面(全部实测):GET /(search) /post?postId= /post/comment(POST) /post/comment/confirmation?postId= /login /logout /my-account?id= /my-account/change-email(POST) /admin*(前缀守卫) /image/... /resources/...;未知路径一律 JSON `"Not Found"`,未知方法 `"Method Not Allowed"`+Allow 头,缺参 `"Missing parameter 'x'"`。
- 派单两线已闭环,均无差分:① comment POST 真发(含 multipart 变体)后 name/comment 均 HTML 实体编码,website 进 `<a href>` 且引号/尖括号编码(仅 scheme 不校验),email 不上任何页;② change-email 的 email 无服务端校验(`a'@b.c` 落库 302),/my-account 渲染为 `a&apos;@b.c`(转义),二阶渲染无差;额外 isAdmin/admin/roleid/username 字段被忽略(/admin 仍 401)。
- 附带发现:POST /post/comment **接受 multipart/form-data**(与 x-www-form-urlencoded 等价,含多余 file part 也被静默忽略,头像仍 avatarDefault);postId 在 GET 与 POST 两条路都被整数校验(`1'`/`abc`/超长 → 400 "Invalid blog post ID"),重复 postId 取最后一个。
- 排除的注入面:search 为绑定参数(`x' OR 1=1-- ` 仍 0 结果,`procrastination' OR '1'='1` 等均落空);login 引号载荷只回 "Invalid username or password";csrf 带引号 → 400 "Invalid CSRF token";/my-account?id= 必须等于会话用户名否则 302 /login;image 路径 `..` 被规范化(404);/admin|/admin/users|/admin/delete 均 401(前缀级守卫,先鉴权后路由)。
- 会话 cookie 是唯一"非标准结构":值形如 `username:token`(匿名态为 `:token`)。篡改用户名半 → **500 "Integrity violation detected"**(integrity 守卫);token 半错 → 401 + 换发新匿名会话;重复 Cookie 取**最后一个**;故无法伪造 administrator 会话。
- 结论:所有可达用户输入面皆为编码/绑定/整数校验,未发现任何差分;下一步方向只能是找回上一轮未枚举到的结构(如 scanner 专用插入点)或换信道具重打。

