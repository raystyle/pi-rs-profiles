---
metadata:
  node_type: memory
name: "PRS sn-5 scanning-non-standard-data-structures"
description: "sn-5 非标准数据结构题:会话 cookie = username:token,已确证 token 为随机服务端记录 + integrity 门(label 必须等于记录用户名),注册/注入/原型/登录采纳全路线实测排除,未翻横幅"
last_updated: 2026-10-12T19:57:47+08:00
created: 2026-10-12T19:57:47+08:00
---

## 2026-10-12 sn-5 冷实例攻坚:未翻横幅(unresolved)

题:web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures
widget-lab-id AA337200EF03F4ADB1C669E54C672A13150D20A25CEE6622930F71C424F0AFFC;实例 0ae6002c0451919c81388922002700c7。
目标:/admin/delete?username=carlos 需 administrator 会话。

### 已确证的机制(实测,可复用)
- 会话 cookie 结构 = `session=<username>:<token>`,冒号以 %3a 编码;裸冒号同样被接受。
- token = 32 字符 base62(= 24 字节 base64),**每次登录都不同**(两次 wiener 登录 → Rsf2H3… 与 skURFA…),/logout 后旧 token 立即失效 ⇒ 服务端记录表按 token 检索,不可离线伪造。
- 校验律(token→记录,再比 label):未知 token → 匿名(/my-account 302→/login;/admin 401);已知 token + label ≠ 记录 username → **500 "Integrity violation detected"**(恒定 2480B 页,digest aa136edf6af38e3e);已知 + 相等 → 已认证。大小写敏感(`Wiener` → 500)。
- /admin 与 /admin/delete?username=carlos 存在;无 admin 记录 → 401 "Admin interface only available if logged in as an administrator"。
- 无注册面(/register 404),application 无评论/搜索以外的写入面 ⇒ 「注册二阶」路线在本 lab 不存在;label 只能由 cookie 提供且被 integrity 门严格比对。

### 已排除(全部实测,响应恒定)
- label 侧 SQLi:AND 真假对照(`wiener' AND '1'='1` vs `='2`)无差分、UNION、`-- -`、`#`、substr 对读 → 全 500;token 侧 SQLi/UNION/`OR 1=1` → 全 302。
- 原型/特殊键(`__proto__`/`constructor`/`toString`/`0`/`true`/`{}`/`.`/`..`/`%00`)→ 全 302(非 JS 对象存储语义)。
- 登录期「标签采纳」:带 `session=administrator:<活匿名 token>` + 该会话自身 csrf 的 POST /login → 500 integrity(不采纳 label);csrf 与会话绑定(错会话 → 400 "session does not contain a CSRF token")。
- /my-account?id= 全变体 → 302 /login(需与记录用户一致)。

### 未解疑点(下一臂的入口)
- 官方题解指向「扫描 session cookie 插入点」;扫描器能报的类别(注入/反射/反序列化)在本实例上均无差分,说明缺口在**结构本身**而非注入:仍待查 token 内部 24 字节是否携带可推断结构(两次登录 token 解码后均为随机字节)、或 label 在**别处**(非 /my-account、/admin、/login)被消费。

