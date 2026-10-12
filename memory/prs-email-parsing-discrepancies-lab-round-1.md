---
metadata:
  node_type: memory
name: "PRS email-parsing-discrepancies lab round 1"
description: "lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies 第 1 轮:三条拒绝文案 + 精确受理面已定,投递侧改写全族否定,未解(31/35 件调用)"
last_updated: 2026-10-12T08:47:05+08:00
created: 2026-10-12T08:47:05+08:00
---

## 实例与面

- 实例 `https://0a1300b30314f37f80513aeb00c50061.web-security-academy.net/`,exploit server `https://exploit-0a4e0016037ff3f6803139f401ed00b3.exploit-server.net/`,邮箱面 `/email`(自称身份 `attacker@exploit-0a4e...exploit-server.net`;页头写「Displaying all emails @exploit-0a4e...exploit-server.net and all subdomains」)。
- 注册面 `POST /register`(字段 csrf/username/email/password;csrf 不轮换,GET /register 取一次可复用整个会话)。确认信文案 `Please check your emails for your account registration link`。

## 判定面(响应体长度即 oracle,实测)

| 长度 | 文案 | 触发 |
|---|---|---|
| 3126 | 受理(请查邮件) | 唯一受理形 |
| 3850 | `Invalid email` | 格式库拒绝 |
| 3893 | `Only emails with the ginandjuice.shop domain are allowed` | 域名不精确等 |
| 3878 | `Registration blocked for security reasons` | 安全黑名单(encoded-word `=?...?=`、裸 `=`) |

**唯一受理形**:`<atext-localpart>@ginandjuice.shop`,即单个 `@`、域名小写精确 `ginandjuice.shop`(子域/前后缀/大写/尾点全拒)。localpart 允许标准 atext 全集(`%` `!` `/` `~` `*` `^` `{` `}` `|` `'` `$` 等实测均过,且可整段内嵌 exploit host);拒:多 `@`、引号(含 balanced)、括号注释、`<` `>`、逗号、空格、控制字符(NUL/CR/LF)、Unicode(ŀ U+0140、全角 ＠)。注意 `+` 在表单体里解码为空格 ⇒ 看起来「被拒」是编码伪影,不是字符集。

## 已否定的投递侧改写族(全部「受理但收件箱仍空」或直接拒)

多 `@`(两向)、encoded-word(`=?x?q?=40<host>?=`)、percent hack(`local%<host>@ginandjuice.shop`、`attacker%<host>@...`)、UUCP 两向(`<host>!user@...`、`user!<host>@...`)、引号/quoted-pair、注释 source route、display-name/尖括号、NUL/CR/LF 截断、双编码 `%2540`(使 app 收到字面 `%40`)、Unicode 溢出、逗号表、`@[host]`。

## 结构事实

- 账号在**确认前不可登录**:`POST /login` 对已受理注册名一律回 `Invalid username or password`。
- `/admin` 未认证 = **401** + `Admin interface only available if logged in as a GinAndJuice user`(授权按登录账号的邮箱域)。
- 受理形响应耗时约 830-1030ms(疑似真发 SMTP),拒绝形约 260-300ms。

## 结论(本轮)

题面所引白皮书四腿(encoded-word / percent hack / UUCP / 注释 source route)在本实现里分别被「安全黑名单」与「格式库」封死;余下窄字符集内未找到任何能令投递域改写的形,收件箱连续 6 次复核全空。判定为**未解**并收口,31/35 件调用。下一臂建议:直接从「app 用哪个库解析该窄字符集」这条线走白盒线索(如端点 `/package.json`、`.git`),或用**只改投递域不改字符串**的第三类机制(如 IDNA/punycode 域解码)重新建模;不要再复投已否定的四族。

