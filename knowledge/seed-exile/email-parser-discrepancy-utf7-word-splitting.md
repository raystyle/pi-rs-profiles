---
title: 邮箱解析差异:UTF-7 encoded-word 拆原子(绕过域白名单)
links:
  - target: logic-flaws-family
    relation: evidences
---

# 邮箱解析差异:UTF-7 encoded-word 拆原子(绕过域白名单)

> evidences: [[logic-flaws-family]]

当应用"用一套逻辑校验邮箱域、用另一个 mailer 发信"时,缺口在两者的**解码时机**,不在 `@` 数量或罕见分隔符。

## 成立的腿(实测)

- **raw 校验 + 解码投递**:校验器只读原始串(按**最后一个** `@` 取域,local 按 atext 白名单),**不做 RFC2047 解码**;
  mailer 解码 encoded-word 后才得到真实收件人。
- 载荷形:`=?utf-7?q?<user>&AEA-<目标域>&ACA-?=@<白名单域>`
  - UTF-7 modified-base64:`&AEA-` = `@`,`&ACA-` = 空格(尾部空格被 MTA 忽略)。
  - raw 串里**没有** `=%XX` ⇒ 只挡 Q-encoding(`=[0-9a-fA-F]{2}`)的过滤层不触发。
  - 校验器视角:local 全是 atext(字母、`=`、`?` 都属 atext),域 = 白名单域 ⇒ 放行;投递侧解码后 = `<user>@<目标域>`。
- 弱形(常被误当解法):`X@白名单域.攻击域`、`X@攻击域.白名单域`、Q-encoding(`=40`)、base64 encoded-word 里塞 `@`
  —— 前者域不符被拒,后者被 `=%XX` 过滤或"解码后 local 仍须 atext"卡住。
- 判据纪律:注册接口的四种闸门要用 **body 长度**区分(接受 / 语法 / 安全过滤 / 域不符),不能只 grep `Invalid email`,
  否则会把"域不符"当"接受"(旧批即栽在此)。

## 依据

- PortSwigger 研究《Splitting the Email Atom》(Gareth Heyes):encoded-word 生成 `@`/`>`/NUL、UTF-7 与 base64 混用、
  Sendmail UUCP bang-path、Postfix 注释源路由、punycode。
- 实战验证:靶场 `lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies`(见实录)。
