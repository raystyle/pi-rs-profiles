---
title: "h2-frontend-sanitizer-matrix"
---

# h2-frontend-sanitizer-matrix

# h2-frontend-sanitizer-matrix

Academy 的 h2 前端(h2→h1 降级)在 request tunnelling 题里**每个注入槽各自的处理**,用 `h2_req` 以同一段种子字节实测(种子 = CRLF CRLF 加一行 `GET /admin HTTP/1.1` 加 `Host: <inst>`):

| 注入槽 | 结果 | 判据形态 |
| --- | --- | --- |
| 头 **值** 里含 CRLF | `RST_STREAM` | 值被拦 |
| 头 **名** 里含 CRLF | `400 {"error":"Invalid request"}` | 名字被拦 |
| 头 **名** 里含裸 LF | `400 {"error":"Newlines in headers are not allowed"}` | 明确文案,可直接读 |
| 头 **名** 含**空格或制表符**(冒号前空格形) | **放行**(请求正常到达,只是过不了 auth 门) | 名字**未**被完整归一化 |
| **`:path` 里含 CRLF** | **放行且原样写进 h1** | 唯一可用的注入面 |

⇒ 实战顺序:先试 `:path`;头名变形(空格/制表)可用来绕名字黑名单,但别指望它单独越权。

## 读通道与记账 oracle(两形态)

1. **读回内层响应原文**:外层 `HEAD <path>` 加 `:path` 注入内层请求,且**内层头块不收尾**(注入不以 CRLF 结束,由前端自己的 CRLF 收尾)⇒ h2 body 直接给出内层响应的原始字节:状态行 + 全部响应头 + 体。用它可以不猜地看到"内层请求实际带着哪些头、返回什么状态"。
2. **期望长度记账**:若内层头块**自己收尾**(注入以 CRLF CRLF 结束),前端立刻回
   `500 Server Error: Received only N of expected M bytes of data`
   其中 M = 外层 path 自身响应长(前端期望长度)、N = 后端实际给出的字节数 ⇒ 这是一个**二值 oracle**:改变注入切法或垫片长度,看 N 是否够 M,就知道装配对不对,不必先猜到成功态。

## 关系

- 方法族:[[h2-tunnelling-and-h2cl-practice]]、[[request-smuggling-family]];题面级数值与帧形见 [[portswigger-platform-specifics]]。


## 记账 oracle 增量

- **M 是逐 path 常数,可预取**:`500 Received only N of expected M` 的 M 是
  该外层 path 自身响应长(/admin=2776、/=8811 本实例)——先 http_dump 取 M
  再谈切法,不必试错。
- **追加块的可读面只有搜索体回显**:内层响应原文隧道里读不到追加块(M 与交付长的差里也没有);唯一的可读面是「外层 `POST` + `search=` 未闭合体」的搜索页 body 回显。

## h1 装配顺序(逐字节实测)

前端把 h2 请求降级成 h1 时按固定模板拼:
`{method} {path} HTTP/1.1` + `\r\nHost: <authority>` + [客户端 h2 头字段,逐条 `\r\n{name}: {value}`] + `\r\nX-SSL-VERIFIED: 0\r\nX-SSL-CLIENT-CN: null\r\nX-FRONTEND-KEY: <9 位>` + `\r\n\r\n`。
⇒ 追加块**永远最后**;客户端头字段与 `:path` 注入字节都排在它**之前**。加一个客户端字段 `Foo: BBB…` 再用搜索体回显,即可把顺序逐字节读出(` HTTP/1.1\r\nHost: <authority>\r\nFoo: …\r\nX-SSL-VERIFIED: 0…`)。

## 信任块不是 ACL 判据(face-3 终判)

「头/正文再分类」能把追加块整体搬进 body(注入自收尾头块 + `Content-Length` = 块长;本实例 authority 57 ⇒ 约 149B),搜索体回显给出密钥;但把块搬出头部后打 `/admin` **仍 401 / 2776**,与基线逐字节相同。穷举否证:

- 自带三行(经 `:path` 或经客户端 h2 字段)、20 条转发/URL 类头电池、`Host: localhost`、名字变体(尾随空格/制表/小写)全 401;
- H2.CL 形(`POST /admin` + `content-length: 0` + DATA 携内层 `GET /admin`)亦 401;
- 带三行打 `/my-account` 仍 302 `/login` ⇒ X-SSL-* 不携带身份;本实例 `/login` 拒绝 `wiener:peter`。

⇒ 该题 `/admin` 的判据是身份/会话,不在前端追加块上;信任位「不可伪造/不可借用」应改读为**根本不在 ACL 路径上**。头名变形与再分类到此为止。

## 追加头块可整体泄漏(密钥可读)

前端追加块的原文与顺序可用「外层 `POST /` + `search=` 未闭合体」读出,搜索页把 body 原样回显:
`\r\nHost: <authority>\r\nX-SSL-VERIFIED: 0\r\nX-SSL-CLIENT-CN: null\r\nX-FRONTEND-KEY: <9 位>\r\n\r\n`。
⇒ 信任位密钥**可泄漏**(每实例变),但这没翻门:同名信任头取**后出现者**(前端追加的 0/null),且 `/admin` 的判据在客户端可自带头之外 ⇒ 泄漏密钥 + 请求行注入精确名 + Content-Length 吸追加块,三法都仍 401。信任位伪造/借用整行记死。
