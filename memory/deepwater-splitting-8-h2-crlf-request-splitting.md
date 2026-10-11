---
metadata:
  node_type: memory
name: "Deepwater splitting-8 h2 CRLF request splitting"
description: "深水第 8 轮 h2 请求拆分:持有式跨客户端捕获已证(管理员原始请求字节落我方评论),但 RQP 响应面从未漏出 302;终止未解"
last_updated: 2026-10-12T05:20:48+08:00
created: 2026-10-12T05:20:48+08:00
---

## 题面与实例

`lab-request-smuggling-h2-request-splitting-via-crlf-injection`,目标用 response queue poisoning 进 /admin 删 carlos。描述原文关键句:管理员约每 10 秒登录一次;后端连接每 10 个请求重置一次。实例 `0acd00a3047553b2811adad300c900b6`(range_launch launch-url,reused:true),起手 banner 未解(carlos 尚在),未被污染。

## 已证机制(本轮核心增量)

1. 持有式跨客户端捕获成立:`h2_crlf_fill`(hold + 定长填充 + 11s 静默)与 `h2split_capture`(drop + 11s 静默)都把**管理员的原始请求字节**写进我方评论。落库评论里可直接读到 `user-agent: Mozilla/5.0 (Victim) ...`、`cookie: victim-fingerprint=...; secret=...`,以及 `GET /`、`GET /login`、`POST /login` 三种请求行 —— 即受害者流量确实被前端路由进我方 pin 住的后端连接。
2. **管理员的请求不带 session**:其浏览器 jar 只有 `victim-fingerprint` 与 `secret`,每个周期全新登录。⇒ 请求面捕获永远拿不到会话,会话只在 `/login` 的 302 响应里 —— 与派单方前鉴一致,判据方向正确。
3. 表单参数边界吃掉了凭证:`POST /post/comment` 的 `comment` 值止于第一个 `&`,故捕获到的 `POST /login` 只到请求头 + `csrf=<bot>`,永远读不到 `username=/password=`(页面上 grep `username=|password=` 仅命中我方 `csrf=`)。想拿凭证不能走评论槽。
4. 陈旧 401 的存活窗:settle 2000ms 时下一次连接必得 401;settle 9500ms 时 `stale_401_hits=0`,401 与queued 状态全消失。⇒ 毒化响应在上游池里活不过 9s(与前鉴吻合),>2s 的静默窗会先把毒耗死。

## RQP 响应面为何拿不到(本轮判缺)

`h2_rq_steal` 的两种模式共跑约 30 个周期、约 40 次管理员登录:唯一外来响应始终是陈旧 401,零个 302。
- cycle 模式(arm→静默→新连接收割):settle 1500/2000 每次 probe1 必得 401(说明我们**抢读**赢了),settle 9500 毒已死。12 轮 × 3 探针覆盖各相位,仍无 302。
- sustain 模式(持连接,让受害者在同一 pin 上被服务):第 1 探针 401,随后连续 200,连接在第 8~9 探针处断开(对应后端每 10 请求重置),末段稳定出现「空体 200 + 新 session cookie」再转 status:null。无 302。
结论:该后端连接**请求可以借走,响应不会漏出** —— 受害者的响应由其自己的前端连接读走,我方探针读到的是自己前一次请求的响应(FIFO 错位一格的滚动队列)。故按当前件面,单靠「arm 后收割」无法取到管理员会话。

## 件面坑(影响可复现性)

- `h2split_diag --seconds 60` 未在 60s 收束,被硬杀于 180s,零输出;`h2_rq_steal --rounds 14 --settle-ms 9500` 越过 400s 预算,只回 `deadline 400s reached`,**整轮 per-round 行全部丢失**(该件只在末尾出信封)。做大静默窗时务必把 rounds 压到能在预算内收口。
- 实例评论页会累积历史轮的捕获评论(化石 session);件内的 own-session 排除是必需的,读页面时也要按 marker 区分本轮。
- `h2_crlf_fill` 的 `APPENDED` 常量按本ecosystem 前端自补字节取值,错值只影响受害者字节落点,不影响评论是否提交(填充腿会补齐)。

## 下一步候选(未验证)

- 把走私请求换成 `POST /login`(带我方有效 session+csrf,CL 超长):让**受害者的 POST /login 字节**成为我方 login 请求体,借受害者 username/password 由后端替我完成管理员登录,响应 302 作为额外的 queued 响应再由我方下一次读回。理论上不依赖「受害者响应漏出」,只依赖已证的「受害者请求落进我方体」。现有件没有同时支持该向量与响应回收的组合(`h2split_capture` 把意外 set-cookie 归入 own 排除,`h2_crlf_fill` 只读评论页),需要新件或改造。
- 若坚持 RQP,需要在**同一前端连接**上让响应错位落在自己的下一个流(而非跨连接收割),并接受每 10 请求一次的重置节奏。

