---
metadata:
  node_type: memory
name: "Deepwater splitting-7 h2 CRLF request splitting"
description: "深水第7轮 lab-h2-request-splitting-via-crlf-injection:bot 存活且请求字节可捕获进公开评论,但管理员 session 只在登录响应下发;RQP 陈旧响应 2.5s 可复取、9s 随上游回收死亡 ⇒ 未解出"
last_updated: 2026-10-12T04:38:59+08:00
created: 2026-10-12T04:38:59+08:00
---

# 深水第 7 轮:lab-request-smuggling-h2-request-splitting-via-crlf-injection

## 实例与题面
- 新实例 `0acd00a3047553b2811adad300c900b6`(range_launch launch-url + /tmp/cj1.json,reused:false)。题面:前端 h2->h1 降级不清洗头,用 **response queue poisoning** 打进 `/admin` 删 carlos;admin 约每 10 秒登录一次;后端连接每 10 请求重置。

## 判决:bot 存活(直接证据)
- 空腹(post 体 CL 超长)smuggled `POST /post/comment` 把受害者浏览器请求字节吞进**公开评论**并落盘:`GET /login` -> `POST /login`(表单体)` -> `GET /`,UA 带 `(Victim) ... Chrome/154`。
- 完整 cookie 头被逐字节捕获:`cookie: victim-fingerprint=3pbmMU4sF6gByARK5YnG2EykAmBSVgQO; secret=kSildvtnzRBCeISodgNnovQ82zwlqXQ8`。
- 对照实测:`secret` 单独与 `victim-fingerprint+secret` 双 cookie 访 `/admin` 均 **401** ⇒ 管理员身份由 `session` 承载,而 bot 登录前的请求里根本没有 session(只在 `POST /login` 响应里下发)。

## 桌面字节账(本轮最有价值的机制发现)
- 前端在降级后的 h1 请求末尾追加的真实字节是 35 字节:`\r\nVia: proxy1\r\nContent-Length: 0\r\n\r\n`;而 `h2split_capture` 内 `FRONTEND_TAIL = 23`(**差 12 字节**)。
- 后果:空腹体实际只从受害者流里取 `over - 12` 字节。两 cookie 的 `GET /`(写出总长 ~813B,cookie 头止于 ~776)的有效 over 窗 = **789-794**,实测 over=792/794 正好吞到 cookie 末位;over<=742 只截到 cookie 中段。
- 硬限:要拿「请求最后一个元素」(POST /login 体 ≈ 请求末尾、session cookie = 第三枚 cookie 在头尾)必须 over 与请求总长**逐字节相等**(1-3 字节窗);over 略大则体无法自收口。
- 填充收口路线失败:`race_send` 40 条独立 h1 连接洪泛 **40/40 回 404** ⇒ 前端**不会**把新 h1 连接路由进「有挂起响应的上游」。只有同客户端连接的填充(`h2split_rqp_catch --mode hungry`)能到达,但持住连接期间受害者落不进来(10 轮 0 字节)。
- 件面缺口:`h2split_capture` 的会话抽取只认 `session=`,因此 `secret=` 的完整捕获不会出现在 `session_candidates` 里(需自读评论页判定)。

## RQP 腿(队列投毒)实测
- 走私 `GET /admin` 造成的陈旧 401 确实留在上游且可被**新 h2 连接**复取:`h2_rq_steal --mode cycle --settle-ms 2500` 8/8 轮 probe1 命中 stale 401(denied)。
- 但陈旧响应随上游回收而亡:settle 9s -> 0/8;`--mode sustain --hold-ms 11000` 持住客户端连接 -> probe1/2 均干净 404 ⇒ 寿命 ~2.5-9s,与 bot 10s 登录周期**无法对齐**;~350s 内 0 条外来响应。
- 落点判据:`path=/prs404probe` 时任何非首页 200 都记 foreign,故 probe 的 404 恒 foreign,candidates 被自家匿名 session 灌满(靠 /admin 复验过滤)。

## 工具与节奏(可复用)
- 命中率经验:burst 8-10 + `--gap-secs 12` 每轮约 50% 有一发受害者请求落进空腹体,但波动大(出现过 0/5 全空批);over 逐个精算后扫窄带比扫宽带有用。
- 本轮未解出:carlos 未删,横幅仍 `Not solved`。下一步杠杆:对 `POST /login` 做逐字节 over 精扫(先由部分捕获的 content-length 反推体长),或找登录后带 session 的导航请求。
