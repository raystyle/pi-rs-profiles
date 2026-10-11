---
metadata:
  node_type: memory
name: "Deepwater R6 - h2 CRLF request splitting RQP"
description: "Deepwater round 6 (lab-request-smuggling-h2-request-splitting-via-crlf-injection, reused instance): split confirmed, but no admin response ever reached our poisoned connections - both RQP modes, the comment carrier and h2.TE all came up empty"
last_updated: 2026-10-12T03:32:35+08:00
created: 2026-10-12T03:32:35+08:00
---

## 2026-10-11 - 深水专攻第 6 轮:h2 CRLF 请求拆分(lab-request-smuggling-h2-request-splitting-via-crlf-injection)

实例 https://0ac6003204f1628c8030cc5200340096.web-security-academy.net/(jar /tmp/cj1.json,range_launch reused:true,重launch 仍同实例,无 fresh-instance 旋钮)。终态:**未解出**,banner is-solved 始终为 false。

### 已确证的事实(可复用)

- **拆分生效**:`x-arm: <value>` 注入值与 `h2_rq_steal.inject_value` 同形(`\r\n\r\n<smuggle>\r\nHost: <H>\r\n`)。arm 的流收到外层响应(200 /post=7854、/=8809),拆出的第二个响应落为 pending(404 / 401 / 8809),随后被**我们自己**的下一次请求消费——队列位移确认。
- **毒化寿命 ≈2 至 3 秒**,非管理员周期(10 秒)。settle=1.2s 时几乎必中(probe1=404);settle=2.0s 时约 64%(25 轮中 16 轮 8809);settle=2.8s 约 35%(20 轮 7 轮 404);settle=4s 约 3/8;settle=10.5s **必为 0**(probe 拿到自己新连接的正常响应)。⇒ 前端自己会清掉多余响应,窗口只有约 2 至 3 秒。
- **判别器技法(零成本)**:arm/probe 用 `/post?postId=1`(我们自己的响应恒 7854 字节),偷到的 pending 用别的路径(404=11 字节,`/`=8809,`/admin`=401+denied 标记)。任何 8809 或 302 行 = 外来响应。全套实验里**从未出现过** 8809/302(路径=/post 时)。
- **h2_rq_hunt 钉住连接 160 秒 273 探针,feed_events=0**(probe-path=/prs404probe 为纯 404,任何非 404 即外来)。pinned/sustain 形同样拿不到池外流量,与上轮阻塞描述一致。
- **评论槽载体(h2_crlf_fill)在本 lab 失败**:`--sink /post?postId=1 --post-id 1 --over 950 --gap-ms 900 --rounds 20`,marker_stored 全 false;arm_status 大多 null(拆出的 POST 体不完整时**前端不回外层响应**)——这是 h2_crlf_fill 模型(前端会把自己的上游连接让别的客户端用)在本 lab 不成立的证据。注意 `h2_crlf_fill` 依赖前端在注入值后追加固定 35 字节 `\r\nVia: proxy1\r\nContent-Length: 0\r\n\r\n`(`APPENDED` 常量),该假设未在本 lab 验证。
- **h2.TE 形(h2_te_steal)同样空手**:cycle rounds=2 probes=4,arms_ok 6,requests 14,foreign_hits 0(注意:该件跑满 rounds 时容易撞 PI_TIMEOUT)。

### 结论与下次切入点

在这台 reused 实例上,**管理员流量从未落到我们毒化的连接上**(循环形与钉住形皆然,合计约 400 次探针零外来)。两种解释未区分:(a) reused 实例的 admin bot 早已停摆(实例自上一轮起长期在线,无重置手段);(b) 前端把后端连接按客户端连接 1:1 绑定,只有我们关连接后才回池,而 admin 常驻浏览器连接另有专属上游。下次应先花一次调用区分这两者——例如用 h2split_diag 看响应头全表里是否出现**不带 Set-Cookie 的行**(admin 请求自带 cookie,响应不会再发新 session;我们的匿名请求恒带 Set-Cookie),或先另起一道新 lab 再回头重拿本题实例。

