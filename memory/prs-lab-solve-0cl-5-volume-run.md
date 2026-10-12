---
metadata:
  node_type: memory
name: "PRS lab solve 0cl-5 volume run"
description: "0cl-5: 0.CL lab solved by sustained pooled-surplus volume (609 plants/600s, 9 primes, cool 8s after hit); banner is-solved+Congratulations read at run end, instance host then 504'd at the academy edge"
last_updated: 2026-10-12T14:48:24+08:00
created: 2026-10-12T14:48:24+08:00
---

## 2026-10-13 — lab-request-smuggling-0cl-request-smuggling, 量击轮 solved

题面: Carlos 每 5 秒访问首页,目标让**他的浏览器**执行 alert()。
实例 launch-url 路径 = `https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling`
(先试的 `.../advanced/lab-0cl-request-smuggling` 404)。注入面已由 raw_http 实证:帖子页把 User-Agent **未转义**渲染进评论表单隐藏域
`<input type=hidden name=userAgent value="…">`,所以载荷 `"><script>alert(1)</script>` 是活的。

### 判定证据
- 攻击轮(volume 609 发/600 秒)末尾同轮内的 `banner_solved` 读回:`bytes 11398 / is_solved_class true / congrats true`(未解态首页是 8314 B)。
- 随后实例主机在 academy 边缘变成 `504 Server Error: Gateway Timeout (0) connecting to <host>`,连 range_launch 也不再返还实例 URL ⇒ 本会话内无法二次复读,账面以轮内读回为准。
- 机制自洽:整轮只用 TLS 客户端(无浏览器),横幅只能由模拟受害者的浏览器执行 alert 触发。

### 机制要点(本轮实证)
1. 真形确认:小写 + 冒号前空格 `content-length : N` 被前端忽略、被后端当真。N 不对时的残留回执是后端自己吐的
   `{"error":"Invalid request"}`(Content-Type: application/json)以及 `"Invalid hostname: 0ad…web-t: 0ad…"` 这种把残留字节回显出来的 400 —— 说明后端**报错后仍继续解析**。
2. **制胜体形**:B 的体内绝不能只有一条「revealed + 截断」,必须放**两条完整请求 + 一条截断**:
   filler(CRLF 垫,padding) + revealed(带载荷 UA) + 盈余发(带载荷 UA) + 截断 smuggled(带载荷 UA)。
   前端只认自己发出的 2 个请求,吃掉 A + 第一条残留响应,于是**盈余那发的 XSS 帖子页留在该上游连接队列里**,该连接下一次被取用时由取用者收下 —— 受害者 GET / 撞上即 alert。
3. 命中信号:`status_count=2 && ct1=image/svg+xml && ct="text/html" && xss_hit=true && bytes≈16–19KB`
   (A 自己的 svg + 帖子页)。它既可能是 B 自己的残留配对,也可能是**继承来的盈余页**(两者观测同形)。
4. **继承是深池 FIFO、不是即取即得**:plant 后 0.3/0.9/1.8/3/5 秒各发全新连接探针,40 发**零继承**;
   而把池空掉(静默 61 秒后单发种植)时反而**完全不失步**(A/B 各走新连接,两份干净 200),
   说明「停手再打」无效,**必须持续量击**把池维持在毒化状态。
5. **量击有上限**:8 worker + drain 250ms 的暴发(2068 发)把前端打瘫(2054/2068 读回 0 字节,末尾连 GET / 都超时)⇒
   调参取 drain ≥700ms、2–4 worker、命中后 `--cool-after-prime-ms 8000` 全局静默(把 5 秒周期的首取机会让给受害者)。
   本轮 9 次 prime(≈1.5%)/609 发,600 秒内翻牌。
6. 偏移 C **不是固定值**:同一 C 在不同轮命中率 1/3~1/20 不等,可信度低 ⇒ 用**全带电池**轮转
   (`--c-list 190…330` 步长 2),别再去钉「今日偏移」;filler CRLF 垫 60 对(120B)保留。

### 件面
`pool_window` 升到 **1.1.0**(项目层):新增 `--mode cycles`(先静默过 keepalive 再单发)/`--mode volume`(多线程量击 +
c-list 轮转 + 命中冷却 + 周期性读横幅)、`--brief`(扫掠行省 head/tail)、classify 增 `ct`/`ct1`(首末 Content-Type),
B 体改成 filler + revealed + 盈余发 + 截断。catalog 已 `npm --prefix packages/rs-agent run rust:catalog` 重生成。

