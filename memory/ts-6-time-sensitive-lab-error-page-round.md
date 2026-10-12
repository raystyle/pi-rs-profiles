---
metadata:
  node_type: memory
name: "ts-6 time-sensitive lab error-page round"
description: "ts-6: lab-race-conditions-exploiting-time-sensitive-vulnerabilities 错误页取证轮 - 发射路径坑 + 令牌形态 + 错误页面阴性"
last_updated: 2026-10-12T18:39:53+08:00
created: 2026-10-12T18:39:53+08:00
---

## 2026-10-12 ts-6 (终面:错误页泄露,温和形)

目标 lab: `lab-race-conditions-exploiting-time-sensitive-vulnerabilities`。实例(冷实例 reused:false):
`https://0af4003c049bf0c78172026100d2005d.web-security-academy.net`,email client
`https://exploit-0abc00d70430f0be81c3013301b7006f.exploit-server.net/email`。

### 发射路径(两个坑)
- `page_read` 与 `range_launch launch-url <lab-page>` 都会在取 portswigger.net 静态页时超时(status line timed out)。
- 可行路径:`http_wait <lab-page> --timeout-secs 120 --out FILE` **不带 --jar**(带 jar 时实测 Unexpected EOF)→ 从 HTML 抽
  `widget-lab-id`(sha256 串)→ `range_launch launch <widget-lab-id> --jar /tmp/cj1.json` 一次成。

### 令牌形态(实证)
- 面:`/forgot-password` GET 表单(POST csrf+username),GET `?user=<u>&token=<T>` 校验,POST 同参数改密。
- 重置信:`/forgot-password?user=wiener&token=a6200535411882662e4af421f7bc4a290a987084`(**40 hex = sha1**),信头时间 `2026-10-12 10:30:42 +0000`(epoch 1791801042)。
- 用户绑定:`user=carlos` + wiener 的 token → 400 `"Invalid token"`(JSON);`user=wiener` + 同 token → 200 改密表单。
- 非会话绑定 / 长有效期:同一 token 数分钟后仍有效(服务端按用户存,非按 session、非秒级过期)。
- JSON 错误面:`"Missing parameter 'username'"`(400)、`"Invalid token"`(400);array 形 `token[]=x` → 200 直接回表单(不报错)。

### 错误页/堆栈/调试面:阴性
逐发(间隔>2s)探畸形输入:`username[]=carlos`(400 Missing parameter)、`token=%ff%fe%00%01`(400 Invalid token)、
`token[]=x&token[]=y` + `X-Debug: 1`(200 表单)。**无 500、无堆栈、无调试输出**——该 lab 的错误面不泄令牌构造。

### 离线复现:负
`ts_seed_sweep` 全电池:
- sec=1791801042,atoms wiener|email,forms 全,sha1 → 840M 候选 0 命中(102s)。
- sec=...42,atoms 空(mode time)→ 420M 0 命中(50s)。
- mode static(atoms wiener|email)→ 144 候选 0 命中。
- sec=41 宽窗 + sha1,sha256 → 超 180s deadline 被杀(件是 1s 窗/哈希 ≈100s,2 哈希 2 秒窗必然超)。
结论:构造**不是**时间+可见原子(wiener/email)在本件电池内的任一面 → 疑含隐藏 secret / 异形 PRNG,
离线不可复现,须源码级泄露(而错误面不给)→ 该轮(错误页温和形)未拿到构造,亦未攻 carlos。

### 纪律遵守
逐发(>2s)、每发读响应、未齐发;实例无 504 迹象;预算 25 内收束;未读题解/档;未改仓、未 git。

