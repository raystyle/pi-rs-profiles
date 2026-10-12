---
metadata:
  node_type: memory
name: "PRS ts-1 time-sensitive lab attempt"
description: "ts-1(lab-race-conditions-exploiting-time-sensitive-vulnerabilities)攻坚未决:token 剖面(用户绑定/40hex/亚秒熵/TTL≥40s)+ 5 类构造被排除 + 新件 ts_rand"
last_updated: 2026-10-12T14:35:23+08:00
created: 2026-10-12T14:35:23+08:00
---

## 2026-10-12 ts-1 攻坚(未决,预算耗尽)

实例 `https://0ab400600468309b80623a5400660060.web-security-academy.net/`(widget `78911FB5...A68AC88A`,jar `/tmp/cj1.json` 有效,range_launch reused:false)。email client = `exploit-0ad7003e047a302c80ac394a01470014.exploit-server.net/email`(只显示 @exploit-<id>.exploit-server.net 及其子域,**carlos 的邮件永不出现**)。

### 已确证的 token 剖面(实测)
- 端面:GET/POST `/forgot-password`(csrf + `username`);邮件链接 `/forgot-password?user=<u>&token=<40hex>`;坏 token 返回 **400 `"Invalid token"`**(application/json),好 token 返回 200 + 改密表单(POST: csrf/token/user/new-password-1/new-password-2)。
- 40 位小写十六进制,与用户绑定(wiener 的新鲜 token 在生成后 7s 内对 `user=carlos` 判 400);TTL ≥40s(同一 token 同用户 +40s 仍 200),旧 token 在生成新 token 后失效(疑似「每用户仅存最新」)。
- **亚秒熵**:同一秒内的两枚 wiener token 恒不相同(06:12:40 ×2、06:15:42 ×2,均不同)⇒ 派单方给的「秒级窗口/同秒复用」假设**证伪**。
- **单包齐放不复用**:h2_burst 一包两 stream(wiener+carlos,burst 445B,single_packet_likely:true)后,wiener 的邮件 token(9c9a845d…@06:34:39)对 carlos 仍 400 ⇒ 即使同刻,值也按用户/按请求变化。

### 被排除的构造(共约 4.6e9 候选离线比对,目标 token 取自邮件)
1. `sha1(identity + 时间串)`:ts_token us 模式,18 种微秒形态 × 15 种拼接 × 邮件秒 ±1s(810M)——空;再以 8 形态 × 6 拼接 × **±30s 窗**(2.9e9,含 msec_int/usec_int/microtime_true_str/float6/sec_us6/sec_dot_us6/php_microtime/uniqid,identity 含 user/email)——空。
2. `sha1(秒级时间串 + 盐)`:ts_token sec 模式 12 形态 × 15 拼接 × 11 盐 × 邮件秒 ±8s(72k)——空。
3. 时间种子 PRNG:新件 **ts_rand**(java.util.Random 48 位 LCG + MT19937,nextBytes(20)/5 词拼接/raw 与 hex 再哈希/带身份,l 约 19 形态)毫秒种子窗 ±15s(570k)——空。
4. 第二模板库 `sha_brute`(±160s,含 email/pw)——空。
5. 参数重复形 `username=carlos&username=wiener`:最后值通吃(邮件仍发 wiener 且链接 user=wiener),无错配。

### 仍未覆盖的缺口(下轮首选)
- **纳秒/ISO 小数族**:19 位 ns 整数、`Instant.now().toString()`(6 或 9 位小数,带/不带 Z)、`LocalDateTime.now().toString()`、`yyyy-MM-dd HH:mm:ss.SSS` —— ts_token 的 `iso_ms` 固定 `.000`,**全部未测**;需新形态扫(µs 步进 × 上述格式 × 身份拼接,1e6/s 量级)。
- **截断哈希**:sha256/sha512 取前 40 位 —— 现有件都按整串比对,未覆盖。
- **HMAC / 静态密钥 / 二次哈希**:仅 sec 粒度试过,µs 粒度未试。
- **lab 应用时钟偏移**:lab 响应无 Date 头,无法独立校准;若 app 容器时钟与邮件中继差 >30s,所有以邮件秒为锚的窗全偏。
- 线上枚举太慢:ureq 每请求全握手,16 线程约 17 req/s ⇒ 任何 >1e3 的在线爆破不可行(ts_token probe 8100 候选跑超 585s 被杀)。

### 件与工具经验
- 新件 `.pi-rs/rust-scripts/ts_rand.rs`(1.0.0,项目层):`<hash> --seed-lo/--seed-hi --user` 离线比种;`gen` 出候选;`verify <base> --vuser U --seed-lo/--seed-hi` 在线投候选(禁跟随重定向、命中即停、状态直方图)。首跑 37ms/570k,可放心放大窗。
- **conn_reuse 不可用于本 lab 的 HTTP/1.1 流水**:lab 响应 `Connection: close`,一包两请求只回第一条响应;真单包须走 **h2_burst**(实测一包两 stream 成功)。
- ts_token 的 `us` 在 16 线程下约 33M 候选/s;`sec` 含 11 盐 × 12 形态 × 15 拼接;`probe` 在线模式每候选一发请求,慎用。
- 邮件页「Sent」列是秒级中继时钟,可作 token 生成秒的锚(±1s),但**不能**证明应用时钟同源。

