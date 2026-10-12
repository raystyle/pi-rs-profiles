---
metadata:
  node_type: memory
name: "PRS ts-2 time-sensitive lab attempt"
description: "ts-2 time-sensitive 题:四缺口全空,判定 construction-unknown;实测同包双请求令牌不同(≤50µs 级熵)、单用户单令牌、严格用户绑定"
last_updated: 2026-10-12T15:09:26+08:00
created: 2026-10-12T15:09:26+08:00
---

## 2026-10-12 题 ts-2 攻坚(未解,收口 construction-unknown)

题:`lab-race-conditions-exploiting-time-sensitive-vulnerabilities`;实例 `0ab400600468309b80623a5400660060`(reused:true);jar `/tmp/cj1.json`;邮件台 `exploit-0ad7003e047a302c80ac394a01470014.exploit-server.net/email`。前端 PHP(`phpsessionid`),重置链接 `/forgot-password?user=<u>&token=<40hex>`。

### 本轮实测确立(证据面)
- **粒度 ≤ ~50µs**:h2_burst 单包 644B/3 流(`single_packet_likely:true`)对同一用户 wiener 发两发,拿到**两个不同** token ⇒ 变化输入在单包内(约 50µs)已不同。故「同刻共享时戳 + 单包」路线对本错题不成立,派单词里的单包要件不是用来对齐时戳的。
- **单用户单令牌**:一轮 8 并发中 4 发 wiener 产出 4 个新 token,但只有**最后写入的那一个**对其属主 200,其余 3 个 400(400 body 15 字节)。
- **严格用户绑定(带阳性对照)**:同轮新鲜 wiener token 对 `user=carlos` 全 400;对 `user=wiener` 200。故绑定不是过期假象。
- **应用时钟不可直读**:动态页与静态资源响应均无 `Date`,全站不发任何 `Set-Cookie`(故也无 Expires 面);raw 邮件只有中继的 `Sent:` 行。邮件台 sent epoch 与本机时钟差 <1s ⇒ 大偏移(>30s)假设无据,但应用自身时钟仍无法独立校准。
- **受害者邮箱不可读**:为 carlos 申请重置,邮箱里无 carlos 邮件(收件人域是 exploit 台,但只有自己那封)。
- 属主身份已核对:`/my-account?id=wiener` 明示用户名 `wiener`、邮箱 `wiener@exploit-0ad7…exploit-server.net`(即我扫的 email 值就是应用侧真值)。

### 离线扫描全空(已用工作量级)
- 毫秒栅格 `--step-us 1000`:±120s(2.7e9)+ ±6h(1.4e10)全族无命中。
- 微秒逐μs:请求窗 600ms(6.8e9)+ 全程请求→发信 1.8s(5.8e9)无命中。
- `reset_time_probe crack` 250 模板(25 编码 × 10 身份位,含 trimmed float、dmy/http-date/space 形态,sha1)±2s 无命中。
- `--counter` 2e6(身份+整数族,含分隔符/双向/plain-double-hmac)无命中。
- 静态盐族:10 个候选 secret(prefix 经 `--salts`、suffix 经 `--pw` 位)±120s 无命中。
- 身份集:wiener / wiener@<exploit 域> / peter / csrf;哈希族:sha1、double、sha256(前20B)、sha256d、sha512(前20B)、HMAC(key=user/email/pw/secret)、packN 系列(4B BE 秒 + 8B BE 微秒 + 身份)。

### 判读
40hex + 单用户单令牌 + 严格用户绑定 + ≤50µs 级熵,却对「已知身份 × 文本化时戳」全族免疫 ⇒ 变化输入要么是**逐请求随机**(random_bytes/rand),要么是**单调时钟/session 级密钥**这类不可外推值;剩余未证伪面只有二进制小端打包时戳、数值 user_id 身份、未知 HMAC 密钥。四缺口(时钟偏移重扫、纳秒/ISO 小数、截断 sha512、静态密钥 HMAC 微秒)全部为空。

### 工具线
`ts_brute` 升 v1.1.0(项目层):新增 `--step-us`(毫秒栅格把偏移校准窗放大到 ±6h 只花 25~215s)与 `sha512`(取前 20 字节 = 40hex 截断族)策略;selftest 绿、lint 清。另记:件头里 `keywords` 行前若插入自定义注释行,cat 解析会丢 keywords 并触发 lint 告警——扩展件头时要让 name/description/version/args/keywords 连续。

