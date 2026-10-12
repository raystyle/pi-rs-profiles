---
metadata:
  node_type: memory
name: "PRS ts-3 time-sensitive reset token round"
description: "ts-3 时间敏感重置令牌攻坚:两未证伪面(二进制打包、数值 user_id)已穷尽为负,61 编码×6 身份细扫 26.4e9 次零命中;硬证一用户一令牌且服务端串行,单包无法对齐;新件 ts3_forge v2.1.0 附 --gen 正控"
last_updated: 2026-10-12T16:28:21+08:00
created: 2026-10-12T16:28:21+08:00
---

## 2026-10-12 ts-3 攻坚轮(instance 0a5500f1...,lab 78911fb5...)

目标:lab-race-conditions-exploiting-time-sensitive-vulnerabilities,取 carlos 重置令牌。终态 binary-unknown(未解)。

实例事实(硬证):
- 重置链:`POST /forgot-password`(csrf+username)→ 邮件客户端 `https://exploit-0a1400230396575c8071348801cf0098.exploit-server.net/email` 读令牌;令牌 40 hex;重置链 `GET /forgot-password?user=U&token=T` 合法 → 200「New password」表单,非法 → **400 JSON `"Invalid token"`**(15 字节)。
- **一用户仅一枚有效令牌**:旧 wiener 令牌在新请求后被 400 掉;新旧并发不下发。
- 令牌**用户绑定为真**:同包双发(wiener+carlos)后把 wiener 令牌喂 carlos → 400;POST 侧同样校验(400)。
- **服务端串行且慢**:单包 4 发同用户令牌各不同,邮件 Sent 跨秒(08:21:33/34),即 h2 多路复用被逐条串行处理、每条含约 0.3-1s 的邮件开销 ⇒ 单包无法把两枚令牌对齐到同一时刻。
- `token[]=abc` 走回初始表单(200)而非 400,类型混淆不构成绕过。

爆破覆盖(ts3_forge v2.1.0,已含 --gen 正控):
- 61 种时间编码(秒/毫秒/微秒/纳秒整数与 hex、sfrac1..9、microtime、uniqid(+more_entropy)、分/时/日、datestr/compact/ISO(含 T/Z/空格)、Rust 与 PHP(float precision 14/17, 秒与毫秒)repr)× 6 身份(anon/user/email/id1-3 十进制 + packed u32/u64 LE-BE)× 两序(t_id、id_t)× 两分隔(""、":")× SHA-1(含可选 double)。
- 细扫 ±5s 微秒栅格:26.4e9 次,零命中;粗扫 ±10min 毫秒栅格:3.2e9 次,零命中(接线修好后重跑)。
- 另有 ts_rand LCG/MT19937 毫秒种子窗 ±60s:零命中。
- 两未证伪面(二进制小端打包时戳、数值 user_id 身份)本轮已穷尽且为**负**。

件侧产出:`ts3_forge` 升到 2.1.0(项目层)。**踩坑记**:v2.0 起把 `probe(pre, time_bytes)` 当两元组传,导致每条候选被追加一次时间分量且 id_t 序被跳过 ⇒ 那一批 58e9 次是无效负证;修法=直接对构造好的 preimage 调 `h1`,并用 `--gen` 造已知明文令牌回灌做端到端正控(命中 (form,ident,sep,order,us))。**纪律:任何大字典爆破件都必须先有 generate→回灌自证的正控,否则负证不可信。**

遗留候选(未证伪,留给后续):前置盐/固定 secret 拼接(sha1(salt||t||id))、三元素 preimage(user+time+email 等 perm)、uniqid('',true) 的 combined-LCG 尾段、后端为 Python 时 `str(time.time())` 的 ns 级最短 repr。

