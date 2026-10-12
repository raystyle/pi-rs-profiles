---
metadata:
  node_type: memory
name: "PRS ts-4 time-sensitive non-time seed scan"
description: "ts-4 终扫(非时间种子族)否定:wiener 令牌正控无一构造命中,判 seed-unknown;新件 ts4_sweep 1.0.0"
last_updated: 2026-10-12T17:39:04+08:00
created: 2026-10-12T17:39:04+08:00
---

## ts-4 终扫:lab-race-conditions-exploiting-time-sensitive-vulnerabilities(非时间种子族)

实例 0af90080034e391680ea44af008a0054(2026-10-12,jar /tmp/ts4.json)。

### 令牌实测事实(正控靶 = wiener)
- 形:40 hex(SHA-1 形),用户绑定(wiener 令牌对 carlos 返回 400 `Invalid token`;wiener 自用返回改密表单)。
- 变率:每次请求变,且**亚秒级** —— 8 次交错并发(carlos/wiener 各 4)得到的 8 个 wiener 令牌落在 :36:38/:39/:40 三秒内,**8 个互不相同**;同一显示秒内 3 个也互不相同 ⇒ 既非 f(second) 也非 f(second,user)。
- 邮件只投给用户注册邮箱:wiener 的落到 catcher(wiener@exploit-0aa6001f...exploit-server.net),carlos 的**不落 catcher**(username 与 email 两形都试过),故无法直读。

### 正控否定面(user=wiener,target=0e2f97c0cdb6fa8d613d4fbfba896b8600f1e50f)
- static 身份电池(146,388):user/email/pw/sha1(pw)/session/csrf/uid1-5 的单、双、三元组 × 18 分隔 × secret 形前后缀 × sha1/sha256t20。
- time×identity 毫秒栅格 ±2s(486M):form sec/ms/us/s.frac6/s frac6/s.frac3 × 11 原子 × 18 分隔 × 双向 × 盐。
- 微秒精度 ±1-2s(0.885e9 + 1.372e9 + 2.100e9):form us_int/s.frac6/microtime(true)-str/php14/php17 × user/email/sha1(pw)/uid × 分隔(含空格)× 双向。
- 计数器 0..2e6 × identity(604M)。
- 宽窗 sec/ms ±120s(39M)、±3600s(490M)。
全零。

### 结论
对齐路死(亚秒变率 + 0.3-0.5s/请求串行化,单包不可对齐);预测路死(无任何已知材料构造命中)。令牌含**不可从已知材料导出的分量**(服务器侧 secret 或每请求熵)。判 **seed-unknown 终档**。

### 造件
`ts4_sweep` 1.0.0(项目层):静态身份电池 + 时间×身份电池;--only-atoms/--only-forms/--only-seps/--no-salts 过滤;9 种时间形;sha1+sha256t20;裸字节比较;8 线程。注意解析坑:布尔旗标须在 parse_kv 里特判,否则吞掉下一个参数(已修)。

