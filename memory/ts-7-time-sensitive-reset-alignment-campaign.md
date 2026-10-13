---
metadata:
  node_type: memory
name: "ts-7 time-sensitive reset alignment campaign"
description: "ts-7 时间敏感重置令牌对齐战役:自建件 ts7_align 四种形态约 700 次对齐无一碰撞,banner solved:false,格宽阻塞(实测间距数已归档)"
last_updated: 2026-10-12T22:28:58+08:00
created: 2026-10-12T22:28:58+08:00
---

## 目标与机制(派单方给定)

lab: `lab-race-conditions-exploiting-time-sensitive-vulnerabilities`(实例 `0ae1000c040be8f38154865e00a10040.web-security-academy.net`,jar `/tmp/ts7-jar.json`)。
令牌 = 哈希(高分辨率时间戳),用户名不入哈希;同刻生成的两枚令牌相同。正形 = wiener 与 carlos 的 `/forgot-password` 同刻双发,读 wiener 邮件里的令牌,立即以该令牌走 carlos 的确认端点。

## 自建件 ts7_align(project 层 `.pi-rs/rust-scripts/ts7_align.rs`,v1.0.0)

两种发射原语 + 邮件轮询 + 逐个投递 + 命中即接管(改密→登录→/admin 删人):
- `--conns 1`(默认):单条 h2 连接多流单包突发(所有流一帧一帧写进一个 buffer 一次 write)。
- `--conns N>1`:每请求一条独立 h2 连接,末字节同步释放(headers+body 除末字节先发,随后紧循环释放各连接末字节+END_STREAM)。
- `--layout` 用 W/C 串描述流形,如 `WCW`;每轮自动记录 `arrivals_us`(各流响应头到达)、`distinct_tokens`/`dups`(同轮 wiener 令牌重复数=格宽直接观测)、`presented` 状态。

## 实测结论(全部为件内记录)

- 对齐尝试总量 ≈ 700 次(单包 h2 40 轮 × 1 对;多连接 WW 对照 6 轮 × 2;7 连接 CWWWWWW 28 轮 × 6;3 连接 WCW 240 轮 × 2),**wiener 同轮双发从未出现过相同令牌(dups 恒 0)**,carlos 侧投递恒 `400 "Invalid token"`,`banner_verdict` solved:false。
- 间距实测:单条 h2 连接的两个流被后端**串行**处理(WW 探针 arrivals 差 303718µs);多连接末字节同步可把两/三条连接压到 6–25µs(h2 形态)与 170–210µs(三连接形态,单步约 85–105µs)内被处理 — **即便最紧的 6–25µs 同刻轮次,两枚令牌仍然不同**。
- 构造侧:对一枚已知令牌 + 其邮件 UTC 秒,在 [sec,sec+1) 微秒窗内跑 ts_seed_sweep(30 种时间编码 × 7 分隔符 × 前后置,420M 候选,sha1)= 零命中 ⇒ 令牌**不是**常见编码的 sha1(时间)。
- 应用面事实:表单 `POST /forgot-password`(csrf+username);邮箱页 `https://exploit-<id>.exploit-server.net/email` 只列 wiener 的信(carlos 邮件不可读);确认端点 `GET /forgot-password?user=&token=`(有效=200 含 `new-password-1` 表单;无效=400 `"Invalid token"`);应用不是 PHP(参数数组被拒,回 JSON `"Missing parameter 'username'"`;会话 cookie 名 phpsessionid)。
- 语义:同一用户同时只有一个有效令牌(突发中最后签发者仍有效,同突发中更早的令牌投递 400)。

## 件自身缺陷(本轮发现并修复)

h2 多流单包突发在 27 条响应后**停摆**——连接级流控窗口耗尽而客户端从不发 WINDOW_UPDATE(表现为后半批流 status=null)。修法:preface 后补一个连接级大窗口增量帧 `frame(8,0,0,&0x7ff0_0000u32.to_be_bytes())`。此缺陷也是"41 流只回 27 个 200"的原因。

## 终局判定

granularity-blocked:令牌时间桶比可达成对齐间距更细(最紧 6–25µs 同刻仍不同令牌),对齐正形在本环境下不可达;非题解、非记录可解释的失败已按实测数据归档。

