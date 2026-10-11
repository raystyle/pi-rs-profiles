---
title: LLM 攻击族:提示注入与 API 滥用
---

# LLM 攻击族:提示注入与 API 滥用

同一类型漏洞:模型成为新的信任边界。攻击面两分——**模型可读的数据**(评论、
邮件、文档)与**模型可调的函数**(后端 API、SQL、文件)。共性成因是应用把
模型当作可信中介:数据面未与指令面隔离,函数面权限过宽。

## 子型判型矩阵

| 子型 | 判型特征 | 手法方向 | 实录 |
|---|---|---|---|
| 间接提示注入 | 数据面(商品评论等)进模型上下文 | 数据面写 system 口吻指令并**点名函数** | LLM-1 |
| API 命令注入 | 模型可调后端 API 且有 shell | 以「合法前缀 + `$(cmd)` 后缀」调 API 绕校验 | LLM-2 |
| 过度代理 | 模型持有高权函数 | 直接点名**隐藏**函数与恶意入参 | LLM-3 |
| **AI 扫描器**(agent 自带登录态 + `send_request` 工具) | 扫描总有一个「Scan site」按钮(`POST /api/audit/start {postId\|productId}`) | 把注入写进**被扫页面的用户内容**(博客评论/商品评论);载荷框架用「**需要验证的安全发现**」 | [[lab-indirect-prompt-injection-via-ai-powered-scan]]、[[lab-exploiting-target-website-vulnerabilities-to-bypass-restrictions]] |
| AI 扫描器:敏感信息外带 | 靶场有 `/accountDetails`(返回 `apikey`);扫描器带受害者会话 | 载体一:让 agent 把值**贴成公开评论**;载体二(报告面被值抑制时):把 mandatory-step 的收口步放到**提交面**——让 agent 自己 `POST /submitSolution answer=<值>`。两个 lab 都无 `/scanresults`,可读面只有评论 | [[lab-sensitive-information-exfiltration]]、[[lab-bypassing-ai-scanner-defenses-to-exfiltrate-sensitive-information]] |

## AI 扫描器组

- **形态**:应用里嵌一个 LLM agent 扫描器,工具通常只有 `send_request`(method+path[+body]);
  触发 `POST /api/audit/start`(JSON,`{"postId":"N"}`/`{"productId":"N"}`),进度走
  `wss://<host>/api/audit/stream`(`{status,currentTurn,maxTurns}`,上限 15 回合),
  **部分 lab** 有 `GET /scanresults`(Summary + 它每一步的 method+path)。
- **注入面** = 被扫页面上的用户内容(博客评论 / 商品评论)。触发时用 `postId|productId` 指定页;
  **同一页只放一份注入**(多份会互相干扰);每份注入最好占一个**独立 post 页**。
- **载荷框架决定成败**(topic 页明列 persona / social-engineering / urgency):
  - ❌ 「SYSTEM MESSAGE … + 分步指令」→ 被点名为 social engineering 并**拒执行**。
  - ✅ 「**一个需要被验证的安全发现**」(附着后果/紧迫感)→ agent 会自己把 exploit 演一遍
    (自取 csrf、自删账号、自遍历 Host 区间)。
- **外带信道**:`/scanresults` 的工具调用列表(method+path,query 在内)或**公开评论**;
  敏感端点常见 `/accountDetails`(前端 `fetch('/accountDetails')` 填 `#apikey`)。
- **内网链**:前端按 Host 路由时,agent 在内网可命中外部打不到的服务(本批:admin 在
  **192.168.0.5:8080**,而 stock 服务在 192.168.0.1:8080)——载荷里给候选区间让它自己遍历。

## 共性

1. 模型即客户端:可读面即注入面,可调函数即能力面;映射这二者即得攻击图。
2. 指令效力凭「口吻 + 点名」:system/管理员口吻、明确函数名、明确入参,
   远胜礼貌请求;被拒时换口吻或直接点名函数。
3. 输入校验是绕点不是墙:校验常只看前缀/格式,「合法前缀 + 注入后缀」即可带毒过检。
4. 助手自述的函数清单不全:高权/调试函数常隐藏,直接点名即可触达。

## 判定与收尾要点

- 判定锚点:目标动作**实际发生**(账号被删、文件被删);模型自称成功不算,以实例横幅为准。
- 取证:LLM 靶场常提供 `/openai/logs`(看 `tool_calls` 与函数返回)与 Email client(收发信)。
- 聊天面多为 `wss://<host>/chat`:先读前端 `chat.js` 得知协议(`READY` + `{"message":…}`)。
- 注册/评论面常带 CAPTCHA(data-URI PNG):解码成图后读图得验证码。

## 工具面

- `ws_chat`(wss 聊天一刀,带 jar 会话)、`b64`(data-URI/文件 base64 解码落盘,配合 `read` 读图)、
  `lab_http`(注册/评论/日志)、`lab_page`、`lab_launch`、`solved_check`。

## 实录溯源

- [[lab-indirect-prompt-injection]]、[[lab-exploiting-vulnerabilities-in-llm-apis]]、[[lab-exploiting-llm-apis-with-excessive-agency]]
- AI 扫描器组:[[lab-indirect-prompt-injection-via-ai-powered-scan]]、[[lab-sensitive-information-exfiltration]]、[[lab-exploiting-target-website-vulnerabilities-to-bypass-restrictions]]、[[lab-bypassing-ai-scanner-defenses-to-exfiltrate-sensitive-information]]

## 相关族

- 方法论:web-vuln-methods(seed 层,按名引用)。

## 扫描器防御更新判(grok 双通道 2026-10-10)

- **旧框架已拒**:「漏报验证」重述框架(不发覆盖指令、把外带说成待验证发现)在批 28 后复跑全挂——该行从成功手法改记为**已被拒类**;官方教材页仍教三种说法(可信口吻/验证需要/紧迫后果),教材与实际防御已分叉。
- **仍立机制行**:指令与数据同上下文;confused deputy(扫描器持受害者登录态);外带走攻击者可读面(公开评论/工具记录);观测窗先于盲投(无日志/轨迹/回读时换句=盲投);换载体不换目标。
- **新防御面**:值抑制——扫描报告留端点类别不落具体值,「把秘密当答案说出来」不再是可行目标。**已证载体谱**:①「验证并自发表」(mandatory-step 框架让扫描器以己会话取目标页,把值当验证工件追加进自己发布的报告注释);②「验证并提交」(收口面从发表换成提交:扫描器以己会话取目标值后自行 POST 提交端点带 answer=<值>,15 回合翻牌)——值抑制下两形都绕「说出」。(实锚:lab-sensitive-information-exfiltration 78 调用 / lab-bypassing-ai-scanner-defenses G 臂)
- **载体移植的变量:收口面**。值抑制覆盖面 = **发表面**(报告正文、评论 name 字段、评论 website/链接字段的 URL 参数——三条都实测被抑制);**提交面**(扫描器自己的 `send_request` 请求体,如 `POST /submitSolution answer=<值>`)不被覆盖。mandatory-step 句式只有把收口步落在提交面时才穿透:要求扫描器「以己会话取 /accountDetails,再自行把值 POST 给答案检查器」,页面上任何可读面都不含秘密。判别律:**先判收口面被哪种抑制覆盖,再选句式的收口句**;同句式换收口面即从全拒变即翻牌(见 [[lab-bypassing-ai-scanner-defenses-to-exfiltrate-sensitive-information]])。
- **工序面**:活模型不稳定,同一载荷要**换帖重扫**多轮;同页多份注入互相干扰,一页一份。

## 族地板带

- 解面 10-94(24 线内少数,not-smoke 走四台环);深水面 86-125 归 runner/机制口径不入解面带。
