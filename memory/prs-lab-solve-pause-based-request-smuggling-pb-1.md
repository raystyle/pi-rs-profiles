---
metadata:
  node_type: memory
name: "PRS lab solve pause-based request smuggling pb-1"
description: "pb-1 冷实例一次解出:POST /resources(无尾斜杠)primer 停 75s 后投 smuggled 请求,响应错位一拍;删 carlos 需带尾斜杠 /admin/delete/ + 版面 csrf/session 重放"
last_updated: 2026-10-12T13:59:15+08:00
created: 2026-10-12T13:59:15+08:00
---

## pb-1 · lab-server-side-pause-based-request-smuggling(A 臂实录)

实例:https://0a9b00f604f4411f80b96c78006d00ff.web-security-academy.net/(range_launch,reused:false)。路径不在 `request-smuggling/advanced/...`,正解 slug 在 sitemap:`request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling`(404 时用 sitemap.xml + text_grep `lab-[^<]*pause[^<]*` 定位)。服务端 Apache/2.4.52,keep-alive timeout=120。

### 面盘(实测)
- `GET|POST /resources`(无尾斜杠)→ 302 `Location: /resources/`;`/resources/` → 404(源站,带 Set-Cookie)。
- `/admin` 外部直达 → 403 `{"Path /admin is blocked"}`(前端 ACL,无 Server 头),走私后可达。

### 可用配方(pause_trace,primer CL = 走私串长度)
`primer = POST /resources`(带 `Content-Length: {CL}`、只发头)→ 静默/排空 75s → 再发走私请求字节 → 用跟随探针把响应拉回来。
- 暂停 < 61s 无效:75s 排空窗内零字节(源站既不早答也不关连接)。
- **响应错位一拍**:发完走私字节后先收到 primer 的 302 `/resources/`(前端缓冲的),走私请求的真响应由下一条请求(探针)领走 —— 判读必须看 probe 阶段,不要以为 smuggle 阶段是答案。

### 三段链(每次 85s wall-clock,一个信封一腿)
1. 走私 `GET /admin/`(Host: localhost)→ 探针拉回 = 真 admin 面板 200(表单 `action='/admin/delete'` + hidden `csrf` + `name='username'`)+ 源站新 session cookie。→ 记下 session 与 csrf 成对。
2. 走私 `POST /admin/delete`(无尾斜杠,+该 session/csrf)→ 源站回 302 `Location: /admin/delete/`(mod_dir 目录补斜杠,未执行删除)。
3. 走私 `POST /admin/delete/`(**带尾斜杠**,Cookie: session=…,`csrf=…&username=carlos`)→ 302 `Location: /` = 删除成功。
4. `banner_verdict` → solved:true + `<h4>Congratulations, you solved the lab!</h4>`。

### 要点
- desync 后的请求由源站按内部来源处理,前端 ACL 被绕过;走私串里的 `Cookie:` 与 `Content-Type/Content-Length` 由源站原样按请求解析(前端只当 primer 的体转发)。
- csrf 与 session 必须成对重放(都取自同一次走私面板响应);token 未使用时跨轮可复用。
- 件面足够,无需造件:`pause_trace`(primer/smuggle/probe 三段 + `--drain`)+ `banner_verdict` + text_grep。

