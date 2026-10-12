---
metadata:
  node_type: memory
name: "PRS 0.CL request smuggling lab advanced - primitive and wall"
description: "PRS 0.CL advanced lab: 0.CL 原语与早响应 gadget 判据已证(隐藏 CL 前端忽略后端处理;必须用未缓存查询串击穿前端缓存),吃字节边界逐配置漂移(实测 61/64)且跨连接不共享,截断 smuggled 送达成未证墙"
last_updated: 2026-10-12T10:17:58+08:00
created: 2026-10-12T10:17:58+08:00
---

## 题目与实例

- lab: `https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling`(topic 页不列 lab 链接,`sitemap.xml` 才解析得到;直拼 `/web-security/request-smuggling/lab-...` 404)。
- 目标:Carlos 每 5 秒访问首页,需在其浏览器执行 `alert()`。实例 `range_launch`(jar /tmp/cj1.json)复用同一实例,nap 120 后 relaunch 仍 `reused:true`。

## 已证事实(可复用的机制层结论)

1. **0.CL 原语成立**:`Content-Length : N`(名字与冒号之间一个空格)前端忽略、后端处理。判据:对 `/post?postId=2` 发该头(无体)会挂死(死锁);`/resources/*` 不挂死,因为静态资源由前端直接应答。
2. **早响应 gadget 必须是「前端未缓存、后端能抢先答」的静态路径**。`/resources/images/blog.svg`、`/resources/labheader/js/labHeader.js`、`/resources/css/labsBlog.css` 首次请求后即被前端缓存(`Cache-Control: public, max-age=3600`,无 X-Cache 头),此后恒为前端命中;给一个**从未用过的查询串**(如 `labHeader.js?cb=<fresh>`)即可强制回源 → 前端转发给后端,后端静态处理抢先应答,前端把这条上游连接放回池里 → 该连接被投毒(下一个请求的前 N 字节被后端当作 A 的 body 吃掉)。
3. **投毒是概率性的**(同配置下约 1/4 到多数不定),且**跨客户端连接不共享**:dispatch 给的「A、B 分两条连接」形在本实例上从未生效(第二条连接总拿到干净响应),**同一条连接**上「先 primer 后 payload」才观察到吃字节(表现为后续请求 400)。
4. **吃字节边界 = A 的隐藏 CL 值 N**,需要 N = 前端转发流中 `revealed` 起点偏移。实测随配置漂移:某配置下 N=61(chopped 56 加前端多出的约 5 字节),另一配置下 N=64(约 8 字节)。右邻值全部 400,说明必须逐字节对齐,不能用范围覆盖。
5. **对齐成功的可辨信号**:attack2 的响应体变成 `labHeader.js` 的 JS(1511 字节级,marker `completedListeners`),而不是 `/?Whatever=Iwant` 的 8264 字节主页。

## 未决的墙(本次卡点)

- 对齐后剩余响应(被走私的 `/post` XSS 页)**没有**被交给后续的独立客户端连接(victim probe 反复拿到干净的 8264),因此未能送达 Carlos。唯一能自洽解释送达的模型是「**截断的 smuggled 请求**」:声明 `Content-Length: 25` 但只发出 3 字节,后端在该连接上停在 body 中途;受害者 GET / 的请求字节补完 body,后端才应答,响应被前端配对给受害者 → 翻牌。此形已实现(`zecl0 --body-len 3 --decl-cl 25`)但边界在对齐窗口内未命中,未取得阳性证据。
- 反复投毒最终把实例打成 504(前端/后端连接池被卡死),`banner_verdict` 返回 status 504。复盘:应该先用小范围确认边界再放量,避免长跑。

## 件

- 新件 `zecl0`(项目 tier):0.CL 单/双连接驱动器,含 `--same-conn`、`--cl/--cl-from/--cl-to/--cl-step` 边界扫描、`--bust`(定宽唯一查询串)、`--body-len/--decl-cl`(截断 parked 形)、`--sim-victim`、`--banner`。
- 新件 `earlygad`(项目 tier):早响应 gadget 探测器 —— 候选路径逐个「带隐藏 CL 的请求 + 紧随一条干净探针」,看探针是否被吃掉(400/长度位移),一次信封给出可用的后端早答路径。

