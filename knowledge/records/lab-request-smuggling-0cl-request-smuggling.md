---
title: lab-request-smuggling-0cl-request-smuggling
---

# lab-request-smuggling-0cl-request-smuggling

> evidences: [[h2-smuggling-family]]

- 题面:0.CL request smuggling;Carlos 每 5s 开首页,让他的浏览器执行 `alert()`;基于 Kettle《HTTP/1.1 Must Die》。**本 lab 无 exploit server**(官方题面只写「Carlos visits the homepage every five seconds」,实例 HTML 无任何 exploit 链接)。 - 机制(公开谱):[[0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)]]。要点 = 畸变头 `Content-Length : N`(H-V:前端隐藏、后端可见)+ early-response gadget 破死锁 → CL.0 把**截断的 XSS 请求**挂在后端 → 前端计数持平后连接回池 → 受害者 `GET /` 的字节补完该请求并收下 XSS 页。 - XSS 面:`GET /post?postId=N` 把请求 `User-Agent` **原样**写进 hidden input 的 value ⇒ `"><svg/onload=alert(1)>` 直接可执行(实测回显 `value=""><svg/onload=alert(1)>">`)。 - 公开帧长度算术(可复算):`N = len(第二条请求头块) - len(陪跑请求头块)`;`M = len(XSS 请求头块) - 尾部 CRLF`。Vinci 公开题解的常量 N=65 与本式吻合。

## 前端行为实测(本 infra)

- **`Expect: 100-continue` 不构成 0.CL**(纠正旧判):判据 = `CL 声明 50` + 一条完整 89B 请求 ⇒ 前端照常消费声明的体并把残余挂住 ⇒ **1 响应**;真忽略 CL 会给 **2 响应**(其一 400)。故"隐藏请求被执行(多一条 404)"只是普通第二条请求被正常解析。 - 20 候选第一跳清点(`desync_probe`):`Content-Length :`/`Content-Length	:` 两形 = **0 响应**(死锁:前端把该连接串行钉住,后续请求永不被应答);其余 1 响应(400/403/200);无 suspect。 - 切片签名(陪跑请求状态码变成切片余字节的 400/404)**在任何已试帧下都未出现**:静态 gadget 上 attack2 恒 200(该面由前端自己回,后端从未见过 primer);25s 窗口下也只回 SVG(响应 ~9.6s 抵达,接近后端 10s keep-alive)。 - 队列错位**存在但不可控**:喷发后新连接 `GET /` 偶得瞬时 400(再查又 200),喷发中 attack1/sim-victim 偶发 400 ⇒ 残留/他人响应确实会被投给新客户端,但停放的载荷落不上(切片偏移不对)。 - 跨连接探针(arm 后同连接与关连接两路 × 多轮)一律回干净首页。

## 受害端载体面(三面全缺)

1. 评论/公开存储位:评论表单匿名可写(post 页有 csrf 隐藏域),但**首页不渲染任何评论**(root HTML 无 comment/userAgent 段),受害者也只訪首页 ⇒ 诱导链无处投递。 2. CSRF 形:需把页面送到受害者浏览器 ⇒ 依赖 exploit server ⇒ 不存在。 3. 缓存承载:`cache_probe` 同 URL 二连(`/resources/css/labsBlog.css`)均无 `X-Cache`/`Age`/`X-Cache-Key`;`Cache-Control: public, max-age=3600` 是应用自带头 ⇒ 无前端缓存可污染。

## 判据现状

**未破**;阻塞 = 切片对齐(前端可能改写/追加头块,使后端看到的偏移 ≠ 客户端字节偏移)。下一步:①用「未完成后端请求 + 公开落库回显」测出前端追加头长度,把 N/M 加上该偏移;②以 attack2 状态码 404(陪跑请求命中)为搜索目标做 N 扫描。

## 复现命令

`range_launch launch-url /web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling --jar <jar> desync_probe <inst>/ --read-ms 2500 zerocl_double <inst>/ --mode split --rounds 10 --sim-victim zerocl_deliver <inst>/ --rounds 3`

## 关系

- 族:[[h2-smuggling-family]]、[[request-smuggling-family]];方法见 [[0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)]]、[[desync-delivery-deficit-and-window-law]];件见 [[0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)]] 的「件」节。
