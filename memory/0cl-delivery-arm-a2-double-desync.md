---
metadata:
  node_type: memory
name: "0CL delivery arm A2 double desync"
description: "0.CL 投递 arm A2:前代 Expect 原语被否证(前端照常消费体);公开双失步按 Vinci 帧实现后仍未投递,串扰 400 证明队列错位存在但切片偏移不对;受害端三载体面全缺(无 exploit server / 首页不渲染评论 / 无前端缓存)"
last_updated: 2026-10-11T07:02:16+08:00
created: 2026-10-11T07:02:16+08:00
---

实验室: PortSwigger /web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling
(目标:让 Carlos 浏览器执行 alert();官方题面明写「Carlos visits the homepage every five seconds」,无 exploit server)。
实例(本轮): https://0ad400ff0444f9a781fd7aec009d0051.web-security-academy.net (lab_id 4bad74c3…, reused:false)。

## 关键纠正:前代的 Expect 型 0.CL 原语被否证

判据实验(conn_reuse 单连接,可复算):`GET / + Host + Expect: 100-continue + Content-Length: 50` 后紧跟一条完整 89B 请求
=> 1 响应(仅首页 8293)。若前端真忽略 CL,后端会吃掉后续请求前 50 字节并再解出残余 => 2 响应(其一 400)。
故前端照常消费声明的体,并把后续字节当新请求头部继续(残余挂住)。
=> 前代 POC 观察到的「隐藏请求被执行(多一条 404)」只是普通第二条请求被正常解析,不是失步。据此判型会把非原语当原语。

## 公开谱(已落知识库方法注 0.CL 双失步与响应队列投递)

真原语 = 畸变头 `Content-Length : N`(冒号前空格)对前端隐藏、对后端可见;死锁需 early-response gadget 破;随后用 CL.0 把截断的 XSS 请求挂在后端,前端计数持平后连接回池,受害者的 `GET /` 补完它并收下 XSS 页。
本轮按 Vinci 公开帧实现(自定义件 zerocl_double),长度算术与公开常量吻合(attack1_body_len = 65)。

## 本轮实测

- 20 候选第一跳清点(desync_probe,read-ms 2500):cl-colon-space/cl-tab-name = 0 响应(死锁),其余 1 响应(400/403/200),suspects 空;与前代批 50 一致。
- 切片判据(静态 gadget + `Content-Length : 20` + 后续完整请求):25s 窗口内只回 SVG(响应 ~9.6s 抵达,接近后端 10s keep-alive),后续请求永不被应答 => 前端把该连接串行钉住;未见 400/404 切片签名。
- 双失步驱动(same 与 split 两模式、含约 3 分钟喷发):attack2 始终 200(svg),从不变成切片后的 404;但出现串扰(喷雾后新连接 GET / 拿到瞬时 400,再查又 200;喷发中 attack1/sim-victim 偶发 400)= 队列错位确实存在,只是落不到我们停放的载荷上(切片偏移不对)。
- 跨连接探针(件 zerocl_deliver,arm 后同连接/关连接两路 x 多轮):一律回干净首页。

## 受害端载体面清点(任务点名的三面)

1. 评论/公开存储位:评论表单匿名可用(post 页有 csrf 隐藏域),但首页不渲染任何评论(root HTML 无 comment/userAgent 段),受害者也只訪首页,且本 lab 无 exploit server(官方题面 + 实例 HTML grep exploit 0 命中;range_launch 亦报 null)=> 诱导链无处投递。
2. CSRF 形:需要把页面送到受害者浏览器 => 同样依赖 exploit server => 不存在。
3. 缓存承载:cache_probe 同 URL 二连(/resources/css/labsBlog.css)均无 X-Cache/Age/X-Cache-Key;Cache-Control: public, max-age=3600 是应用自带头 => 无前端缓存可污染。

## 终态与下一步

未破。阻塞点不在受害端投递面,而在切片对齐:串扰 400 证明待体状态与队列错位真实存在,但吃掉 N 字节后余下字节解不出陪跑请求行 => N 需按前端改写的偏移修正(前端可能改写/追加头块,使后端看到的偏移不等于客户端字节偏移)。下一步:(1) 用未完成后端请求 + 公开落库回显测出前端追加头长度,把 N/M 加上该偏移;(2) 或改为以 attack2 状态码 404(陪跑请求命中)为搜索目标做 N 扫描。

件:zerocl_double v1.1.0(按下式铸帧;same/split;--sim-victim 与 --victim-delay-ms 收割探针)、zerocl_deliver v1.0.0(arm + 第二条连接探针)。

