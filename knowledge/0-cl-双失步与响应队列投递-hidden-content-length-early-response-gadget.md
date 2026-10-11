---
title: "0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)"
---

# 0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)

# 0.CL 双失步与响应队列投递(hidden Content-Length + early-response gadget)

族:[[request-smuggling-family]]、[[h2-smuggling-family]];交付律见 [[desync-delivery-deficit-and-window-law]];题面实录见 [[records/lab-request-smuggling-0cl-request-smuggling]]。资料来源:James Kettle《HTTP/1.1 Must Die》0.CL 与 double desync 段,以及公开题解(turbo-intruder `0cl-exploit.py`)。

## 原语(H-V 0.CL)

畸变头 `Content-Length : N`(冒号前留空格)对**前端不可见**、对**后端可见**:前端按无体请求立即转发(把畸变头原样带给后端),后端按 N 等体。这才是 0.CL;`Expect: 100-continue` **不是**(见末节反例)。

## 死锁与早响应 gadget

前端隐藏 CL 后不再计数,若后端苦等体不回,则前端串行阻塞:实测同一连接上后续请求"0 响应"(既非 400 也非超时关闭)。破法 = 让 primer 命中一条**后端读体前先回**的路径(early-response gadget):静态文件(nginx 静态面、IIS 保留名 `/nul`)、服务器级重定向。

gadget 判定:该路径在畸变 CL 下仍回 200/302/404,且连接保持待体。**反例信号**:若该路径的响应其实由前端自己服务(前端自有静态面),则后端从未见过 primer => 无待体状态,第二种请求会被正常应答而非切片。

## 双失步

1. primer = gadget 路径 + `Content-Length : N`,N = 第二条请求头块中"要暴露的请求行"之前的字节数。
2. 同连接紧跟第二条请求;其后端视角的前 N 字节被当作 primer 的体吃掉,余下字节成为后端新请求(陪跑请求)。前端眼里这仍是**一条**请求,只等一个响应。

## 挂起与收割

第二条请求声明 `Content-Length: M`,其 M 字节体 = **截断的 XSS 请求**(缺尾部 CRLF)。后端在陪跑响应之后把这个半截请求挂住,而前端计数已平 => 连接回池。下一个客户端请求(受害者的 `GET /`)的字节补完它 => 后端产出 XSS 页,前端按"受害者那条请求"投递 => 受害者浏览器执行。

帧算术(可复算):`N = len(第二条请求头块) - len(暴露请求头块)`;`M = len(XSS 请求头块) - (尾部 CRLF 长度)`。

## 判据(逐环单独实测,勿跳步)

- (a) 畸变 CL 请求在 gadget 路径上:0 响应 = 死锁(H-V 存在);正常 200 = 前端自己服务了该面(gadget 无效)。
- (b) 第二条请求的响应:变成"切片余字节"的响应(暴露请求的状态码),而不是它本来的状态码 => 切片成立。
- (c) 静默后新连接探针是否拿到 XSS 页 => 跨连接投递成立。

## 反例:`Expect: 100-continue` 不是 0.CL

实测前端**照常消费声明的体**:`primer(CL=L) + 一条完整请求(89B 以上)` 时,前端把后续字节吃进体并挂住残余 => **1 响应**;若前端真忽略 CL,后端会吃掉后续请求的前 L 字节并再解出残余垃圾 => **2 响应**(其一为 400)。故"隐藏请求被执行"(多一条响应)只是普通第二条请求被正常解析,不构成失步;据此判型会把非原语当原语。

## 件

`zerocl_double`(按下式铸帧;same/split 两模式;`--sim-victim` 做收割探针)、`zerocl_deliver`(arm + 第二条连接探针,判跨连接投递)、`conn_reuse`(字节级帧)、`desync_probe`(20 候选第一跳清点)。

## 相关族

HTTP/1.1 基础失步见 [[request-smuggling-family]];前端净化矩阵见 [[h2-frontend-sanitizer-matrix]]。