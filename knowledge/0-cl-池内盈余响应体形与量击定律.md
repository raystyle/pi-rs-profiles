---
title: "0.CL 池内盈余响应体形与量击定律"
---

# 0.CL 池内盈余响应体形与量击定律

# 0.CL 池内盈余响应体形与量击定律

0.CL 失步的可交付形态:前端忽略小写 `content-length : N`(冒号前带空格)而原样转发,后端当真,于是 A 的头块之后紧邻的 N 字节被当作 A 的体吃掉;吃掉之后的剩余字节在后端被重新解析成请求。N 不对时的可见回执是后端自己吐的 400(`Content-Type: application/json`、`{"error":"Invalid request"}`,或 `"Invalid hostname: <残留字节回显>"`),这类回执证明**后端报错后仍继续解析后续字节**——这是盈余投递能成立的前提。

## 制胜体形(前端两请求/后端多响应)

B 的体内只放「一条 revealed + 一条截断」不够:前端只认自己发出的 2 个请求(A、B),后端在残留里多解出的响应会被前端按序配对。因此 B 的体必须是:

```
filler(CRLF 垫,建议 60 对/120B)
revealed(完整请求,带载荷 UA)
surplus(完整请求,带载荷 UA)   ← 这一发才是交付物
truncated(截断的 smuggled 请求,带载荷 UA)
```

前端吃掉 A + 第一条残留响应(revealed)后即认为该上游连接空闲;**surplus 的响应留在该连接队列里**,被路由到这条连接的下一个请求(任意客户端)收下。受害者周期性 GET / 撞上即执行 alert,横幅翻牌。三发都带载荷 UA,因为哪一发被配对无法预先确定。

命中判读:`status_count=2 && ct1=image/svg+xml && ct=text/html && xss_hit=true && bytes≈16–19KB`(A 自己的静态资源 + 帖子页)。它既可能是 B 自己的残留配对,也可能是**继承来的盈余页**,两者观测同形,判读时不可区分也不必区分。

## 池继承定律(FIFO 深池)

- 继承是**深池 FIFO**:新种下的毒排在最尾,不会立刻被取走 —— plant 后 0.3/0.9/1.8/3/5 秒各发全新连接探针,40 发零继承。
- 反过来,**把池空掉就完全失效**:静默过上游 keepalive 超时(实测 61 秒)后单发种植,A 与 B 各走一条全新连接,两份干净 200,**一次失步都不发生**。
- 结论:「停手等受害者」的策略不成立,必须**持续量击**把池长期维持在毒化状态,让受害者 5 秒周期的每一次访问都有机会取到毒。

## 量击上限与冷却

- 高并发暴发会把前端打瘫:8 worker + drain 250ms、约 2000 发后读回几乎全空(0 字节),连 GET / 都超时;恢复需要数分钟。
- 安全配比:drain ≥700ms、2–4 worker、命中后**全局冷却** 8 秒(`--cool-after-prime-ms`),把剩余毒的首次取用机会让给受害者的 5 秒周期。该配比下约 609 发/600 秒、9 次命中,一轮十分钟内翻牌。

## 偏移不是常数

同一 C 值在不同轮次命中率在 1/3 到 1/20 之间浮动,单点「测今日偏移」不可靠。做法是**全带电池轮转**(如 190–330 步长 2)配 CRLF 垫,不再钉死单个 C。

## 件面

`pool_window` 1.1.0(项目层)承担全部 IO:`--mode volume` 多线程量击 + `--c-list` 电池轮转 + `--cool-after-prime-ms` 命中冷却 + `--banner-every` 周期读横幅;`--mode cycles` 做「静默过 keepalive 再单发」的空池对照;`--brief` 压缩扫掠输出;classify 回 `ct`/`ct1`(首末 Content-Type)与 `xss_hit`,命中判读不必读原始字节。

## Links

- refines: [[0-cl-双失步与响应队列投递-hidden-content-length-early-response-gadget]]

- refines: [[desync-delivery-deficit-and-window-law]]
