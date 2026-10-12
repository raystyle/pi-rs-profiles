---
metadata:
  node_type: memory
name: "0cl-3 deepwater lab-request-smuggling-0cl unresolved"
description: "0cl-3 未解:小写 content-length : N 形态可造前端忽略/后端吃体,但 prime 不稳(~35%)、偏移命中带窄(C≈280-310)、跨客户端交付 66 探为零;新件 clform_scan/zc0cl2/zc0cl3"
last_updated: 2026-10-12T10:52:59+08:00
created: 2026-10-12T10:52:59+08:00
---

## 2026-10-12 0cl-3 深水专攻 lab-request-smuggling-0cl-request-smuggling

**终态:未解 (not solved)。** 实例 `0a5f009c045073b6803130b400cb003b.web-security-academy.net`(widget-lab-id `4BAD74C356692BBAAB9602C955308F8A1B04CB866034F32286993566EFC8CC66`,reused:false)。目标 = 令 Carlos(每 5s 访首页)执行 alert()。

### 已确证(可复用)
1. **XSS 反射面**:`/post?postId=N` 把请求 User-Agent 原样(未转义)写进评论表单隐藏域 `<input required type="hidden" name="userAgent" value="...">`。实测 UA=`POC"><script>alert(1)</script>` 使响应体 8326→8345,+19 = 载荷增量(未转义)。首页 `/` 不反射任何头(header_fuzz 25 头全零)。
2. **0.CL 畸变头形态**:`content-length : N`(**全小写**、冒号前一个空格)是唯一造成「前端忽略 + 后端按值吃体」的形态。大写 `Content-Length : N` 两层都忽略(a1 立即 200 且探针干净 404)。控制实验:正常 `Content-Length: N` 前端等体并吃掉下一请求前 N 字节(探针 400)。
3. **前置 gadget 早答**:`/resources/*` 用未用过的查询串 + `content-length : N` + 无体 → 后端先答 200 再等 N 字节。前导 CRLF 被容忍(`\r\n\r\n\r\nGET /` 得 200)。
4. **前端缓存真实存在**:同一 URL `/` 有时带 `Set-Cookie: session=`(后端)有时不带(缓存命中);`/resources/*` 带 `Cache-Control: public, max-age=3600`。随机未用路径 `/zz<rand>` = 保证 miss,但用它做 gadget 时不再早答(6/6 零响应)。
5. **吃体不稳**:同参数下后端被 prime 约 30-40%(第 2 响应 400),其余 2×200。N 极大(100000)时出现「整条 B 被吃、只回 A 一条」的挂起态。
6. **偏移**:B 头块按我方构造 163-164 字节,实测命中带在 C≈280-310(后端实际吃得比 163 多约 120-150,疑前端转发改写/加头)。加 128 对 CRLF 填充后 C=280/310 曾令残留解析成 revealed 帖子页(post_page=true)。

### 未打通
- **交付**:66 次新连接受害者探测(独立连接 `GET /`)从未拿到被投毒帖子页 → 上游跨客户端共享未证实(与派单方上轮结论一致)。deliver 30 次种植中 3 次吃体成功、均 cut 成 400,残留未落填充带内。
- **横幅未翻**:banner_verdict solved=false。

### 环境坑
- portswigger.net 页面/`/api/widgets` 的 ureq 读超时频发(`range_launch`、`http_dump` 都中招)。页面取回改用 `http_wait --timeout-secs 60`(1.1s 成功);`range_launch` 重试一次即成功。
- 实例 host 长 55 字符,使 B 头块偏长(派单方上轮 61/64 应来自更短 tag/头块)。

### 新件(project tier,均带 --selftest)
- `clform_scan` 1.0.0 — 畸变 Content-Length 头形态扫描(FE_WAIT/IGNORED/SPLIT)。
- `zc0cl2` 1.0.0 — 0.CL 双发利用件(可换形态/管线化/sim-victim)。
- `zc0cl3` 1.0.0 — 偏移扫描 sweep + 投递 deliver;`--filler-crlf N` 插 N 对 CRLF 做漂移容忍;`--a-prefix` 换 A 路径。

### 下一步候选(未验证)
- 多 A 多 B 同写/交错读写提高同上游连接命中率。
- 交付改走前端缓存投毒(按受害者键缓存被投毒响应),而非跨连接共享。
- 偏移用细扫多 rep(命中带疑 <2 宽)。

