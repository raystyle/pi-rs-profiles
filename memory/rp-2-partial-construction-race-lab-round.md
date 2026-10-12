---
metadata:
  node_type: memory
name: "rp-2 partial-construction race lab round"
description: "rp-2 重发轮未解:实测试穿 confirm 400/403 阶梯与守卫,约 260 次播撒 + 两次单包齐放零翻转;pcreg_burst/pcreg_race 的 urlencode 盲区"
last_updated: 2026-10-12T09:55:36+08:00
created: 2026-10-12T09:55:36+08:00
---

## 2026-10-11 rp-2 重发轮 lab-race-conditions-partial-construction 未解

实例:`0a70006904822c138055c6a10083002c.web-security-academy.net`(range_launch reused:false,建台无卡死,jar /tmp/cj1.json 首跳 22s 直过)。

### 面盘(实测,可复用)
- 注册 `POST /register`:csrf + username + email + password,字段由 `/resources/static/users.js` 的 createRegistrationForm 动态建;成功页 "Please check your emails"。
- confirm 页 `GET /confirm?token=X` 惰性(恒 200 渲染按钮表单,表单 POST 到 `/confirm?<query>`,无 csrf)。
- confirm 校验阶梯(POST;token 只读 query string,放 body 无效 → "Missing parameter: token"):
  - 无参 → 400 `Missing parameter: token`
  - 空串 `token=` → 403 `Forbidden`
  - 数组 `token[]=` → 400 `Incorrect token: Array`
  - 其他 → 400 `Incorrect token: <照抄提交值>`
- 错误文案回显的是提交值,不是存储 token —— 上游派单词的「变异型 oracle 反射存储值」假设被证伪。
- `token%5B%5D=`(百分号括号)→ "Missing parameter: token":PHP 不把 name 解码后再解数组,数组载荷必须是字面量 `[]`。而 `pcreg_burst` / `pcreg_race` 都用 urlencode 拼候选,永远发不出字面 `token[]=`(两件的取值维探索因此是空的)。
- 无 SQLi:`'`、`' OR '1'='1`、`%`、`_`、`*` 全部 400 Incorrect,回显安全。
- 空白 token 403 守卫稳:`?token=&x=1`、`?x=1&token=`、`?token`(无等号)全 403。
- 邮箱白名单是 endsWith 严格判:`rp2b@exploit-...exploit-server.net` 与 `rp2w@ginandjuice.shop.exploit-...exploit-server.net` 均 Invalid email address;被拒注册不入邮箱(收件箱始终空)。login 只认 username。

### 竞态面(全 miss)
- 实例每请求固定 ~1.3s(GET / 实测 1.67s/req,2 worker 5 秒只发 6 发);register_ms 1302/1517。
- 带会话 cookie 的 race_spread 播撒(6 worker/15ms/25s)只发 120 发,全 400;无 cookie 版 30s 发 140 发,全 400 —— 1.3s 是每请求时延,不是会话锁。
- 播撒期间注册 7 个账号(均 200 成功),对应约 260 发 confirm,零非 400;7 个账号登录全部 Invalid username or password。
- h2_burst 单包齐放(register + 6 个 `/confirm?token[]=`,burst_bytes 1312、single_packet_likely:true,两种流序 + 有/无 cookie 两版):register 200,confirm 全 400 Array。工具回执按 stream id 排序,故同连接流是否并行从回执无法判定。

### 结论
该实例上「半构造窗口」从未被观察到:所有可达 confirm 载荷要么被守卫挡(空串 403),要么被绑成字面量 "Array";无一条能命中 NULL/空 token。未解,判机制/环境 blocked(非预算型放弃)。

