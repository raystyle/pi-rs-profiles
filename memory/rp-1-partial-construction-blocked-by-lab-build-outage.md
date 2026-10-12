---
metadata:
  node_type: memory
name: "rp-1 partial-construction blocked by lab build outage"
description: "rp-1(lab-race-conditions-partial-construction)未解:实例容器全程 504,launch 句柄被 CloudFront 30s 源超时切断,判为 PortSwigger 侧建台失败;同时记录 pi jar 大营销 cookie 致 portswigger.net 请求挂起、裁剪 jar 必须保留 login.portswigger.net 的 auth0"
last_updated: 2026-10-12T09:22:31+08:00
created: 2026-10-12T09:22:31+08:00
---

## 2026-10-12 rp-1 深水题未解(环境侧阻断)

题:lab-race-conditions-partial-construction,widget-lab-id `36e4a9ea055e676d694da84e3520445fb2fa3bbc8f0fce922c9100971a4e90a9`,lab-instances.json 登记实例 `0a7f004204a206c480b8d6a800af00dd.web-security-academy.net`。

终局证据(未触达目标一次):
- 实例根 URL 在整场会话(约 15 分钟、5 次探测)恒 504,容器从未起来。
- 带 auth cookie 打 launch URL(两种 jar 均测)= 挂到 30.7s 后 `Unexpected EOF`;不跟随重定向亦然 ⇒ 卡在第一跳,不是 OIDC 链深处。30s 量级 = CloudFront 默认源响应超时。
- 反证源站健康:同域动态页 `/web-security/race-conditions/lab-race-conditions-partial-construction` 1.1s 返 200 且 `x-cache: Miss from cloudfront` ⇒ 不是 portswigger.net 整体故障。
判:该 lab 的建台任务在 PortSwigger 侧卡死/失败,本会话无可用实例。

## 发射面两个新事实(可复用)

1. **pi jar 的巨型营销 cookie 会让 portswigger.net 请求挂死**。`/tmp/cj1.json` 带全套 portswigger.net cookie(Cookie 头 5949B,含 `.AspNetCore.CookiesC1` 3995B、`ph_phc_*posthog`、`sa-user-id*`、`_pk_*`、`stg_*`、`visitor_id*`)时,GET `https://portswigger.net/`、POST `/api/widgets`、GET launch 一律挂到客户端超时;同一 URL 不带 jar 秒回 200/404。用 `jar_pick`(本次新件)裁成 4 个 cookie(.AspNetCore.Cookies/C1/C2 + SessionId,4420B)后 GET 秒回 ⇒ 挂死跟某个被裁掉的 cookie 相关,与总大小无关。
2. **裁剪必须连 login.portswigger.net 一起留**。只留 `portswigger.net` 一个 host 键时,launch 会落 `portswigger.net/error?error=invalid_request&error_description=...we couldn't find your session`(OIDC authorize 阶段没 auth0 SSO 会话);说明 launch 链要 login.portswigger.net 的 `auth0`/`auth0_compat`。同一裁剪还丢了 `Authenticated_UserVerificationId`,该键疑似与 .AspNetCore 票根同为识别会话所需。

## cookie 解密现状
- `~/.pi-rs/agent/chrome/engine-profile/Default/Cookies` 可解(21 条,peanuts/v10),但**不含**任何会话票根(只有 marketing + `AWSALBAPP-0..3`),即引擎档未登录 PortSwigger。
- `~/.pi-rs/agent/chrome/headed-profile/Default/Cookies` 有 23 条 portswigger 相关 cookie 但 **0 可解**;其 `Local State` 无 `os_crypt.encrypted_key`(只有 `os_crypt.portal.prev_init_success:true`),Chromium 155 走 portal/keyring ⇒ 离线解不开,需 CDP 活读。
- headed profile `Login Data` 0 行,无保存口令 ⇒ 无凭据可重建会话。

## 新增件(项目层 .pi-rs/rust-scripts)
- `jar_pick` 1.0.0:jar 过滤/二分(host 选择、keep/drop 具名 cookie、--list 报逐 cookie 字节数)。
- `http_wait` 1.0.0:可设 `--timeout-secs` 的单次 HTTP(带 jar、可 follow),用于把「建台阻塞」与「客户端 30s 超时」区分开——现有 http 件全是硬编码 30s,range_launch/http_session 对 >30s 的发射面结构性失明。

