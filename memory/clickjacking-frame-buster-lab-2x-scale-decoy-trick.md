---
metadata:
  node_type: memory
name: "Clickjacking frame-buster lab 2x scale decoy trick"
description: "frame buster 绕过 = sandbox=allow-forms;decoy 对齐失败时用 2x scale 放大按钮容差即解"
last_updated: 2026-10-11T04:40:31+08:00
created: 2026-10-11T04:40:31+08:00
---

## 2026-10-10 — 终态:Clickjacking with a frame buster script 已解 (arm A)

靶面: POST /my-account/change-email (form: email + csrf);GET /my-account?email=<v> 把邮件输入框预填成 <v>(22 字节差分实测确认预填)。帧破脚本 `if(top != self){DOMContentLoaded -> document.body.innerHTML='This page cannot be framed'}`。

绕过: `<iframe sandbox="allow-forms" src=".../my-account?email=attacker@evil-user.net">` —— 无 allow-scripts 则帧破脚本不执行,allow-forms 保留表单提交;会话 cookie 为 SameSite=None;Secure,沙箱不透明源仍随表单 POST 带上(本地 CDP 点击自测:wiener 邮箱确实被改成载荷值)。

几何(踩坑与解):
- 朴素对齐失败:浏览器测得按钮 rect=(32,444,152,33) @780x493 视口,33px 高 decoy 精确覆盖;受害者 bot(视口 1050x861)反复取页 11+ 次仍不翻牌。
- 判读:受害者帧内布局与我方测量偏移 >16px(字体/滚动条),33px 按钮容差 ±16px 不够;父文档收不到 mousedown(事件进了 iframe),iframe 无第二次 load,即点击没落到按钮上。
- 解法:iframe 套 `transform-origin:0 0; transform: translate(-16px,-521px) scale(2)`(布局不变,仅视觉缩放),按钮变 304x66、中心落在页面 (200,400),decoy 同尺寸同位 ⇒ 容差 ±33px,一次即解。

判读面:受害者 bot 对交付页反复轮询(每 ~3.5s GET /exploit/),改存 /exploit 后无需重新 DELIVER 即被下一轮取走。自测法:父页 `new Image().src='/d-'+encodeURIComponent(...)` 把视口/rect/elementFromPoint 写进 exploit server 访问日志(GET /log 读回),比截图定位快。

