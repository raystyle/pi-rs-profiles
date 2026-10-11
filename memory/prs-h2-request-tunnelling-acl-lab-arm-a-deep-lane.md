---
metadata:
  node_type: memory
name: "PRS h2 request-tunnelling ACL lab arm A deep lane"
description: "h2 request-tunnelling ACL lab: reclassification leak (face 3) reproduced (key 68014100) but /admin stays 401 - the X-SSL/Frontend-Key block is not the ACL position (session/role gate; trio identity-less; wiener:peter invalid)"
last_updated: 2026-10-11T06:21:08+08:00
created: 2026-10-11T06:21:08+08:00
---

Lab lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling (real slug; topic page widget-lab-id 2C96A65B...). Fresh instance 0aa200e703abcd5080eb8fa300f900e6.web-security-academy.net. Launch key: the default jar failed (Auth0 login form); range_launch launch <widget-lab-id> --jar /tmp/cj1.json worked.

## Face-3 experiment (header/body reclassification leak) - three-step result

Step 1 (in-frame line separators): h2_req with --hdr2/--path uses hpack with caller-controlled bytes, so the CLIENT does not strip - no client wall. The FRONT-END is the sanitizer: header VALUE CRLF -> RST_STREAM, header NAME CRLF -> 400 {"error":"Invalid request"}, bare LF in name -> 400 Newlines in headers are not allowed. Only :path CRLF passes through raw. (Re-measured, matches the archive.)

Step 2 (leak): CONFIRMED on this instance. The front-end's h1 assembly is:
{method} {path} HTTP/1.1 + \r\nHost: <authority> + [client h2 header fields, each \r\n{name}: {value}] + \r\nX-SSL-VERIFIED: 0\r\nX-SSL-CLIENT-CN: null\r\nX-FRONTEND-KEY: <9 digits> + \r\n\r\n.
The trust block is appended LAST. Injecting a self-terminated request via :path (/ HTTP/1.1\r\nHost: H\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 149\r\n\r\nsearch=) makes the block the BODY; the blog search page reflects it verbatim. Fresh key on this instance = 68014100. Assembly order proven with a client field Foo: BBB... - the reflection shows ' HTTP/1.1\r\nHost: <authority>\r\nFoo: ...\r\nX-SSL-VERIFIED: 0...', i.e. client fields sit BETWEEN Host and the trust block.

Step 3 (reuse the reclassified trust position on /admin): FAILS. With the block reclassified out of the headers, GET /admin still returns 401 / content-length 2776 ("Admin interface only available if logged in as an administrator") - byte-identical to the un-injected baseline.

## Why step 3 fails - the trust block is not the ACL position

- Injected trio (X-SSL-VERIFIED: 1, X-SSL-CLIENT-CN: administrator, X-FRONTEND-KEY: 68014100) via :path, block swallowed -> /admin 401.
- Same trio as client h2 header fields -> /admin 401.
- 20-header battery (X-Forwarded-*, X-Remote-*, X-Original-URL, X-Admin, X-User, trio) -> /admin 401.
- Host: localhost (front-end Host swallowed) -> /admin 401.
- Name-variant battery (trailing space / trailing tab / lowercase of all three) -> /admin 401.
- H2.CL shape (POST /admin + content-length: 0 + DATA-carried GET /admin with the trio), --repeat 2 -> both streams 401/2776.
- GET /my-account with the trio -> 302 /login (identity-less); plain /my-account -> 302 /login. So the X-SSL headers carry NO identity at all.
- wiener:peter is REJECTED by this lab's /login ("Invalid username or password") - the standard low-priv login cannot be used.

Conclusion: /admin's gate is identity/session-based and is invariant to every client-controllable header, including the fully reclassified X-SSL-* / X-FRONTEND-KEY block carried in the downgraded byte stream. The prior verdict "trust position neither forgeable nor borrowable" is refined: the trust position is not on the ACL path on this instance at all - reclassification leaks it (key readable) but does not move the door.

## Operational notes

- range_launch launch <widget> --jar /tmp/cj1.json is the working launch path when ~/.pi-rs/agent/lab-jar.json's SessionId is stale.
- The request-tunnelling topic page carries only academy-labstatus widget ids (no lab hrefs); the correct slug is lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling (NOT lab-bypass-access-controls-via-http-2-request-tunnelling, which 404s).
- Block byte budget on this instance: authority 57 -> the appended block + ' HTTP/1.1' is ~149 bytes; Content-Length: 149 on the injected request swallows it exactly.

