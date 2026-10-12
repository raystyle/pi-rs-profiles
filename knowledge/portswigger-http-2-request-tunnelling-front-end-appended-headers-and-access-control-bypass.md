---
title: "PortSwigger HTTP/2 request-tunnelling front-end appended headers and access-control bypass"
---

# PortSwigger HTTP/2 request-tunnelling front-end appended headers and access-control bypass

The PortSwigger "bypassing access controls via HTTP/2 request tunnelling" lab's front-end (h2 → h1.1 downgrade) writes, per forwarded request: the request line `{method} {path} HTTP/1.1`, then `Host: <:authority>`, then the client's headers, then its own appended block, then a blank line. That appended block is `Host: <host>`, `X-SSL-VERIFIED: 0`, `X-SSL-CLIENT-CN: null`, `X-FRONTEND-KEY: <16-digit secret>`, `Content-Length: <n>`. X-FRONTEND-KEY is the app-side shared secret proving the request came through the front-end; the /admin ACL requires it together with the admin trust bits `X-SSL-VERIFIED: 1` and `X-SSL-CLIENT-CN: administrator` (any single one alone is 401).

The injection surface is CRLF in the h2 `:path` (space/CRLF pass the front-end; a header NAME works too but the injected first line needs a colon). Reading the secret: send `POST /post/comment` whose `:path` embeds the full request head plus a `Content-Length: L` and a `comment=` body, so the front-end's appended block becomes the `comment` parameter value; read it back at `/post?postId=1`. L must be at or below the exact total body length (bisect; a larger L deadlocks the read).

Bypass: tunnel a `/admin` request that carries `X-FRONTEND-KEY: <leaked secret>` plus the forged `X-SSL-VERIFIED: 1` and `X-SSL-CLIENT-CN: administrator`, and append a decoy request whose header block is left open so the front-end's own appended block attaches to the decoy instead of to `/admin`. The app then serves the admin panel (200) and `GET /admin/delete?username=carlos` returns 302 to `/admin`, flipping the banner. Isolating the same way with `Content-Length: 116` on the `/admin` request (swallowing the appended block into the body) also works.
