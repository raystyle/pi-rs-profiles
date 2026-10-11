---
title: "h1 edge Host ambiguity handling"
---

# h1 edge Host ambiguity handling

The `<id>.h1-web-security-academy.net` front-end (HTTP/1 generation, seen 2026-10) polices ambiguous Host requests at the edge. Behaviour (live-probed):

- Single Host must name a *known* academy instance. `Host: <lab>.` (trailing dot) and `Host: <LAB-UPPERCASE>` return 421 Invalid host. A single foreign-but-known host (`Host: <exploit-server>`) is accepted and the edge proxies the request to that vhost, so one can address any academy vhost through the lab's IP/SNI.
- Duplicate `Host` headers are accepted only when every value resolves to the first value's identity: `<lab>:<digits>`, `<lab><suffix>`, `<prefix>.<lab>` pass; any value resolving to another known vhost returns 400 {"error":"Duplicate header names are not allowed"}; a value with a non-host character ('@', '%', Unicode dot U+3002/U+FF0E/U+FF61, tab, space, NUL) returns 403; a non-numeric port or a second colon returns 500 "No host found". Failed values never reach the cache or the app.
- The back-end app reflects the LAST Host value into `<script src="//HOST/resources/js/tracking.js">` and only returns 200 when HOST begins with the lab host (otherwise a cacheable 11-byte "Not Found" 404).
- The cache (X-Cache, max-age=30) keys on the path plus query and is scoped per resolved vhost; the absolute-URI authority is not part of the key and does not influence routing (the Host header does). Cacheable responses served for another vhost do not seed the lab-vhost entry, so cross-vhost seeding via `Host: <exploit-server>` fails.
- HTTP/2 with `:authority` plus a literal `host`, or repeated `host` fields, is answered with RST_STREAM PROTOCOL_ERROR.

Consequence for cache-poisoning-via-ambiguous-requests: the classic request (first Host = lab for the cache key, last Host = an attacker vhost for the app's URL generation) is refused, and no obfuscation (Unicode dot, %2e, tab-strip, userinfo '@', NUL truncation) survives. Reflecting a lab-prefixed junk host cannot work either: browsers must validate the subresource certificate and every academy SAN is a left-side wildcard, so no cert-valid name starts with the lab host.

Mechanism-first probes that produced this map: `duphost_probe` (verdict + wire), `raw_matrix` (variant batteries; headers are re-serialized as `k: v`, so obfuscations must ride the value or a raw request file), `conn_reuse` (byte-exact frames via `--send`), `burp_interp` (reply after surgery; it normalizes header names), `page_read`/`doc_read` for the theory page's ambiguous-request list (duplicate Host, absolute URL, line wrapping).
- 复验哨读数(2026-10-12,env 恢复后新实例实测):三面零漂移——真 exploit 主机次 Host 仍 400 duplicate,同 vhost 各形 200 且应用反射末值,非法/未知主机 403。新增方法论陷阱:探针次 Host 若用「实例号拼 exploit-server.net」的自造形(如 `<labid>.exploit-server.net`),边缘按应用族 vhost 放行并反射,会得出假的「边缘已变更」;判变更必须用本实例横幅读出的真 exploit 主机。
- 附带观测:反向序(首 Host 取 `exploit-<实例号>.exploit-server.net`)回 421 Invalid host,与正向 400 分层。
