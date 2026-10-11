---
metadata:
  node_type: memory
name: "lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling"
description: "Arm A solved H2 request-tunnelling cache poisoning lab; three traps: padding >= outer CL, no-space payload must parse, cache hits lock out re-poisoning"
last_updated: 2026-10-11T04:27:15+08:00
created: 2026-10-11T04:27:15+08:00
---

## 2026 run (arm A, canonical academy path)

- Lab: /web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling
- Launch: page_read lab page -> lab_id 97e46bf5...; range_launch launch-url --jar /tmp/cj1.json -> reused:false
- Instance: https://0ad400d30478a77582eebaf200b1004a.web-security-academy.net/
- Verdict: solved (banner `academyLabBanner is-solved` + "Congratulations, you solved the lab!"); page_alert on / fired=true (alerts: ["alert:1"])

### Mechanism that worked
- Outer HTTP/2 request: `HEAD /` whose `:path` carries a CRLF-injected HTTP/1.1 pipeline:
  `/ HTTP/1.1\r\nHost: H\r\n\r\nGET /resources/x?<payload> HTTP/1.1\r\nHost: H\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nHost: H\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nHost: H\r\nX:`
- Gadget: `GET /resources/<seg>?<payload>` -> 302 with `Location: /resources/<seg>/?<payload>` — payload reflected RAW (headers are not HTML-escaped).
- Front-end over-reads `Content-Length` bytes for the HEAD response (no body sent), so the tunnelled 302+pages' raw bytes become the cached body of `/`. Home page CL = 8641 B.
- Cache is method-agnostic: the HEAD-poisoned entry is served to the victim's `GET /` (x-cache: hit).

### Three traps (each cost a round)
1. Padding: tunnelled bytes MUST total >= outer Content-Length (8641). /resources 302 (~200B) + one /post?postId=1 (7886B) = ~8100 < 8641 -> front-end blocks forever, returning NOTHING (no RST, no error): the failed piece showed status null / bytes 0. Two big pages fixed it.
2. Injection position: CRLF is RST_STREAM'd in a header NAME or VALUE, but accepted (silently) in the `:path` pseudo-header — that is the only working vector.
3. Payload parsing: `<img/src=x/onerror=alert(1)>` does NOT execute — an unquoted attribute value runs through `/`, so it parses as a single `src="x/onerror=alert(1)"` (no onerror). Confirmed by web_fetch markdown `![](x/onerror=alert(1))`. No-whitespace executable forms: `<script>alert(1)</script>` (used, fired) or `<svg/onload=alert(1)>`.

### Operational note
- Cache hits cannot be overwritten: after any clean render (incl. our own GET / check) the entry is locked clean for max-age=30s, and our HEADs merely HIT it. Re-poisoning only happens on the next MISS. Keep the poll interval (1s) far below the victim's 15s cycle.

### Artifact
- Fixed `.pi-rs/rust-scripts/h2_tunnel_head_poison.rs` v1.0.2: compile error (`report::failure` returns `()`, `.unwrap_or(())` invalid), first filler request only (padding short), default payload changed to `<script>alert(1)</script>`; rules recorded in the `//!` header.

