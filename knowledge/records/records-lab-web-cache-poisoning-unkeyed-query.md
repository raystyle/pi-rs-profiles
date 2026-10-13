---
title: "records/lab-web-cache-poisoning-unkeyed-query"
---

# records/lab-web-cache-poisoning-unkeyed-query

PortSwigger: Web cache poisoning via an unkeyed query string.

Mechanism: the front-end cache key is method + path only; the query string is unkeyed. The origin renders `<link rel="canonical" href='//<host><request-target>'/>` - the raw request target is echoed unescaped inside a single-quoted attribute, which is the injection point.

Exploit: `GET /?zzq='/><script>alert(1)</script>` renders `href='//HOST/?zzq='/><script>alert(1)</script>'/>` and the response is stored under key `/`, so every later visitor of `/` executes `alert(1)`.

Storage law: only a MISS stores a body; HITs never refresh or extend the entry. `Cache-Control: max-age=35` bounds the poisoned window to 35 s from the storing MISS. A burst shorter than the TTL cannot cross the stale boundary, so it sprays HITs forever. Fire one byte-exact burst whose duration exceeds the TTL: a 40-variant `raw_matrix` run (~46 s) crossed at index 26, and every later variant HIT the poisoned copy. Sustained coverage needs no trick - each MISS is ours, so the entry is poisoned at all times except the MISS instant.

Recon law (observe the reflection without waiting): path variants `//`, `///`, `////` also render the home page yet key differently, so `//?probe=X` is a MISS that reveals the raw reflection while key `/` stays clean. `Cache-Control: no-cache` and a `Cookie` header do NOT force a pass-through on this cache.

Piece note: `poison_loop` rides ureq + `url` and percent-encodes `<`/`>`, so it cannot carry a byte-exact XSS payload; `raw_matrix` with explicit request lines preserves the bytes.

Evidence: MISS at burst index 26 returned an 8521-byte body (digest 31a4546387d8c889) which all subsequent HITs served; banner then read `<h4>Congratulations, you solved the lab!</h4>`.

[[cache-poisoning-family]]
