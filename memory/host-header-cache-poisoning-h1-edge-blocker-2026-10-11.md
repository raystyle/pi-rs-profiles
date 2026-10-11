---
metadata:
  node_type: memory
name: "Host header cache poisoning h1 edge blocker 2026-10-11"
description: "Arm H unsolved: h1 edge duplicate-Host identity check blocks the ambiguous-request poison; mechanism mapped in knowledge note h1-edge-host-ambiguity-handling"
last_updated: 2026-10-11T19:08:28+08:00
created: 2026-10-11T19:08:28+08:00
---

Arm H, 2026-10-11, instance 0a63004b...h1-web-security-academy.net: NOT solved.

Blocker: the intended ambiguous-request poison needs a request the lab cache scopes as the lab while the upstream is the exploit server - first Host = lab, last Host = exploit server - and the h1 edge's duplicate-Host identity check refuses every such value with 400 Duplicate header names are not allowed (evidence: raw_matrix + duphost_probe batteries, variants EXPLOIT, EXPLOIT:443, EXPLOIT., LAB.EXPLOIT, LAB.EXPLOIT.). Every obfuscation that would make the browser resolve the reflected host to the exploit server is rejected too (Unicode dot U+3002/U+FF0E/U+FF61, %2e, tab-strip, userinfo '@', NUL truncation -> 403/500/RST_STREAM), and absolute-URI plus Host=exploit does not seed the lab-vhost cache entry. Reflectable lab-prefixed junk hosts cannot serve our JS because no cert-valid name starts with the lab host (all academy SANs are left wildcards). Exploit server kept staged: alert(document.cookie) at /resources/js/tracking.js with Cache-Control max-age=600. Full mechanism map is in the project knowledge note h1-edge-host-ambiguity-handling.
