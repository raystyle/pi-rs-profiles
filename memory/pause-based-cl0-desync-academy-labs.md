---
metadata:
  node_type: memory
name: "Pause-based CL.0 desync academy labs"
description: "Pause-based CL.0 desync recipe: POST /resources primer, 90s hold, blob drained by next request; Host: localhost + POST /admin/delete/ for the academy admin gate."
last_updated: 2026-10-11T12:01:10+08:00
created: 2026-10-11T12:01:10+08:00
---

Target: academy pause-based request smuggling (frontend blocks /admin with 403 JSON; backend returns 401 Admin interface only available to local users).

Working primitive (one connection):
- primer: `POST /resources` with `Content-Length: <len(smuggled blob)>`, body withheld.
- hold ~90s: nothing returns (frontend relays the upstream response only after the request body is finished).
- send the blob: backend early-answers the directory primer (POST /resources -> 302 /resources/) WITHOUT consuming the declared body, so the leftover blob is parsed as a fresh request; its response is queued.
- frontend delivers exactly ONE upstream response per client request, so the primer 302 returns right after sending, and the smuggled request response is drained by the NEXT request on the same connection (response-queue poisoning).

Two deviations that cost runs:
- primer CL must equal the FINAL byte length of the smuggled blob (host token substituted before measuring, else mis-frame -> 400 Invalid request).
- connection dies at ~121s (Apache Keep-Alive timeout=120); 140s pause returns EOF, 90s is inside the window.

Backend gate + objective:
- the local-users check is on `Host: localhost` on the smuggled request (X-Forwarded-For / X-Real-IP batteries do NOT satisfy it).
- admin panel = GET /admin/ (Host: localhost); returns a rotating csrf token each render.
- delete handler lives at `POST /admin/delete/` (TRAILING SLASH); a POST to /admin/delete only 302s to /admin/delete/. Body `csrf=<token>&username=carlos` -> 302 Location / and the banner flips to solved.

Tools: pause_sweep (grid + multi-request blob drained by N probes), pause_trace (primer/{CL}/pause/smuggle/probe), banner_verdict. pause_trace computes {CL} BEFORE {HOST} substitution - use a literal host in --smuggle.

