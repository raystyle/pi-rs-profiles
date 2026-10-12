---
metadata:
  node_type: memory
name: "PRS lab sn-6 scanning non-standard data structures"
description: "sn-6 scanning-non-standard-data-structures: banner NOT flipped - session token is opaque+authenticated (all byte flips 302), label globally validated (mismatch 500 everywhere, no consumer/injection), no injection on search/postId/login/id, no mass assignment, no trust bypass; new pieces sess_struct + cookie_fuzz"
last_updated: 2026-10-12T21:03:38+08:00
created: 2026-10-12T21:03:38+08:00
---

Lab: essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures (widget id AA337200EF03F4ADB1C669E54C672A13150D20A25CEE6622930F71C424F0AFFC). Objective: find a vuln in a non-standard data structure, exploit, delete carlos; login wiener:peter. Instance https://0a57008703d8d90580ab44a100c80030.web-security-academy.net. Verdict banner_verdict --out /tmp/sn6-verdict.json = solved:false (not flipped).

Dispatched surfaces both NEGATIVE:
- Token 24-byte structure (item 1): session value is `username:base64(24 bytes)`; the token half decodes to 24 opaque bytes. Diffing 10 tokens (9 anonymous + 1 wiener) shows EVERY byte position varies (0 stable) -> no version/user/timestamp field; 9 same-identity (anonymous) tokens all differ -> randomized per issue. Single-byte flips of a live token: all 24 -> 302 (control 200) -> token is authenticated (MAC/encrypted) or a random server-side id; NOT forgeable.
- Label hidden consumer (item 2): the username half is validated against the token's identity in GLOBAL middleware - any label != token identity yields HTTP 500 "Integrity violation detected" on EVERY page (/, /post, /my-account, /admin). No reflection anywhere (probe label never appears in body). No comment/post-author/header/log consumer.

Other surfaces closed: no injection in either cookie half (raw/decoded/label x SQLi/delay/path/JSON/template payloads -> only 302/500); no time channel in label, raw token, decoded token, `?id=`, `?search=`, `?postId=` (confirmation), multi-vendor pg_sleep/SLEEP/WAITFOR/randomblob; login not injectable (administrator'-- -> login page 200; csrf enforced first, "Missing parameter 'csrf'"); search is a literal HTML-escaped substring match (`'` matches all 5 posts because all bodies contain an apostrophe; `'--` -> 0); /post?postId= is integer-validated (400 "Invalid blog post ID"); no mass assignment on /my-account/change-email (extra username/role/admin form fields and JSON body ignored); no trust bypass on /admin (X-Username/X-Role/X-User headers, role/user/admin cookies, Basic auth, XFF -> 401); 29-path endpoint sweep found nothing but /admin, /admin/delete, /post/comment, /post/comment/confirmation.

Environment/transport notes: /logout KILLS the server-side session; re-login ROTATES and kills the previous token, so a token captured earlier goes 302 - always re-verify the control row before trusting a cookie-structure scan. csrf is per-session (same value across login/comment/change-email forms of one session). The app returns JSON for errors ("Not Found" 404, "Invalid CSRF token" 400, "Missing parameter 'csrf'", "Invalid blog post ID", "Missing parameter: postId").

Pieces authored this round (project tier): sess_struct (label:base64 token byte-layout diff: hex/ascii per token + per-position stable/varying) and cookie_fuzz (scan-insertion-point driver: fires token-decoded / token-raw / label-raw variants plus single-byte flips of a live token, flags any status outside the 302/500 reject baseline).

