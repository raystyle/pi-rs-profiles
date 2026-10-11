---
metadata:
  node_type: memory
name: "lab-nosql-injection-extract-unknown-fields B arm run"
description: "B arm (orchestration-btest): 不委派 decision, direct json_oracle extraction, solved; reset-link param name equals the minted field name resetToken."
last_updated: 2026-10-11T07:56:42+08:00
created: 2026-10-11T07:56:42+08:00
---

# lab-nosql-injection-extract-unknown-fields / B arm (orchestration-btest)

## Verdict
Solved — banner `solved:true`, `solved_class:true`, "Congratulations, you solved the lab!".
Instance: https://0a8f00a703ac92598639942d002b00bd.web-security-academy.net/ (ephemeral).
Budget: 29 rs_execute calls (A arm was 33). No subagent spawned.

## 编排决策: 不委派
Scenario = 标定后盲提取 (calibrated blind extraction). Playbook row: 谓词冻结且分片互不共享游标/速率/连接才中心化分片;游标或连接仍共享则整段单代理;基线>0.45 直接不切.
Baseline self-check ≈0.85 because: the piece `json_oracle` already existed (built in the A arm) and the family note names the mechanism ($where + JSON.stringify(this)); calibration cost 3 probes. Extraction shares one oracle + one cookie jar + one connection, i.e. no independent shards. -> 0 children. Delegating would have added coordination tax with no parallel gain.

## Trajectory
1. Launch via range_launch launch-url (widget + OIDC) with /tmp/cj1.json app-session jar.
2. Recon: /login is a form whose button calls `jsonSubmit('/login')` from /resources/js/login.js -> POST /login with Content-Type: application/json, body `{"username":..,"password":..}`.
3. Calibration pair on carlos:
   - plain wrong password -> "Invalid username or password" (FALSE)
   - `password:{"$ne":"x"}` -> "Account locked: please reset your password" (TRUE)
   - `$where 1==1` -> TRUE, `$where 1==2` -> FALSE. Predicate frozen: TRUE marker = "Account locked".
4. json_oracle #1, wrap `{"username":"carlos","password":{"$ne":"x"},"$where":"{WHERE}"}`, expr `JSON.stringify(this)` -> 133 chars, only 4 fields: _id/username/password/email. **No unknown field present yet.**
5. GET /forgot-password -> csrf hidden field; POST csrf+username=carlos -> "Please check your email for a reset password link."
6. **The unknown field is minted lazily by the reset request.** json_oracle #2, expr `Object.keys(this).join('|')` -> `_id|username|password|email|resetToken`.
7. json_oracle #3, expr `this.resetToken` -> value `dd7a7b3debbcae18` (16 chars).
8. Reset-link param name is NOT the PS canonical `temp-forgot-password-token` and NOT `token`; both returned the 3164-byte username form. url_fuzz over 12 candidate param names in ONE envelope found `?resetToken=` -> 3361 bytes + "New password" marker.
9. GET /forgot-password?resetToken=... -> form with csrf + resetToken + new-password-1/2; POST -> 302.
10. JSON login carlos:hacked1234 -> 302 /my-account?id=carlos. banner_verdict -> solved.

## Mechanism delta worth keeping
- The reset-token field does not exist on the user document until a password reset is requested; dump the doc BEFORE the request and you conclude (wrongly) that there is no unknown field.
- **The reset-link query-parameter name equals the document field name** (`resetToken`); it is not the PortSwigger-generic `temp-forgot-password-token`. A 12-value url_fuzz (length + marker clustering) settled it in one call instead of guessing.
- Accounting: json_oracle cost 1076 requests / 142s for 133 chars, 315 requests for 38 chars, 139 requests for 16 chars — the length probe plus per-char 255-range bisect is what drives the count; short exprs (keys/field value) are far cheaper than a whole-document dump.

