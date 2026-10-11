---
metadata:
  node_type: memory
name: "arm-H lab-race-conditions-partial-construction"
description: "arm H lab-race-conditions-partial-construction: unsolved; confirm blank-token 403 guard, ginandjuice-only email policy, login/confirm races all negative; new pcreg_burst piece"
last_updated: 2026-10-11T18:37:27+08:00
created: 2026-10-11T18:37:27+08:00
---

## lab-race-conditions-partial-construction / arm H - unsolved, mechanism mapped

Instance: https://0a7f004204a206c480b8d6a800af00dd.web-security-academy.net (fresh launch, reused:false).
Mailbox: https://exploit-0ae30084049906b38090d5ba0109005a.exploit-server.net/email (shows only @<that host> and its subdomains).

Objective: register a confirmed @ginandjuice.shop account (staff), log in, delete carlos via /admin.

Facts measured (all HTTP through pieces):
- POST /register (form: csrf, username, email, password) -> 200 "Please check your emails for your account registration link". CSRF is session-bound and enforced (bogus value -> 400 `"Invalid CSRF token (session does not contain a CSRF token)"`; all app errors are JSON strings).
- Email policy: @ginandjuice.shop accepted (page 2636 B); @example.com rejected (3144 B); @<exploit-host> and @mail.<exploit-host> rejected (3119 B) - the mailbox domain is blocked, so the confirmation token is not readable and a race is mandatory.
- Unconfirmed account login -> 200 "Invalid username or password" (no separate unverified message).
- POST /confirm: no token -> 400 `"Missing parameter: token"`; blank or %20 -> 403 `"Forbidden"` (pre-lookup guard that also holds in an h2 single-packet burst); non-blank -> 400 `"Incorrect token: <echo>"`. GET /confirm?token=* -> static 200 page. Duplicate params: first value wins (not PHP $_GET). SQL metachars safe.
- Surface: /admin 401 unauthenticated, /my-account 302 -> /login, no /api/*, /robots.txt 404. No email-change or reset surface.

Races attempted, all negative:
- pcreg_race spray: 313 confirm requests across 5 register rounds - blanks 403, literals 400, no login hit.
- pcreg_burst (new project piece, authored this run) mode=confirm: 20-24 pre-warmed lanes behind one register, delays 0-1200 ms then 0-23 ms at 1 ms steps, candidates blank/0/null/undefined/false/Array/<none>/{SID}/{CSRF}/{U}/{E}, with and without the registering session cookie: no status outside {400,403}.
- pcreg_burst mode=login: 18 own-session login lanes (delays 0-1200 ms) racing the registration of the same account - all failed, so the partially constructed row is never loginable.
- h2_burst single packet: 1 register + 7 confirm streams in one write - same 403/400 split; burst_bytes 1735 exceeded the MSS (single_packet_likely=false).

Reading: blank/whitespace tokens are refused by a guard and every guessable literal is a plain lookup miss at every sampled offset, so the partial-construction value is not recoverable by guessing blank/literal/identity values with connection-level alignment. Remaining lever: true sub-millisecond last-byte-sync alignment (h2_lbs_race) with the register stream armed and confirm streams released, or a value derived from the server-side generator.

Artifacts: piece .pi-rs/rust-scripts/pcreg_burst.rs (v1.2.0, project tier, lint-clean); specs /tmp/confirm_parse_matrix.json and /tmp/surface_matrix.json; jars /tmp/reg4.json (csrf LPzkeFN5HyEKOvLWAcePJvYBUSyIfZQe), /tmp/cj1.json.

