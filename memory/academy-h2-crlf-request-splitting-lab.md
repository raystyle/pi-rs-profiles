---
metadata:
  node_type: memory
name: "Academy H2 CRLF Request Splitting Lab"
description: "arm F H2 CRLF-injection lab: capture mechanism proven (admin bot request leaked to comment sink, Cookie truncated at session=), but no admin session; plus instance-wedge and egress quirks"
last_updated: 2026-10-11T12:55:59+08:00
created: 2026-10-11T12:55:59+08:00
---

## 2026-10 arm F: academy H2 CRLF-injection lab run

Target: `/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection` (instance 0af2006003b0e87280ec037700e900f2).

Outcome: unsolved. carlos not deleted, no admin session obtained.

What was proven (mechanism, not verdict):
- `h2_req --hdr2 'foo||<CRLF><CRLF>GET /admin HTTP/1.1<CRLF>Host: <h><CRLF>' --repeat 3` splits the request: client stream 3 of the same connection received the smuggled `/admin` 401. CRLF injection into a header value survives the H2->H1 downgrade.
- `h2_rq_steal` cycle mode reproduced response-queue shifting (7 foreign `/admin` 401 hits in 72 probes), but every foreign response was our own smuggled one; the victim's login response never landed on our streams.
- `h2_crlf_fill` (victim-request capture into the `/post?postId=1` comment sink) DOES work on this lab: stored comments contained the admin bot's raw requests (`Mozilla/5.0 (Victim)`, `POST /login`, `GET /`), i.e. the front-end pipelines other clients' requests into our pinned upstream.
- Captured Cookie line: `cookie: victim-fingerprint=<32>; secret=<32>; session=...` — the `session=` value starts at request offset 792 and ends at 824; the whole request is ~826 bytes. `--over 788` truncates at `; sess`; we never landed an `--over >= 824` capture.

Blockers hit:
- `h2_crlf_fill` with `--over >= 824`: the hungry smuggled POST body declares ~988 bytes; if a SHORTER victim request is pipelined first the body never completes, and one wedged upstream poisons the shared pool for all later rounds (arm_status null en masse). `--over 3000` additionally makes the ~3400-byte `pad` h2 header get rejected outright.
- Instance recovery after a wedge takes ~1-2 min (front-end proxy "Communication timed out" 500s, then 400 "Invalid request"); the lab's own 10-request back-end recycle is not enough. Re-requesting `range_launch` returns the same instance (reused:true) and does NOT reset state.
- Environment: intermittent `connect: Network is unreachable (os error 101)` from tokio/rustls pieces (retry succeeds), and a ~2 min window where cargo could not reach rsproxy.cn, which made every rs piece fail to compile (init check_only reported rust/rust-script fine, so it is pure egress).

Pieces worth keeping: `h2_crlf_fill` was patched to 1.0.2 so the filler pad is chunked across streams (600 bytes each) instead of one oversized header; unverified improvement.

