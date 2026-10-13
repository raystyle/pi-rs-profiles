---
title: PortSwigger Burp Scanner essential-skills labs - app shapes and traps
---

# PortSwigger Burp Scanner essential-skills labs - app shapes and traps

Two Academy labs under `/web-security/essential-skills/using-burp-scanner-during-manual-testing/` exist purely to teach "Scan a specific request / Scan selected insertion point". Both are reachable and attackable without Burp; the app behind each is a stock clone with one hidden weakness. Facts below are the current state after direct probing.

## Launch

Instance delivery is pure HTTP via [[lab-launch]]. `range_launch` must be given `--widget-source <the lab's own page path>`: with the default `/web-security/` the *targeted-scanning* lab launches fine, but the *non-standard-data-structures* lab 302s straight back to `/web-security/` and yields no instance URL. Key is the `portswigger.net` `.AspNetCore.CookiesC1/C2` app session in a per-instance jar copy.

## Lab: "Discovering vulnerabilities quickly with targeted scanning" (read /etc/passwd, 10-minute timer)

Shop clone. Reaches: `/`, `/product?productId=N`, `POST /product/stock`, `/image/<path>`, and an unlinked `/filter` that returns the listing page.

- The only dynamic endpoint is `POST /product/stock`. It takes exactly the two form fields `productId` and `storeId`, ignores `Content-Type` (a urlencoded body is still parsed when labelled `application/json`), and rejects any XML or JSON body with 400 `"No such product or store"`. `GET /product/stock` -> 405.
- It answers a plain small integer for *any* `(productId, storeId)` pair. The value is **per-instance state, not a function of the input string**: `productId=1&storeId=1` returns 732 on one instance and 32 on the relaunched instance at the same host, while arbitrary strings (`/etc/passwd`, `/dev/null`, `AAAAA`) also get values, and equivalent spellings of one path (`/etc/passwd`, `/etc//passwd`, `/etc/./passwd`) each get their own. Read it as a seeded mock/DB-backed stock lookup, not a hash and not a filesystem read.
- No file-read sink is reachable: `/image/` rejects literal and encoded traversal (`..`, `..%2f`, `..%252f`, `%2e%2e%2f`, double-encoding) with a JSON 404 while the honest `/image/productcatalog/products/N.jpg` serves `image/jpeg` with `Cache-Control: public, max-age=3600`; `/image?filename=` does not exist, `/resources/` traversal 404s, and `/product?productId=` answers 400 `"Invalid product ID"`.
- All seven scanner families leave the stock request unchanged: quoted SQL payloads, `SLEEP`/`pg_sleep`/`LOAD_FILE`/boolean pairs, `;sleep 8` and `| sleep 8` (no delay), arithmetic template syntax (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, literal `1337*1337`) reflected as plain JSON-400 text with no 49 / 1787569, and session-cookie / `Accept-Language` traversal. A 40-name endpoint wordlist surfaces nothing beyond the routes above.
- The lab timer is enforced by the app: at expiry the page becomes "Time's up!" with a `GET /try-again` link (302 -> `/`) that restarts the clock; re-launching through `range_launch` returns the existing instance and does *not* reset the clock by itself.

## Lab: "Scanning non-standard data structures" (wiener:peter, delete carlos)

Blog clone: `/`, `/post?postId=N`, `POST /post/comment`, `/login` (hidden `csrf` field), `/my-account`, `/my-account/change-email`, `/admin`, `/logout`.

- The "non-standard data structure" is the session cookie: `<username>%3a<32-char base62 token>`. Anonymous is an empty username with a token; after login the value is e.g. `wiener%3aiqnGyq25rnENBH8etMHd63T7ZJy4XPQI`.
- **The app splits that value on the FIRST colon.** Any payload containing a colon (`http://IP:PORT`, base64, etc.) is cut in half: the username becomes the fragment before the colon and the token becomes the rest, so the request degrades to a fresh anonymous session (302 plus a new cookie). Detect this before concluding a payload was filtered.
- Auth semantics, all four observed: cookie username known + token valid -> the account page renders; cookie username unknown + valid token -> 500 `Internal Server Error` (no stack) on both `/my-account` and `/admin`; known username + invalid token -> 302 + new anonymous cookie; `/my-account?id=X` when `X` differs from the cookie username -> 302 (session dropped). The pre-colon part is looked up as a user, the post-colon part as a session; both must line up, and `administrator:<someone else's token>` is a 500 rather than admin access.
- Comments post straight to `POST /post/comment` (`csrf`, `postId`, `comment`, `name`, `email`, `website`) and are public immediately, with no moderation step. `name` renders inside `<a id="author" href="<website>">` and is HTML-escaped (`<b>BX</b>` -> `&lt;b&gt;BX&lt;/b&gt;`); the server enforces "Name must be length 64 or less." In form-urlencoded bodies a literal `+` decodes to a space, which silently mangles payloads.
- The `website` value is escaped too: `http://x.com"><svg/onload=alert(1)>` renders as `href="http://x.com&quot;&gt;&lt;svg/onload=alert(1)&gt;"`, so neither the author name nor the link target is an injection point.
- `/admin` answers 401 for a plain wiener session, so the admin cookie has to be captured, not guessed.
- Six narrow scanner passes over the lab's own requests report zero suspects: `POST /post/comment` sqli+xss (78 probes), `POST /post/comment` ssti+crlf+path+cmdi (96 probes, `truncated`), `GET /my-account?id=wiener` crlf+ssti (30), `GET /my-account?id=wiener` sqli+ssti+path (48), `POST /login` sqli+xss (50) and `POST /login` ssti+crlf (51, covering the csrf/username/password slots with the header-block oracle). The weakness is not reachable through those slots with those families.
- The session cookie is the lab's headline insertion point, but CRLF payloads are cookie-unsafe and get skipped (`skipped_cookie_unsafe` runs 4-25 per pass), so the crlf family cannot be delivered into a cookie value through the scanner; that test was hand-rolled with `raw_http` against a real `wiener:<token>` session. Four legs, response header block identical in shape every time: plain cookie -> 200; `%0d%0a` inside the username (`session=wiener%0d%0aZXQJ-CRLF%3a<token>`) -> 500, i.e. the CRLF reaches the username field and the unknown user crashes the page; a bare CRLF inside the header value -> 302 `/login` plus a fresh anonymous cookie, with the injected text absorbed as its own request header; `%0d%0a` appended to the token -> 302 plus a fresh anonymous cookie. No injected header, no marker, no malformed Location/Set-Cookie - the cookie's CRLF surface is closed.

## Tool coverage notes

- `dbg_cli net scan` families are `sqli,xss,cmdi,path` plus `xxe` (whole-body XML with DOCTYPE entities), `ssrf` (loopback / cloud-metadata URLs, aimed only at slots whose original value was URL-shaped), `ssti` (arithmetic signatures 49 / 1787569, baseline-screened) and `crlf` (judged by whether the injected header lands in the *response* header block, not the body). Any other name yields "empty battery"; `--speed fast|normal|thorough` picks the probe set (`speed: 2` = normal in the receipt).
- Slots come in eight shapes: `query:N`, `cookie:N`, `form:N`, `json:<path>[i]`, `header:N` (Referer/User-Agent/`x-*`), `path:<i>:<seg>`, `pname:<new>`, `body:xml`. Payloads that cannot survive a slot are skipped rather than mangled (`skipped_cookie_unsafe` counts the ones dropped for the cookie slot), and a scan that hits its probe cap reports `truncated: true` instead of silently dropping probes.
- A full seven-family run does not finish inside a lab window: on the stock template it ran past 5 minutes and then died with `net: reply: Resource temporarily unavailable (os error 11)`; `--max-probes 120 --budget-ms 110000` still ran beyond 200s, so the budget flag does not bound the wall clock. Two narrow passes (four families, then three) complete in under a minute each and together cover all seven - 53 and 33 probes, zero `suspects`.
- Scans do **not** release their interception: a following scan on the same pattern errors `pattern "..." already intercepted`. Release it with `net intercept off --pattern <P>` (newer client builds; `remaining_intercepts` in the receipt confirms the list is empty).
- The pattern glob's `*` spans scheme and host only: `*/product/stock` matches, while `*/stock` never matches `/product/stock`.
- `net scan` waits 20s for a matching live request. Backgrounding the scan and clicking via `setTimeout` is unreliable (a backgrounded tab throttles timers) - click synchronously and click twice about 8s apart to straddle the arm/click race. Images are cached (`max-age=3600`), so a re-visit fires no `/image/...` request unless the browser cache is cleared (`Network.clearBrowserCache`) or an uncached image is used; a one-family pass over the image route then takes minutes, not seconds.
- OOB for exfil: the self-hosted base is an authoritative DNS canary for `oob.dthack.io` (markers resolve) plus an HTTP listener on `:9999`; from the sandbox the DNS leg is the dependable one, since direct egress to `:9999` times out.

## Links

- depends-on: [[lab-launch]]
