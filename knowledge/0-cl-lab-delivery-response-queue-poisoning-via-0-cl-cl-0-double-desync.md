---
title: "0.CL lab delivery: response queue poisoning via 0.CL->CL.0 double desync"
---

# 0.CL lab delivery: response queue poisoning via 0.CL->CL.0 double desync

## Question
How does the smuggled XSS response reach Carlos's browser in the PortSwigger "0.CL request smuggling" lab (path `/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling`)? Pure literature research.

## Synthesized answer (public sources)
- **No exploit server.** Official lab text: "Carlos visits the homepage every five seconds. To solve the lab, exploit the vulnerability to execute alert() in his browser." No ACCESS_LOG/exploit-server/delivery reference anywhere on the page. All writeups simulate the victim by voluntarily sending `GET / HTTP/1.1 Host: <lab> User-Agent: foo` in their Turbo Intruder script (optional). So Carlos only GETs `/`; delivery is back-end response-queue poisoning, not a delivered page.
- **Frame sequence (double desync):** stage1 = early-response gadget path + malformed `Content-Length : %s` (space before colon; front-end ignores, back-end honours), empty body -> 0.CL deadlock broken by the gadget. stage2 = `stage2_chopped + stage2_revealed + smuggled` in one write: chopped converts to CL.0, revealed is the request the back-end answers, `smuggled` (the `GET /post?postId=N` request carrying `User-Agent: <xss>`) is left queued. The queued XSS response is then delivered to Carlos's next `GET /` on the pooled back-end connection.
- **Mechanism = (a)+(c):** early-response gadget (c) breaks the deadlock; the smuggled request becomes a malicious prefix left in the queue so the victim's request receives the harmful response (Kettle: "The malicious prefix then poisons the victim's request, causing a harmful response"). Not (b) cache poisoning - sources discuss the back-end response queue, no cache-key/TTL.
- **Early-response gadget in-lab:** static-file paths - blog: `/resources/images/blog.svg` & `/resources/css/labsBlog.css`; Brandon: `/resources/css/anything` (worked best); Vinci: `/resources/images/blog.svg`. Kettle's paper gadget examples: nginx static files; IIS reserved name `/con`; server-level redirects.
- **Pooling:** Kettle's defense list says "Disable upstream connection reuse (may impact performance)" - reuse is the default the attack relies on; RQP = "server sending everyone random responses intended for other users". Lab writeups confirm the queued response reaches Carlos's separate connection. No explicit lab-config statement - inferred from working PoCs.

## Caveat (own prior live testing, not public sources)
My earlier batch on a 0.CL lab instance found the front-end did not reuse back-end connections and no 0.CL holding primitive was present (logged infra-blocked) - see [[records/lab-request-smuggling-0cl-request-smuggling]]. This conflicts with the public writeups; likely instance/batch-specific. Public mechanism stands.

## Sources
- Lab page: https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling
- Kettle paper "HTTP/1.1 Must Die": https://portswigger.net/research/http1-must-die
- Official blog walkthrough: https://portswigger.net/blog/http-1-1-must-die-conquering-the-0-cl-challenge
- Brandon T. Elliott: https://brandon-t-elliott.github.io/0-cl-request-smuggling
- Nicolò Vinci: https://nicolovinci.com/posts/0cl/
- Canonical Turbo script: https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/0cl-exploit.py
- Kettle livestream: https://www.youtube.com/watch?v=B7p8dIB7bFg

## Open questions
- Exact lab front-end (nginx?) and its upstream pool config - no source states it.
- Whether Carlos's homepage response must be poisoned in a specific window (race) vs. deterministic.

## Relations
- [[records/lab-request-smuggling-0cl-request-smuggling]]
- [[desync-delivery-deficit-and-window-law]]
- [[request-smuggling-family]]