---
title: "Academy lab: flawed enforcement of business rules (coupon alternation)"
---

# Academy lab: flawed enforcement of business rules (coupon alternation)

Objective: buy the Lightweight "l33t" Leather Jacket ($1337) on $100 store credit at `/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules`.

Mechanism: the cart coupon endpoint `POST /cart/coupon` (fields `csrf`, `coupon`) rejects only the coupon applied *immediately before* — alternating two distinct codes never repeats and keeps discounting. `NEWCUST5` is printed in the shop banner; `SIGNUP30` is accepted without the newsletter hand-out. `SIGNUP30` removes 30% of the running total, `NEWCUST5` removes a flat $5, and the total floors at $0.00.

Evidence (instance 0a2000c0043cb86d8121cfcf001c0089): login `wiener:peter` (session cookie rotates on POST /login), add `productId=1` via `POST /cart`, then 7 alternating applications — SIGNUP30 1337 → 930.9 (via ×0.7), NEWCUST5 −5 each round — final total $0.00. `POST /cart/checkout` returns 303 to `/cart/order-confirmation?order-confirmed=true`; the banner then reads `<h4>Congratulations, you solved the lab!</h4>` (`widgetcontainer-lab-status is-solved`).

Tooling: `coupon_cycle` piece (project tier) drives login, cart fill, the alternating loop with a per-round total curve, stop at total ≤ store credit, checkout and banner check — one AgentResult envelope instead of one HTTP call per coupon.

Related: [[money_loop]] handles the sibling gift-card/credit-cycle lab; [[banner_verdict]] reads the solved verdict.