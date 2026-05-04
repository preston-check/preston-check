---
title: "First-Five Outreach Targets"
subtitle: "The fastest path to first customer is five conversations with people you already know"
audience: "operator only"
date: "2026-05-04"
---

# First-Five Outreach Targets

The single highest-leverage thing you can do this week is contact five
fintech-adjacent people from your existing network. Not strangers,
not cold outbound, not LinkedIn search. Specifically people who:

* Already know you (or know someone you know who can warm-intro)
* Are currently working at a fintech / DeFi / crypto-custody / payments shop
* Have either built or are about to undergo a security audit
* Would respond to a casual ping from you within 24 hours

## The exercise — 15 minutes, today

Open a fresh page. Make a table:

| Name | Where they work | Connection | Last contact | Likely fit |
|---|---|---|---|---|
|     |                 |            |              | bullseye / adjacent / long-tail |

Fill in five rows. The bar for "fit" is low — most people in fintech
adjacent roles are at least adjacent. Don't over-think it.

## Outreach — same day

Send each one a personalized message in their preferred channel
(text, WhatsApp, email, LinkedIn DM, Slack, whatever). The
template:

```
Hey <Name>,

I just shipped Preston-Check (preston-check.com) — a pre-deployment
security scanner narrowed specifically to fintech compliance (PCI-DSS,
MiCA, DORA, OWASP API + Smart Contract Top 10, FATF). 294 hand-curated
checks. Open source.

Wondering if you'd be willing to spend 15 minutes giving me feedback
on the kind of report it generates against <their stack>? No
expectation that you'd buy anything — I genuinely want to know if it
solves a problem you have, or if I'm building the wrong thing.

— <your handle>
```

Personalize the `<their stack>` reference. If they ship in
TypeScript/Solidity/Java, mention that those have the deepest catalog
coverage. If you don't know their stack, omit the phrase entirely.

## What you're listening for

The five conversations are intentionally NOT pitches. They're
diagnostic. Three signals to listen for:

**1. Does the framing land?**
> "Yeah we use Snyk and it's noisy. Anything fintech-narrow is interesting."

→ The "fintech-narrow" thesis works. Lean into it in subsequent outreach.

**2. Is there a specific pain you're solving?**
> "We're prepping SOC 2 right now and the evidence-package step is killing us."

→ Compliance evidence bundles are the lead feature. Position around that.

**3. Would they actually pay?**
> "We have a budget for security tools — what's it cost?"

→ This is the buying signal. Send them the EARLY50 promo code link.

If three or more conversations produce ANY of these signals, you have
product-market fit signals. If none do, the thesis needs adjustment
before any further outreach.

## Track outcomes — simple Google Sheet

Five columns:

```
| Name | Date contacted | Channel | Reply? | Outcome |
|------|----------------|---------|--------|---------|
| ...  | ...            | ...     | y/n    | "interested" / "not now" / "ghosted" / "bought" / "referred X" |
```

Update each row as it progresses. After all five close (any outcome),
the table tells you what to do next:

| Pattern | Next move |
|---|---|
| 3+ "interested", 0 "bought" | Discovery calls — diagnose what's blocking the close |
| 1+ "bought" | First-customer playbook (`docs/sales/playbook.md` § First-customer playbook) |
| 0 replies | Either your messaging is off, or these aren't the right targets — try a different five |
| 1+ "referred X" | Warm intro to X is the next outreach |

## Don't skip this exercise

Most operators skip "talk to five existing contacts" and go straight
to cold-emailing strangers or running paid ads. Both are 10x lower
signal than a personal ping to someone who knows you. The five
conversations are how you find out *whether you should be selling at
all* before you spend three months selling.

If you genuinely cannot list five fintech-adjacent contacts, that's
a meta-signal — your network might not be the right place to launch
this product, OR you need to spend a month at industry meetups
before launching.

## Time budget

- 15 minutes today: write the list
- 10 minutes today: send the five messages
- Over the next 7 days: any conversations that result, ~30 min each
- 30 minutes at end of week: tally the table, decide next steps

Total: 1-2 hours of operator time over a week, for a near-perfect
calibration of whether the product solves a real problem and whether
it solves it for people who buy things.
