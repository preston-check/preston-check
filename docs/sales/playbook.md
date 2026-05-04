---
title: "Preston-Check — Sales Playbook"
subtitle: "Outreach to first paying customer in 4 weeks"
audience: "operator only"
date: "2026-05-04"
---

# Sales Playbook

This is the operator-only playbook for converting the first ~10 paying
customers. Everything in this doc is opinionated; deviate when
something obvious applies. The general shape is: 5 outbound
conversations per week → 1-2 demos → 1 closed deal in the first
month, ramping to 2-3 per month by month three.

## Pre-flight checklist (before the first call)

Verify these are working — five-minute check, blocks all sales:

```bash
for u in https://preston-check.com/ \
         https://app.preston-check.com/ \
         https://app.preston-check.com/#/settings; do
  printf "%-50s " "$u"
  curl -so /dev/null -w "%{http_code}\n" "$u" --max-time 6
done

# Stripe Checkout reachability
curl -s -X POST 'https://preston-check-billing.preston-check-edge.workers.dev/checkout' \
  -H 'Content-Type: application/json' \
  -d '{"plan": "pro_unlimited", "email": "test@example.com"}' \
  | grep -q '"url"' && echo "checkout: OK" || echo "checkout: FAIL"

# Homebrew formula points at latest tag
brew info preston-check/preston-check/preston-check 2>/dev/null | grep version
```

All four should report green. If any fail, fix before reaching out.

## Promo codes (live, ready to use)

Five codes in your Stripe account. Pick the right one for the conversation:

| Code | Discount | Use case | Uses left |
|---|---|---|---|
| `FOUNDING100` | 100% off first year | The first customer ever — give it away to anchor the launch story | 1 |
| `CONFERENCE` | 100% off first year | Booth / event giveaway, expires 14 days | 5 |
| `EARLY50` | 50% off first year | Early adopter pricing for outbound (months 1-3) | 20 |
| `SOC2READY` | 33% off first year | "We're prepping SOC 2" cold-email response | 20 |
| `PARTNER25` | 25% off perpetually | Referral / partner program — cuts forever | 50 |

Customer applies the code on the Stripe Checkout page (`+ Add promotion code` link near the price). All codes work for both Pro tiers.

To create more codes: use the Stripe dashboard → Products → Coupons.

## Ideal customer profile

Don't sell to everyone. Three concentric circles:

**Bullseye (highest conversion):**
- US/EU fintech with **5–50 engineers**
- Currently preparing for **SOC 2 / PCI-DSS / MiCA / DORA audit**
- Has a CTO or Head of Security who reads pull requests
- Stack involves at least one of: Solidity, Java, TypeScript, Go (the four languages with deepest catalog coverage)

**Adjacent (medium conversion):**
- Crypto custody / DeFi protocol with public smart contracts
- Series A-C startup with active VC pressure on security
- Compliance-led organization that's done one audit and is preparing the next

**Long tail (low conversion, defer):**
- < 5 engineers (no time to integrate any tooling)
- > 500 engineers (long enterprise sales cycle, not where to start)
- Pre-seed (no budget yet, will pay later when revenue arrives)
- Banks / FIs with mature internal AppSec teams (high friction; come back at year 2)

## Outreach templates

### Cold email — fintech founder

Subject: `<Name>, 294 fintech-specific security checks for ~10 mins of your time`

```
Hi <Name>,

I built Preston-Check for the gap I kept hitting at <fintech-vertical>:
generic security scanners flag 50 issues per scan and 45 are noise.

It's 294 hand-curated checks scoped specifically to fintech compliance —
PCI-DSS, MiCA, DORA, NYDFS, OWASP API + Smart Contract Top 10, FATF Travel
Rule. Open-source under Apache 2.0. The catalog is built from real
incident post-mortems (Wormhole, Cetus, Beanstalk Farms, the 21,201-call
session-polling attack that named the project), not regex pulled from
public repos.

Three install paths:
  brew install preston-check/preston-check/preston-check
  docker run --rm -v $(pwd):/src ghcr.io/preston-check/scan:latest
  curl -fsSL https://get.preston-check.com/install.sh | sh

Free forever for the scanner. The SaaS tier ($999/repo or $4,999/year
unlimited) adds branded compliance evidence bundles that go straight to
your auditor.

Worth a 10-minute demo? I can show you a real findings report from a
fintech codebase including the AI-generated patches.

— Preston (preston@preston-check.com)
```

### Cold email — fintech CTO

Subject: `Cutting your SOC 2 evidence-prep time by ~70%`

```
<Name>,

Most pre-deployment scanners produce reports SOC 2 auditors won't accept
without manual reformatting. Preston-Check ships compliance evidence
bundles mapped directly to PCI-DSS / SOC 2 / ISO 27001 / MiCA / DORA
control catalogs — the bundle IS the evidence document.

Open-source scanner (294 checks). Closed SaaS layer wraps the output as
the auditor-ready PDF. $4,999/year unlimited repos.

I've got 5 founding-customer slots at 50% off the first year. Code:
EARLY50 on the Stripe checkout. 14-day refund-no-questions-asked.

Demo (10 min): https://calendly.com/preston-check/intro
Try it now: brew install preston-check/preston-check/preston-check

— Preston
```

### Warm intro — referral

Subject: `<Mutual contact> mentioned you might find this useful`

```
<Name>,

<Mutual> mentioned you're <preparing for X audit / shipping a new fintech
product / dealing with security tooling fatigue>. Preston-Check might
help.

It's a fintech-narrow pre-deployment security scanner — 294 hand-curated
checks scoped to PCI-DSS, MiCA, DORA, OWASP API + Smart Contract Top 10,
FATF, etc. Open-source under Apache 2.0, scans run locally (no source
code leaves your machine), AI-augmented findings include suggested
patches.

Easy to try: `brew install preston-check/preston-check/preston-check`
then run `preston-check --high-and-up` in any repo.

Happy to do a 15-min walk-through of the kind of findings + suggested
patches it produces if useful. Otherwise enjoy.

— Preston
```

### LinkedIn DM — security engineer

```
Hey <Name>, saw your post about <recent SOC 2 / MiCA / Solidity audit
topic>. Built Preston-Check (preston-check.com) — 294 fintech-narrow
security checks + AI auto-fix, open source. Worth a look if you're
preparing for an audit.
```

## Discovery call script

15-minute call. Four questions, in order. Each answer determines
whether to proceed.

**Q1 — context** (2 min)
> "Walk me through your current pre-deployment security setup. What scanners do you run, and what do you do with the output?"

Listen for: Snyk Code, Semgrep, GitHub Advanced Security, manual code review, nothing. Anyone running nothing → high-conversion. Anyone running 3+ tools → fatigue, our positioning works. Anyone running just GitHub Advanced Security → easy switch.

**Q2 — compliance** (3 min)
> "When was your last SOC 2 / PCI-DSS audit and what's the next one?"

Listen for: actively preparing → highest urgency. Last one was rough → highest pain. Never had one → too early; defer 6 months.

**Q3 — pain** (5 min)
> "What's the most painful part of your current security tooling?"

Listen for any of:
- "False positives" → emphasize AI false-positive filter
- "Auditors don't trust the output" → emphasize compliance evidence bundles
- "Too noisy / too many alerts" → emphasize fintech-narrow curation
- "Hard to integrate with our CI" → demo the GitHub Action right then
- "Cost is too high" → segue into pricing tiers + early-adopter promo

**Q4 — close** (5 min)
> "If I could show you a real Preston-Check report on your codebase right now, would that be useful?"

Three answers:

- **"Yes, let's do it"** → schedule a follow-up demo for tomorrow. Don't try to do it on this first call.
- **"Send me a link, I'll try it myself"** → send the install command + EARLY50 promo code. Follow up 48h later asking what they saw.
- **"Not now"** → ask "what would change that?" and respect the answer. Add to a 90-day follow-up list.

Don't pitch pricing on the first call unless they ask. Pricing is the fastest way to lose a deal that hasn't surfaced the value yet.

## Demo recipe (15 min, after first call)

The wow-moment sequence in order. Don't deviate; this is what works.

**Setup** (90 sec)
- Screen-share your terminal at any large fintech repo (Bloxcross,
  digital_escrow, or a public fintech project on GitHub)
- Have `preston-check --version` ready to show v1.7.x
- Have the customer portal `app.preston-check.com/#/findings` open in a tab
- Have a real Stripe Checkout URL ready (use FOUNDING100 if it's the right close)

**Act 1 — install + scan** (3 min)
```
brew install preston-check/preston-check/preston-check
preston-check --high-and-up
```
Let it run. Talk while the output streams: explain the 294 checks,
the catalog curation, the 1.3M traces it was validated against. By
the time you're done explaining, the scan is done.

**Act 2 — score-as-headline** (1 min)
The terminal output ends with a score and a letter grade. Stop.
Read the grade aloud. *"This codebase is at A−. That's the top
quartile of fintechs your size."*

**Act 3 — the AI moat** (3 min)
```
preston-check --ai-fix --high-and-up | head -100
```
Find one critical finding with a suggested patch. Read the patch
aloud. *"This isn't just 'you have SQL injection at line 142.' It's
the actual fix, ready to git apply. That's the difference."*

**Act 4 — compliance evidence** (3 min)
```
preston-check --framework "PCI-DSS" --report pci-evidence.md
```
Open the resulting PDF. Show the framework-citation column on
every finding. *"This is what your auditor wants. Right now most
tools produce JSON your auditor's intake person has to manually
reformat. We produce the evidence bundle directly."*

**Act 5 — pricing** (3 min)
- Free forever for the scanner
- $4,999/year unlimited repos for branded reports + multi-repo
  dashboard
- 50% off first year via EARLY50 (or 100% off first year for
  founding customers via FOUNDING100)
- 14-day refund window, no questions

**Act 6 — close** (1.5 min)
> "Want me to send you the EARLY50 link now so you can play with it
> on your team's repos?"

Send the Stripe Checkout URL. Stay on the call until they've clicked
through and seen the dashboard if they're high-intent.

## Objection handling

The eight most common objections and the one-line responses that work:

| Objection | Response |
|---|---|
| "We already use Snyk" | "Snyk is excellent for general-purpose. We're fintech-narrow — different cohort. Customers run both. Want to compare reports?" |
| "We don't have budget" | "Free tier is the same scanner — you only pay for the audit-ready packaging. Try the free version first." |
| "We don't want our code leaving our machines" | "It doesn't. Scans run locally. The opt-in telemetry is aggregate scores only, no source." |
| "Too many tools already" | "Replaces Semgrep + Snyk Code + a manual fintech-checklist spreadsheet for the 294 fintech-specific checks. Reduces your stack, doesn't add to it." |
| "We need SSO / SOC 2 / Enterprise features" | "All on the Enterprise tier — let's get on a call with sales@preston-check.com." |
| "Open source — what's your moat?" | "The catalog is curated, not crawled. AI auto-fix improves with scan volume. The annual State of Fintech Security report is the canonical industry benchmark in 2-3 years. Open source IS the funnel." |
| "We need a security review of your tool first" | "Read the source — it's all on GitHub. Apache 2.0. SECURITY.md has our disclosure policy. Happy to answer specific questions." |
| "Can we self-host?" | "Enterprise tier includes on-premise deployment. Pro is SaaS-only because the audit-package layer needs the dashboard." |

## First-customer playbook (after they pay)

Once a Stripe webhook fires for the first paying customer:

**Within 1 hour:**
1. Stripe email arrives confirming the subscription
2. Generate a license file: `tools/issue-license.sh --customer <slug> --tier pro --expires +1y`
3. Email the customer:
   - Welcome message
   - Attach the `.license` file
   - Install path reminder: `brew install preston-check/preston-check/preston-check`
   - License install location: `~/.preston-check/license`
   - Quick-start command: `preston-check --high-and-up --report security-audit.md`
   - Direct link to schedule a 30-min onboarding call

**Within 7 days:**
4. Schedule and run a 30-min onboarding call
5. Walk through their first scan together
6. Identify their top three pain points; address what's actionable
7. Set expectations on AI augmentation (bring your own key)
8. Add them to the founding-customer Slack / email list

**Within 30 days:**
9. Check in: did they integrate into CI? See any value?
10. Ask for a written quote / testimonial if they're happy
11. Invite them to be cited in the State of Fintech Security 2026 report

**Within 90 days:**
12. Renewal-prep call: any change requests, anything they'd build differently
13. Discuss expansion (more repos, Enterprise tier, custom checks)
14. Ask for one referral

## Metrics that matter (track in spreadsheet for now)

Forget complex CRM until you have 10+ customers:

| Metric | Where it's tracked | Target |
|---|---|---|
| Outbound emails sent / week | Manual Google Sheet | 25 |
| Reply rate | same | > 8% |
| Discovery calls / week | Calendly + Sheet | 3-5 |
| Demo calls / week | Calendly + Sheet | 1-3 |
| Closed deals / month | Stripe dashboard | month 1: 1 / month 3: 3 / month 6: 5 |
| Free-tier scan volume | D1 telemetry table | grow weekly |
| Free → Pro conversion | Stripe + telemetry repo_hash join | track from month 3 |

Replace the Google Sheet with the admin portal Sales tab once that ships
with real data persistence (Q4 2026 per the build sequence).

## What to NOT do in the first 90 days

- Build new product features in response to one customer's "would be nice"
- Hire a sales rep
- Sign up for HubSpot / Salesforce / a "sales-stack-of-the-week"
- Pursue Enterprise pipeline (those have 6-month sales cycles; you need
  cash and feedback faster than that)
- Run paid ads
- Pay for any "we'll generate leads for you" service
- Underprice — early-adopter pricing is 50% off, not 90%

The cheapest, fastest, highest-signal path is **20 personal cold
emails to fintech CTOs in your network plus 5 discovery calls per
week**. Two months of that produces enough conversation to validate
or invalidate the entire thesis.

## When to come back to this playbook

Re-read at: 5 closed customers, 25 closed customers, 100 closed
customers. Each milestone is a different sales motion; this doc covers
the first one.
