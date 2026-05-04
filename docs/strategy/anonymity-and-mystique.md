---
title: "Preston-Check — Anonymity and Mystique"
subtitle: "How to remain pseudonymous while running a SaaS business"
author: "Preston-Check Maintainers"
date: "2026-05-04"
---

# Anonymity and Mystique

The maintainer wants to remain anonymous in the Satoshi Nakamoto tradition.
This is achievable but the model has to be different from Bitcoin's, because
Preston-Check is not a protocol — it is a SaaS business that takes payment,
signs contracts, ships releases on a schedule, and answers customer support
tickets. Pure unaccountable anonymity is incompatible with that surface
area. What is achievable, and what compounds into mystique, is a hybrid:
**a pseudonymous public identity backed by a regulated legal entity that no
one cares about**.

## The Satoshi precedent — what it actually proved

Satoshi Nakamoto worked because four conditions held simultaneously:

1. **No revenue.** Bitcoin had no SaaS to bill, no contracts to sign, no
   refunds to process. KYC was never required of the maintainer.
2. **No support obligation.** When something broke, the protocol was the
   protocol — no SLA, no support ticket, no irate customer.
3. **Mathematical self-evidence.** The code worked. People could verify
   the protocol on their own machine. The maintainer's identity added
   nothing to its credibility.
4. **A clean exit.** Satoshi posted, contributed, and disappeared. No
   ongoing performance was required. The mystique compounds in absence.

Three of those four conditions do not hold for Preston-Check. We have
revenue, support obligations, and ongoing performance demands. Only #3 —
self-evidence — applies, and that is the lever we pull hardest. The code
is the credibility. The catalog is the proof.

## The hybrid model

The maintainer is **publicly pseudonymous**. The legal operating entity is
**publicly named** but uninteresting (a Wyoming or Delaware LLC named
something neutral like "Catalog Holdings LLC"). Customer-facing
communications go through pseudonymous channels (`@preston-check` on
GitHub, `hello@preston-check.com`). Contracts and Stripe payouts go
through the LLC, signed by an attorney-of-record who is not the founder.
The founder's real-world identity is a matter of corporate registration
records that nobody reads, not a fact you ever volunteer.

This is different from Satoshi but it is sufficient for the goal:

* The face of the project — the GitHub repo, the website, the State of
  Fintech Security report, the conference talks (when given), the social
  presence — is pseudonymous.
* The legal-and-compliance plumbing — Stripe Atlas, EIN, payroll, audit
  firm, accountant, registered agent — runs through a quiet LLC that
  satisfies KYC for everyone who needs to satisfy KYC.
* No public-facing artifact ever connects the two.

## Practical operational rules

### Identity hygiene

Adopt a single pseudonym and use it consistently. The strongest version
is a mononym or initialed handle that resists curiosity and ages well.
Suggested options, in order of mystique-density:

* **"Preston"** as a mononym. Overlays the project name. Plays with the
  ambiguity of whether this is the original Preston Braswell, an heir, or
  a third-party voice speaking through the persona. Highest mystique
  density; also the highest "cute" risk if it reads as a costume.
* **"P. Braswell"** — half-revealing, half-claiming the heritage. The
  archivist-of-the-attack persona. Risky if a real Preston Braswell
  surfaces and objects.
* **"PCM"** (Preston-Check Maintainer) — austere, functional, signals the
  collective rather than the individual. Lowest cute risk, lowest
  mystique density.
* **A clean invented handle** — "Cipher", "Sentinel", "The Custodian".
  Avoids the heritage games but sacrifices the connective tissue with the
  founding story.

The recommendation is **"Preston" as a mononym**. The project name and
the founding story already do the work; the mononym lets the maintainer
inhabit them without pretending to be a corporation, and it survives
press attention because journalists default to "Preston" the way the
crypto press defaults to "Satoshi". Use it everywhere: GitHub commits,
blog posts, conference talks, Twitter/Mastodon/Bluesky.

### Git and code attribution

Configure a project-scoped git identity:

```bash
cd /path/to/preston-check
git config user.name  "Preston"
git config user.email "preston@preston-check.com"
```

This sets the repo-local identity without affecting global git config.
Every commit from this repository is then attributed to "Preston" via
the project email. The project's `homebrew-tap` and `scan-action`
repositories should use the same identity.

Do **not** rewrite commit history to retroactively anonymize earlier
commits. Force-pushing a rewritten history is a destructive operation
that breaks anyone who has cloned the repo, and earlier commits are
already tagged in releases that have been published. From this commit
forward, the identity is Preston; before, it is whatever it was. The
Satoshi precedent allows for some prehistory — Bitcoin's early commits
have inconsistent metadata too.

### Email and channels

Role-based addresses, never personal:

| Address                           | Purpose                              |
|-----------------------------------|--------------------------------------|
| `hello@preston-check.com`         | General inbound.                     |
| `sales@preston-check.com`         | Enterprise pipeline.                 |
| `security@preston-check.com`      | Vulnerability disclosure (per `SECURITY.md`). |
| `support@preston-check.com`       | Paid customer support.               |
| `press@preston-check.com`         | Journalist inquiries.                |
| `preston@preston-check.com`       | The maintainer's voice (sparingly).  |

All forward to the maintainer's actual mailbox via Cloudflare Email
Routing or similar; nothing on the public side reveals the destination.

### Social presence

Three channels, all pseudonymous:

* **GitHub** — `@preston-check-maintainer` or simply commits as `Preston`
  on the project's bot account.
* **One blog** — at `preston-check.com/notes`. Long-form, infrequent,
  technical. Treat it like Satoshi's emails: rare, dense, citable.
* **One social account** — choose one platform and ignore the others.
  Mastodon for the developer-credibility slant; X for reach; Bluesky for
  the technical-fintech crowd. Recommendation: **Mastodon at
  `@preston@hachyderm.io`** plus a syndicated mirror to X. Mastodon's
  subculture rewards quietly competent technical maintainers; X rewards
  drama. The mystique pattern wants the former.

Decline podcast appearances for the first 18 months. Decline conference
keynotes that require an in-person identity. Accept written interviews
that the publication will do over email — and reply through
`press@preston-check.com`.

### Conference talks

The Satoshi-strict version is to give zero talks. The pragmatic version
is to give written-only talks: pre-recorded video with the speaker
off-screen, slides + voice, attribution to "Preston, Preston-Check
maintainer". OWASP Global AppSec, BlackHat Briefings, and FS-ISAC have
all accepted pre-recorded sessions before. The recording is the talk;
the body in the room is delegated to a co-author or representative or
omitted entirely (some sessions accept "submitter not present" if the
material is strong).

In-person talks are eventually unavoidable for Stage 4–5 (Cited /
Embedded) positioning, but they can be deferred for years. Snyk's
founders gave hundreds of talks; the Sigstore project did most of its
adoption from chair-bound technical talks at small events. Volume of
appearances is not the lever.

### Press and the "How real is this maintainer?" question

Journalists will eventually ask "are you really anonymous?" The honest
answer is "the maintainer is pseudonymous; the legal operating entity is
public; you're welcome to file a Wyoming records request." That is the
Satoshi-cut response — it neither confirms nor denies an underlying
identity, while pointing at a public artifact that proves the project is
not a fly-by-night operation. Customers and auditors care about the
second half of that sentence. Bloggers care about the first half. Both
get what they want.

If a journalist gets close to identifying the maintainer, two things
help: (1) the project's professional infrastructure (LLC, registered
agent, audit firm, support contracts) is uninteresting to write about
because it's identical to every other SaaS, and (2) the work itself is
the story — every release, every CVE-driven check, every State of
Fintech Security report is a fresh content beat that is more interesting
than the maintainer's biography.

### Customer-facing trust

The hardest test of the model is enterprise sales. A $30k/yr Enterprise
buyer wants to know there's a real entity to sue if things go wrong. The
LLC satisfies this. The maintainer can attend Enterprise calls under the
pseudonym; the contract is signed by the attorney-of-record on behalf of
the LLC. Nothing on the customer's end exposes the maintainer's real
identity, and nothing on the maintainer's end forces the disclosure.

For SOC 2 / ISO 27001 audits of the SaaS itself, the audit firm needs to
see the operator. This is where pseudonymity legitimately strains: most
audit firms will not certify a control environment they cannot
attribute. Solution: the audit firm signs an NDA with the LLC and the
maintainer disclosed under the NDA. The audit report names the LLC, not
the maintainer. The customer sees a SOC 2 Type II report with no
identifying information about the operator beyond the LLC. This is the
pattern Bitwarden, Tailscale's early years, and several other
pseudonymous-founder operations used.

## What to lean into — the mystique playbook

Anonymity by itself is not mystique. Mystique is *anonymity plus
substance*. Three habits compound into the Satoshi-tier brand effect:

### 1. Annual essay, written like the whitepaper

Once a year, on the anniversary of the founding incident (February
each year), Preston publishes a long-form essay at
`preston-check.com/notes/year-N`. Topic: the State of Fintech Security
report's headline finding, narrated as a manifesto. Cite real incidents
by name. Argue for specific reforms. Keep it under 5,000 words. Sign it
"— Preston". This becomes the project's intellectual core. After three
years it is the canonical fintech-security-zeitgeist artifact, the way
Snyk's State of Open Source Security or Verizon's DBIR became.

### 2. Sparse, citable releases

Every release is a small whitepaper. The CHANGELOG is rigorous. The
release notes for v1.7.x today already lean this way (each line cites
the bug, the lesson, the source). Maintain that style. Quality of prose
in releases is a meaningful brand surface; people who scan changelogs
read the personality of the maintainer there before anywhere else.

### 3. Disappear from the social timeline

The single highest-leverage mystique move is **not posting**. Satoshi's
mystique is partly the rarity: 575 forum posts over two years, then
silence forever. Post quarterly, not daily. Each post is short and only
about the project. No personal life, no hot takes, no political
opinions. The signal-to-noise ratio is the whole game.

## What this means for the ongoing work

A specific list of changes the project benefits from making now:

1. **Configure repo-local git identity** to "Preston" + project email.
   `git config user.name "Preston" ; git config user.email
   "preston@preston-check.com"`. Do this in `preston-check`,
   `homebrew-tap`, and `scan-action` repos. Future commits all
   attribute consistently.
2. **Switch CI bot accounts to the project bot.** The
   threat-intel-sync workflow already commits as `preston-check-bot`
   — extend the same pattern to anywhere else CI commits.
3. **Audit identity leaks** in the public repo. The sweep run for
   v1.7.4 caught references to a specific platform name and a personal
   home-directory path; both have been replaced with neutral language.
4. **Form the legal entity.** Wyoming LLC, Stripe Atlas, registered
   agent. Roughly $300 setup, $200/year. This is the unblocker for
   Pro-tier billing and Enterprise contracts.
5. **Set up role-based email forwarding** through Cloudflare Email
   Routing or Fastmail. Six addresses, all forward to one inbox.
6. **Adopt the mononym** ("Preston") consistently across GitHub, the
   website, the docs, the State of Fintech Security report, and any
   future blog posts.
7. **Schedule the annual essay** for February each year. Nothing else
   needs to be on a public schedule.

Most of this is paperwork plus discipline; none of it is engineering.
The hardest part is the discipline — the temptation to talk about the
project in your real-world voice, on your real-world social accounts,
will be constant. The mystique is destroyed the first time the
maintainer says "yeah, that's my project" at a fintech meetup.

## Where pseudonymity ends

The model fails in three places, and you should know them in advance:

1. **Subpoena.** A US-issued subpoena to the LLC's registered agent
   compels disclosure of the beneficial owner under the Corporate
   Transparency Act (effective 2024). The maintainer's identity is
   discoverable by US federal authorities through this channel. Plan
   for it; do nothing illegal under the pseudonym.
2. **Hostile fork or competitor's PI.** A motivated competitor with
   $50k can hire a private investigator to attempt to deanonymize the
   maintainer. Most of the standard tradecraft (writing-style analysis,
   commit-time-zone correlation, social-graph mapping) works against
   single-maintainer pseudonyms. The defense is operational
   discipline (single-purpose machines, dedicated VPN, no
   cross-contamination of accounts) and time. After 3+ years the
   correlation surface shrinks.
3. **A regrettable in-person event.** A casual mention at a meetup, a
   tagged photo at a conference, a leaked Calendly link with a
   real-name email — any of these collapse the identity. Treat the
   pseudonym like an undercover operative would treat a cover identity:
   never break it casually, never break it because someone seems
   trustworthy. The cost of breaking it is permanent.

## Conclusion

Pseudonymous SaaS is harder than pseudonymous protocol, but it is
achievable. The model is: pseudonymous public identity + boring legal
entity + disciplined silence + annual substantive output. Three years of
this and "Preston" is a name that means something in the fintech
security world the same way "Satoshi" means something in the crypto
world — and it means that without anyone, including you, having to
sustain a public personality.

The single most important rule: **let the work speak**. Every shipped
release, every State of Fintech Security report, every weekly threat-
intel PR is the mystique. Anonymity without substance is a costume.
Anonymity with substance is a brand asset that compounds for as long as
the work continues.
