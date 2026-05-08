---
title: "Preston-Check — IP Filing & Protection Manual"
subtitle: "Step-by-step procedures, supporting documentation, and timing for patents, trademarks, copyrights, trade secrets, and defensive publications"
audience: "operator + appointed IP counsel"
status: "operational playbook"
not_legal_advice: true
related:
  - docs/ip-moat-strategy.md
---

# IP Filing & Protection Manual

This is the operator's playbook for executing the IP strategy in
`docs/ip-moat-strategy.md`. It walks step-by-step through every type of
filing — provisional patents, non-provisional patents, PCT international
extensions, trademarks (US + Madrid), copyrights, trade-secret-protection
hygiene, defensive publications, and Open Invention Network membership
— with the supporting documentation you need to assemble before each
step, the costs to expect, and the timing constraints that determine
sequencing.

This is not legal advice. Every filing in this manual must be reviewed
by qualified counsel before submission. The manual exists to make your
first meeting with counsel productive: rather than spending billable
hours getting up to speed on Preston-Check, your attorney can react to
a specific package and execute. The procedures below assume US primary
filings with international extensions; non-US-primary strategies require
adjustments.

## How to use this manual

Read the entire document once before doing anything. Several decisions
made early (LLC jurisdiction, inventor naming, public-disclosure timing)
constrain options later. After the first read-through, work through
sections 1–4 sequentially because they're prerequisites; sections 5–11
can run in parallel once 1–4 are complete.

The manual references templates and worked examples in the
`tools/ip-templates/` directory of this repository. Where a template is
referenced (e.g., "use template T-1.2"), the file lives at
`tools/ip-templates/T-1.2-name.md` and is the operator's starting point.

## Section 1 — Pre-filing prerequisites

These are the foundations every filing depends on. None of them require
counsel; all of them require operator action.

### 1.1 — Form the operating LLC

The operating LLC is the legal entity that will own all IP. The
standalone-identity strategy requires that filings go through this
entity rather than through the operator's personal name, both for
pseudonymity preservation and for clean licensing-transaction
mechanics.

Recommended jurisdiction: Wyoming. Reasons: strongest charging-order
protection in the US for single-member LLCs, no state income tax,
operator address can be replaced with registered-agent address on all
public filings, low formation cost (~$100 plus $50/year annual report).
Delaware is the conventional choice but offers weaker pseudonymity for
small entities. Nevada is comparable to Wyoming. Non-US jurisdictions
(BVI, Cayman, Estonian e-Residency) have specific use cases but
complicate USPTO filings — defer unless there's a specific reason.

Steps:

1. Register the LLC name. Suggested format: a generic-sounding holding
   name that doesn't tie back to the operator (e.g., "Catalog
   Holdings LLC", "Verified Systems LLC", or similar). Avoid names
   that include "Preston-Check" — the methodology trademark should be
   distinct from the entity name.
2. Register a Wyoming registered agent. Cost: $50–$200/year. Several
   reputable services exist (Northwest Registered Agent, Registered
   Agents Inc.). The registered agent's address replaces the
   operator's address on all public filings.
3. File Articles of Organization with the Wyoming Secretary of State.
   Filing fee: $100. Online via wyobiz.wyo.gov or by mail.
4. Obtain an EIN from the IRS. Free. Online at irs.gov/businesses/
   small-businesses-self-employed/apply-for-an-employer-identification-
   number-ein-online. Required for opening a bank account and for
   USPTO filings.
5. Open a business bank account in the LLC's name. Required for
   licensing-revenue receipts and for the LLC to be the recognized
   payor of filing fees. Many banks accept fully online formation;
   Mercury and Relay are common operator-friendly choices.
6. Draft and execute an Operating Agreement. Even single-member LLCs
   benefit from a formal agreement — it documents the operator as the
   sole member and establishes the procedural rules that protect the
   liability shield. Template available at `tools/ip-templates/
   T-1.1-llc-operating-agreement.md`.

Outputs: Articles of Organization (PDF), EIN letter (PDF), bank
account credentials, signed Operating Agreement (PDF). Store all four
in encrypted storage; copies will be requested by counsel and by the
USPTO assignment forms.

### 1.2 — Establish a record of conception

Patents require evidence of when each invention was conceived and
reduced to practice. The repository's git history is partial evidence;
operator-side notes, design docs, and chat transcripts are richer
evidence. Assemble a per-invention "conception record" before filing:

For each of the five candidate inventions in `docs/ip-moat-strategy.md`,
gather:

1. The earliest dated commit, design-doc edit, or message that
   describes the invention's concept. Screenshot with timestamp; a
   GitHub permalink to the commit is acceptable.
2. The first commit that demonstrates a working implementation
   (reduction to practice). Screenshot or permalink.
3. Any operator-side notes, sketches, or chat transcripts that show
   the conception process. Date-stamped and named.
4. A one-paragraph narrative tying these artifacts together: "On
   2026-04-XX I conceived the [invention name] approach. The first
   working implementation was committed at [commit hash] on
   2026-MM-DD. Witnesses: none required for solo inventorship."

Store the per-invention record at `tools/ip-templates/conception/
{invention-id}.md`. Templates are at
`tools/ip-templates/T-1.2-conception-record.md`. Counsel will use
these to draft the inventor's oath/declaration accompanying each
filing.

### 1.3 — Conduct preliminary prior-art searches

A serious prior-art search before filing saves $5,000–$10,000 in
attorney time per invention and identifies abandonable claims early.
You can do the first-pass search yourself; counsel will refine it.

Tools to use, in order:

1. Google Patents (patents.google.com) — full-text search, free, with
   citation graph. Good first pass.
2. USPTO Patent Public Search (ppubs.uspto.gov) — official USPTO
   database, more authoritative than Google Patents but less ergonomic.
3. Espacenet (worldwide.espacenet.com) — European Patent Office's
   global database. Catches non-US prior art that USPTO search misses.
4. Lens.org — free aggregator with good citation tools.
5. Patently-O (patentlyo.com) and IPWatchdog — secondary sources for
   recent significant cases relating to your subject matter.

For each candidate invention, run searches across the three primary
databases using:

- The exact technical terminology in your draft claim language
- Synonyms and adjacent terms (e.g., for the LLM-vs-detector loop:
  "adversarial generation", "detection evasion", "model diversity",
  "GAN-based detection")
- The IPC/CPC classification codes most relevant to the field. For
  Preston-Check's inventions, primary classes are G06F 21/57
  (vulnerability detection), G06F 21/56 (malware detection), G06N
  3/02 (neural network architectures for relevant claims), and G06F
  16/9536 (information retrieval relevance ranking).
- Date-bounded to the past 10 years for relevance, but include older
  results in the report for completeness.

For each search, document:

- The exact query string
- The database used
- The date of the search
- The top 20 results (title, patent number, assignee, filing date,
  abstract excerpt)
- A per-result one-line analysis: "blocks-our-claim-X", "adjacent-but-
  distinguishable", "irrelevant".

Store results at `tools/ip-templates/prior-art/{invention-id}.md`.
Counsel will refine the search and produce a formal Prior Art Search
Report. Template at `tools/ip-templates/T-1.3-prior-art-report.md`.

### 1.4 — Public disclosure timing audit

This is the most important timing constraint in the manual: most
non-US jurisdictions enforce absolute novelty with no grace period.
The moment substantial public disclosure occurs, foreign filing rights
are extinguished. The US grace period (12 months from public
disclosure) is the only widely-recognised exception, but relying on it
forecloses international protection.

Audit what's already public:

1. Pull the GitHub repo's commit history. Identify the earliest
   commits that publicly describe each candidate invention's core
   technique. The relevant commits are likely the ones that introduced
   `tools/sandbox_validate.py`, `tools/correlator.py`,
   `tools/adversarial_loop.py`, `tools/dual_use_audit.py`,
   `tools/telemetry_aggregate.py`, and `tools/orchestrate.py`.
2. List any public talks, blog posts, social media posts, or
   advisory disclosures referencing the invention's technique.
3. Note the dates of `docs/threat-intel-pipeline-design.md`,
   `docs/ip-moat-strategy.md`, and any other docs that describe
   inventions in detail.

If any of these dates are within the past 12 months, US protection is
still available; if any are within the past 30 days for inventions
with international filing intent, file provisional applications
URGENTLY before the next public commit.

If substantial public disclosure has already occurred more than 12
months ago, filing is no longer possible for that invention; that's
the moment to consider defensive publication instead (see Section 7).

Produce a disclosure timing report at
`tools/ip-templates/disclosure-timing.md` listing every public
artifact, date, and which invention it relates to. Counsel will use
this to determine which jurisdictions remain available and to
calibrate filing urgency.

### 1.5 — Decide on inventor naming strategy

Patent law requires named natural-person inventors. Most jurisdictions
do not permit legal-entity-only inventorship. This is the trickiest
part of the standalone-identity strategy.

Three viable approaches, in order of pseudonymity-preservation:

The strongest pseudonymity option is to file under the operator's
real legal name as inventor, with the LLC as assignee. The natural
person's name appears in patent records (USPTO assignment records are
public), but the LLC owns the patent and the LLC's name appears in
licensing transactions. This breaks the persona's pseudonymity at the
USPTO record layer but keeps it intact for everyday business
purposes. Acceptable if the persona doesn't require absolute
anonymity.

A weaker option is to file under a non-pseudonymous co-inventor (e.g.,
a hired patent agent or a contributor) who agrees to be listed. This
is mechanically possible for inventions where someone else
contributed substantively, but inventor-listing requires honest
representation of contribution; you cannot list someone who did not
actually invent.

The strongest pseudonymity option is to abandon patenting entirely
for inventions where pseudonymity matters more than patent protection
and rely on trade-secret protection plus defensive publication. This
gives up the patent moat but preserves the persona.

Recommended path for Preston-Check: file under operator's real legal
name with LLC as assignee. The pseudonym (Preston X) is the public-
facing identity; the legal-name appearance in USPTO records is
acceptable because most prospective customers and partners never look
at USPTO data, and IP buyers in due diligence will already need
operator legal identity for transaction purposes. This is the
standard approach for solo founders building IP-heavy businesses
under personas.

Document the decision: write a one-page decision memo at
`tools/ip-templates/inventor-naming-decision.md` stating the choice,
the reasoning, and the trade-offs accepted. Counsel will need this to
draft the assignment correctly.

## Section 2 — Selecting and engaging IP counsel

You need three distinct types of legal services. Don't try to combine
them — patents, trademarks, and corporate IP work require different
specialisations and the cost of generalists doing specialist work is
higher than the cost of three specialists.

### 2.1 — Patent counsel (registered patent attorney or agent)

Required for: drafting and prosecuting all patent filings (provisional,
non-provisional, PCT). Must be a USPTO-registered practitioner; USPTO
maintains a public roster at oedci.uspto.gov.

What to look for:

1. Registered patent attorney (preferred) or registered patent agent
   (acceptable). Attorneys can also handle litigation; agents cannot.
   For pure prosecution, agents are equivalent and typically cheaper.
2. Direct experience prosecuting patents in software security tooling.
   Adjacent fields are acceptable: fuzzing tools, static analysis,
   intrusion detection, anti-malware. Avoid pure-mechanical or pure-
   biotech firms even if they're cheaper.
3. At least 5 years of post-registration experience and at least one
   issued patent in your subject area visible in their public record
   (use ppubs.uspto.gov to search by attorney/agent name).
4. Comfort with solo-founder + LLC-assignee structures. Larger firms
   are often better at large-corporate clients and worse at solo
   founders.
5. Clear flat-fee or capped-fee policies for provisional drafting.
   Avoid attorneys who only quote hourly for provisional work; the
   work is sufficiently bounded that a flat fee is normal.

Where to find: the AIPLA member directory (aipla.org), specialised
boutique firms (Schwegman Lundberg & Woessner, KPPB Law, Marathon
Patent Group), or independent registered agents (often $300–$500/hour
versus $700–$1200/hour for big-firm attorneys, with comparable quality
for prosecution work).

Initial engagement deliverable: signed engagement letter specifying
scope (provisional drafting for the five candidate inventions),
flat-fee per provisional ($5,000–$15,000 typical), and clear
deliverables. Template at `tools/ip-templates/T-2.1-patent-engagement.md`.

### 2.2 — Trademark counsel

Required for: USPTO trademark filings, Madrid Protocol extensions,
trademark watch service, certification-mark filing for the detection-
time benchmark. Trademark work is technically simpler than patent
work; many patent attorneys handle trademarks competently as a
secondary service.

What to look for:

1. USPTO bar admission for federal trademark filings (different
   registration from patent practitioners).
2. Experience with certification marks specifically. Most attorneys
   handle ordinary trademarks; certification marks are a less common
   category and require specific expertise. The detection-time
   benchmark filing depends on this.
3. Madrid Protocol experience for international extensions.
4. Comfort with the common-law-trademark-establishment process if any
   marks have been used in commerce before federal filing.

Where to find: same firms as patent counsel often handle trademarks;
also consider trademark-focused firms (TrademarkNow, Gerben IP,
Schwegman LM&W's trademark group). Online services (LegalZoom, Trademark
Engine) handle simple ordinary trademarks but should not be used for
certification marks or Madrid Protocol filings — the cost savings are
swallowed by complications later.

Initial engagement deliverable: engagement letter specifying scope (4
US trademark filings + Madrid Protocol for top 2), flat-fee per
mark per class ($1,000–$2,500), trademark-watch-service annual fee
($500–$1,500/year). Template at `tools/ip-templates/
T-2.2-trademark-engagement.md`.

### 2.3 — Corporate / IP-strategy counsel

Required for: assignment agreements between operator and LLC,
licensing-agreement templates, employment-contract templates with IP
assignment clauses, NDAs, trade-secret-protection policies, OIN
membership review.

What to look for: corporate counsel with explicit IP-licensing
experience, ideally tech-licensing background. Wyoming-based counsel
preferred for jurisdiction familiarity but not required if your patent
counsel has Wyoming experience.

Initial engagement deliverable: hourly retainer ($300–$700/hour) with
a budget cap for the initial scope (LLC IP-assignment policy,
licensing agreement template, NDA template, trade-secret policy
draft). Template at `tools/ip-templates/T-2.3-corporate-engagement.md`.

### 2.4 — Counsel-engagement timing

Engage all three counsel types in parallel after Section 1 is
complete. Patent counsel is the time-critical one because of the
public-disclosure clock; trademark and corporate counsel are less
urgent.

First-meeting agenda for patent counsel:

1. Overview of Preston-Check (15 min): what the product does, the
   commercial model, the open-core split.
2. Walkthrough of `docs/ip-moat-strategy.md` (10 min): the strategic
   frame and the five candidate inventions.
3. Hand over the prior-art search reports per invention (15 min): let
   counsel review and identify the strongest claims.
4. Discuss inventor-naming decision (5 min): confirm the operator's
   choice from Section 1.5 and walk through the assignment chain.
5. Disclosure timing report review (10 min): confirm available
   jurisdictions and filing urgency.
6. Engagement letter signing (5 min): scope, fees, timeline.
7. Provisional drafting kickoff (5 min): which inventions to file
   first, what supporting materials counsel needs from you.

Total time: 65 minutes. Send all the materials in advance so counsel
arrives prepared. This first meeting is what determines whether you
get a productive engagement or burn $2,000 in onboarding time.

## Section 3 — Patent filing procedure

This section walks through the patent process from provisional to
issuance, with the operator's role at each step.

### 3.1 — Provisional patent applications

Provisionals are inexpensive ($300 USPTO fee for small entities)
twelve-month placeholders that lock in the priority date. They don't
require formal claim language or formal drawings; they require a
written description detailed enough that someone skilled in the art
could practice the invention. Conversion to non-provisional within
twelve months is required to keep the priority date.

Per-invention deliverables for provisional drafting:

1. **Specification draft** (3,000–8,000 words). Counsel writes this
   based on the invention's design doc. For Preston-Check's
   inventions, much of the specification is already written in
   `docs/threat-intel-pipeline-design.md` — counsel adapts that text
   to USPTO format. Operator review: read the draft for technical
   accuracy; reject any specification that misrepresents how the
   invention actually works (a subtly-wrong specification can void
   the patent later).

2. **Drawings** (3–8 figures per invention). For software inventions,
   drawings are typically: system architecture diagram, data-flow
   diagram, state machine, sequence diagram. Counsel can use the
   ASCII diagrams in `docs/threat-intel-pipeline-design.md` as the
   basis; formal redrawing in patent format is a ~$200 expense per
   figure if commissioned externally, or $0 if counsel does it
   in-house. Operator review: confirm each figure represents the
   invention accurately.

3. **Inventor declaration** (signed by operator). USPTO form AIA/01.
   States that the named inventor believes themselves to be the
   original inventor, has reviewed the application, and acknowledges
   the duty of disclosure. Template at
   `tools/ip-templates/T-3.1-inventor-declaration.md`.

4. **Application data sheet** (USPTO form AIA/14). States the
   inventor's identity, address (LLC's registered-agent address is
   acceptable), and assignment information.

5. **Assignment** (operator → LLC). Separate document recording that
   the inventor assigns all rights to the LLC. Counsel drafts;
   operator and LLC officer (often the same person) sign. Recorded
   with USPTO via Form PTO-1595 ($40 fee per document).

6. **Filing fee payment**: small entity $300, micro entity $150 if
   the LLC qualifies (gross income under $208,000). Pay via USPTO's
   EFS-Web or Patent Center.

Provisional filing day-of process:

1. Counsel uploads via Patent Center.
2. USPTO returns an Application Number and a Filing Receipt within
   24 hours.
3. Mark the priority date on every public reference to the invention
   from this point forward (in marketing materials: "Patent
   Pending"; in code comments: nothing required, but useful for the
   operator's own records).
4. Set a calendar reminder for ten months from filing date to begin
   non-provisional drafting.

Costs per provisional: $300 USPTO fee + $5,000–$15,000 attorney fee +
$40 assignment-recording fee + $0–$1,600 drawings = approximately
**$5,500–$17,000 per invention**.

### 3.2 — Non-provisional conversion (within 12 months)

The non-provisional is the actual patent application that gets
examined and (hopefully) granted. It must be filed within 12 months
of the provisional or the priority date is lost.

Additional deliverables on top of the provisional:

1. **Formal claims** (10–25 claims per patent typical). The most
   important part of the application — claims define the legal scope
   of the patent. Counsel drafts; operator reviews carefully.
   Independent claims are the broadest; dependent claims add
   limitations. Strategy: file 1 or 2 broad independent claims
   willing to be narrowed during prosecution, plus a fan of dependent
   claims that establish fallback positions.

2. **Abstract** (≤150 words). Concise statement of the invention.
   Counsel drafts.

3. **Information Disclosure Statement (IDS)** listing all known
   prior art. Operator must disclose any reference they're aware of
   that could be material to patentability. The prior-art search
   from Section 1.3 feeds directly into this. Failure to disclose
   known material art is fraud and can void the patent.

4. **Filing fee**: small entity $400 + $200 search fee + $500
   examination fee = $1,100. Micro entity halves these. Plus
   excess-claim fees if more than 3 independent or 20 total claims.

5. **Inventor declaration update** if any inventor information has
   changed.

Non-provisional prosecution timeline:

1. **Filing day**: USPTO returns filing receipt within 24 hours.
2. **6–12 months**: USPTO assigns to an examiner. No action required.
3. **12–18 months from filing**: First Office Action issued. The
   examiner identifies prior art and rejects some or most claims.
   This is normal; expect it. Counsel responds with arguments and
   claim amendments.
4. **18–30 months from filing**: One or two more rounds of Office
   Action and response.
5. **30–36 months from filing**: Notice of Allowance (claims
   granted) or Final Rejection (claims denied; appeal or abandon).
6. **36 months**: Patent issues if allowed. Issue fee paid: $480
   small entity. Maintenance fees due at 3.5, 7.5, and 11.5 years
   ($2,000, $3,760, $7,700 small entity respectively).

Costs per non-provisional through grant: $1,500 USPTO fees + $10,000–
$25,000 attorney fees through prosecution + $480 issue fee +
maintenance fees later = approximately **$12,000–$28,000 per invention
through grant**.

### 3.3 — PCT international extension (within 12 months of priority)

For inventions worth international protection, file a PCT application
within 12 months of the priority date. PCT preserves the option to
file in 150+ jurisdictions; actual national-phase entries happen at
month 30 and cost separately per country.

Recommended PCT priorities for Preston-Check (in order):
US (already covered by non-provisional), EPO (European Patent
Office — covers all EU member states with a single grant), United
Kingdom (separate from EPO post-Brexit), Canada, Australia, Japan,
South Korea, India, China.

PCT filing deliverables:

1. **PCT application** — counsel adapts the non-provisional. Same
   specification, same claims, with international-format adjustments.
2. **Filing fee**: $1,330 base + $213 per claim over 30 + $11
   per page over 30 + transmission fee $240 = approximately $1,800–
   $2,500 per invention.
3. **International search report** issued within 16 months from
   priority. Counsel uses this to refine claim strategy before
   national-phase entries.

Cost per PCT filing: approximately **$5,000–$8,000 per invention
through international search report**, then per-country costs at month
30 ranging from $5,000 (Canada) to $25,000 (Japan, with translation)
each.

### 3.4 — Open Invention Network membership pledge

After provisional filings but before national-phase prosecution
completes, file the OIN membership pledge. OIN provides a non-
aggression framework: members agree not to assert their patents
against the Linux ecosystem and against other OIN members. Joining
signals defensive intent and meaningfully reduces patent-troll-target
risk.

Steps:

1. Visit openinventionnetwork.com/license.
2. Review the OIN License (the non-aggression covenant).
3. Sign as the LLC. Free; no annual fees.
4. Provide the patent application numbers as they're filed.

Alternative if OIN is too broad: draft a custom non-aggression pledge
limited to specific use cases (e.g., open-source security tools,
academic research, good-faith implementations under a defined-class
licence). Corporate counsel from Section 2.3 drafts this; it's
typically a 2–4 page document published on the company's website
alongside the patent portfolio.

## Section 4 — Trademark filing procedure

This section covers the four candidate trademarks identified in
`docs/ip-moat-strategy.md`: corpus name, methodology spec name,
attestation index name, detection-time benchmark name.

### 4.1 — Pre-filing trademark clearance

Before filing, conduct a clearance search for each mark. This
identifies existing similar marks that could block registration or
draw an opposition. Clearance is critical because filing a
conflicting mark wastes the filing fee (non-refundable) and can draw
a cease-and-desist from the existing mark holder.

Self-service clearance steps:

1. **USPTO TESS search** at tmsearch.uspto.gov. Search for the
   exact mark and for similar marks (different spellings, missing
   spaces, plural variants).
2. **Common-law search**: Google the proposed mark. Look for
   businesses using the same or similar name in any industry.
3. **Domain search**: check if the .com, .io, and .com domain
   variations are owned by an existing business in your space.
4. **State trademark search**: each state has its own trademark
   registry. A federal mark conflicts with prior state-registered
   marks in the same class.
5. **Markify or Trademarkia search**: paid services that aggregate
   federal + state + common-law data. $30–$100 per search; useful
   for the four primary marks.

For each candidate mark, document:

- The exact mark including capitalisation and any stylisation
- The classes of goods/services it will cover (Nice Classification;
  for software products typically class 9 + class 42)
- The clearance results (any conflicts found, any similar marks in
  related classes)
- A go/no-go recommendation

Trademark counsel from Section 2.2 reviews and refines. Output: a
per-mark clearance memo at `tools/ip-templates/trademark-clearance/
{mark-name}.md`. Template at `tools/ip-templates/T-4.1-clearance-memo.md`.

### 4.2 — US trademark filing

Each mark gets one application per class of goods/services. For
Preston-Check, all four marks should file in classes 9 (downloadable
software / data) and 42 (computer services). Two classes per mark = 8
total class filings.

Per-class deliverables:

1. **Trademark Electronic Application System (TEAS)** form. Two
   versions: TEAS Plus ($250/class, more required upfront) or TEAS
   Standard ($350/class, more flexibility). For most filings, TEAS
   Plus is the cheaper-but-stricter option.
2. **Mark drawing**. For word marks, just the words in standard
   characters. For stylised or logo marks, a JPEG or PDF of the
   mark.
3. **Specimen of use** (for use-in-commerce filings) or **statement
   of bona fide intent to use** (for ITU filings). For Preston-Check,
   intent-to-use is appropriate for marks not yet in commerce; once
   commerce starts, file a Statement of Use within 6 months
   ($100/class fee).
4. **Identification of goods/services**. Must be specific. The USPTO's
   ID Manual at idm-tmng.uspto.gov has pre-approved descriptions; use
   those if possible.
5. **Owner information**: LLC name, address, EIN.
6. **Signature**: applicant must sign a verified declaration.

Per-mark filing process:

1. Counsel files via TEAS.
2. USPTO returns serial number and filing receipt within 24 hours.
3. **3–6 months**: examining attorney issues an Office Action or
   approves for publication.
4. **6–9 months**: mark published in the Official Gazette for 30
   days. Third parties can file opposition during this window.
5. **9–12 months**: if no opposition, registration issues. Total
   per-mark fee through registration: $250–$350/class + $1,000–$2,500
   attorney fee per class = approximately **$1,250–$2,850 per class
   per mark**.

For all four marks across two classes: 4 × 2 × $1,250–$2,850 =
approximately **$10,000–$23,000** total US trademark portfolio.

### 4.3 — Madrid Protocol international extensions

Once the US base mark is registered, Madrid Protocol allows extension
to 100+ jurisdictions through a single filing. Madrid is much cheaper
than separate filings per country; recommended for the methodology
mark and the attestation index mark, which have global commercial
implications.

Per-mark Madrid steps:

1. **International Application** filed with USPTO (which forwards to
   WIPO). Form MM2.
2. **Designate jurisdictions**: pick the countries to extend to.
   Recommended for Preston-Check: EUIPO (covers EU), UK, Canada,
   Australia, Japan, South Korea, China, India.
3. **Filing fees**: WIPO base fee 653 Swiss francs (~$720) + per-
   country fees ranging from 100–500 Swiss francs each. For 8
   jurisdictions: approximately $2,500–$5,000 per mark.
4. **Attorney fee**: $2,000–$4,000 per mark per Madrid filing.

Per-mark Madrid total: approximately **$4,500–$9,000**. For two marks
extended internationally: **$9,000–$18,000**.

### 4.4 — Certification mark for the detection-time benchmark

The detection-time benchmark is best protected as a certification
mark rather than an ordinary trademark. Certification marks are filed
under USPTO Section 4 and require additional documentation specific
to the certification process being registered.

Additional deliverables:

1. **Certification standards document**. A formal written description
   of what's being certified (in this case, the methodology for
   measuring time-to-detection) and how the certification is awarded.
2. **Statement of non-use as a trademark**. The certification-mark
   owner must not use the mark themselves to identify their own
   goods/services — only to certify others.
3. **Statement of governance**. Description of who decides whether a
   given product/service meets the certification standard.

Costs are similar to ordinary trademark filing ($350/class) but
attorney fees are higher ($3,000–$6,000) due to the certification
standards document. Total: approximately **$3,500–$7,000**.

## Section 5 — Copyright registration

Copyright protection arises automatically upon creation of an original
work; registration is optional but provides significant litigation
benefits (statutory damages, attorney fees, presumption of validity).
Register the high-value works:

The methodology specification document. The attestation schema
document. The corpus structure (database registrations are separate
from text copyright; both are useful). The IP moat strategy document
(internal but high-value).

### 5.1 — Per-work registration steps

1. **Visit copyright.gov/registration**.
2. **Choose the appropriate form**:
   - TX (literary works): for documents like the methodology
     specification.
   - CA (corrections/amplifications): for updates to previously-
     registered works.
   - Group registration is available for related works filed
     together — cheaper per work.
3. **Filing fee**: $45 single work / $65 multiple works / $85 group
   of unpublished works. Online filing only.
4. **Upload deposit copy**: PDF of the work to register.
5. **Owner information**: LLC name and address; the LLC is the
   author (under work-for-hire) or the assignee.

Per-work cost: $45–$85. For the four high-value works above:
approximately **$200–$340**. Counsel review optional (~$500 if used);
copyright registration is straightforward enough to do pro se.

### 5.2 — EU database right registration (for the corpora)

In the EU, sui generis database rights provide additional protection
for the corpora's structure beyond copyright. Filing is per-member-
state and varies; for most jurisdictions there's no formal
registration (rights arise automatically) but evidence of substantial
investment in compiling the database is required. Document the corpus
development process (time spent, labelling effort, curatorial
decisions) so the database right is assertable later if challenged.

## Section 6 — Trade-secret protection procedure

Trade secrets protect what isn't patented or published. The
synthesis prompt library, the orchestration code (in a private repo),
the rolling-current corpus snapshot, the quorum-anomaly model
parameters, and operational logs are the trade-secret-protected
assets per `docs/ip-moat-strategy.md`.

Trade-secret protection requires affirmative steps to maintain. Failure
to protect equals abandonment.

### 6.1 — Confidentiality marking

Every internal document containing trade-secret information must be
marked. Standard format at the top of the document:

```
CONFIDENTIAL — TRADE SECRET
Property of [LLC name]
Disclosure prohibited without written authorization
```

Apply this marking automatically to: any file in the private
orchestration repo, internal design documents, prompt-library files,
operational logs, internal incident reviews, customer data exports.
Tooling: a pre-commit hook on the private repo can verify marking
presence on every commit.

### 6.2 — Access controls

Only personnel with a need-to-know should access trade-secret material.
For a solo-operator LLC this is trivial (only you); document the
policy anyway because it matters when contractors are engaged later.

Apply: hardware-bound key for repo access, MFA on all accounts,
encrypted-at-rest storage (Cloudflare R2 + KMS, or operator's
hardware-encrypted laptop).

### 6.3 — Confidentiality agreements

Every contractor, employee, advisor, or business partner who could
access trade-secret material must sign an NDA before the access
begins. Template at `tools/ip-templates/T-6.3-mutual-nda.md`. Corporate
counsel reviews; operator signs as LLC officer.

### 6.4 — Trade-secret policy document

Document the LLC's trade-secret protection policy. Required for
later litigation if a misappropriation claim is made — the court
will examine whether reasonable measures were in place. Template at
`tools/ip-templates/T-6.4-trade-secret-policy.md`. Items to cover:

- What's classified as a trade secret
- Marking procedures
- Access controls
- Confidentiality obligations of personnel
- Procedures for handling alleged misappropriation
- Annual review and update cadence

Sign and date the policy; review annually.

### 6.5 — Departure procedure

If a contractor or employee leaves: revoke all access immediately;
exit-interview review of trade-secret obligations; written
acknowledgment that the obligations survive termination; review
recent communications for any signs of competitive intent.

For a solo operator, this is theoretical until first hire. Have the
template ready before the first hire so onboarding includes the right
documents.

## Section 7 — Defensive publications

For inventions you don't want to patent (cost, pseudonymity, or
strategic reasons) but want to bar competitors from patenting,
defensive publication establishes prior art that blocks future
filings.

Two routes:

### 7.1 — IP.com Prior Art Database

Submit at ip.com. Cost: $135–$250 per disclosure. Provides timestamped
publication that's indexed by USPTO and EPO examiners during prior-
art search. Recommended for short technical disclosures.

### 7.2 — Open Invention Network's Linux Defenders + Defensive
Publication Program

Free for OIN members. Combines disclosure with a non-aggression
covenant. Better long-term value than IP.com if you've joined OIN.

### 7.3 — Academic conference / journal publication

Highest-credibility route but slowest (3–12 months from submission to
publication). Suitable for the methodology specification, which is
substantial enough for journal-paper-length treatment. Costs
typically zero for open-access journals (some have author-fee models
$500–$3,000); peer-review delay is the trade-off.

For Preston-Check, recommended approach: publish the methodology spec
at IP.com defensively (cheap, fast) AND submit it to a security venue
(USENIX Security, IEEE S&P, CCS) for the credibility benefits. The
two channels reinforce each other.

## Section 8 — Domain and handle defensive registrations

These are not IP filings but are part of the moat. Register them
proactively before someone else takes them.

### 8.1 — Domain registrations

Domains to register if not already owned: preston-check.com (already
owned), preston-check.org, preston-check.io, preston-check.dev,
preston-check.ai, preston-check.security. Plus the methodology mark
domain (when the mark name is finalised) and the attestation index
domain.

Cost: $15–$50 per domain per year. Register through a registrar that
supports privacy WHOIS (Cloudflare Registrar, Namecheap with WhoisGuard,
or any registrar supporting GDPR-compliant WHOIS minimisation).

### 8.2 — Social handle registrations

Reserve the relevant handles on Twitter/X, LinkedIn, GitHub, Mastodon,
Bluesky, and any developer-focused platforms relevant to the
audience. Even handles you don't intend to use should be reserved to
prevent impersonation. Cost: free (just time).

### 8.3 — Methodology certification web property

When the methodology spec name is finalised and trademarked, set up a
dedicated web property at the methodology-name domain (for example,
vac-methodology.org or similar). This becomes the canonical reference
for licensees and certification claimants. Cost: domain registration
plus minimal hosting; can run on Cloudflare Pages alongside the
existing infrastructure.

## Section 9 — Supporting documentation library

This section enumerates the templates and reference documents you'll
need across all filings. Each is a starting point; counsel will adapt
to the specific filing.

| Template ID | Purpose | Section |
|---|---|---|
| T-1.1 | LLC operating agreement | 1.1 |
| T-1.2 | Conception record (per invention) | 1.2 |
| T-1.3 | Prior-art search report | 1.3 |
| T-1.4 | Public-disclosure timing audit | 1.4 |
| T-1.5 | Inventor naming decision memo | 1.5 |
| T-2.1 | Patent counsel engagement letter | 2.1 |
| T-2.2 | Trademark counsel engagement letter | 2.2 |
| T-2.3 | Corporate counsel engagement letter | 2.3 |
| T-3.1 | Inventor declaration | 3.1 |
| T-3.2 | Assignment (operator → LLC) | 3.1 |
| T-3.3 | Provisional application cover sheet | 3.1 |
| T-3.4 | Information disclosure statement | 3.2 |
| T-4.1 | Trademark clearance memo | 4.1 |
| T-4.2 | Specimen of use | 4.2 |
| T-4.3 | Statement of bona fide intent to use | 4.2 |
| T-4.4 | Certification standards document | 4.4 |
| T-5.1 | Copyright registration form fields | 5.1 |
| T-6.1 | Confidentiality marking standard | 6.1 |
| T-6.2 | Access control policy | 6.2 |
| T-6.3 | Mutual NDA | 6.3 |
| T-6.4 | Trade-secret policy | 6.4 |
| T-6.5 | Departure procedure | 6.5 |
| T-7.1 | Defensive publication coversheet | 7.1 |

The templates themselves are not yet committed to the repo. Operator
should engage counsel to draft customised versions; the bracketed
items above are pointers for what to ask for.

## Section 10 — Timeline and budget overview

The full IP protection programme is a multi-year, multi-six-figure
investment. Plan it in four phases.

### Phase 1 — Months 0–3 (prerequisites and provisionals)

LLC formation, EIN, bank account, conception records, prior-art
searches, disclosure-timing audit, counsel engagement, provisional
patent filings on all five inventions. Critical-path: provisionals
must file before substantial public disclosure of the inventions.

Phase 1 cost: $35,000–$80,000 (LLC: $500; counsel onboarding: $5,000;
provisional drafting + filing: $25,000–$75,000).

### Phase 2 — Months 3–9 (trademarks and methodology publication)

US trademark filings on all four marks. Madrid Protocol filings on
the top two. Methodology-specification publication (defensive +
academic). Copyright registrations on high-value works. OIN
membership.

Phase 2 cost: $15,000–$30,000.

### Phase 3 — Months 9–24 (non-provisional conversions and PCT)

Convert provisionals to non-provisionals before the 12-month
deadline. File PCT applications on the inventions worth international
protection. Begin patent-prosecution responses to first Office
Actions.

Phase 3 cost: $80,000–$180,000.

### Phase 4 — Months 24+ (national-phase entries and ongoing maintenance)

PCT national-phase entries in selected jurisdictions at month 30.
Continued patent prosecution. Annual trademark watch service.
Trademark renewals at 5- and 10-year marks. Patent maintenance fees
at 3.5, 7.5, 11.5 years.

Phase 4 cost: $50,000–$200,000+ depending on national-phase footprint.

### Total budget envelope

Through patent grant on all five inventions and full international
protection: **$200,000–$500,000 over 4 years**, with ongoing annual
maintenance of $20,000–$50,000/year thereafter.

This is real money. The strategic case for the investment is in
`docs/ip-moat-strategy.md` — the IP portfolio's value at exit
(typical multiple is 3–10× cost for security-tooling acquisitions
with comparable IP). If the operator's planned exit is a sale to a
strategic acquirer, the IP portfolio is often the single highest-
value asset transferred. If the planned exit is bootstrapping to
profitability and continued operation, the IP portfolio is the
defensive moat that justifies premium pricing on licensing channels.

## Section 11 — Maintenance and renewals (post-filing)

After everything is filed, the ongoing work is much smaller but
non-zero. Set calendar reminders for:

### Patents

- 3.5 years after grant: small entity maintenance fee $2,000.
- 7.5 years: $3,760.
- 11.5 years: $7,700.
- Year 17–20: patent expires; no renewal possible.
- PCT national-phase: at month 30 from priority, decide which
  jurisdictions to enter.

### Trademarks

- 5–6 years after registration: file Section 8 declaration of use
  ($225/class) and Section 15 declaration of incontestability
  (optional, $200/class).
- 9–10 years: combined Section 8 + Section 9 renewal ($425/class).
- Every 10 years thereafter: Section 9 renewal.
- Madrid Protocol: 10-year renewal cycles per international
  registration.

### Copyrights

- No renewal required. Copyright lasts life-of-author + 70 years (or
  for corporate authorship, 95 years from publication / 120 years
  from creation, whichever is shorter).

### Trade secrets

- Annual policy review and acknowledgment by all personnel with
  access.
- Any departure → immediate access revocation + acknowledgment of
  surviving obligations.

### Domain registrations

- Annual auto-renewal at the registrar. Verify auto-renewal is on for
  every defensive registration.

## Section 12 — Disclaimer

Nothing in this manual is legal advice. Patent, trademark, copyright,
and trade-secret law all involve jurisdiction-specific rules and
case-specific factors that this manual cannot address. Every filing
described here must be reviewed by qualified counsel in the relevant
jurisdictions before submission. The cost ranges quoted are
approximate and based on US fee schedules current as of 2026; verify
current fees at uspto.gov, copyright.gov, and counsel quotes before
committing budget.

The manual is a planning artifact, intended to make counsel meetings
productive and to ensure the operator has assembled the right
supporting documentation before each filing. It is not a substitute
for engagement with qualified counsel.

The strategy framework underlying this manual is in
`docs/ip-moat-strategy.md`. The technical foundation is in
`docs/threat-intel-pipeline-design.md` and
`docs/threat-intel-pipeline-threat-model.md`. Read all three together
before beginning any filing.
