# Admin Portal — Cloudflare Pages Deploy

The admin portal lives at `admin.preston-check.com` behind Cloudflare
Access. Deploy is automated via `.github/workflows/admin-pages.yml`,
which fires on every master push touching `web/admin/**`,
`web/landing/icons/**`, `web/landing/assets/**`, or the workflow
itself.

The workflow currently skips with a notice because the Cloudflare
secrets aren't configured yet. Five one-time steps unblock it.

## 1. Create the Cloudflare account (if you don't have one)

Free tier is sufficient for Pages. Sign up at
<https://dash.cloudflare.com>. The same account will eventually host
the telemetry Worker and (when ready) the customer portal too.

## 2. Create an API token scoped to Pages

Cloudflare dashboard → My Profile → API Tokens → "Create Token" →
"Edit Cloudflare Workers" template (or create custom with the
permissions below).

Required permissions on the token:

| Resource         | Permission |
|------------------|------------|
| Account · Cloudflare Pages | Edit |
| Account · Account Settings | Read |
| User · User Details | Read |

Copy the token. Store it somewhere safe — Cloudflare won't show it
again.

## 3. Get your account ID

Cloudflare dashboard → any zone → right side rail → "Account ID".
A 32-character hex string.

## 4. Add both as repo secrets

Repo Settings → Secrets and variables → Actions → New repository
secret. Add two:

* `CLOUDFLARE_API_TOKEN` — the token from step 2
* `CLOUDFLARE_ACCOUNT_ID` — the ID from step 3

Once both secrets exist, the next push to master that touches
`web/admin/**` will deploy automatically. To deploy now without
waiting for a push, run the workflow manually:

```bash
gh workflow run admin-pages.yml --repo preston-check/preston-check
```

The first run creates the Pages project named `preston-check-admin`
in your Cloudflare account.

## 5. Bind the custom domain + set up Cloudflare Access

After the first successful deploy:

**a) Custom domain.** Cloudflare dashboard → Workers & Pages →
preston-check-admin → Custom domains → "Set up custom domain" →
enter `admin.preston-check.com`. Cloudflare will prompt you to add
a CNAME record pointing the subdomain at the project; in Route 53
add `admin.preston-check.com.` CNAME → `preston-check-admin.pages.dev`.
SSL provisions automatically once DNS verifies.

**b) Cloudflare Access policy.** This is the part that makes the
admin portal admin-only:

Cloudflare Zero Trust dashboard → Access → Applications → "Add an
application" → Self-hosted → application name "Preston-Check Admin",
session duration 24h, application domain `admin.preston-check.com`.
Then add a policy:

* Action: Allow
* Configure rules: Include → Emails → `you@your-real-mailbox.example`
  (and any backup recovery contact you trust)
* Authentication providers: GitHub OAuth (recommended) or one-time
  PIN to email

Save. Anyone visiting `https://admin.preston-check.com/` will now be
required to authenticate before the portal loads, and only the
identities in the Allow list can pass.

## Local preview during development

```bash
cd web/admin
python3 -m http.server 8081
# open http://localhost:8081/
```

The admin portal references shared brand assets via `../landing/...`
in source. The deploy workflow stages those assets into a flat
`out/landing/...` layout and rewrites the references — so production
is self-contained, while local source-tree development continues to
read from the canonical locations.

## What the deploy workflow does

1. Checks for Cloudflare credentials — skips cleanly if they're absent
   (no failed deploy, just a notice in the run summary).
2. Stages `web/admin/*` plus `web/landing/{icons,assets}/` into an
   `out/` directory.
3. Rewrites `../landing/` references in `out/index.html` and
   `out/styles.css` to `landing/` so the staged tree is self-contained.
4. Adds an `out/_headers` file with sensible cache directives:
   immutable for hashed brand assets, 1d for CSS/JS, 5min for HTML.
5. Calls `wrangler pages deploy out --project-name=preston-check-admin`.

Cloudflare Pages handles the rest — atomic deploys, instant cache
invalidation, free SSL on the bound custom domain.

## Why Cloudflare Access in front

The admin portal is the operator's daily driver. It exposes customer
PII, revenue data, license issuance, and pipeline information that
must never be reachable from a public IP. Cloudflare Access enforces
authentication at the edge, so even a misconfigured deploy or a
mistyped path can't leak the admin surface to the open web.

Combined with the hardware-bound license signing key (see
`docs/portals-and-kpis.md` "Security boundaries"), the threat model
is: even if the admin portal were fully compromised, the attacker
gets a read-only view — they can't issue licenses, since signing
requires the operator's local hardware.
