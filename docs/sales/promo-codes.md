---
title: "Active Promo Codes"
audience: "operator only"
date: "2026-05-04"
---

# Active Promo Codes

Live in Stripe (live mode) as of 2026-05-04. Customer applies the code
on the Stripe Checkout page via "+ Add promotion code".

| Code | Discount | Duration | Max uses | Expires | Use case |
|---|---|---|---|---|---|
| `FOUNDING100` | 100% off | first year only | 1 | 30 days | The first paying customer ever — give it away to anchor the launch story |
| `CONFERENCE` | 100% off | first year only | 5 | 14 days | Conference / event giveaway |
| `EARLY50` | 50% off | first year only | 20 | 90 days | Early-adopter outbound (months 1-3) |
| `SOC2READY` | 33% off | first year only | 20 | 60 days | "We're prepping SOC 2" cold-email response |
| `PARTNER25` | 25% off | perpetual | 50 | 365 days | Referral / partner program |

All codes work for both Pro tiers ($999/repo and $4,999 unlimited).
None apply to Enterprise (sales-led, no Checkout).

## How customers redeem

1. Click any "Upgrade" button at `https://app.preston-check.com/#/settings`
2. On the Stripe Checkout page, click **"+ Add promotion code"** above the price
3. Enter the code, click apply
4. Total drops, complete the form
5. After Stripe redirects back, the success banner shows on the customer portal Billing tab

## Operator commands — manage promo codes

```bash
# Set up SK once per shell (the live secret key from your password manager)
export SK=sk_live_...

# List all active promo codes
curl -s -u "$SK:" -H 'Stripe-Version: 2024-04-10' \
  'https://api.stripe.com/v1/promotion_codes?limit=20&active=true&expand[]=data.coupon' \
  | python3 -m json.tool | head -80

# Disable a promo code
PROMO=$(curl -s -u "$SK:" 'https://api.stripe.com/v1/promotion_codes?code=EARLY50' \
  | grep -oE '"id":\s*"promo_[^"]*"' | head -1 | cut -d'"' -f4)
curl -s -u "$SK:" -X POST "https://api.stripe.com/v1/promotion_codes/$PROMO" -d 'active=false'

# Create a new promo code
EXP=$(date -u -v+90d +%s)
COUPON=$(curl -s -u "$SK:" -H 'Stripe-Version: 2024-04-10' \
  -X POST https://api.stripe.com/v1/coupons \
  --data-urlencode "percent_off=40" --data-urlencode "duration=once" \
  --data-urlencode "max_redemptions=10" --data-urlencode "name=Black Friday" \
  | grep -oE '"id":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
curl -s -u "$SK:" -H 'Stripe-Version: 2024-04-10' \
  -X POST https://api.stripe.com/v1/promotion_codes \
  --data-urlencode "coupon=$COUPON" --data-urlencode "code=BLACKFRIDAY40" \
  --data-urlencode "max_redemptions=10" --data-urlencode "expires_at=$EXP"
```

## When to deprecate

- **FOUNDING100** — the moment the first customer redeems. Reserve a
  fresh "FOUNDER100-2" if needed for a second strategic free-year deal.
- **CONFERENCE** — refresh per event. Disable after each conference.
- **EARLY50** — replace with a smaller discount (`LAUNCH25` at 25% off)
  once you've signed 5+ customers; the price discount narrative shifts
  from "early adopter" to "we're established now."
- **SOC2READY** — keep indefinitely; SOC 2 prep is a year-round trigger.
- **PARTNER25** — keep; this is a perpetual referral incentive.

Audit usage monthly via the Stripe dashboard → Coupons. Anything not
redeemed in 90 days, retire.
