"""Subscription billing for the Russian market (operator-billed, 99/270/399 ₽).

A provider-independent subscription service that lives next to the Stripe
code (`api/routers/payments.py`) without touching it. Its data — phone
numbers, payments, consents, device seats — belongs to a SEPARATE database
(`DATABASE_URL_BILLING`), because 152-ФЗ requires Russian users' personal
data to be stored on Russian soil, and the main Supabase/Railway stack is
not. The main API never sees a phone number: a device receives a signed
"pass" (entitlement token, `api/billing/entitlement.py`) that carries no
personal data.

Everything here is OFF by default. `BILLING_ENABLED=false` (the default)
mounts no route and runs nothing; `ROLE=billing` selects the deployment
that serves `/billing/v1`. See docs/BILLING.md.
"""
