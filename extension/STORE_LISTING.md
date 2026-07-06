# Chrome Web Store Listing

## Name
Cleanway — Protection from scam links
<!-- AUTHORITATIVE: this equals the manifest _locales extension_name — the string Chrome actually renders. To change it, edit extension/src/_locales/*/messages.json + rebuild. -->

## Short Description (132 chars max)
Automatic phishing detection + privacy audit. 16 signals + ML. Your browsing data never leaves your device.

## Detailed Description

Cleanway automatically checks every link you encounter against 16 threat-intelligence signals — 10 named blocklist feeds plus reputation, visual identity, ML model, and heuristics — trained to catch phishing.

WHAT IT DOES:
- Scans every link on every page — red, yellow, green badges show safety at a glance
- Right-click any link to check it, or any page for a Privacy Audit
- Finds phishing links in your Gmail and Outlook that your browser missed
- Most checks resolve instantly on-device against a local blocklist; only unknown domains query the server

PRIVACY FIRST:
Your browsing data NEVER leaves your device. We only see domain names for safety checks — never full URLs, never page content, never your browsing history. Even if our servers are breached, attackers learn nothing about your online life.

16 THREAT-INTELLIGENCE SIGNALS:
10 named blocklist feeds (Google Safe Browsing, URLhaus, PhishStats, abuse.ch ThreatFox, Spamhaus DBL, SURBL, AlienVault OTX, IPQualityScore, MalwareBazaar, Feodo Tracker) + reputation (Tranco popularity rank) + visual identity (brand favicon hashes, typosquat watchtower) + CatBoost ML model + LLM judge on ambiguous verdicts + heuristics.

PRIVACY AUDIT:
Right-click any page to see what data it collects: trackers, cookies, data collection forms, fingerprinting attempts. Grade A through F. Runs 100% on your device.

FREE PLAN:
- 10 API checks per day
- Unlimited local checks (bloom filter)
- Privacy Audit (grade only)
- Link safety badges

PERSONAL PLAN ($4.99/mo):
- Unlimited checks
- Full Privacy Audit breakdown
- Weekly Security Report
- Security Score with tips

FAMILY PLAN ($9.99/mo):
- Everything in Personal
- Up to 6 devices
- Family Hub with E2E encrypted alerts

PERMISSIONS EXPLAINED:
- "Access to the page you're actively using + Gmail / Outlook / Yahoo Mail" — Required to badge links inline. Domain is extracted on-device; only the domain is checked, never page content. (activeTab + host access scoped to api.cleanway.ai and the 3 webmail hosts — NOT all websites.)
- "Storage" — Stores your settings and check history ON YOUR DEVICE only.

Open source clients. Privacy policy: https://cleanway.ai/privacy-policy

## Category
Productivity

## Language
English

## Website
https://cleanway.ai

## Support URL
https://cleanway.ai/support

## Privacy Policy URL
https://cleanway.ai/privacy-policy
