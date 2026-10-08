# Chrome Web Store Listing

## Name
Cleanway — Protection from scam links
<!-- AUTHORITATIVE: this equals the manifest _locales extension_name — the string Chrome actually renders. To change it, edit extension/src/_locales/*/messages.json + rebuild. -->

## Short Description (132 chars max)
Automatic phishing detection + privacy audit. 16 signals + ML. We check domains, not your full URLs or page content.

## Detailed Description

Cleanway automatically checks every link you encounter against 16 threat-intelligence signals — 10 named blocklist feeds plus reputation, visual identity, ML model, and heuristics — trained to catch phishing.

WHAT IT DOES:
- Scans every link on every page — red, yellow, green badges show safety at a glance
- Right-click any link to check it, or any page for a Privacy Audit
- Optional, off until you switch it on in Settings: checks the emails you open in Gmail, Outlook and Yahoo Mail for phishing
- Most checks resolve instantly on-device against a local blocklist; only unknown domains query the server

PRIVACY FIRST:
For link and page checks we only see domain names — never full URLs, never page content, never your browsing history. The one exception is the optional email scanner: it is off until you switch it on in Settings, and while it is on, each email you open in Gmail, Outlook or Yahoo Mail (its subject, sender, reply-to, text and links) is sent to our server to be checked for phishing and is not stored.

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
- "Read and change data on the websites you visit" — Required to badge links inline on every page. The domain is extracted on-device; only the domain of an unknown link is checked with api.cleanway.ai, never page content.
- Optional: "Gmail / Outlook / Yahoo Mail" — Requested only when you switch on "Scan emails I open in Gmail, Outlook and Yahoo for phishing" in Settings (off by default). While it is on, each email you open there is sent to api.cleanway.ai — the subject, the sender's name and address, the Reply-To address, the text, and the address and text of each link (not the HTML). It is checked for phishing and not stored; the domains of its links are also checked with Google Safe Browsing. Switch it off any time: scanning stops at once and the access is given back.
- "Scripting" — Turns the optional email scanner on and off: it is injected into those three mail sites only while you have it switched on.
- "Storage" — Stores your settings and check history ON YOUR DEVICE only. If you sign in (optional, for Family Hub and settings sync), the extension also keeps its own Cleanway sign-in tokens there; "Sign out" in Settings deletes them.

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
